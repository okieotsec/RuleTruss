"""Assemble packets into bidirectional flows and infer which side initiated each one.

The direction of a flow is an inference with a stated confidence and the evidence behind it. A capture that starts
mid-conversation, sees only one direction, or sees UDP without a handshake cannot prove who initiated, and the result
says so. Silence in a capture is never read as absence: see coverage_notes().
"""
import ipaddress
import os

from .. import limits
from ..model import CaptureInfo, Evidence, Flow
from . import appid
from .fingerprint import DeviceTracker
from .reader import LINK_NAMES, CaptureStats, iter_packets, sniff

TH_FIN, TH_SYN, TH_RST, TH_ACK = 0x01, 0x02, 0x04, 0x10
TCP_IDLE_SPLIT = 3600.0
UDP_IDLE_SPLIT = 120.0
SAMPLES_PER_DIRECTION = 3
EVIDENCE_PACKETS = 8
MIDSTREAM_WINDOW = 1.0


class _State:
    __slots__ = (
        "bytes",
        "closed",
        "decoded",
        "ends",
        "first_ts",
        "flags",
        "icmp",
        "key",
        "last_ts",
        "nums",
        "payload_seen",
        "pkts",
        "proto",
        "samples",
        "syn",
        "syn_seq",
        "synack",
        "truncated",
        "version",
        "vlan",
    )

    def __init__(self, key, packet):
        self.key = key
        self.proto = packet.proto
        self.version = packet.version
        self.ends = [(packet.src, packet.sport), (packet.dst, packet.dport)]
        self.pkts, self.bytes = [0, 0], [0, 0]
        self.first_ts = self.last_ts = packet.ts
        self.flags = [0, 0]
        self.syn = []                     # [(direction, packet number)] pure SYNs
        self.syn_seq = None
        self.synack = []
        self.closed = False
        self.samples, self.decoded = [], [0, 0]
        self.nums = []
        self.icmp = []
        self.vlan = packet.vlan
        self.payload_seen = False
        self.truncated = 0


def _key(packet):
    a, b = (packet.src, packet.sport or 0), (packet.dst, packet.dport or 0)
    return (packet.proto, *(sorted((a, b))))


class FlowTracker:
    def __init__(self, capture_id, source_id, max_flows=None):
        self.capture_id, self.source_id = capture_id, source_id
        self.max_flows = limits.MAX_FLOWS if max_flows is None else max_flows
        self.active = {}
        self.done = []
        self.dropped_flows = 0
        self.capture_start = None

    def add(self, packet):
        if self.capture_start is None:
            self.capture_start = packet.ts
        key = _key(packet)
        state = self.active.get(key)
        if state is not None and self._should_split(state, packet):
            self.done.append(state)
            del self.active[key]
            state = None
        if state is None:
            if len(self.active) + len(self.done) >= self.max_flows:
                self.dropped_flows += 1
                return
            state = _State(key, packet)
            self.active[key] = state
        direction = 0 if (packet.src, packet.sport) == state.ends[0] else 1
        state.pkts[direction] += 1
        state.bytes[direction] += len(packet.payload)
        state.last_ts = max(state.last_ts, packet.ts)
        if packet.truncated:
            state.truncated += 1
        if len(state.nums) < EVIDENCE_PACKETS:
            state.nums.append(packet.number)
        if packet.proto == "tcp":
            self._tcp(state, packet, direction)
        elif packet.proto in ("icmp", "icmp6") and len(state.icmp) < 6:
            state.icmp.append((direction, packet.number, packet.icmp_type, packet.icmp_code))
        if packet.payload:
            state.payload_seen = True
            if state.decoded[direction] < SAMPLES_PER_DIRECTION and packet.proto in ("tcp", "udp"):
                state.decoded[direction] += 1
                hits = appid.decode_payload(packet.proto, packet.payload, packet.sport, packet.dport)
                state.samples.append((direction, packet.number, hits))

    @staticmethod
    def _should_split(state, packet):
        if packet.proto == "tcp":
            pure_syn = packet.flags & TH_SYN and not packet.flags & TH_ACK
            if pure_syn and (state.closed or (state.synack and state.syn_seq is not None and packet.seq != state.syn_seq)):
                return True
            return packet.ts - state.last_ts > TCP_IDLE_SPLIT
        return packet.ts - state.last_ts > UDP_IDLE_SPLIT

    @staticmethod
    def _tcp(state, packet, direction):
        flags = packet.flags
        state.flags[direction] |= flags
        if flags & TH_SYN and not flags & TH_ACK:
            state.syn.append((direction, packet.number))
            if state.syn_seq is None:
                state.syn_seq = packet.seq
        elif flags & TH_SYN and flags & TH_ACK:
            state.synack.append((direction, packet.number))
        if flags & (TH_FIN | TH_RST):
            state.closed = True

    def finish(self):
        flows = []
        for index, state in enumerate(self.done + list(self.active.values()), start=1):
            flows.append(self._to_flow(state, f"{self.capture_id}-f{index}"))
        self.done, self.active = [], {}
        return flows

    # ------------------------------------------------------------ direction inference
    def _role_votes(self, state):
        votes = {0: 0, 1: 0}
        named = {}
        for direction, _number, hits in state.samples:
            for hit in hits:
                if hit.role == "client":
                    votes[direction] += 1
                    named.setdefault(direction, hit)
                elif hit.role == "server":
                    votes[1 - direction] += 1
                    named.setdefault(1 - direction, hit)
        return votes, named

    def _infer(self, state):
        """Return (initiator index or None, confidence, basis list, notes list)."""
        end = [f"{ip}:{port}" if port else ip for ip, port in state.ends]
        notes = []
        if state.proto == "tcp":
            syn_dirs = {d for d, _ in state.syn}
            if len(syn_dirs) == 1:
                d = next(iter(syn_dirs))
                number = next(n for dd, n in state.syn if dd == d)
                basis = [f"SYN (no ACK) sent by {end[d]} in packet {number}"]
                if any(dd == 1 - d for dd, _ in state.synack):
                    basis.append(f"SYN-ACK from {end[1 - d]} in packet "
                                 f"{next(n for dd, n in state.synack if dd == 1 - d)}: handshake answered")
                else:
                    notes.append("A SYN was seen but no SYN-ACK was captured: the connection may have been blocked, "
                                 "refused, or the reply path was not visible to the capture.")
                return d, "high", basis, notes
            if len(syn_dirs) == 2:
                first = min(state.syn, key=lambda item: item[1])
                notes.append("SYNs were seen from both sides (simultaneous open, or two separate attempts merged).")
                return first[0], "medium", [f"first SYN was from {end[first[0]]} in packet {first[1]}",
                                            "SYN also seen from the other side"], notes
            if state.synack:
                d, number = state.synack[0]
                notes.append("The initial SYN was not captured (asymmetric visibility or the capture started mid-handshake).")
                return 1 - d, "medium", [f"SYN-ACK sent by {end[d]} in packet {number}, so {end[1 - d]} sent the SYN"], notes
            return self._midstream(state, end, notes)
        if state.proto in ("icmp", "icmp6"):
            echo_req = (8, 128)
            echo_rep = (0, 129)
            for d, number, itype, _code in state.icmp:
                if itype in echo_req:
                    return d, "high", [f"ICMP echo request sent by {end[d]} in packet {number}"], notes
            for d, number, itype, _code in state.icmp:
                if itype in echo_rep:
                    notes.append("Only an echo reply was captured; the request was not.")
                    return 1 - d, "medium", [f"ICMP echo reply sent by {end[d]} in packet {number}"], notes
            notes.append("ICMP control or error message: it reports on another conversation and does not itself initiate one.")
            return 0, "unknown", [f"first ICMP message type {state.icmp[0][2] if state.icmp else '?'} sent by {end[0]}"], notes
        return self._datagram(state, end, notes)

    def _midstream(self, state, end, notes):
        notes.append("No SYN or SYN-ACK was captured: the capture began after this connection was set up, so the "
                     "initiator is not proven.")
        votes, named = self._role_votes(state)
        if votes[0] != votes[1]:
            d = 0 if votes[0] > votes[1] else 1
            hit = named.get(d)
            return d, "medium", [f"payload semantics: {end[d]} sent a {hit.name} request-type message"], notes
        guess = self._port_heuristic(state)
        if guess is not None:
            return guess[0], "low", [guess[1]], notes
        return 0, "unknown", ["no handshake and no port or payload evidence to tell client from server"], notes

    @staticmethod
    def _port_heuristic(state):
        (_, p0), (_, p1) = state.ends
        if p0 is None or p1 is None:
            return None
        known0, known1 = (state.proto, p0) in appid.PORT_HINTS, (state.proto, p1) in appid.PORT_HINTS
        if known0 != known1:
            server = 0 if known0 else 1
            return 1 - server, (f"port {(p0, p1)[server]} is a well-known service port, so that side is assumed to be the "
                                "server (heuristic, not proven)")
        if p0 < 1024 <= p1 or p1 < 1024 <= p0:
            server = 0 if p0 < p1 else 1
            return 1 - server, (f"port {(p0, p1)[server]} is below 1024 and the other is not, so that side is assumed to be "
                                "the server (heuristic)")
        return None

    def _datagram(self, state, end, notes):
        votes, named = self._role_votes(state)
        if votes[0] != votes[1]:
            d = 0 if votes[0] > votes[1] else 1
            hit = named.get(d)
            return d, "medium", [f"payload semantics: {end[d]} sent a {hit.name} request-type message"], notes
        try:
            dst0 = ipaddress.ip_address(state.ends[1][0])
        except ValueError:
            dst0 = None
        if dst0 is not None and (dst0.is_multicast or str(dst0).endswith(".255")):
            return 0, "medium", [f"{end[0]} sent to {dst0}, a multicast or broadcast address"], [
                ("Multicast and broadcast datagrams are one-to-many; the sender is the source, not a client of a "
                 "session.")]
        two_way = state.pkts[0] and state.pkts[1]
        near_start = self.capture_start is not None and state.first_ts - self.capture_start < MIDSTREAM_WINDOW
        guess = self._port_heuristic(state) if state.proto in ("udp", "tcp") else None
        if two_way:
            if guess is not None and guess[0] == 0 and not near_start:
                return 0, "medium", [f"first datagram seen was from {end[0]} and the port pattern agrees: {guess[1]}"], notes
            if guess is not None and guess[0] == 1 - 0 and guess[0] != 0:
                notes.append("The first datagram seen came from the side that looks like the server; the capture may have "
                             "started in the middle of the exchange.")
                return 1, "low", [guess[1]], notes
            if near_start:
                notes.append("The flow begins right at the start of the capture, so the first datagram may not be the first "
                             "of the conversation.")
            return 0, "low", [f"first datagram seen was from {end[0]}; UDP has no handshake to prove who started"], notes
        notes.append("Only one direction was captured; this may be a reply whose request is outside the capture, or "
                     "traffic that is never answered.")
        return 0, "low", [f"only datagrams from {end[0]} were seen"], notes

    def _to_flow(self, state, flow_id):
        initiator, confidence, basis, notes = self._infer(state)
        if initiator is None:
            initiator = 0
        responder = 1 - initiator
        (src_ip, src_port), (dst_ip, dst_port) = state.ends[initiator], state.ends[responder]
        icmp_type = icmp_code = None
        if state.icmp:
            first = state.icmp[0]
            icmp_type, icmp_code = first[2], first[3]
        apps, app_notes, hostnames = appid.identify(state.proto, state.samples, (src_port, dst_port), state.payload_seen)
        notes = notes + app_notes
        if state.proto == "tcp" and (state.pkts[0] == 0 or state.pkts[1] == 0) and not any("SYN was seen" in n for n in notes):
            notes.append("Only one direction of this connection was captured (asymmetric visibility), so replies, or the requests they "
                         "answer, are missing from what is analysed.")
        if state.truncated:
            notes.append(f"{state.truncated} packet(s) in this flow were cut short by the capture (snap length), so payload "
                         "decoding may be incomplete.")
        flags_seen = []
        for d, label in ((initiator, "initiator"), (responder, "responder")):
            names = [n for bit, n in ((TH_SYN, "SYN"), (TH_ACK, "ACK"), (TH_FIN, "FIN"), (TH_RST, "RST")) if state.flags[d] & bit]
            if names:
                flags_seen.append(f"{label}: {'+'.join(names)}")
        evidence = [Evidence(self.source_id, "packet", ",".join(str(n) for n in state.nums)
                             + (", ..." if sum(state.pkts) > len(state.nums) else ""),
                             f"{state.proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port}, {sum(state.pkts)} packets")]
        return Flow(flow_id=flow_id, source_id=self.source_id, ip_version=state.version, proto=state.proto,
                    initiator=src_ip, responder=dst_ip, initiator_port=src_port, responder_port=dst_port,
                    direction_confidence=confidence, direction_basis=basis, pkts_fwd=state.pkts[initiator],
                    pkts_rev=state.pkts[responder], bytes_fwd=state.bytes[initiator], bytes_rev=state.bytes[responder],
                    first_ts=state.first_ts, last_ts=state.last_ts, icmp_type=icmp_type, icmp_code=icmp_code, apps=apps,
                    tcp_flags_seen=flags_seen, hostnames=hostnames, notes=notes, evidence=evidence, vlan=state.vlan)


def coverage_notes(info, stats, dropped):
    """Plain statements about what this capture can and cannot show."""
    notes = [("Absence from this capture is not evidence of absence: devices, subnets, ports and protocols that never "
              "appear may simply not have been visible to the capture point or active during this period.")]
    if info.observation_point:
        notes.append(f"Observation point (as supplied by the user): {info.observation_point}. Traffic that does not pass "
                     "that point is not seen, for example traffic between two devices on a switch port that is not mirrored.")
    else:
        notes.append("No observation point was supplied, so it is unknown which network segment this capture covers.")
    if stats.fragments:
        notes.append(f"{stats.fragments} IP fragment(s) were not reassembled; their traffic is not attributed to a flow.")
    if stats.errors:
        notes.append(f"{stats.errors} packet(s) could not be decoded and were skipped.")
    if stats.truncated:
        notes.append(f"{stats.truncated} packet(s) were truncated by the capture's snap length.")
    if stats.skipped_non_ip:
        notes.append(f"{stats.skipped_non_ip} non-IP frame(s) were not analysed as traffic; ARP and LLDP among them were read for "
                     "device identification.")
    if dropped:
        notes.append(f"The flow limit was reached: {dropped:,} further flow(s) were not recorded.")
    notes.extend(stats.limits_hit)
    return notes


def analyze_capture(path, capture_id, source_id, filename, observation_point=""):
    """Read a capture and return (CaptureInfo, [Flow])."""
    return analyze_capture_full(path, capture_id, source_id, filename, observation_point)[:2]


def analyze_capture_full(path, capture_id, source_id, filename, observation_point="", progress=None):
    """Read a capture and return (CaptureInfo, [Flow], DeviceFacts). `progress` is called as (packets, bytes consumed, file size)."""
    stats = CaptureStats()
    tracker = FlowTracker(capture_id, source_id)
    devices = DeviceTracker(source_id)
    fmt = sniff(path)
    for packet in iter_packets(path, stats, on_l2=devices.add_l2, progress=progress):
        tracker.add(packet)
        devices.add_packet(packet)
    flows = tracker.finish()
    info = CaptureInfo(capture_id=capture_id, filename=limits.clip(filename), format=fmt, size_bytes=os.path.getsize(path),
                       packets_read=stats.read, packets_decoded=stats.decoded,
                       packets_skipped=stats.skipped_non_ip + stats.errors, first_ts=stats.first_ts, last_ts=stats.last_ts,
                       link_types=[LINK_NAMES.get(stats.linktype, str(stats.linktype))], snaplen_truncated=stats.truncated,
                       observation_point=limits.clip(observation_point, 200), limits_hit=list(stats.limits_hit),
                       flows=len(flows))
    info.coverage_notes = coverage_notes(info, stats, tracker.dropped_flows)
    return info, flows, devices.facts()
