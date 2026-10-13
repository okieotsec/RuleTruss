"""Read PCAP and PCAPNG files with dpkt and decode each packet down to IP / transport headers.

Only the headers and a short payload prefix are kept. Nothing from a capture is ever executed or evaluated.
"""
import os
import struct
from dataclasses import dataclass

import dpkt

from .. import limits

PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
PAYLOAD_KEEP = 1500
DLT_NULL, DLT_EN10MB, DLT_RAW, DLT_LINUX_SLL, DLT_IPV4, DLT_IPV6, DLT_LINUX_SLL2, DLT_LOOP = 0, 1, 101, 113, 228, 229, 276, 108
DLT_RAW_ALT = 12
LINK_NAMES = {DLT_NULL: "null/loopback", DLT_EN10MB: "Ethernet", DLT_RAW: "raw IP", DLT_LINUX_SLL: "Linux cooked",
              DLT_LINUX_SLL2: "Linux cooked v2", DLT_IPV4: "raw IPv4", DLT_IPV6: "raw IPv6", DLT_LOOP: "OpenBSD loopback",
              DLT_RAW_ALT: "raw IP"}
DECODE_ERRORS = (dpkt.Error, struct.error, ValueError, IndexError, KeyError, AttributeError, TypeError)


@dataclass
class Packet:
    number: int
    ts: float
    version: int
    src: str
    dst: str
    proto: str                 # tcp, udp, icmp, icmp6, sctp or other:N
    sport: int = None
    dport: int = None
    flags: int = 0
    seq: int = 0
    payload: bytes = b""
    wire_len: int = 0
    icmp_type: int = None
    icmp_code: int = None
    vlan: int = None
    truncated: bool = False
    fragment: bool = False


class UnsupportedCapture(ValueError):
    """The file is not a PCAP or PCAPNG file, or is damaged beyond reading. Safe to show."""


def sniff(path):
    """Return 'pcap' or 'pcapng' from the file's magic bytes (never from its name)."""
    with open(path, "rb") as handle:
        magic = handle.read(4)
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    if magic in PCAP_MAGICS:
        return "pcap"
    raise UnsupportedCapture("this is not a PCAP or PCAPNG capture file (unrecognised file header)")


def _ip_text(raw):
    import ipaddress
    return str(ipaddress.ip_address(raw))


def _decode_ip(number, ts, ip, vlan):
    """Decode a dpkt IP/IP6 object to a Packet, or None for unsupported content."""
    if isinstance(ip, dpkt.ip.IP):
        version = 4
        proto_num = ip.p
        fragment = bool(ip.offset)
        more = bool(ip.mf)
        payload_len_expected = ip.len - (ip.hl * 4)
    else:
        version = 6
        proto_num = getattr(ip, "p", ip.nxt)
        fragment = False
        more = False
        payload_len_expected = ip.plen
    transport = ip.data
    src, dst = _ip_text(ip.src), _ip_text(ip.dst)
    packet = Packet(number, ts, version, src, dst, f"other:{proto_num}", vlan=vlan, wire_len=getattr(ip, "len", 0) or 0)
    packet.fragment = fragment
    if fragment:
        packet.truncated = False
        return packet
    raw_len = len(bytes(transport)) if not isinstance(transport, (bytes, bytearray)) else len(transport)
    packet.truncated = bool(payload_len_expected and raw_len < payload_len_expected and not more)
    if isinstance(transport, dpkt.tcp.TCP):
        packet.proto, packet.sport, packet.dport = "tcp", transport.sport, transport.dport
        packet.flags, packet.seq = transport.flags, transport.seq
        packet.payload = bytes(transport.data)[:PAYLOAD_KEEP]
    elif isinstance(transport, dpkt.udp.UDP):
        packet.proto, packet.sport, packet.dport = "udp", transport.sport, transport.dport
        packet.payload = bytes(transport.data)[:PAYLOAD_KEEP]
    elif isinstance(transport, dpkt.icmp.ICMP):
        packet.proto, packet.icmp_type, packet.icmp_code = "icmp", transport.type, transport.code
        packet.payload = bytes(transport.data)[:64]
    elif isinstance(transport, dpkt.icmp6.ICMP6):
        packet.proto, packet.icmp_type, packet.icmp_code = "icmp6", transport.type, transport.code
        packet.payload = bytes(transport.data)[:64]
    elif proto_num == 132:
        packet.proto = "sctp"
        raw = bytes(transport)
        if len(raw) >= 4:
            packet.sport, packet.dport = struct.unpack("!HH", raw[:4])
    return packet


def decode_frame(number, ts, buf, linktype):
    """Decode one captured frame. Returns a Packet, or None if it is not IP (ARP, STP, etc.)."""
    vlan = None
    if linktype == DLT_EN10MB:
        eth = dpkt.ethernet.Ethernet(buf)
        tags = getattr(eth, "vlan_tags", None)
        if tags:
            vlan = tags[0].id
        ip = eth.data
    elif linktype in (DLT_RAW, DLT_RAW_ALT, DLT_IPV4, DLT_IPV6):
        version = buf[0] >> 4 if buf else 0
        ip = dpkt.ip.IP(buf) if version == 4 else dpkt.ip6.IP6(buf) if version == 6 else None
    elif linktype == DLT_LINUX_SLL:
        ip = dpkt.sll.SLL(buf).data
    elif linktype == DLT_LINUX_SLL2:
        sll2 = dpkt.sll2.SLL2(buf)
        ip = sll2.data
    elif linktype in (DLT_NULL, DLT_LOOP):
        ip = dpkt.loopback.Loopback(buf).data
    else:
        raise UnsupportedCapture(f"link type {linktype} is not supported (Ethernet, raw IP, Linux cooked and loopback are)")
    if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
        return None
    return _decode_ip(number, ts, ip, vlan)


class CaptureStats:
    def __init__(self):
        self.read = 0
        self.decoded = 0
        self.skipped_non_ip = 0
        self.errors = 0
        self.fragments = 0
        self.truncated = 0
        self.first_ts = None
        self.last_ts = None
        self.linktype = None
        self.limits_hit = []
        self.interfaces = 1


def iter_packets(path, stats, max_packets=limits.MAX_PACKETS):
    """Yield Packet objects from a capture file, updating `stats`. Stops (and records it) at the packet limit."""
    size = os.path.getsize(path)
    if size > limits.MAX_CAPTURE_BYTES:
        raise limits.LimitExceeded(f"capture is {size:,} bytes; the limit is {limits.MAX_CAPTURE_BYTES:,}")
    kind = sniff(path)
    with open(path, "rb") as handle:
        try:
            reader = dpkt.pcapng.Reader(handle) if kind == "pcapng" else dpkt.pcap.Reader(handle)
        except (dpkt.Error, ValueError, struct.error) as error:
            raise UnsupportedCapture(f"the capture header could not be read: {error}") from error
        stats.linktype = reader.datalink()
        if stats.linktype not in LINK_NAMES:
            raise UnsupportedCapture(f"link type {stats.linktype} is not supported")
        number = 0
        try:
            for ts, buf in reader:
                number += 1
                stats.read = number
                if number > max_packets:
                    stats.limits_hit.append(f"stopped after {max_packets:,} packets; the rest of the file was not analysed")
                    stats.read = max_packets
                    return
                if stats.first_ts is None or ts < stats.first_ts:
                    stats.first_ts = ts
                if stats.last_ts is None or ts > stats.last_ts:
                    stats.last_ts = ts
                try:
                    packet = decode_frame(number, ts, buf, stats.linktype)
                except UnsupportedCapture:
                    raise
                except DECODE_ERRORS:
                    stats.errors += 1
                    continue
                if packet is None:
                    stats.skipped_non_ip += 1
                    continue
                if packet.fragment:
                    stats.fragments += 1
                if packet.truncated:
                    stats.truncated += 1
                stats.decoded += 1
                yield packet
        except (dpkt.Error, struct.error, ValueError, EOFError) as error:
            stats.limits_hit.append(f"the capture file ends abruptly or is damaged after packet {number} ({error}); "
                                    "packets before that point were analysed")
