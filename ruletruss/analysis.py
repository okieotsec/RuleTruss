"""Turn flows and configured policy into things a person can review.

Everything produced here keeps its origin: communications are OBSERVED, rule comparisons are CONFIGURED-versus-observed,
and nothing here proposes a change (that is migrate.py).
"""
import ipaddress
from dataclasses import dataclass, field

from . import netutil
from .evaluate import ALLOW, DENY, Probe, evaluate_connection
from .model import Subnet

CONF_RANK = {"high": 3, "medium": 2, "low": 1, "unknown": 0}
CONF_NAMES = {3: "high", 2: "medium", 1: "low", 0: "unknown"}
APP_RANK = {"confirmed": 3, "probable": 2, "possible": 1}
ICMP_TYPE_NAMES = {0: "echo reply", 3: "destination unreachable", 8: "echo request", 11: "time exceeded"}
ICMP6_TYPE_NAMES = {128: "echo request", 129: "echo reply", 1: "destination unreachable"}
PROTO_LABEL = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "icmp6": "ICMPv6", "sctp": "SCTP"}


@dataclass
class Context:
    """What the user told us: device labels and subnet definitions. Nothing here is inferred from traffic."""
    labels: dict = field(default_factory=dict)          # ip text to label
    subnets: list = field(default_factory=list)         # list[Subnet]

    def __post_init__(self):
        self._nets = []
        for s in self.subnets:
            self._nets.append((ipaddress.ip_network(s.cidr, strict=False), s))
        self._nets.sort(key=lambda item: -item[0].prefixlen)

    def subnet_of(self, ip):
        addr = ipaddress.ip_address(ip)
        for net, subnet in self._nets:
            if addr.version == net.version and addr in net:
                return subnet
        return None

    def short_name(self, ip):
        """'SCADA-1 10.20.0.10' (label first) or just the address: for one-line statements."""
        label = self.labels.get(ip, "")
        return f"{label} {ip}" if label else ip

    def label(self, ip):
        return self.labels.get(ip, "")

    def name(self, ip):
        """'10.20.1.15 (labelled "Engineering workstation")' or just the address."""
        label = self.label(ip)
        return f'{ip} (labelled "{label}")' if label else ip

    def zone_aliases(self, ip):
        """The zone names the user gave this address's subnet. 'outside|wan' names one segment in two products."""
        subnet = self.subnet_of(ip)
        return [z.strip() for z in subnet.zone.split("|") if z.strip()] if subnet and subnet.zone else []

    def zone_of(self, ip):
        aliases = self.zone_aliases(ip)
        return aliases[0] if aliases else None


def build_context(labels=None, subnets=None):
    subs = [s if isinstance(s, Subnet) else Subnet(**s) for s in (subnets or [])]
    return Context(dict(labels or {}), subs)


@dataclass
class Communication:
    comm_id: str
    initiator: str
    responder: str
    proto: str
    responder_port: int = None
    icmp_type: int = None
    flows: int = 0
    packets_fwd: int = 0
    packets_rev: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    direction_confidence: str = "unknown"
    direction_basis: list = field(default_factory=list)
    apps: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    flow_ids: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    replied: bool = False
    capture_ids: list = field(default_factory=list)


def aggregate(flows):
    """Group flows by (initiator, responder, protocol, responder port). Confidence is the weakest across the flows."""
    groups = {}
    for f in flows:
        key = (f.initiator, f.responder, f.proto, f.responder_port if f.proto in ("tcp", "udp", "sctp") else f.icmp_type)
        c = groups.get(key)
        if c is None:
            c = Communication(comm_id=f"k{len(groups) + 1}", initiator=f.initiator, responder=f.responder, proto=f.proto,
                              responder_port=f.responder_port, icmp_type=f.icmp_type, first_ts=f.first_ts,
                              last_ts=f.last_ts, direction_confidence="high")
            groups[key] = c
        c.flows += 1
        c.packets_fwd += f.pkts_fwd
        c.packets_rev += f.pkts_rev
        c.first_ts, c.last_ts = min(c.first_ts, f.first_ts), max(c.last_ts, f.last_ts)
        c.replied = c.replied or f.pkts_rev > 0
        if CONF_RANK[f.direction_confidence] < CONF_RANK[c.direction_confidence]:
            c.direction_confidence = f.direction_confidence
            c.direction_basis = list(f.direction_basis)
        elif not c.direction_basis:
            c.direction_basis = list(f.direction_basis)
        c.flow_ids.append(f.flow_id)
        if f.source_id not in c.capture_ids:
            c.capture_ids.append(f.source_id)
        if len(c.evidence) < 6:
            c.evidence.extend(f.evidence[:1])
        for note in f.notes:
            if note not in c.notes and len(c.notes) < 8:
                c.notes.append(note)
        for app in f.apps:
            existing = next((a for a in c.apps if a.name == app.name), None)
            if existing is None:
                c.apps.append(app)
            elif APP_RANK[app.confidence] > APP_RANK[existing.confidence]:
                c.apps[c.apps.index(existing)] = app
    out = sorted(groups.values(), key=lambda c: (c.initiator, c.responder, c.proto, c.responder_port or 0))
    for c in out:
        c.apps.sort(key=lambda a: -APP_RANK[a.confidence])
    return out


def _port_text(c):
    if c.proto in ("icmp", "icmp6"):
        names = ICMP6_TYPE_NAMES if c.proto == "icmp6" else ICMP_TYPE_NAMES
        if c.icmp_type is None:
            return "ICMP messages"
        return f"{PROTO_LABEL[c.proto]} type {c.icmp_type} ({names.get(c.icmp_type, 'other')})"
    return f"destination port {c.responder_port}" if c.responder_port is not None else "an unknown port"


def explain_short(c, ctx):
    """The same statement in one line: who started what with whom, on what, and how sure we are. Details live in the full text."""
    proto = PROTO_LABEL.get(c.proto, c.proto.upper())
    src, dst = ctx.short_name(c.initiator), ctx.short_name(c.responder)
    count = f"{c.flows} {proto} {'connection' if c.proto in ('tcp', 'sctp') else 'flow'}{'s' if c.flows != 1 else ''}"
    where = _port_text(c).replace("destination port", "port")
    if c.direction_confidence == "high":
        lead = f"{src} initiated {count} to {dst} on {where}"
    elif c.direction_confidence == "medium":
        lead = f"{src} most likely initiated {count} to {dst} on {where}"
    elif c.direction_confidence == "low":
        lead = f"{src} and {dst} exchanged {proto} on {where}; initiator unclear"
    else:
        lead = f"{src} and {dst} exchanged {proto} on {where}; initiator unknown"
    parts = [lead]
    best = c.apps[0] if c.apps else None
    if best is not None:
        parts.append({"confirmed": f"{best.name} identified by decoding", "probable": f"{best.name} probable",
                      "possible": f"{best.name} possible (port number only)"}[best.confidence])
    else:
        parts.append("application not identified")
    if c.direction_confidence in ("medium", "low", "unknown"):
        parts.append(f"direction {c.direction_confidence} confidence")
    if not c.replied and c.proto == "tcp":
        parts.append("no reply seen")
    return " \u00b7 ".join(parts) + "."


def explain_communication(c, ctx):
    """One plain-language paragraph for a communication, matching how confident the evidence is."""
    proto = PROTO_LABEL.get(c.proto, c.proto.upper())
    src, dst = ctx.name(c.initiator), ctx.name(c.responder)
    count = f"{c.flows} {proto} connection{'s' if c.flows != 1 else ''}" if c.proto in ("tcp", "sctp") else \
        f"{c.flows} {proto} flow{'s' if c.flows != 1 else ''}"
    where = _port_text(c)
    if c.direction_confidence == "high":
        lead = f"{src} initiated {count} to {dst} on {where}."
    elif c.direction_confidence == "medium":
        why = c.direction_basis[0] if c.direction_basis else "indirect evidence"
        lead = f"{src} most likely initiated {count} to {dst} on {where} ({why})."
    elif c.direction_confidence == "low":
        why = c.direction_basis[0] if c.direction_basis else "weak evidence"
        lead = (f"{src} and {dst} exchanged {proto} traffic on {where}; {c.initiator} appears to be the initiating side, "
                f"but with low confidence ({why}).")
    else:
        lead = f"{src} and {dst} exchanged {proto} traffic on {where}; which side initiated could not be determined."
    parts = [lead]
    confirmed = [a for a in c.apps if a.confidence == "confirmed"]
    probable = [a for a in c.apps if a.confidence == "probable"]
    possible = [a for a in c.apps if a.confidence == "possible"]
    if confirmed:
        parts.append(f"{confirmed[0].name} was identified from packet decoding ({confirmed[0].basis}).")
    elif probable:
        parts.append(f"{probable[0].name} is probable ({probable[0].basis}).")
    elif possible:
        parts.append(f"{possible[0].name} is possible, because of the port number only; the application was not confirmed "
                     f"({possible[0].basis}).")
    else:
        parts.append("The application could not be identified from the captured payload.")
    if not c.replied and c.proto == "tcp":
        parts.append("No reply was captured from the responder.")
    parts.extend(c.notes[:3])
    return " ".join(parts)


# ------------------------------------------------------------------ inventory and matrix

def inventory(flows, ctx, extra_ips=()):
    """Devices and subnets seen, with counts only. A device's role is never inferred from its traffic.

    `extra_ips` are addresses seen without any flow (for example only in ARP or LLDP); they get a row with zero counts.
    """
    devices = {}
    for ip in extra_ips:
        devices[ip] = {"ip": ip, "label": ctx.label(ip), "initiated_flows": 0, "received_flows": 0, "peers_initiated_to": set(),
                       "peers_received_from": set(), "uncertain_direction": 0}
    for f in flows:
        for ip, outgoing in ((f.initiator, True), (f.responder, False)):
            d = devices.setdefault(ip, {"ip": ip, "label": ctx.label(ip), "initiated_flows": 0, "received_flows": 0,
                                        "peers_initiated_to": set(), "peers_received_from": set(), "uncertain_direction": 0})
            if outgoing:
                d["initiated_flows"] += 1
                d["peers_initiated_to"].add(f.responder)
            else:
                d["received_flows"] += 1
                d["peers_received_from"].add(f.initiator)
            if f.direction_confidence in ("low", "unknown"):
                d["uncertain_direction"] += 1
    out = []
    for ip, d in sorted(devices.items(), key=lambda item: netutil.ip_sort_key(item[0])):
        subnet = ctx.subnet_of(ip)
        out.append({"ip": ip, "label": d["label"], "subnet": subnet.cidr if subnet else "",
                    "subnet_label": subnet.label if subnet else "",
                    "initiated_flows": d["initiated_flows"], "received_flows": d["received_flows"],
                    "peers_initiated_to": len(d["peers_initiated_to"]), "peers_received_from": len(d["peers_received_from"]),
                    "uncertain_direction_flows": d["uncertain_direction"],
                    "note": "Counts of what this capture saw. A device's function is not inferred from its traffic."})
    subnets = {}
    for d in out:
        key = d["subnet"] or "(not in a defined subnet)"
        s = subnets.setdefault(key, {"subnet": key, "label": d["subnet_label"], "devices": 0})
        s["devices"] += 1
    return {"devices": out, "subnets": sorted(subnets.values(), key=lambda s: s["subnet"])}


def matrix(comms, ctx):
    """Initiating subnet by responding subnet. Each cell counts communications and connections; direction is preserved."""
    cells = {}
    for c in comms:
        a = ctx.subnet_of(c.initiator)
        b = ctx.subnet_of(c.responder)
        key = (a.cidr if a else "(undefined)", b.cidr if b else "(undefined)")
        cell = cells.setdefault(key, {"from": key[0], "to": key[1], "communications": 0, "flows": 0, "low_confidence": 0})
        cell["communications"] += 1
        cell["flows"] += c.flows
        if c.direction_confidence in ("low", "unknown"):
            cell["low_confidence"] += 1
    return sorted(cells.values(), key=lambda x: (x["from"], x["to"]))


# ------------------------------------------------------------------ observed versus configured

WHY_KEYS = (("application", "application condition"), ("identity", "identity condition"), ("schedule", "schedule"),
            ("unresolved", "unresolved object"), ("unavailable information", "unknown zone or unresolved object"),
            ("unreadable", "unreadable entry"), ("reflexive", "reflexive ACL"), ("interface", "unknown interface"))


def _why_short(decision):
    """A few words for why a decision is undecidable."""
    text = " ".join(decision.uncertain or [decision.basis]).lower()
    reasons = [label for key, label in WHY_KEYS if key in text]
    return ", ".join(dict.fromkeys(reasons)) or "an unsupported condition"


def zone_for(ip, ctx, policy):
    """The zone/interface of an address in this policy's own vocabulary.

    The user's subnet zone is used when the policy has an interface or zone of that name (a subnet can list aliases such as
    'outside|wan'); otherwise a unique match on the policy's interface networks decides; otherwise the zone is unknown.
    """
    aliases = ctx.zone_aliases(ip)
    known = [a for a in aliases if a in policy.interfaces]
    if known:
        return known[0]
    if aliases and not policy.interfaces:
        return aliases[0]
    addr = ipaddress.ip_address(ip)
    matches = []
    for name, info in policy.interfaces.items():
        for net in info.get("nets", []):
            n = ipaddress.ip_network(net, strict=False)
            if n.version == addr.version and addr in n:
                matches.append((n.prefixlen, name))
    if not matches:
        return _external_zone(policy, addr)
    best = max(p for p, _ in matches)
    top = {n for p, n in matches if p == best}
    return next(iter(top)) if len(top) == 1 else None


def _same_segment(policy, a, b):
    """True when two addresses are in the same one of the policy's networks (so they do not pass the gateway)."""
    x, y = ipaddress.ip_address(a), ipaddress.ip_address(b)
    for info in policy.interfaces.values():
        for net in info.get("nets", []):
            n = ipaddress.ip_network(net, strict=False)
            if n.version == x.version == y.version and x in n and y in n:
                return True
    return False


def _crosses(policy, probe, c):
    """Does this traffic pass the device the policy came from, as far as zones can tell?"""
    if probe.src_zone != probe.dst_zone or policy.vendor == "panos":
        return True
    return policy.vendor == "unifi" and not _same_segment(policy, c.initiator, c.responder)


PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8", "224.0.0.0/4", "0.0.0.0/8",
    "fc00::/7", "fe80::/10", "::1/128", "ff00::/8")]


def _external_zone(policy, addr):
    """UniFi: an address outside every known network that is not private, local or multicast belongs to External (the Internet side).

    Documentation ranges (198.51.100.0/24 and so on) count as Internet here, because examples use them for it.
    """
    if policy.vendor != "unifi" or any(addr in net for net in PRIVATE_NETS if net.version == addr.version):
        return None
    for name, info in policy.interfaces.items():
        if name.lower() == "external" and info.get("origin") == "SYSTEM_DEFINED":
            return name
    return None


def probe_for(c, ctx, policy):
    proto = c.proto
    return Probe(src=c.initiator, dst=c.responder, proto=proto,
                 sport=None, dport=c.responder_port if proto in ("tcp", "udp", "sctp") else None,
                 icmp_type=c.icmp_type if proto in ("icmp", "icmp6") else None,
                 icmp_code=0 if proto in ("icmp", "icmp6") and c.icmp_type is not None else None,
                 src_zone=zone_for(c.initiator, ctx, policy), dst_zone=zone_for(c.responder, ctx, policy))


def compare_observed(policy, comms, ctx):
    """For every observed communication: what does the configured policy do with it?"""
    rows = []
    hits = {}
    for c in comms:
        probe = probe_for(c, ctx, policy)
        forward, reply = evaluate_connection(policy, probe)
        if forward.rule_id:
            hits.setdefault(forward.rule_id, []).append(c.comm_id)
        row = {"comm_id": c.comm_id, "outcome": forward.outcome, "rule_id": forward.rule_id, "rule": forward.original_id,
               "basis": forward.basis, "uncertain": forward.uncertain,
               "zones": [probe.src_zone, probe.dst_zone], "evidence": forward.evidence, "return_path": None,
               "crosses_device": bool(probe.src_zone and probe.dst_zone and _crosses(policy, probe, c)),
               "direction_confidence": c.direction_confidence}
        if reply is not None:
            row["return_path"] = {"outcome": reply.outcome, "rule": reply.original_id, "basis": reply.basis,
                                  "kind": "zone pair" if policy.default_mode == "zone_pairs" else "stateless"}
        if forward.outcome == ALLOW:
            row["reading"] = "Observed traffic is permitted by the configured policy."
            if c.direction_confidence in ("low", "unknown"):
                row["reading"] += " The initiating side is uncertain, so the reverse direction should be checked as well."
        elif forward.outcome == DENY:
            row["reading"] = ("Observed traffic would be denied by this configuration. Either the traffic does not pass "
                              "through this device, the capture was taken before enforcement, the export is not what is "
                              "running, or the zones/subnets you defined do not match; the capture alone cannot tell which.")
        else:
            row["reading"] = "Cannot be decided from the export: " + ("; ".join(forward.uncertain[:3]) or forward.basis)
        if row["return_path"] and row["return_path"]["outcome"] != ALLOW:
            row["reading"] += (" A policy for the reverse zone pair matches the replies and blocks them (it applies to all connection "
                               "states), so the connection would not work."
                               if policy.default_mode == "zone_pairs" else
                               " The policy is stateless and the reply direction is not permitted, so the connection would not work.")
        row["reading_short"] = {ALLOW: "Permitted", DENY: "Would be denied"}.get(forward.outcome, "Cannot decide: " + _why_short(forward))
        if row["return_path"] and row["return_path"]["outcome"] != ALLOW:
            row["reading_short"] += "; reply path blocked" if row["return_path"]["outcome"] == DENY else "; reply path uncertain"
        if forward.outcome == ALLOW and c.direction_confidence in ("low", "unknown"):
            row["reading_short"] += "; initiator uncertain"
        rows.append(row)
    return rows, hits


def unobserved_rules(policy, hits):
    """Enabled allow rules that no observed communication matched first. This does not show the rule is unused."""
    note = ("No traffic in the supplied captures matched this rule first. That does not show it is unused: the capture "
            "may not cover the period, location or protocol that needs it.")
    out = []
    for r in policy.rules:
        if (r.enabled and r.action == "allow" and r.rule_id not in hits and r.extra.get("stage") != "unbound"
                and r.extra.get("new_connections") is not False):
            out.append({"rule_id": r.rule_id, "rule": r.original_id, "src": r.src.text(), "dst": r.dst.text(),
                        "svc": r.svc.text(), "note": note})
    return out


# ------------------------------------------------------------------ static rule analysis

def _nets(addr):
    return [ipaddress.ip_network(n, strict=False) for n in addr.nets]


def addr_covers(outer, inner):
    """True when every address in `inner` is surely in `outer`. Conservative: unknowns give False."""
    if outer.negate or inner.negate or outer.unresolved:
        return False
    if outer.any:
        return True
    if inner.any:
        return False
    if inner.unresolved or not inner.nets:
        return False
    outs = _nets(outer)
    return all(any(n.version == o.version and n.subnet_of(o) for o in outs) for n in _nets(inner))


def _ranges_cover(outer, inner):
    if outer is None:
        return True
    if inner is None:
        return False
    return netutil.ranges_subset(inner, outer)


def entry_covers(a, b):
    if a.established and not b.established:
        return False
    if a.proto != "ip" and a.proto != b.proto:
        return False
    if a.icmp_type is not None and a.icmp_type != b.icmp_type:
        return False
    if a.icmp_code is not None and a.icmp_code != b.icmp_code:
        return False
    return _ranges_cover(a.sports, b.sports) and _ranges_cover(a.dports, b.dports)


def svc_covers(outer, inner):
    if outer.unresolved:
        return False
    if outer.any:
        return True
    if inner.any or inner.unresolved or not inner.entries:
        return False
    return all(any(entry_covers(a, b) for a in outer.entries) for b in inner.entries)


def zones_cover(outer, inner):
    return not outer or (bool(inner) and set(inner) <= set(outer))


def _scope(rule):
    return rule.extra.get("stage"), rule.extra.get("bind"), rule.extra.get("acl")


def _states(rule):
    states = rule.extra.get("states")
    return None if states is None else set(states)


def states_cover(a, b):
    """Connection states (UniFi): does rule `a` match every state rule `b` matches? None means all states."""
    sa, sb = _states(a), _states(b)
    if sa is None:
        return True
    return sb is not None and sb <= sa


def states_overlap(a, b):
    sa, sb = _states(a), _states(b)
    return sa is None or sb is None or bool(sa & sb)


def rule_covers(a, b):
    """Does rule `a` match everything that rule `b` matches, with no extra conditions of its own?"""
    if a.condition_unknowns():
        return False
    if not states_cover(a, b):
        return False
    a_type = a.extra.get("rule_type", "universal")
    if a_type != "universal" and a_type != b.extra.get("rule_type"):
        return False
    if _scope(a) != _scope(b):
        return False
    return (zones_cover(a.src_zones, b.src_zones) and zones_cover(a.dst_zones, b.dst_zones) and addr_covers(a.src, b.src)
            and addr_covers(a.dst, b.dst) and svc_covers(a.svc, b.svc))


def covers_everything(addr):
    """True for 'any' and for an explicit 0.0.0.0/0 or ::/0 (how some products write 'any' for one address family)."""
    if addr.negate or addr.unresolved:
        return False
    return addr.any or any(n in ("0.0.0.0/0", "::/0") for n in addr.nets)


def _overlap_addr(a, b):
    if a.negate or b.negate or a.unresolved or b.unresolved:
        return True            # cannot rule out
    if a.any or b.any:
        return True
    return any(x.version == y.version and (x.subnet_of(y) or y.subnet_of(x)) for x in _nets(a) for y in _nets(b))


def _overlap_svc(a, b):
    if a.unresolved or b.unresolved or a.any or b.any:
        return True
    for x in a.entries:
        for y in b.entries:
            if x.proto not in ("ip", y.proto) and y.proto != "ip":
                continue
            if x.icmp_type is not None and y.icmp_type is not None and x.icmp_type != y.icmp_type:
                continue
            if x.dports is not None and y.dports is not None and not netutil.ranges_overlap(x.dports, y.dports):
                continue
            return True
    return False


def rule_overlap(a, b):
    za = not a.src_zones or not b.src_zones or set(a.src_zones) & set(b.src_zones)
    zb = not a.dst_zones or not b.dst_zones or set(a.dst_zones) & set(b.dst_zones)
    return bool(za and zb and states_overlap(a, b) and _overlap_addr(a.src, b.src) and _overlap_addr(a.dst, b.dst)
                and _overlap_svc(a.svc, b.svc))


def _predefined(rule):
    """A policy the platform itself defines (UniFi: SYSTEM_DEFINED, DERIVED, ORCHESTRATED), not one the owner wrote."""
    return rule.extra.get("origin") not in (None, "", "USER_DEFINED")


def analyze_rules(policy, max_pairs=2_000_000):
    """Shadowed, redundant and conflicting rules, plus rules that are very broad or cannot be evaluated."""
    findings = []
    active = [r for r in policy.rules if r.enabled and r.extra.get("stage") != "unbound" and r.extra.get("new_connections") is not False]
    groups = {}
    for r in active:
        groups.setdefault((r.extra.get("stage"), r.extra.get("bind"), r.extra.get("acl")), []).append(r)
    pairs = 0
    for rules in groups.values():
        rules.sort(key=lambda r: r.position)
        for j, later in enumerate(rules):
            for earlier in rules[:j]:
                pairs += 1
                if pairs > max_pairs:
                    findings.append({"kind": "limit", "severity": "info", "message": "Rule comparison stopped early because of "
                                     "the size of the rule base; later rules were not checked against each other."})
                    break
                if rule_covers(earlier, later):
                    same = earlier.action == later.action
                    findings.append({
                        "kind": "redundant" if same else "shadowed", "severity": "warning" if not same else "info",
                        "rule_id": later.rule_id, "rule": later.original_id, "by_rule_id": earlier.rule_id, "by_rule": earlier.original_id,
                        "message": (f"Rule {later.original_id} ({later.action}) can never match: everything it covers is already "
                                    f"handled by earlier rule {earlier.original_id} ({earlier.action})."
                                    + ("" if same else " The two rules have different actions, so this is a conflict whose later "
                                       "rule is ignored.")),
                        "evidence": [*earlier.evidence[:1], *later.evidence[:1]]})
                    break
                catch_all_deny = ((later.action == "deny" and covers_everything(later.src) and covers_everything(later.dst)
                                   and later.svc.any)
                                  or later.extra.get("default_policy"))      # a built-in final policy is meant to follow specific ones
                if earlier.action != later.action and not catch_all_deny and rule_overlap(earlier, later):
                    findings.append({
                        "kind": "conflict", "severity": "info", "rule_id": later.rule_id, "rule": later.original_id,
                        "by_rule_id": earlier.rule_id, "by_rule": earlier.original_id,
                        "message": (f"Rules {earlier.original_id} ({earlier.action}) and {later.original_id} ({later.action}) "
                                    "overlap with different actions; the earlier one wins where they overlap."),
                        "evidence": [*earlier.evidence[:1], *later.evidence[:1]]})
    for r in policy.rules:
        if not r.enabled:
            findings.append({"kind": "disabled", "severity": "info", "rule_id": r.rule_id, "rule": r.original_id,
                             "message": f"Rule {r.original_id} is disabled; it is kept for reference and not translated as "
                                        "active.", "evidence": r.evidence[:1]})
        elif (r.action == "allow" and r.extra.get("stage") != "unbound" and not r.unsupported
              and covers_everything(r.src) and covers_everything(r.dst) and not _predefined(r)
              and r.extra.get("new_connections") is not False and (r.svc.any or not (r.src_zones and r.dst_zones))):
            where = f" from {', '.join(r.src_zones)} to {', '.join(r.dst_zones)}" if r.src_zones and r.dst_zones else ""
            findings.append({"kind": "broad", "severity": "warning", "rule_id": r.rule_id, "rule": r.original_id,
                             "message": (f"Rule {r.original_id} allows traffic{where} from any source to any destination"
                                         f"{' on any service' if r.svc.any else ' on ' + r.svc.text()}."),
                             "evidence": r.evidence[:1]})
        if r.enabled and r.condition_unknowns():
            findings.append({"kind": "unevaluated", "severity": "info", "rule_id": r.rule_id, "rule": r.original_id,
                             "message": f"Rule {r.original_id} has conditions this tool does not evaluate: "
                                        + "; ".join(r.condition_unknowns()) + ".", "evidence": r.evidence[:1]})
    findings.extend(_default_findings(policy))
    return findings


ZONE_ORDER = ("internal", "external", "gateway", "vpn", "hotspot", "dmz")


def _applies_to_new(rule):
    return rule.extra.get("new_connections") is not False


def zone_matrix(policy):
    """Source zone by destination zone, as UniFi's own matrix shows it: what each pair ends in and how many policies sit before that.

    Only for zone-pair policy sets (UniFi). Returns None otherwise. Every number counts policies in the export; nothing is inferred.
    """
    if policy.default_mode != "zone_pairs":
        return None
    names = set(policy.interfaces)
    for r in policy.rules:
        names.update(r.src_zones)
        names.update(r.dst_zones)
    zones = sorted(names, key=lambda n: (ZONE_ORDER.index(n.lower()) if n.lower() in ZONE_ORDER else len(ZONE_ORDER), n.lower()))
    pairs = {}
    for r in policy.rules:
        for src in r.src_zones:
            for dst in r.dst_zones:
                pairs.setdefault((src, dst), []).append(r)
    cells = []
    for src in zones:
        for dst in zones:
            rules = sorted(pairs.get((src, dst), []), key=lambda r: r.extra.get("index", r.position))
            cells.append(_matrix_cell(src, dst, rules))
    return {"zones": zones, "cells": cells,
            "note": "Each cell is the zone pair's own policy list, first match wins. Counts are policies in the export; policies that only "
                    "apply to existing connections (replies, invalid packets) are counted separately."}


def _matrix_cell(src, dst, rules):
    final = next((r for r in reversed(rules) if r.extra.get("default_policy") and r.enabled), None)
    body = [r for r in rules if r is not final]
    live = [r for r in body if r.enabled]
    custom = [r for r in live if not _predefined(r)]
    new = [r for r in custom if _applies_to_new(r)]
    cell = {"src": src, "dst": dst, "policies": len(rules), "enabled": len([r for r in rules if r.enabled]),
            "default": {"action": final.action, "name": final.original_id} if final else None,
            "custom_allow": len([r for r in new if r.action == "allow"]), "custom_block": len([r for r in new if r.action == "deny"]),
            "predefined_allow": len([r for r in live if _predefined(r) and _applies_to_new(r) and r.action == "allow"]),
            "predefined_block": len([r for r in live if _predefined(r) and _applies_to_new(r) and r.action == "deny"]),
            "custom_replies_only": len([r for r in custom if not _applies_to_new(r)]),
            "custom_disabled": len([r for r in body if not r.enabled and not _predefined(r)]),
            "predefined": len([r for r in live if _predefined(r)]),
            "replies_allowed": any(r.action == "allow" and not _applies_to_new(r) for r in live),
            "undecidable": len([r for r in live if r.condition_unknowns() or r.src.unresolved or r.dst.unresolved or r.svc.unresolved])}
    if not rules:
        cell.update(label="No policy listed", tone="none")
    elif final is None:
        cell.update(label="No default listed", tone="none")
    elif final.action == "allow":
        n = cell["custom_block"] + cell["predefined_block"]
        cell.update(label="Allow all" if not n else f"Allow, {n} blocked", tone="allow" if not n else "mixed")
    else:
        n = cell["custom_allow"] + cell["predefined_allow"]
        base = "Block (replies allowed)" if cell["replies_allowed"] else "Block all"
        cell.update(label=base if not n else f"Block, {n} allowed", tone="block" if not n else "mixed")
    return cell


def _default_findings(policy):
    """UniFi: the zone pairs whose final policy is the predefined 'Allow All Traffic' (the platform's built-in posture)."""
    pairs = sorted(r.scope for r in policy.rules if r.extra.get("default_policy") and r.enabled and r.action == "allow")
    if not pairs:
        return []
    return [{"kind": "default", "severity": "info", "rule_id": "", "rule": "",
             "message": (f"{len(pairs)} zone pair(s) end in the predefined Allow All Traffic, so anything not blocked earlier is allowed: "
                         + "; ".join(pairs) + "."), "evidence": []}]
