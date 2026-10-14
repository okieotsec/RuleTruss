"""The vendor-neutral intermediate model.

Three kinds of thing are kept apart everywhere in the application and never stored in the same list:

  * OBSERVED   (Flow, CaptureInfo): what was seen on the wire, with how sure the tool is.
  * CONFIGURED (PolicySet, Rule): what a device was configured to permit or deny, as the export says.
  * PROPOSED   (see migrate.py): what this tool suggests, always labelled with its basis and warnings.

Matching helpers return True (matches), False (does not match) or None (cannot be decided from what is known, for
example an unresolved FQDN object). Callers must treat None as "unknown", never as False.
"""
import ipaddress
from dataclasses import dataclass, field, fields, is_dataclass

from . import netutil

ANY_PROTO = "ip"


def to_plain(value):
    """Convert model objects to JSON-ready dicts and lists. Private attributes (leading underscore) are skipped."""
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_plain(getattr(value, f.name)) for f in fields(value) if not f.name.startswith("_")}
    if isinstance(value, dict):
        return {str(k): to_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_plain(v) for v in value]
    return value


@dataclass
class Evidence:
    """Where a statement comes from. kind is config, packet, flow or user."""
    source_id: str
    kind: str
    ref: str            # "lines 12-14", "packets 15,16,18", "rule id 7"
    text: str = ""      # already redacted and clipped


@dataclass
class Issue:
    """A translation warning, unsupported condition or unresolved input. severity: info, warning or blocker."""
    severity: str
    code: str
    message: str
    evidence: list = field(default_factory=list)


# ---------------------------------------------------------------- addresses and services

@dataclass
class AddrSet:
    any: bool = False
    nets: list = field(default_factory=list)          # CIDR strings, normalised
    negate: bool = False
    unresolved: list = field(default_factory=list)    # names that could not be turned into addresses
    refs: list = field(default_factory=list)          # original object or group names, for display

    def _parsed(self):
        cached = self.__dict__.get("_cache")
        if cached is None or cached[0] != len(self.nets):
            cached = (len(self.nets), [ipaddress.ip_network(n, strict=False) for n in self.nets])
            self.__dict__["_cache"] = cached
        return cached[1]

    def contains(self, ip_text):
        """True, False or None (unknown because of unresolved members)."""
        if self.any:
            return True
        ip = ipaddress.ip_address(ip_text)
        hit = any(ip.version == n.version and ip in n for n in self._parsed())
        if hit:
            result = True
        elif self.unresolved:
            return None
        else:
            result = False
        return (not result) if self.negate else result

    def is_unrestricted(self):
        return self.any and not self.negate

    def fqdn_names(self):
        """Host names among the unresolved members (FQDN objects, alias host names), in lower case."""
        out = []
        for u in self.unresolved:
            for prefix in ("fqdn:", "fqdn ", "host name "):
                if u.startswith(prefix) and u[len(prefix):].strip():
                    out.append(u[len(prefix):].strip().lower())
        return out

    def text(self):
        if self.any:
            return "any"
        parts = list(self.nets) + [f"?{u}" for u in self.unresolved]
        body = ", ".join(parts) if parts else "(empty)"
        return f"NOT [{body}]" if self.negate else body


@dataclass
class SvcEntry:
    proto: str = ANY_PROTO              # tcp, udp, icmp, icmp6, sctp, proto:N, or ip for any protocol
    sports: list = None                 # None means any; else [[lo, hi], ...]
    dports: list = None
    icmp_type: int = None
    icmp_code: int = None
    established: bool = False           # TCP ACK/RST set: matches replies, not connection initiation

    def matches(self, proto, sport=None, dport=None, icmp_type=None, icmp_code=None, tcp_established=False):
        if self.established and not tcp_established:
            return False
        if self.proto != ANY_PROTO and self.proto != proto:
            return False
        unknown = False
        for want, have in ((self.sports, sport), (self.dports, dport)):
            if want is None:
                continue
            if have is None:
                unknown = True
            elif not netutil.ranges_contain(want, have):
                return False
        for want, have in ((self.icmp_type, icmp_type), (self.icmp_code, icmp_code)):
            if want is None:
                continue
            if have is None:
                unknown = True
            elif want != have:
                return False
        return None if unknown else True

    def text(self):
        out = self.proto
        if self.established:
            out += " established"
        if self.sports:
            out += f" sport {netutil.ranges_text(self.sports)}"
        if self.dports:
            out += f" dport {netutil.ranges_text(self.dports)}"
        if self.icmp_type is not None:
            out += f" type {self.icmp_type}" + (f" code {self.icmp_code}" if self.icmp_code is not None else "")
        return out


@dataclass
class ServiceSet:
    any: bool = False
    entries: list = field(default_factory=list)
    unresolved: list = field(default_factory=list)
    refs: list = field(default_factory=list)

    def match(self, proto, sport=None, dport=None, icmp_type=None, icmp_code=None, tcp_established=False):
        if self.any:
            return True
        unknown = False
        for entry in self.entries:
            result = entry.matches(proto, sport, dport, icmp_type, icmp_code, tcp_established)
            if result:
                return True
            if result is None:
                unknown = True
        return None if unknown or self.unresolved else False

    def text(self):
        if self.any:
            return "any"
        parts = [e.text() for e in self.entries] + [f"?{u}" for u in self.unresolved]
        return "; ".join(parts) if parts else "(empty)"


# ---------------------------------------------------------------- configured policy

@dataclass
class Rule:
    rule_id: str                        # unique inside the policy set: "<policy_id>#<n>"
    original_id: str                    # the id, name or line number the vendor used
    position: int                       # evaluation order, starting at 1
    action: str                         # allow or deny
    original_action: str = ""           # permit, accept, drop, reject, ...
    name: str = ""
    enabled: bool = True
    scope: str = ""                     # ACL or rulebase the rule belongs to
    src_zones: list = field(default_factory=list)     # empty means any (interfaces for ACL platforms)
    dst_zones: list = field(default_factory=list)
    src: AddrSet = field(default_factory=lambda: AddrSet(any=True))
    dst: AddrSet = field(default_factory=lambda: AddrSet(any=True))
    svc: ServiceSet = field(default_factory=lambda: ServiceSet(any=True))
    applications: list = field(default_factory=list)  # application conditions; the evaluator cannot decide these
    users: list = field(default_factory=list)         # identity conditions
    schedule: str = None
    log: bool = False
    comment: str = ""
    unsupported: list = field(default_factory=list)   # conditions this tool cannot evaluate or translate
    notes: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)         # vendor-specific values kept for provenance

    def condition_unknowns(self, probe=None):
        """Conditions that make a decision uncertain even when addresses and services match.

        With a `probe` whose sender MAC is known, a source MAC filter that the MAC satisfies is no longer in doubt.
        """
        out = []
        if self.applications and "any" not in [a.lower() for a in self.applications]:
            out.append("application condition: " + ", ".join(self.applications))
        if self.users:
            out.append("identity condition: " + ", ".join(self.users))
        if self.schedule:
            out.append(f"schedule: {self.schedule}")
        known_mac = probe is not None and getattr(probe, "src_mac", None) and self.extra.get("src_macs")
        out.extend(u for u in self.unsupported if not (known_mac and u.startswith("source MAC address filter")))
        return out


@dataclass
class NatRule:
    nat_id: str
    kind: str                           # static, dynamic, pat, destination, source, twice, unknown
    original_src: AddrSet = field(default_factory=lambda: AddrSet(any=True))
    original_dst: AddrSet = field(default_factory=lambda: AddrSet(any=True))
    translated_src: AddrSet = field(default_factory=AddrSet)
    translated_dst: AddrSet = field(default_factory=AddrSet)
    service: str = ""
    in_zone: str = ""
    out_zone: str = ""
    enabled: bool = True
    notes: list = field(default_factory=list)
    evidence: list = field(default_factory=list)


@dataclass
class PolicySet:
    policy_id: str
    source_id: str
    vendor: str                         # cisco-ios, cisco-asa, panos, fortios, pfsense, opnsense
    platform: str = ""
    version: str = ""
    hostname: str = ""
    stateful: bool = True               # True: replies to permitted connections are allowed without a rule
    default_action: str = "deny"
    default_basis: str = ""
    default_mode: str = "implicit_deny"    # implicit_deny | security_level | explicit_only
    zone_levels: dict = field(default_factory=dict)    # ASA: interface to security level
    interfaces: dict = field(default_factory=dict)     # name to {"nets": [...], "zone": str}
    rules: list = field(default_factory=list)
    nat_rules: list = field(default_factory=list)
    # Which addresses rules are written against: original-packet (as received, before any NAT), internal-real (the real
    # internal host after destination NAT is undone), or unknown.
    address_context: str = "unknown"
    objects_summary: dict = field(default_factory=dict)
    issues: list = field(default_factory=list)
    unresolved: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def issue(self, severity, code, message, evidence=None):
        self.issues.append(Issue(severity, code, message, evidence or []))


# ---------------------------------------------------------------- observed traffic

@dataclass
class AppGuess:
    name: str
    confidence: str                     # confirmed (decoded payload), probable (partial payload), possible (port only)
    basis: str


@dataclass
class Flow:
    flow_id: str
    source_id: str
    ip_version: int
    proto: str
    initiator: str
    responder: str
    initiator_port: int = None
    responder_port: int = None
    direction_confidence: str = "unknown"   # high, medium, low, unknown
    direction_basis: list = field(default_factory=list)
    pkts_fwd: int = 0                   # initiator to responder
    pkts_rev: int = 0
    bytes_fwd: int = 0
    bytes_rev: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    icmp_type: int = None
    icmp_code: int = None
    apps: list = field(default_factory=list)
    tcp_flags_seen: list = field(default_factory=list)
    hostnames: list = field(default_factory=list)   # names seen in the payload (TLS server name, HTTP Host, DNS query): untrusted text
    notes: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    vlan: int = None


@dataclass
class CaptureInfo:
    capture_id: str
    filename: str
    format: str                         # pcap, pcapng, zeek-conn
    size_bytes: int = 0
    packets_read: int = 0
    packets_decoded: int = 0
    packets_skipped: int = 0
    first_ts: float = None
    last_ts: float = None
    link_types: list = field(default_factory=list)
    snaplen_truncated: int = 0
    observation_point: str = ""         # supplied by the user, never guessed
    limits_hit: list = field(default_factory=list)
    coverage_notes: list = field(default_factory=list)
    flows: int = 0


# ---------------------------------------------------------------- user-supplied context

@dataclass
class Subnet:
    cidr: str
    label: str = ""
    zone: str = ""                      # optional zone or interface name; 'outside|wan' lists the names different products use
    external: bool = False              # outside your control (the Internet, a vendor, a partner): reached through egress policies


@dataclass
class DeviceLabel:
    ip: str
    label: str


@dataclass
class Group:
    name: str
    members: list = field(default_factory=list)       # IP addresses or CIDRs
    gateway_isolated: bool = False      # members are endpoints isolated behind a gateway (they reach outside only through an egress policy)
    note: str = ""


# ---------------------------------------------------------------- reading stored JSON back into model objects

_NESTED = {
    (AddrSet, "unresolved"): None,
    (SvcEntry, "sports"): None,
    (ServiceSet, "entries"): ("list", SvcEntry),
    (Rule, "src"): ("one", AddrSet), (Rule, "dst"): ("one", AddrSet), (Rule, "svc"): ("one", ServiceSet),
    (Rule, "evidence"): ("list", Evidence),
    (NatRule, "original_src"): ("one", AddrSet), (NatRule, "original_dst"): ("one", AddrSet),
    (NatRule, "translated_src"): ("one", AddrSet), (NatRule, "translated_dst"): ("one", AddrSet),
    (NatRule, "evidence"): ("list", Evidence),
    (Issue, "evidence"): ("list", Evidence),
    (PolicySet, "rules"): ("list", Rule), (PolicySet, "nat_rules"): ("list", NatRule), (PolicySet, "issues"): ("list", Issue),
    (Flow, "apps"): ("list", AppGuess), (Flow, "evidence"): ("list", Evidence),
}


def from_plain(cls, data):
    """Rebuild a model object from the dict produced by to_plain. Unknown keys are ignored; nothing is executed."""
    if not isinstance(data, dict):
        raise ValueError(f"expected an object for {cls.__name__}")
    kwargs = {}
    names = {f.name for f in fields(cls)}
    for key, value in data.items():
        if key not in names:
            continue
        spec = _NESTED.get((cls, key))
        if spec and spec[0] == "list":
            value = [from_plain(spec[1], v) for v in value]
        elif spec and spec[0] == "one":
            value = from_plain(spec[1], value)
        elif cls is SvcEntry and key in ("sports", "dports") and value is not None:
            value = [tuple(r) for r in value]
        kwargs[key] = value
    return cls(**kwargs)


# ---------------------------------------------------------------- device identification

@dataclass
class MacBinding:
    """A MAC address seen together with an IP address. basis: arp or dhcp (the device announced it), or frame (the MAC that
    carried this IP's packets, which is the router's when the IP is on another network)."""
    mac: str
    ip: str
    basis: str
    packets: int = 1
    evidence: list = field(default_factory=list)


@dataclass
class L2Sender:
    """A MAC that sent frames with no IP layer (ARP, LLDP, spanning tree and so on)."""
    mac: str
    frames: int = 1
    kinds: list = field(default_factory=list)
    evidence: list = field(default_factory=list)


@dataclass
class Observation:
    """One thing a device told us about itself, or a weak hint. source_type: self-reported or weak-hint. It is attached to an IP,
    a MAC, or both; nothing here is a statement of what the device is for."""
    kind: str
    value: str
    confidence: str                     # confirmed, probable or possible
    source_type: str = "self-reported"
    basis: str = ""
    ip: str = ""
    mac: str = ""
    evidence: list = field(default_factory=list)


@dataclass
class DeviceFacts:
    bindings: list = field(default_factory=list)
    l2_senders: list = field(default_factory=list)
    observations: list = field(default_factory=list)
    limits_hit: list = field(default_factory=list)
