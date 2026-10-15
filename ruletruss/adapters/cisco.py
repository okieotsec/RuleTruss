"""Cisco ASA and Cisco IOS / IOS-XE adapter (running-config text).

Supported: named and numbered standard and extended IPv4 ACLs, IPv6 ACLs, ASA object / object-group definitions
(network, service, protocol, icmp-type) including nested groups, ACL bindings (`access-group`, `ip access-group`,
`ipv6 traffic-filter`), ASA security levels, ASA `name` entries, and a record of NAT statements.

Not evaluated, and always reported as such: time ranges, reflexive ACLs, TCP flag matches other than `established`,
DSCP/precedence/TOS/TTL/fragment matches, ASA identity (user, security-group) conditions, FQDN objects, zone-based
firewall policy on IOS, and ASA Modular Policy Framework.
"""
import ipaddress
import re

from .. import limits, netutil
from ..model import AddrSet, NatRule, PolicySet, Rule, ServiceSet, SvcEntry
from .common import Lines, Resolver, cap_expansion, dedupe, spend_visit

ICMP_TYPES = {"echo-reply": (0, None), "unreachable": (3, None), "net-unreachable": (3, 0), "host-unreachable": (3, 1),
              "protocol-unreachable": (3, 2), "port-unreachable": (3, 3), "packet-too-big": (3, 4),
              "source-quench": (4, None), "redirect": (5, None), "alternate-address": (6, None), "echo": (8, None),
              "router-advertisement": (9, None), "router-solicitation": (10, None), "time-exceeded": (11, None),
              "ttl-exceeded": (11, 0), "parameter-problem": (12, None), "timestamp-request": (13, None),
              "timestamp-reply": (14, None), "information-request": (15, None), "information-reply": (16, None),
              "mask-request": (17, None), "mask-reply": (18, None), "traceroute": (30, None),
              "conversion-error": (31, None), "mobile-redirect": (32, None)}
ICMP6_TYPES = {"unreachable": (1, None), "packet-too-big": (2, None), "time-exceeded": (3, None),
               "parameter-problem": (4, None), "echo": (128, None), "echo-request": (128, None),
               "echo-reply": (129, None), "membership-query": (130, None), "membership-report": (131, None),
               "membership-reduction": (132, None), "router-solicitation": (133, None),
               "router-advertisement": (134, None), "neighbor-solicitation": (135, None),
               "neighbor-advertisement": (136, None), "neighbor-redirect": (137, None)}
# Options on an ACE that change what it matches but that this tool does not evaluate.
UNSUPPORTED_OPTIONS = {"reflect": "reflexive ACL (builds temporary return entries)", "evaluate": "reflexive ACL evaluation",
                       "fragments": "fragment matching", "dscp": "DSCP match", "precedence": "IP precedence match",
                       "tos": "type-of-service match", "ttl": "TTL match", "option": "IP options match",
                       "packet-length": "packet length match", "match-any": "TCP flag match", "match-all": "TCP flag match",
                       "ack": "TCP flag match", "fin": "TCP flag match", "psh": "TCP flag match",
                       "rst": "TCP flag match", "syn": "TCP flag match", "urg": "TCP flag match",
                       "vlan": "VLAN match", "cos": "CoS match", "sgt": "security group tag match",
                       "user": "identity (user) condition", "user-group": "identity (user group) condition",
                       "security-group": "security group tag condition", "object-group-user": "identity condition",
                       "dynamic": "dynamic ACL"}
OPTION_ARGS = {"dscp": 1, "precedence": 1, "tos": 1, "reflect": 1, "evaluate": 1, "ttl": 2, "packet-length": 2, "vlan": 1,
               "cos": 1, "sgt": 1, "user": 1, "user-group": 1, "security-group": 1}
STANDARD_NUMBERED = list(range(1, 100)) + list(range(1300, 2000))
LOG_WORDS = {"log", "log-input"}
LOG_ARGS = {"disable", "default", "emergencies", "alerts", "critical", "errors", "warnings", "notifications",
            "informational", "debugging"}


def detect(text):
    """'asa', 'ios' or None, from the content of a configuration."""
    head = text[:200_000]
    if re.search(r"(?m)^ASA Version|^: Saved|^\s*nameif\s|^\s*security-level\s|^access-list \S+ (?:line \d+ )?extended", head):
        return "asa"
    if re.search(r"(?m)^ip access-list (?:extended|standard)|^ipv6 access-list|^access-list \d+ (?:permit|deny)|"
                 r"^\s*ip access-group|^version \d+\.\d+|^Building configuration", head):
        return "ios"
    return None


def _is_mask(text):
    try:
        value = int(ipaddress.IPv4Address(text))
    except ValueError:
        return False
    inverted = value ^ 0xFFFFFFFF
    return (inverted + 1) & inverted == 0


class _Parser:
    def __init__(self, text, source_id, flavour):
        self.flavour = flavour                      # asa or ios
        self.lines = Lines(text, source_id)
        self.source_id = source_id
        vendor = "cisco-asa" if flavour == "asa" else "cisco-ios"
        self.policy = PolicySet(policy_id=source_id, source_id=source_id, vendor=vendor,
                                platform="Cisco ASA" if flavour == "asa" else "Cisco IOS / IOS-XE",
                                stateful=(flavour == "asa"), default_mode="acl_binding",
                                default_basis="implicit deny at the end of each applied ACL",
                                address_context="internal-real" if flavour == "asa" else "original-packet")
        self.names = {}                              # ASA `name` entries
        self.net_objects = {}                        # name to ("leaf" members)
        self.net_defs = {}                           # object / object-group network
        self.svc_defs = {}                           # object / object-group service
        self.proto_defs = {}
        self.icmp_defs = {}
        self.port_groups = {}                        # ASA object-group service NAME tcp  (ports only)
        self.group_proto = {}                        # protocol of a port-only service group
        self.acls = {}                               # name to list of ACE records
        self.bindings = []                           # (acl, stage, interface, line)
        self.remarks = {}
        self.ipv6_acls = set()
        self.problem_seen = set()
        self.pending_unsupported = []

    # ------------------------------------------------------------ plumbing
    def issue(self, severity, code, message, line=None):
        key = (code, message)
        if key in self.problem_seen:
            return
        self.problem_seen.add(key)
        self.policy.issue(severity, code, message, [self.lines.evidence(line)] if line else [])

    def blocks(self):
        """Top-level statements with their indented children: (line number, tokens, [(line number, tokens)])."""
        out = []
        for number, raw in enumerate(self.lines.raw, start=1):
            if not raw.strip() or raw.lstrip().startswith(("!", ":")):
                continue
            if raw[0] in " \t":
                if out:
                    out[-1][2].append((number, raw.split()))
                continue
            out.append((number, raw.split(), []))
        return out

    # ------------------------------------------------------------ addresses
    def addr_leaf(self, value):
        """Convert one leaf (kind, text...) to a list of CIDR strings, or None if not an address."""
        kind, *rest = value
        try:
            if kind == "host":
                return [str(netutil.parse_ip_or_net(self.names.get(rest[0], rest[0])))]
            if kind == "net":
                return [str(netutil.parse_ip_or_net(rest[0]))]
            if kind == "mask":
                return [str(netutil.net_from_mask(self.names.get(rest[0], rest[0]), rest[1]))]
            if kind == "wild":
                return [str(netutil.net_from_wildcard(rest[0], rest[1]))]
            if kind == "range":
                lo, hi = ipaddress.ip_address(rest[0]), ipaddress.ip_address(rest[1])
                return [str(n) for n in ipaddress.summarize_address_range(lo, hi)]
        except (netutil.ParseProblem, ValueError, TypeError):           # TypeError: a range from an IPv4 to an IPv6 address
            return None
        return None

    def network_set(self, name, line):
        """Resolve a network object or group by name."""
        def problem(severity, code, message):
            self.issue(severity, code, message, line)
        resolver = Resolver(self.net_defs, lambda value: self.addr_leaf(value), problem)
        nets, unresolved = resolver.resolve(name)
        if name not in self.net_defs:
            self.issue("warning", "unresolved-object", f"network object or group {name!r} is not defined in this export",
                       line)
        return AddrSet(nets=dedupe(nets), unresolved=dedupe(unresolved), refs=[name])

    def parse_addr(self, tokens, i, acl_line):
        """Parse an address specification starting at tokens[i]. Returns (AddrSet, next index)."""
        if i >= len(tokens):
            raise netutil.ParseProblem("address expected")
        word = tokens[i]
        if word == "any":
            return AddrSet(any=True), i + 1
        if word == "any4":
            return AddrSet(nets=["0.0.0.0/0"], refs=["any4"]), i + 1
        if word == "any6":
            return AddrSet(nets=["::/0"], refs=["any6"]), i + 1
        if word == "host":
            host = self.names.get(tokens[i + 1], tokens[i + 1])
            return AddrSet(nets=[str(netutil.parse_ip_or_net(host))]), i + 2
        if word in ("object", "object-group"):
            return self.network_set(tokens[i + 1], acl_line), i + 2
        if word == "interface":
            iface = self.policy.interfaces.get(tokens[i + 1], {})
            ips = list(iface.get("host_ips", []))
            if ips:
                return AddrSet(nets=ips, refs=[f"interface {tokens[i + 1]}"]), i + 2
            return AddrSet(unresolved=[f"interface {tokens[i + 1]}"], refs=[f"interface {tokens[i + 1]}"]), i + 2
        if word in ("user", "user-group", "security-group", "object-group-user", "object-group-security"):
            self.pending_unsupported.append(UNSUPPORTED_OPTIONS.get(word, "identity condition"))
            return self.parse_addr(tokens, i + 2, acl_line)
        if "/" in word or ":" in word:
            return AddrSet(nets=[str(netutil.parse_ip_or_net(word))]), i + 1
        value = self.names.get(word, word)
        if self.flavour == "asa":
            if i + 1 >= len(tokens):
                raise netutil.ParseProblem("mask expected")
            return AddrSet(nets=[str(netutil.net_from_mask(value, tokens[i + 1]))]), i + 2
        if i + 1 < len(tokens) and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", tokens[i + 1]):
            return AddrSet(nets=[str(netutil.net_from_wildcard(value, tokens[i + 1]))]), i + 2
        return AddrSet(nets=[str(netutil.parse_ip_or_net(value))]), i + 1       # standard ACL: a bare host address

    # ------------------------------------------------------------ ports and services
    def parse_ports(self, tokens, i):
        """Parse eq/neq/gt/lt/range or a port object-group at tokens[i]. Returns (ranges or None, next index)."""
        if i >= len(tokens):
            return None, i
        op = tokens[i]
        if op == "eq":
            ports, j = [], i + 1
            while j < len(tokens):
                try:
                    ports.append(netutil.port_number(tokens[j]))
                except netutil.ParseProblem:
                    break
                j += 1
            if not ports:
                raise netutil.ParseProblem("port expected after eq")
            return netutil.merge_ranges([(p, p) for p in ports]), j
        if op == "range":
            lo, hi = netutil.port_number(tokens[i + 1]), netutil.port_number(tokens[i + 2])
            if lo > hi:
                raise netutil.ParseProblem("port range runs backwards")
            return [(lo, hi)], i + 3
        if op == "gt":
            p = netutil.port_number(tokens[i + 1])
            if p >= 65535:
                raise netutil.ParseProblem("no port is greater than 65535")        # an empty list would read as 'any port'
            return [(p + 1, 65535)], i + 2
        if op == "lt":
            p = netutil.port_number(tokens[i + 1])
            if p <= 0:
                raise netutil.ParseProblem("no port is less than 0")
            return [(0, p - 1)], i + 2
        if op == "neq":
            p = netutil.port_number(tokens[i + 1])
            out = ([(0, p - 1)] if p > 0 else []) + ([(p + 1, 65535)] if p < 65535 else [])
            return out, i + 2
        return None, i

    def service_entries(self, name, depth=0, seen=()):
        """Resolve an object-group service / object service to SvcEntry list. Returns (entries, unresolved)."""
        if not spend_visit(self, depth, name, self.issue):
            return [], [name]
        if name in seen or depth > limits.MAX_OBJECT_DEPTH:
            self.issue("warning", "group-cycle", f"service group {name} is nested too deeply or contains itself")
            return [], [name]
        if name not in self.svc_defs and name not in self.proto_defs and name not in self.icmp_defs:
            return [], [name]
        entries, unresolved = [], []
        for kind, value in self.svc_defs.get(name, []) + self.proto_defs.get(name, []) + self.icmp_defs.get(name, []):
            if kind == "ref":
                sub, sub_un = self.service_entries(value, depth + 1, (*seen, name))
                entries.extend(sub)
                unresolved.extend(sub_un)
            else:
                entries.append(value)
            if cap_expansion(entries, unresolved, name, self.issue):
                break
        return entries, unresolved

    def parse_service_tokens(self, tokens, i):
        """ASA service-object / IOS service group line: PROTO [source OP] [destination OP] or icmp type."""
        proto = tokens[i].lower()
        if proto == "tcp-udp":
            first, _ = self.parse_service_tokens(["tcp", *tokens[i + 1:]], 0)
            second, _ = self.parse_service_tokens(["udp", *tokens[i + 1:]], 0)
            return first + second, len(tokens)
        name = netutil.proto_name(proto)
        if name is None:
            raise netutil.ParseProblem(f"unknown protocol {proto!r}")
        j = i + 1
        sports = dports = None
        icmp_type = icmp_code = None
        if name in ("tcp", "udp", "sctp"):
            while j < len(tokens):
                if tokens[j] == "source":
                    sports, j = self.parse_ports(tokens, j + 1)
                elif tokens[j] == "destination":
                    dports, j = self.parse_ports(tokens, j + 1)
                else:
                    ports, j = self.parse_ports(tokens, j)
                    if ports is None:
                        break
                    dports = ports
        elif name in ("icmp", "icmp6") and j < len(tokens):
            icmp_type, icmp_code = self.icmp_spec(name, tokens, j)[:2]
        return [SvcEntry(name, sports, dports, icmp_type, icmp_code)], len(tokens)

    def icmp_spec(self, proto, tokens, i):
        """Parse an ICMP type (and optional code) at tokens[i]. Returns (type, code, next index)."""
        table = ICMP6_TYPES if proto == "icmp6" else ICMP_TYPES
        word = tokens[i]
        if netutil.is_uint(word):
            code = None
            if i + 1 < len(tokens) and netutil.is_uint(tokens[i + 1]):
                code = int(tokens[i + 1])
                return int(word), code, i + 2
            return int(word), None, i + 1
        if word in table:
            return (*table[word], i + 1)
        raise netutil.ParseProblem(f"unknown ICMP type {word!r}")

    # ------------------------------------------------------------ definitions
    def read_definitions(self):
        for number, tokens, children in self.blocks():
            head = tokens[0]
            if head == "hostname" and len(tokens) > 1:
                self.policy.hostname = limits.clip(tokens[1])
            elif head == "ASA" and tokens[1:2] == ["Version"]:
                self.policy.version = limits.clip(" ".join(tokens[2:]))
            elif head == "version" and self.flavour == "ios" and len(tokens) > 1:
                self.policy.version = limits.clip(tokens[1])
            elif head == "name" and len(tokens) >= 3 and self.flavour == "asa":
                self.names[tokens[2]] = tokens[1]
            elif head == "interface":
                self.read_interface(number, tokens, children)
            elif head == "object" and len(tokens) >= 3:
                self.read_object(number, tokens, children)
            elif head == "object-group" and len(tokens) >= 3:
                self.read_group(number, tokens, children)
            elif head == "same-security-traffic":
                self.policy.objects_summary["same-security-traffic"] = " ".join(tokens[1:])
                self.issue("info", "same-security-traffic", "same-security-traffic is configured; "
                           "same-level and intra-interface rules were not modelled", number)

    def read_interface(self, number, tokens, children):
        name = tokens[1] if len(tokens) > 1 else ""
        info = {"nets": [], "host_ips": [], "zone": name, "line": number}
        nameif = None
        for _, ctokens in children:
            if ctokens[0] == "nameif" and len(ctokens) > 1:
                nameif = ctokens[1]
            elif ctokens[0] == "security-level" and len(ctokens) > 1 and netutil.is_uint(ctokens[1]):
                info["level"] = int(ctokens[1])
            elif ctokens[:2] == ["ip", "address"] and len(ctokens) >= 4 and netutil.is_uint(ctokens[2][0]):
                try:
                    net = netutil.net_from_mask(ctokens[2], ctokens[3])
                    info["nets"].append(str(net))
                    info["host_ips"].append(f"{ctokens[2]}/32")
                except netutil.ParseProblem:
                    pass
            elif ctokens[0] == "ipv6" and ctokens[1:2] == ["address"] and len(ctokens) > 2 and "/" in ctokens[2]:
                try:
                    info["nets"].append(str(netutil.parse_ip_or_net(ctokens[2])))
                except netutil.ParseProblem:
                    pass
            elif ctokens[0] == "shutdown":
                info["shutdown"] = True
        key = nameif if self.flavour == "asa" else name
        if self.flavour == "asa" and not nameif:
            return                                   # a physical interface with no name is not in the data path
        info["zone"] = key
        info["physical"] = name
        self.policy.interfaces[key] = info
        if "level" in info:
            self.policy.zone_levels[key] = info["level"]

    def read_object(self, number, tokens, children):
        kind, name = tokens[1], tokens[2]
        if kind == "network":
            members, pending_nat = [], []
            for cnum, ctokens in children:
                word = ctokens[0]
                if word == "host" and len(ctokens) > 1:
                    members.append(("leaf", ("host", ctokens[1])))
                elif word == "subnet" and len(ctokens) > 1 and ("/" in ctokens[1] or len(ctokens) > 2):
                    members.append(("leaf", ("net", ctokens[1]) if "/" in ctokens[1] else ("mask", ctokens[1], ctokens[2])))
                elif word == "range" and len(ctokens) > 2:
                    members.append(("leaf", ("range", ctokens[1], ctokens[2])))
                elif word == "fqdn":
                    members.append(("leaf", ("fqdn", ctokens[-1])))
                    self.issue("warning", "fqdn-object", f"object {name} is an FQDN object; it is not resolved and any "
                               "rule using it is reported as undecidable", cnum)
                elif word == "nat":
                    pending_nat.append((cnum, ctokens))
            self.net_defs.setdefault(name, []).extend(members)
            own = [n for _, value in members if _ == "leaf" for n in (self.addr_leaf(value) or [])]
            for cnum, ctokens in pending_nat:
                self.read_object_nat(cnum, name, ctokens, own)
        elif kind == "service":
            entries = []
            for cnum, ctokens in children:
                if ctokens[0] == "service" and len(ctokens) > 1:
                    try:
                        entries.extend(self.parse_service_tokens(ctokens, 1)[0])
                    except (netutil.ParseProblem, IndexError):
                        self.issue("warning", "service-parse", f"could not read a service in object {name}", cnum)
            self.svc_defs[name] = [("leaf", e) for e in entries]

    def read_object_nat(self, number, obj_name, tokens, own_nets=()):
        m = re.match(r"nat \((\S+),(\S+)\) (static|dynamic) (.*)", " ".join(tokens))
        if not m:
            self.issue("warning", "nat-parse", f"could not read the NAT statement under object {obj_name}", number)
            return
        inz, outz, kind, rest = m.groups()
        mapped = rest.split()[0] if rest else ""
        try:
            translated = AddrSet(nets=[str(netutil.parse_ip_or_net(mapped))], refs=[mapped]) if re.fullmatch(
                r"[\d.]+", mapped) else AddrSet(unresolved=[rest], refs=[rest])
        except netutil.ParseProblem:                      # '1.2.3' is made of digits and dots but is not an address
            translated = AddrSet(unresolved=[rest], refs=[rest])
        self.policy.nat_rules.append(NatRule(
            nat_id=f"{self.source_id}#nat{len(self.policy.nat_rules) + 1}", kind=kind,
            original_src=AddrSet(nets=list(own_nets), refs=[obj_name], unresolved=[] if own_nets else [f"object {obj_name}"]),
            translated_src=translated,
            in_zone=inz, out_zone=outz, evidence=[self.lines.evidence(number)]))

    def read_group(self, number, tokens, children):
        kind, name = tokens[1], tokens[2]
        if kind == "network":
            members = []
            for cnum, ctokens in children:
                word = ctokens[0]
                try:
                    if word == "network-object":
                        members.extend(self.network_object_member(ctokens[1:]))
                    elif word == "group-object":
                        members.append(("ref", ctokens[1]))
                    elif word == "description":
                        continue
                    elif self.flavour == "ios":
                        members.extend(self.network_object_member(ctokens))
                except (netutil.ParseProblem, IndexError):
                    self.issue("warning", "group-member-parse", f"could not read a member of network group {name}", cnum)
            self.net_defs.setdefault(name, []).extend(members)
        elif kind == "service":
            group_proto = tokens[3].lower() if len(tokens) > 3 else None
            members = []
            for cnum, ctokens in children:
                word = ctokens[0]
                try:
                    if word == "port-object":
                        ports, _ = self.parse_ports(ctokens, 1)
                        protos = ["tcp", "udp"] if group_proto == "tcp-udp" else [group_proto or "tcp"]
                        members.extend(("leaf", SvcEntry(p, None, ports)) for p in protos)
                    elif word == "service-object":
                        if ctokens[1] == "object":
                            members.append(("ref", ctokens[2]))
                        else:
                            members.extend(("leaf", e) for e in self.parse_service_tokens(ctokens, 1)[0])
                    elif word == "group-object":
                        members.append(("ref", ctokens[1]))
                    elif word in ("description", "remark"):
                        continue
                    elif self.flavour == "ios":
                        members.extend(("leaf", e) for e in self.parse_service_tokens(ctokens, 0)[0])
                except (netutil.ParseProblem, IndexError):
                    self.issue("warning", "group-member-parse", f"could not read a member of service group {name}", cnum)
            self.svc_defs[name] = members
            if group_proto:
                self.port_groups[name] = group_proto
        elif kind == "protocol":
            members = []
            for _, ctokens in children:
                if ctokens[0] == "protocol-object" and len(ctokens) > 1:
                    proto = netutil.proto_name(ctokens[1])
                    if proto:
                        members.append(("leaf", SvcEntry(proto)))
                elif ctokens[0] == "group-object" and len(ctokens) > 1:
                    members.append(("ref", ctokens[1]))
            self.proto_defs[name] = members
        elif kind == "icmp-type":
            members = []
            for _, ctokens in children:
                if ctokens[0] == "icmp-object" and len(ctokens) > 1:
                    try:
                        itype, icode, _ = self.icmp_spec("icmp", ctokens, 1)
                        members.append(("leaf", SvcEntry("icmp", None, None, itype, icode)))
                    except netutil.ParseProblem:
                        pass
                elif ctokens[0] == "group-object" and len(ctokens) > 1:
                    members.append(("ref", ctokens[1]))
            self.icmp_defs[name] = members

    def network_object_member(self, tokens):
        word = tokens[0]
        if word == "host":
            return [("leaf", ("host", tokens[1]))]
        if word == "object":
            return [("ref", tokens[1])]
        if "/" in word:
            return [("leaf", ("net", word))]
        if len(tokens) > 1 and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", tokens[1]):
            return [("leaf", ("mask", word, tokens[1]) if _is_mask(tokens[1]) else ("wild", word, tokens[1]))]
        if word == "range" and len(tokens) > 2:
            return [("leaf", ("range", tokens[1], tokens[2]))]
        return [("leaf", ("host", word))]

    # ------------------------------------------------------------ ACLs and bindings
    def read_acls(self):
        counters = {}
        pending_remark = {}
        for number, tokens, children in self.blocks():
            head = tokens[0]
            if head == "access-list" and len(tokens) > 2:
                name = tokens[1]
                rest = tokens[2:]
                if rest[0] == "line" and len(rest) > 2:
                    rest = rest[2:]
                if rest[0] == "remark":
                    pending_remark[name] = " ".join(rest[1:])
                    continue
                kind = "extended"
                if rest[0] in ("extended", "standard", "webtype", "ethertype"):
                    kind = rest[0]
                    rest = rest[1:]
                elif self.flavour == "ios" and netutil.is_uint(name):
                    kind = "standard" if int(name) in STANDARD_NUMBERED else "extended"
                self.add_ace(name, kind, rest, number, counters, pending_remark)
            elif head == "ip" and tokens[1:3] in (["access-list", "extended"], ["access-list", "standard"]) and len(tokens) > 3:
                name = tokens[3]
                self.read_named_acl(name, tokens[2], children, counters, pending_remark)
            elif head == "ipv6" and tokens[1:2] == ["access-list"] and len(tokens) > 2:
                self.ipv6_acls.add(tokens[2])
                self.read_named_acl(tokens[2], "extended", children, counters, pending_remark)
            elif head == "access-group" and len(tokens) >= 3:
                self.read_access_group(number, tokens)
            elif head == "interface":
                self.read_interface_bindings(tokens, children)

    def read_named_acl(self, name, kind, children, counters, pending_remark):
        for cnum, ctokens in children:
            rest = ctokens
            if rest and netutil.is_uint(rest[0]):
                rest = rest[1:]                      # sequence number
            if not rest:
                continue
            if rest[0] == "remark":
                pending_remark[name] = " ".join(rest[1:])
                continue
            if rest[0] in ("permit", "deny"):
                self.add_ace(name, kind, rest, cnum, counters, pending_remark)

    def read_interface_bindings(self, tokens, children):
        name = tokens[1] if len(tokens) > 1 else ""
        for cnum, ctokens in children:
            is_binding = ctokens[:2] in (["ip", "access-group"], ["ipv6", "traffic-filter"])
            if is_binding and len(ctokens) >= 4 and ctokens[3] in ("in", "out"):
                self.bindings.append((ctokens[2], ctokens[3], name, cnum))

    def read_access_group(self, number, tokens):
        # access-group NAME {in|out} interface IFNAME   |   access-group NAME global
        if tokens[2] == "global":
            self.bindings.append((tokens[1], "global", "", number))
        elif len(tokens) >= 5 and tokens[2] in ("in", "out") and tokens[3] == "interface":
            self.bindings.append((tokens[1], tokens[2], tokens[4], number))
        else:
            self.issue("warning", "access-group-parse", "an access-group statement was not understood", number)

    def add_ace(self, name, kind, tokens, number, counters, pending_remark):
        if kind in ("webtype", "ethertype"):
            self.issue("info", "acl-type-skipped", f"{kind} ACL {name} is not a packet filter this tool evaluates", number)
            return
        if not tokens or tokens[0] not in ("permit", "deny"):       # "access-list NAME extended" alone leaves nothing to read
            return
        action = tokens[0]
        counters[name] = counters.get(name, 0) + 1
        v6_only = name in self.ipv6_acls
        record = {"acl": name, "line": number, "index": counters[name], "action": action, "kind": kind,
                  "comment": pending_remark.pop(name, "")}
        try:
            record.update(self.parse_ace(tokens[1:], kind, number))
            if v6_only:                                   # an IPv6 ACL's 'any' means any IPv6 address, not any address
                for side in ("src", "dst"):
                    if record[side].any:
                        record[side] = AddrSet(nets=["::/0"], refs=["any (IPv6)"])
        except _Unsupported as unsup:
            record.update(src=AddrSet(any=True), dst=AddrSet(any=True), svc=ServiceSet(any=True),
                          unsupported=[str(unsup)], enabled=True, error=True)
            self.issue("warning", "ace-unsupported", f"an entry in ACL {name} uses {unsup}; the rule is marked "
                       "undecidable and cannot be translated", number)
        except (netutil.ParseProblem, IndexError) as error:
            record.update(src=AddrSet(any=True), dst=AddrSet(any=True), svc=ServiceSet(any=True),
                          unsupported=[f"unreadable entry ({error})"], enabled=True, error=True)
            self.issue("warning", "ace-parse", f"an entry in ACL {name} could not be read ({error}); it is kept as an "
                       "undecidable rule so nothing is silently dropped", number)
        self.acls.setdefault(name, []).append(record)

    def parse_ace(self, tokens, kind, number):
        unsupported, log, enabled, schedule, established = [], False, True, None, False
        self.pending_unsupported = unsupported
        if kind == "standard":
            src, i = self.parse_addr(tokens, 0, number)
            rest = tokens[i:]
            dst, svc = AddrSet(any=True), ServiceSet(any=True)
        else:
            proto_entries, i, proto_group = self.parse_protocol(tokens, 0, number)
            src, i = self.parse_addr(tokens, i, acl_line=number)
            src_ports = None
            if proto_group is None and any(e.proto in ("tcp", "udp", "sctp") for e in proto_entries):
                src_ports, i = self.parse_port_or_group(tokens, i, proto_entries)
            dst, i = self.parse_addr(tokens, i, acl_line=number)
            dst_ports = icmp_type = icmp_code = None
            if i < len(tokens) and any(e.proto in ("tcp", "udp", "sctp") for e in proto_entries):
                dst_ports, i = self.parse_port_or_group(tokens, i, proto_entries)
            elif i < len(tokens) and any(e.proto in ("icmp", "icmp6") for e in proto_entries):
                if tokens[i] == "object-group":
                    group_entries, group_unres = self.service_entries(tokens[i + 1])
                    if group_unres:
                        unsupported.append(f"unresolved ICMP group {tokens[i + 1]}")
                    proto_entries = [SvcEntry(proto_entries[0].proto, None, None, e.icmp_type, e.icmp_code)
                                     for e in group_entries] or proto_entries
                    i += 2
                elif tokens[i] not in LOG_WORDS and tokens[i] not in UNSUPPORTED_OPTIONS and \
                        tokens[i] not in ("inactive", "time-range", "established"):
                    icmp_type, icmp_code, i = self.icmp_spec(proto_entries[0].proto, tokens, i)
            svc_entries = []
            for e in proto_entries:
                svc_entries.append(SvcEntry(e.proto, src_ports if src_ports else e.sports,
                                            dst_ports if dst_ports else e.dports,
                                            icmp_type if icmp_type is not None else e.icmp_type,
                                            icmp_code if icmp_code is not None else e.icmp_code))
            svc = ServiceSet(any=all(e.proto == "ip" and not e.sports and not e.dports for e in svc_entries),
                             entries=svc_entries, refs=[tokens[1]] if proto_group else [])
            if proto_group is not None:
                svc.unresolved = proto_group
            rest = tokens[i:]
        j = 0
        while j < len(rest):
            word = rest[j]
            if word in LOG_WORDS:
                log = True
                j += 1
                while j < len(rest) and (rest[j] in LOG_ARGS or netutil.is_uint(rest[j]) or rest[j] == "interval"):
                    j += 1
                continue
            if word == "inactive":
                enabled = False
            elif word == "time-range" and j + 1 < len(rest):
                schedule = rest[j + 1]
                j += 1
            elif word == "established":
                established = True
            elif word in UNSUPPORTED_OPTIONS:
                unsupported.append(UNSUPPORTED_OPTIONS[word])
                j += OPTION_ARGS.get(word, 0)
            else:
                unsupported.append(f"unrecognised text {word!r} in the entry")
            j += 1
        if established and kind != "standard":
            svc = ServiceSet(any=False, entries=[SvcEntry(e.proto, e.sports, e.dports, e.icmp_type, e.icmp_code, True)
                                                 for e in svc.entries], refs=svc.refs)
        return {"src": src, "dst": dst, "svc": svc, "log": log, "enabled": enabled, "schedule": schedule,
                "unsupported": dedupe(unsupported)}

    def parse_protocol(self, tokens, i, number):
        """Protocol position of an ACE. Returns (entries, next index, unresolved-service-names-or-None)."""
        word = tokens[i].lower()
        if word in ("object", "object-group"):
            name = tokens[i + 1]
            entries, unresolved = self.service_entries(name)
            if unresolved:
                self.issue("warning", "unresolved-object", f"service object or group {name!r} is not fully defined", number)
            return (entries or [SvcEntry("ip")]), i + 2, (unresolved or None) if unresolved else []
        proto = "ip" if word == "ipv6" else netutil.proto_name(word)
        if proto is None:
            raise netutil.ParseProblem(f"unknown protocol {word!r}")
        return [SvcEntry(proto)], i + 1, None

    def parse_port_or_group(self, tokens, i, proto_entries):
        if i < len(tokens) and tokens[i] == "object-group" and tokens[i + 1] in self.port_groups:
            group_name = tokens[i + 1]
            entries, _ = self.service_entries(group_name)
            ports = netutil.merge_ranges([tuple(r) for e in entries for r in (e.dports or [])
                                          if e.proto in {p.proto for p in proto_entries} or True])
            return ports or None, i + 2
        return self.parse_ports(tokens, i)

    # ------------------------------------------------------------ assembly
    def build_rules(self):
        policy = self.policy
        by_acl = {}
        for acl, stage, interface, line in self.bindings:
            by_acl.setdefault(acl, []).append((stage, interface, line))
            family = "6" if acl in self.ipv6_acls else ""
            if stage in ("in", "out") and interface in policy.interfaces:
                policy.interfaces[interface][f"acl_{stage}{family}"] = acl
            elif stage in ("in", "out"):
                self.issue("warning", "binding-unknown-interface", f"ACL {acl} is applied to interface {interface!r}, "
                           "which is not defined in this export", line)
                policy.interfaces.setdefault(interface, {"nets": [], "host_ips": [], "zone": interface})[
                    f"acl_{stage}{family}"] = acl
        position = 0
        for acl, records in self.acls.items():
            bindings = by_acl.get(acl) or [("unbound", "", 0)]
            if not by_acl.get(acl):
                self.issue("info", "acl-not-applied", f"ACL {acl} is defined but not applied to an interface in this "
                           "export; its entries are listed but not evaluated")
            for stage, interface, bind_line in bindings:
                for record in records:
                    position += 1
                    rule = Rule(
                        rule_id=f"{self.source_id}#{position}", original_id=f"{acl}:{record['index']}", position=record["index"],
                        action="allow" if record["action"] == "permit" else "deny", original_action=record["action"],
                        name=acl, enabled=record.get("enabled", True), scope=acl,
                        src_zones=[interface] if stage == "in" else [], dst_zones=[interface] if stage == "out" else [],
                        src=record["src"], dst=record["dst"], svc=record["svc"], schedule=record.get("schedule"),
                        log=record.get("log", False), comment=record.get("comment", ""),
                        unsupported=list(record.get("unsupported", [])),
                        evidence=[self.lines.evidence(record["line"])] + ([self.lines.evidence(bind_line)] if bind_line else []),
                        extra={"stage": stage, "bind": interface, "acl": acl, "kind": record["kind"]})
                    if stage == "unbound":
                        rule.notes.append("The ACL is not applied to an interface in this export, so it filters nothing here.")
                    if stage == "global":
                        rule.notes.append("Global access rule (ASA): evaluated after the interface ACL, inbound only.")
                    policy.rules.append(rule)
                    if record["acl"] in self.ipv6_acls:
                        rule.extra["ipv6"] = True
        policy.stats = {"rules": len(policy.rules), "acls": len(self.acls), "bindings": len(self.bindings),
                        "nat_rules": len(policy.nat_rules)}
        if len(policy.rules) > limits.MAX_RULES:
            raise limits.LimitExceeded(f"more than {limits.MAX_RULES:,} rules")
        if self.flavour == "ios":
            policy.issue("info", "stateless", "IOS ACLs are stateless: reply traffic is only allowed if an ACL entry "
                         "(or `established` for TCP) permits it. Reflexive ACLs, CBAC and zone-based firewalls are not "
                         "modelled.")
        else:
            policy.issue("info", "asa-order", "ASA evaluates the interface ACL, then the global ACL, then the implicit "
                         "deny; with no ACL on the ingress interface, security levels decide (higher to lower is allowed).")

    def read_nat(self):
        for number, tokens, _ in self.blocks():
            text = " ".join(tokens)
            if self.flavour == "asa" and tokens[0] == "nat" and len(tokens) > 3:
                m = re.match(r"nat \((\S+),(\S+)\) (?:after-auto )?(?:line \d+ )?source (static|dynamic) (\S+) (\S+)(.*)", text)
                kind = "twice"
                if m:
                    inz, outz, mode, real, mapped, tail = m.groups()
                    original = self.network_set(real, number) if real != "any" else AddrSet(any=True)
                    translated = self.network_set(mapped, number) if mapped not in ("interface", "any") else AddrSet(
                        unresolved=[mapped], refs=[mapped])
                    self.policy.nat_rules.append(NatRule(
                        nat_id=f"{self.source_id}#nat{len(self.policy.nat_rules) + 1}", kind=f"{kind}-{mode}",
                        original_src=original, translated_src=translated, in_zone=inz, out_zone=outz,
                        service=tail.strip(), evidence=[self.lines.evidence(number)],
                        notes=["destination or service translation in this statement is kept as text only"
                               if "destination" in tail or "service" in tail else ""]))
                else:
                    self.issue("warning", "nat-parse", "a NAT statement was not understood", number)
            elif self.flavour == "ios" and text.startswith("ip nat "):
                self.policy.nat_rules.append(NatRule(
                    nat_id=f"{self.source_id}#nat{len(self.policy.nat_rules) + 1}", kind="unknown",
                    notes=["IOS NAT statement kept as text; addresses are not resolved"],
                    evidence=[self.lines.evidence(number)]))


class _Unsupported(Exception):
    """A construct the adapter recognises but cannot evaluate."""


def parse(text, source_id, flavour=None):
    """Parse a Cisco configuration into a PolicySet. `flavour` is 'asa' or 'ios'; detected when omitted."""
    flavour = flavour or detect(text)
    if flavour not in ("asa", "ios"):
        raise ValueError("this does not look like a Cisco ASA or IOS configuration (no ACLs or ASA markers found)")
    parser = _Parser(text, source_id, flavour)
    parser.read_definitions()
    parser.read_acls()
    parser.read_nat()
    parser.build_rules()
    if parser.policy.stats["rules"] == 0:
        parser.policy.issue("warning", "no-rules", "no ACL entries were found in this export")
    if flavour == "asa" and any(re.match(r"^(class-map|policy-map|service-policy)", r) for r in parser.lines.raw):
        parser.policy.issue("info", "mpf-not-modelled", "Modular Policy Framework (class-map / policy-map) is present but "
                            "not modelled; inspection or connection limits there are not reflected in decisions")
    if flavour == "ios" and any(r.startswith(("zone security", "zone-pair")) for r in parser.lines.raw):
        parser.policy.issue("warning", "zbf-not-modelled", "zone-based policy firewall configuration is present but is not "
                            "parsed; traffic permitted by an ACL may still be filtered by it")
    parser.policy.default_mode = "acl_binding"
    if flavour == "asa":
        parser.policy.default_mode = "acl_binding"
    return parser.policy
