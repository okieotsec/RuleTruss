"""Fortinet FortiOS adapter: `show full-configuration` / `show` CLI text.

Reads interfaces, zones, address / address6 / addrgrp objects (nested), VIPs, custom and group services, the predefined
services listed in PREDEFINED, and `config firewall policy` / `policy6` in the order they appear (the order FortiOS
evaluates them). Policy-level NAT and VIPs are recorded as NAT context.

Not evaluated, always reported: identity (user, group, FSSO) conditions, internet-service (ISDB) objects, application
and URL-category conditions, schedules other than `always`, geography / MAC / dynamic / wildcard-FQDN addresses, UTM
profiles, central NAT, and local-in policies. Only the first VDOM (or `root`) is read when VDOMs are enabled.
"""
import ipaddress
import re
import shlex

from .. import limits, netutil
from ..model import AddrSet, NatRule, PolicySet, Rule, ServiceSet, SvcEntry
from .common import Lines, dedupe

# FortiOS predefined services. These values are this project's table, not read from the export: check them against your
# FortiOS version. Anything not listed here is reported as unresolved rather than guessed.
PREDEFINED = {
    "ALL": None, "ALL_TCP": [SvcEntry("tcp")], "ALL_UDP": [SvcEntry("udp")], "ALL_ICMP": [SvcEntry("icmp")],
    "ALL_ICMP6": [SvcEntry("icmp6")], "PING": [SvcEntry("icmp", icmp_type=8)], "GRE": [SvcEntry("gre")],
    "ESP": [SvcEntry("esp")], "AH": [SvcEntry("ah")],
    "HTTP": [SvcEntry("tcp", None, [(80, 80)])], "HTTPS": [SvcEntry("tcp", None, [(443, 443)])],
    "SSH": [SvcEntry("tcp", None, [(22, 22)])], "TELNET": [SvcEntry("tcp", None, [(23, 23)])],
    "FTP": [SvcEntry("tcp", None, [(21, 21)])], "SMTP": [SvcEntry("tcp", None, [(25, 25)])],
    "DNS": [SvcEntry("tcp", None, [(53, 53)]), SvcEntry("udp", None, [(53, 53)])],
    "NTP": [SvcEntry("udp", None, [(123, 123)])], "TFTP": [SvcEntry("udp", None, [(69, 69)])],
    "SNMP": [SvcEntry("tcp", None, [(161, 162)]), SvcEntry("udp", None, [(161, 162)])],
    "SYSLOG": [SvcEntry("udp", None, [(514, 514)])], "RDP": [SvcEntry("tcp", None, [(3389, 3389)])],
    "SMB": [SvcEntry("tcp", None, [(445, 445)])], "LDAP": [SvcEntry("tcp", None, [(389, 389)])],
    "KERBEROS": [SvcEntry("tcp", None, [(88, 88)]), SvcEntry("udp", None, [(88, 88)])],
    "VNC": [SvcEntry("tcp", None, [(5900, 5900)])], "DHCP": [SvcEntry("udp", None, [(67, 67)])],
    "MYSQL": [SvcEntry("tcp", None, [(3306, 3306)])], "MS-SQL": [SvcEntry("tcp", None, [(1433, 1433)])],
}


def detect(text):
    return bool(re.search(r"(?m)^config (firewall policy|system interface|firewall address)\b", text[:300_000]))


def _split(line):
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        return line.split()


class _Section:
    def __init__(self, name, line, parent=None):
        self.name, self.line, self.parent = name, line, parent
        self.entries, self.sets, self.sections = [], {}, []


class _Entry:
    def __init__(self, key, line, parent):
        self.key, self.line, self.parent = key, line, parent
        self.sets, self.sections, self.last_line = {}, [], line


def build_tree(lines):
    """Turn config text into nested _Section / _Entry objects. Unbalanced input raises ValueError."""
    root = _Section("", 0)
    current = root
    depth = 0
    for number, raw in enumerate(lines.raw, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        words = _split(line)
        head = words[0].lower()
        if head == "config" and len(words) > 1:
            section = _Section(" ".join(words[1:]), number, current)
            current.sections.append(section)
            current = section
            depth += 1
        elif head == "edit" and len(words) > 1 and isinstance(current, _Section):
            entry = _Entry(words[1], number, current)
            current.entries.append(entry)
            current = entry
            depth += 1
        elif head in ("set", "append") and len(words) > 1:
            if head == "append" and words[1] in current.sets:
                current.sets[words[1]] = current.sets[words[1]] + words[2:]
            else:
                current.sets[words[1]] = words[2:]
            if isinstance(current, _Entry):
                current.last_line = number
        elif head == "unset" and len(words) > 1:
            current.sets.pop(words[1], None)
        elif head == "next" and isinstance(current, _Entry):
            current.last_line = number
            current = current.parent
            depth -= 1
        elif head == "end" and isinstance(current, _Section):
            current = current.parent or root
            depth -= 1
        if depth > limits.MAX_XML_DEPTH:
            raise limits.LimitExceeded("configuration blocks are nested too deeply")
    return root


def _find(node, name):
    """Every section called `name` anywhere below `node`, in file order."""
    found = []
    for section in getattr(node, "sections", []):
        if section.name == name:
            found.append(section)
        found.extend(_find(section, name))
    for entry in getattr(node, "entries", []):
        found.extend(_find(entry, name))
    return found


class _Parser:
    def __init__(self, text, source_id):
        self.lines = Lines(text, source_id)
        self.source_id = source_id
        self.tree = build_tree(self.lines)
        self.policy = PolicySet(policy_id=source_id, source_id=source_id, vendor="fortios", platform="Fortinet FortiOS",
                                stateful=True, default_action="deny", default_basis="implicit deny policy",
                                address_context="original-packet")
        self.addresses, self.groups, self.services, self.service_groups, self.vips = {}, {}, {}, {}, {}
        self.zones = {}
        self.seen = set()

    def issue(self, severity, code, message, line=None):
        key = (code, message)
        if key not in self.seen:
            self.seen.add(key)
            self.policy.issue(severity, code, message, [self.lines.evidence(line)] if line else [])

    def scope(self):
        """The tree to read: the whole file, or the first VDOM when VDOMs are enabled."""
        vdoms = _find(self.tree, "vdom")
        if not vdoms or not vdoms[0].entries:
            return [self.tree]
        chosen = next((e for e in vdoms[0].entries if e.key == "root"), vdoms[0].entries[0])
        if len(vdoms[0].entries) > 1:
            self.issue("warning", "multi-vdom", f"{len(vdoms[0].entries)} VDOMs found; only {chosen.key!r} is read")
        glob = [s for s in self.tree.sections if s.name == "global"]
        return [*glob, chosen]

    def get(self, scopes, name):
        out = []
        for scope in scopes:
            out.extend(_find(scope, name))
        return out

    # ------------------------------------------------------------ objects
    def read_objects(self, scopes):
        for section in self.get(scopes, "system interface"):
            for entry in section.entries:
                ip = entry.sets.get("ip", [])
                nets = []
                if len(ip) >= 2:
                    try:
                        nets.append(str(netutil.net_from_mask(ip[0], ip[1])))
                    except netutil.ParseProblem:
                        pass
                self.policy.interfaces[entry.key] = {"nets": nets, "zone": entry.key,
                                                     "alias": " ".join(entry.sets.get("alias", []))}
        for section in self.get(scopes, "system zone"):
            for entry in section.entries:
                members_ = entry.sets.get("interface", [])
                self.zones[entry.key] = members_
                self.policy.interfaces.setdefault(entry.key, {"nets": [], "zone": entry.key, "members": members_})
        for name, kind in (("firewall address", 4), ("firewall address6", 6)):
            for section in self.get(scopes, name):
                for entry in section.entries:
                    self.addresses[entry.key] = (kind, entry)
        for section in self.get(scopes, "firewall addrgrp") + self.get(scopes, "firewall addrgrp6"):
            for entry in section.entries:
                self.groups[entry.key] = entry.sets.get("member", [])
        for section in self.get(scopes, "firewall vip"):
            for entry in section.entries:
                self.vips[entry.key] = entry
        for section in self.get(scopes, "firewall service custom"):
            for entry in section.entries:
                self.services[entry.key] = entry
        for section in self.get(scopes, "firewall service group"):
            for entry in section.entries:
                self.service_groups[entry.key] = entry.sets.get("member", [])

    def address_nets(self, name, depth=0, seen=()):
        if name in seen or depth > limits.MAX_OBJECT_DEPTH:
            self.issue("warning", "group-cycle", f"address group {name!r} is nested too deeply or contains itself")
            return [], [name]
        if name == "all":
            return ["0.0.0.0/0", "::/0"], []
        if name in self.groups:
            nets, unresolved = [], []
            for member in self.groups[name]:
                n, u = self.address_nets(member, depth + 1, (*seen, name))
                nets += n
                unresolved += u
            return nets, unresolved
        if name in self.vips:
            vip = self.vips[name]
            ext = vip.sets.get("extip", [""])[0]
            try:
                lo, _, hi = ext.partition("-")
                if hi:
                    span = ipaddress.summarize_address_range(ipaddress.ip_address(lo), ipaddress.ip_address(hi))
                    return [str(n) for n in span], []
                return [str(netutil.parse_ip_or_net(ext))], []
            except (netutil.ParseProblem, ValueError):
                return [], [f"vip {name}"]
        if name in self.addresses:
            kind, entry = self.addresses[name]
            kind_set = entry.sets.get("type", ["ipmask"])[0]
            try:
                if kind_set == "ipmask":
                    if kind == 6:
                        return [str(netutil.parse_ip_or_net(entry.sets.get("ip6", ["::/0"])[0]))], []
                    sub = entry.sets.get("subnet", [])
                    if len(sub) >= 2:
                        return [str(netutil.net_from_mask(sub[0], sub[1]))], []
                elif kind_set == "iprange":
                    lo = ipaddress.ip_address(entry.sets.get("start-ip", [""])[0])
                    hi = ipaddress.ip_address(entry.sets.get("end-ip", [""])[0])
                    return [str(n) for n in ipaddress.summarize_address_range(lo, hi)], []
            except (netutil.ParseProblem, ValueError):
                pass
            self.issue("warning", "address-unresolved", f"address {name!r} (type {kind_set}) cannot be resolved to IP "
                       "addresses; rules that use it are reported as undecidable", entry.line)
            value = entry.sets.get("fqdn", [name])[0] if kind_set == "fqdn" else name
            return [], [f"{kind_set}:{value}"]
        self.issue("warning", "unresolved-object", f"address {name!r} is not defined in this export")
        return [], [name]

    def addr_set(self, names, negate, family):
        """`family` is 4 or 6: `config firewall policy` only ever sees IPv4 and `policy6` only IPv6."""
        if not names or "all" in names or "ALL" in names:
            everything = ["0.0.0.0/0"] if family == 4 else ["::/0"]
            return AddrSet(nets=[] if negate else everything, negate=False, refs=["all"])
        nets, unresolved = [], []
        for name in names:
            n, u = self.address_nets(name)
            nets += n
            unresolved += u
        return AddrSet(nets=dedupe(nets), unresolved=dedupe(unresolved), negate=negate, refs=list(names))

    def custom_service(self, name, entry):
        entries = []
        proto = entry.sets.get("protocol", ["TCP/UDP/SCTP"])[0].upper()
        if proto in ("TCP/UDP/SCTP", "TCP/UDP"):
            for key, p in (("tcp-portrange", "tcp"), ("udp-portrange", "udp"), ("sctp-portrange", "sctp")):
                for token in entry.sets.get(key, []):
                    dst, _, src = token.partition(":")
                    try:
                        entries.append(SvcEntry(p, netutil.parse_port_ranges(src) if src else None,
                                                netutil.parse_port_ranges(dst) if dst else None))
                    except netutil.ParseProblem:
                        self.issue("warning", "service-parse", f"service {name!r} has a port range that could not be read",
                                   entry.line)
        elif proto in ("ICMP", "ICMP6"):
            icmp_type = entry.sets.get("icmptype", [None])[0]
            icmp_code = entry.sets.get("icmpcode", [None])[0]
            entries.append(SvcEntry("icmp" if proto == "ICMP" else "icmp6",
                                    icmp_type=int(icmp_type) if icmp_type and icmp_type.isdigit() else None,
                                    icmp_code=int(icmp_code) if icmp_code and icmp_code.isdigit() else None))
        elif proto == "IP":
            number = entry.sets.get("protocol-number", ["0"])[0]
            entries.append(SvcEntry(netutil.proto_name(number) or f"proto:{number}"))
        return entries

    def service_entries(self, name, depth=0, seen=()):
        """Returns (entries or None for any, unresolved)."""
        if name in seen or depth > limits.MAX_OBJECT_DEPTH:
            return [], [name]
        if name in self.services:
            return self.custom_service(name, self.services[name]), []
        if name in self.service_groups:
            entries, unresolved = [], []
            for member in self.service_groups[name]:
                e, u = self.service_entries(member, depth + 1, (*seen, name))
                if e is None:
                    return None, []
                entries += e
                unresolved += u
            return entries, unresolved
        if name in PREDEFINED:
            return PREDEFINED[name], []
        self.issue("warning", "unresolved-object", f"service {name!r} is not defined in this export and is not in this "
                   "tool's table of predefined FortiOS services")
        return [], [name]

    def service_set(self, names, negate):
        if not names:
            return ServiceSet(any=True)
        entries, unresolved = [], []
        for name in names:
            e, u = self.service_entries(name)
            if e is None:
                return ServiceSet(any=not negate)
            entries += e
            unresolved += u
        if negate:
            return ServiceSet(entries=[], unresolved=[f"negated service {', '.join(names)}"], refs=list(names))
        return ServiceSet(entries=entries, unresolved=unresolved, refs=list(names))

    # ------------------------------------------------------------ policies
    def expand_intf(self, names):
        if not names or "any" in names:
            return []
        out = []
        for name in names:
            out.append(name)
            out.extend(self.zones.get(name, []))
        return dedupe(out)

    def read_policies(self, scopes):
        position = 0
        for family, key in ((4, "firewall policy"), (6, "firewall policy6")):
            for section in self.get(scopes, key):
                for entry in section.entries:
                    position += 1
                    s = entry.sets
                    action = s.get("action", ["deny"])[0]
                    unsupported = []
                    users = s.get("users", []) + s.get("groups", []) + s.get("fsso-groups", [])
                    if s.get("internet-service", ["disable"])[0] == "enable" or s.get("internet-service-name"):
                        unsupported.append("internet-service (ISDB) destination")
                    if s.get("internet-service-src", ["disable"])[0] == "enable":
                        unsupported.append("internet-service (ISDB) source")
                    schedule = s.get("schedule", ["always"])[0]
                    apps = s.get("application", []) + s.get("app-category", [])
                    for tag in ("url-category", "web-category"):
                        if s.get(tag):
                            unsupported.append(f"URL category: {' '.join(s[tag])}")
                    profile_keys = ("ips-sensor", "av-profile", "webfilter-profile", "application-list", "ssl-ssh-profile",
                                    "profile-group", "dnsfilter-profile")
                    if any(k in s for k in profile_keys):
                        self.issue("info", "profiles-not-evaluated", "UTM / security profiles on policies (IPS, antivirus, web "
                                   "filter, application control) are not evaluated; they can block traffic a policy 'accepts'")
                    if s.get("application-list"):
                        apps = apps + [f"application-list {s['application-list'][0]}"]
                    svc = self.service_set(s.get("service", []), s.get("service-negate", ["disable"])[0] == "enable")
                    pid = s.get("name", [""])[0]
                    rule = Rule(
                        rule_id=f"{self.source_id}#{position}", original_id=entry.key, position=position,
                        action="allow" if action in ("accept", "ipsec") else "deny", original_action=action, name=pid,
                        enabled=s.get("status", ["enable"])[0] != "disable", scope=key,
                        src_zones=self.expand_intf(s.get("srcintf", [])), dst_zones=self.expand_intf(s.get("dstintf", [])),
                        src=self.addr_set(s.get("srcaddr" if family == 4 else "srcaddr6", s.get("srcaddr", [])),
                                          s.get("srcaddr-negate", ["disable"])[0] == "enable", family),
                        dst=self.addr_set(s.get("dstaddr" if family == 4 else "dstaddr6", s.get("dstaddr", [])),
                                          s.get("dstaddr-negate", ["disable"])[0] == "enable", family),
                        svc=svc, applications=apps, users=users, schedule=None if schedule == "always" else schedule,
                        log=s.get("logtraffic", ["utm"])[0] == "all",
                        comment=" ".join(s.get("comments", [])), unsupported=unsupported,
                        evidence=[self.lines.evidence(entry.line, entry.last_line)], extra={"family": family})
                    if "action" not in s:
                        rule.notes.append("No action is set; FortiOS treats a policy without an action as deny.")
                    self.policy.rules.append(rule)
                    if s.get("nat", ["disable"])[0] == "enable":
                        self.policy.nat_rules.append(NatRule(
                            nat_id=f"{self.source_id}#nat{len(self.policy.nat_rules) + 1}", kind="source",
                            original_src=rule.src, original_dst=rule.dst,
                            translated_src=AddrSet(unresolved=["egress interface address"]),
                            in_zone=",".join(rule.src_zones), out_zone=",".join(rule.dst_zones),
                            notes=[f"source NAT enabled on policy {entry.key}"], evidence=[self.lines.evidence(entry.line)]))

    def read_vips(self):
        for name, vip in self.vips.items():
            mapped = vip.sets.get("mappedip", [""])
            n, u = [], []
            for token in mapped:
                nets, unresolved = self.address_nets(token) if token in self.addresses else ([], [])
                if not nets:
                    try:
                        nets = [str(netutil.parse_ip_or_net(token))]
                    except netutil.ParseProblem:
                        unresolved = [token]
                n += nets
                u += unresolved
            ext = self.address_nets(name)[0]
            self.policy.nat_rules.append(NatRule(
                nat_id=f"{self.source_id}#nat{len(self.policy.nat_rules) + 1}", kind="destination",
                original_dst=AddrSet(nets=ext, refs=[name]), translated_dst=AddrSet(nets=n, unresolved=u),
                service=" ".join(vip.sets.get("extport", []) + vip.sets.get("mappedport", [])),
                in_zone=" ".join(vip.sets.get("extintf", [])), evidence=[self.lines.evidence(vip.line, vip.last_line)],
                notes=["virtual IP: policies that use it match the external (pre-NAT) address"]))

    def run(self):
        scopes = self.scope()
        for section in self.get(scopes, "system global"):
            if section.sets.get("hostname"):
                self.policy.hostname = limits.clip(section.sets["hostname"][0])
        m = re.search(r"#config-version=(\S+)", "\n".join(self.lines.raw[:5]))
        if m:
            self.policy.version = limits.clip(m.group(1))
        self.read_objects(scopes)
        self.read_policies(scopes)
        self.read_vips()
        if self.get(scopes, "firewall central-snat-map") or any(
                s.sets.get("central-nat", ["disable"])[0] == "enable" for s in self.get(scopes, "system settings")):
            self.issue("warning", "central-nat", "central NAT is configured; it is not modelled")
        self.policy.stats = {"rules": len(self.policy.rules), "nat_rules": len(self.policy.nat_rules),
                             "addresses": len(self.addresses), "address_groups": len(self.groups),
                             "services": len(self.services) + len(self.service_groups)}
        if not self.policy.rules:
            self.issue("warning", "no-rules", "no `config firewall policy` entries were found in this export")
        return self.policy


def parse(text, source_id):
    """Parse FortiOS CLI configuration text into a PolicySet."""
    if not detect(text):
        raise ValueError("this does not look like a FortiOS configuration (no `config firewall ...` or "
                         "`config system interface` section)")
    return _Parser(text, source_id).run()
