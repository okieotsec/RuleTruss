"""Palo Alto PAN-OS adapter: a firewall's running or candidate configuration as XML.

Reads zones, interface addresses, address / address-group / service / service-group objects (nested), security rules in
order, and NAT rules. Documented behaviour used (see docs/SOURCES.md): security rules match the original (pre-NAT)
addresses and the post-NAT zones; traffic that matches no rule is handled by the default rules (intrazone allow,
interzone deny).

Not evaluated, always reported: application conditions (App-ID), `application-default` services, user and HIP conditions,
URL categories, dynamic address groups, FQDN addresses, schedules, and Panorama device-group inheritance.
"""
import ipaddress

from .. import limits, netutil
from ..model import AddrSet, Evidence, NatRule, PolicySet, Rule, ServiceSet, SvcEntry
from .common import dedupe
from .xmlsafe import members, parse_xml, snippet, text

# Built-in services documented by Palo Alto Networks. Anything else with application-default is undecidable here.
BUILTIN_SERVICES = {"service-http": [SvcEntry("tcp", None, [(80, 80), (8080, 8080)])],
                    "service-https": [SvcEntry("tcp", None, [(443, 443)])]}


def detect(text_):
    head = text_[:4000]
    return "<config" in head and ("urldb=" in head or "<devices>" in text_[:200_000])


class _Parser:
    def __init__(self, root, source_id):
        self.root = root
        self.source_id = source_id
        self.policy = PolicySet(policy_id=source_id, source_id=source_id, vendor="panos", platform="Palo Alto PAN-OS",
                                version=limits.clip(root.get("version", "")), stateful=True, default_mode="panos",
                                default_action="deny", default_basis="interzone-default deny / intrazone-default allow",
                                address_context="original-packet")
        self.addresses, self.groups, self.services, self.service_groups = {}, {}, {}, {}
        self.seen = set()

    def issue(self, severity, code, message, name=None):
        key = (code, message)
        if key not in self.seen:
            self.seen.add(key)
            self.policy.issue(severity, code, message, [Evidence(self.source_id, "config", name or "", "")] if name else [])

    # ------------------------------------------------------------ objects
    def read_scope(self, scope):
        for entry in scope.findall("address/entry"):
            name = entry.get("name", "")
            if (n := entry.find("ip-netmask")) is not None:
                self.addresses[name] = ("net", (n.text or "").strip())
            elif (n := entry.find("ip-range")) is not None:
                self.addresses[name] = ("range", (n.text or "").strip())
            elif (n := entry.find("fqdn")) is not None:
                self.addresses[name] = ("fqdn", (n.text or "").strip())
            elif entry.find("ip-wildcard") is not None:
                self.addresses[name] = ("wildcard", text(entry, "ip-wildcard"))
            else:
                self.addresses[name] = ("unknown", "")
        for entry in scope.findall("address-group/entry"):
            name = entry.get("name", "")
            if entry.find("static") is not None:
                self.groups[name] = ("static", members(entry, "static"))
            else:
                self.groups[name] = ("dynamic", [text(entry, "dynamic/filter")])
        for entry in scope.findall("service/entry"):
            name = entry.get("name", "")
            entries = []
            for proto in ("tcp", "udp", "sctp"):
                node = entry.find(f"protocol/{proto}")
                if node is not None:
                    try:
                        dports = netutil.parse_port_ranges(text(node, "port")) if text(node, "port") else None
                        sports = netutil.parse_port_ranges(text(node, "source-port")) if text(node, "source-port") else None
                        entries.append(SvcEntry(proto, sports, dports))
                    except netutil.ParseProblem:
                        self.issue("warning", "service-parse", f"service {name!r} has a port list that could not be read")
            self.services[name] = entries
        for entry in scope.findall("service-group/entry"):
            self.service_groups[entry.get("name", "")] = members(entry, "members")

    def address_nets(self, name, depth=0, seen=()):
        """Resolve an address object or group. Returns (nets, unresolved)."""
        if name in seen or depth > limits.MAX_OBJECT_DEPTH:
            self.issue("warning", "group-cycle", f"address group {name!r} is nested too deeply or contains itself")
            return [], [name]
        if name in self.addresses:
            kind, value = self.addresses[name]
            try:
                if kind == "net":
                    return [str(netutil.parse_ip_or_net(value))], []
                if kind == "range":
                    lo, _, hi = value.partition("-")
                    return [str(n) for n in ipaddress.summarize_address_range(
                        ipaddress.ip_address(lo.strip()), ipaddress.ip_address(hi.strip()))], []
            except (netutil.ParseProblem, ValueError):
                pass
            self.issue("warning", "address-unresolved", f"address {name!r} ({kind}) cannot be resolved to IP addresses; "
                       "rules that use it are reported as undecidable")
            return [], [f"{kind}:{value or name}"]
        if name in self.groups:
            kind, mem = self.groups[name]
            if kind == "dynamic":
                self.issue("warning", "dynamic-group", f"address group {name!r} is dynamic (tag filter); its members are "
                           "not known from the configuration")
                return [], [f"dynamic group {name}"]
            nets, unresolved = [], []
            for member in mem:
                n, u = self.address_nets(member, depth + 1, (*seen, name))
                nets += n
                unresolved += u
            return nets, unresolved
        try:                                         # a literal IP written directly in the rule
            return [str(netutil.parse_ip_or_net(name))], []
        except netutil.ParseProblem:
            self.issue("warning", "unresolved-object", f"address {name!r} is not defined in this export")
            return [], [name]

    def addr_set(self, names, negate=False):
        if not names or "any" in names:
            return AddrSet(any=not negate)               # "NOT any" matches nothing: an empty set
        nets, unresolved = [], []
        for name in names:
            n, u = self.address_nets(name)
            nets += n
            unresolved += u
        return AddrSet(nets=dedupe(nets), unresolved=dedupe(unresolved), negate=negate, refs=list(names))

    def service_entries(self, name, depth=0, seen=()):
        if name in seen or depth > limits.MAX_OBJECT_DEPTH:
            return [], [name]
        if name in BUILTIN_SERVICES:
            return list(BUILTIN_SERVICES[name]), []
        if name in self.services:
            return list(self.services[name]), []
        if name in self.service_groups:
            entries, unresolved = [], []
            for member in self.service_groups[name]:
                e, u = self.service_entries(member, depth + 1, (*seen, name))
                entries += e
                unresolved += u
            return entries, unresolved
        self.issue("warning", "unresolved-object", f"service {name!r} is not defined in this export")
        return [], [name]

    def service_set(self, names):
        if not names or "any" in names:
            return ServiceSet(any=True), []
        entries, unresolved, notes = [], [], []
        for name in names:
            if name == "application-default":
                unresolved.append("application-default (ports depend on the application)")
                notes.append("service is application-default: the allowed ports come from the App-ID database, which this "
                             "tool does not have")
                continue
            e, u = self.service_entries(name)
            entries += e
            unresolved += u
        return ServiceSet(entries=entries, unresolved=unresolved, refs=list(names)), notes

    # ------------------------------------------------------------ interfaces, zones, rules
    def read_network(self, device):
        iface_ips = {}
        for node in device.findall("network/interface//entry"):
            entries = (node.findall("layer3/ip/entry") + node.findall("ip/entry")
                       + node.findall("layer3/units/entry/ip/entry"))
            for ip_entry in entries:
                name = node.get("name", "")
                try:
                    iface_ips.setdefault(name, []).append(str(ipaddress.ip_interface(ip_entry.get("name", "")).network))
                except ValueError:
                    continue
        return iface_ips

    def read_zones(self, vsys, iface_ips):
        for zone in vsys.findall("zone/entry"):
            name = zone.get("name", "")
            ifaces = []
            for kind in ("layer3", "layer2", "virtual-wire", "tap", "tunnel", "external"):
                ifaces += members(zone, f"network/{kind}")
            nets = []
            for iface in ifaces:
                nets += iface_ips.get(iface, [])
            self.policy.interfaces[name] = {"nets": dedupe(nets), "zone": name, "interfaces": ifaces}

    def read_security_rules(self, vsys, scope_label, offset=0):
        rules = vsys.findall("rulebase/security/rules/entry") if scope_label == "local" else vsys
        for index, entry in enumerate(rules, start=1):
            position = offset + index
            name = entry.get("name", f"rule-{position}")
            action = text(entry, "action", "allow")
            applications = members(entry, "application")
            users = [u for u in members(entry, "source-user") if u != "any"]
            unsupported = []
            for tag, label in (("category", "URL category"), ("source-hip", "HIP profile"), ("destination-hip", "HIP profile")):
                vals = [v for v in members(entry, tag) if v != "any"]
                if vals:
                    unsupported.append(f"{label}: {', '.join(vals)}")
            if entry.find("profile-setting") is not None:
                self.issue("info", "profiles-not-evaluated", "security profiles / profile groups on rules (antivirus, URL "
                           "filtering, etc.) are not evaluated; they can block traffic a rule 'allows'")
            svc, notes = self.service_set(members(entry, "service"))
            rule_type = text(entry, "rule-type", "universal")
            rule = Rule(
                rule_id=f"{self.source_id}#{position}", original_id=name, position=position,
                action="allow" if action == "allow" else "deny", original_action=action, name=name,
                enabled=text(entry, "disabled", "no") != "yes", scope=scope_label,
                src_zones=[z for z in members(entry, "from") if z != "any"],
                dst_zones=[z for z in members(entry, "to") if z != "any"],
                src=self.addr_set(members(entry, "source"), text(entry, "negate-source") == "yes"),
                dst=self.addr_set(members(entry, "destination"), text(entry, "negate-destination") == "yes"),
                svc=svc, applications=[a for a in applications if a != "any"], users=users,
                schedule=text(entry, "schedule") or None,
                log=text(entry, "log-end", "yes") == "yes" or text(entry, "log-start") == "yes",
                comment=text(entry, "description"), unsupported=unsupported, notes=notes,
                evidence=[Evidence(self.source_id, "config", f'security rule "{name}" (position {position})', snippet(entry))],
                extra={"rule_type": rule_type, "scope": scope_label})
            if rule.svc.unresolved and not rule.applications:
                rule.notes.append("application-default with no application restriction: effective ports are unknown.")
            self.policy.rules.append(rule)

    def read_nat(self, vsys):
        for index, entry in enumerate(vsys.findall("rulebase/nat/rules/entry"), start=1):
            name = entry.get("name", f"nat-{index}")
            translated_src = AddrSet()
            if entry.find("source-translation") is not None:
                for static in ("static-ip/translated-address", "dynamic-ip-and-port/translated-address/member",
                               "dynamic-ip/translated-address/member"):
                    node = entry.find(f"source-translation/{static}")
                    if node is not None and node.text:
                        n, u = self.address_nets(node.text.strip())
                        translated_src = AddrSet(nets=n, unresolved=u, refs=[node.text.strip()])
                        break
                else:
                    translated_src = AddrSet(unresolved=["interface address"], refs=["interface address"])
            translated_dst = AddrSet()
            node = entry.find("destination-translation/translated-address")
            if node is not None and node.text:
                n, u = self.address_nets(node.text.strip())
                translated_dst = AddrSet(nets=n, unresolved=u, refs=[node.text.strip()])
            kind = "destination" if translated_dst.nets or translated_dst.unresolved else "source"
            self.policy.nat_rules.append(NatRule(
                nat_id=f"{self.source_id}#nat{index}", kind=kind, original_src=self.addr_set(members(entry, "source")),
                original_dst=self.addr_set(members(entry, "destination")), translated_src=translated_src,
                translated_dst=translated_dst, service=text(entry, "service"),
                in_zone=",".join(members(entry, "from")), out_zone=",".join(members(entry, "to")),
                enabled=text(entry, "disabled", "no") != "yes",
                evidence=[Evidence(self.source_id, "config", f'NAT rule "{name}"', snippet(entry))]))

    def run(self):
        root = self.root
        if root.tag != "config":
            raise ValueError("this XML is not a PAN-OS configuration (the top element is not <config>)")
        if root.find("shared") is not None:
            self.read_scope(root.find("shared"))
        devices = root.findall("devices/entry")
        if not devices:
            raise ValueError("no <devices> section found; export the full running configuration")
        has_groups = root.find("devices/entry/device-group") is not None
        if has_groups or root.find("readonly/devices/entry/device-group") is not None:
            self.issue("warning", "panorama", "Panorama device groups are present; only the firewall's own rulebase is read "
                       "and device-group pre/post rules are not merged")
        device = devices[0]
        if len(devices) > 1:
            self.issue("info", "multi-device", "more than one device entry; only the first is read")
        self.policy.hostname = limits.clip(text(device, "deviceconfig/system/hostname"))
        iface_ips = self.read_network(device)
        vsyses = device.findall("vsys/entry")
        if not vsyses:
            raise ValueError("no <vsys> found in the configuration")
        if len(vsyses) > 1:
            self.issue("info", "multi-vsys", f"{len(vsyses)} virtual systems present; only {vsyses[0].get('name')!r} is read")
        vsys = vsyses[0]
        self.read_scope(vsys)
        self.read_zones(vsys, iface_ips)
        self.read_security_rules(vsys, "local")
        self.read_nat(vsys)
        self.policy.stats = {"rules": len(self.policy.rules), "nat_rules": len(self.policy.nat_rules),
                             "zones": len(self.policy.interfaces), "addresses": len(self.addresses),
                             "address_groups": len(self.groups), "services": len(self.services)}
        self.policy.issue("info", "panos-nat-context", "PAN-OS security rules use the original (pre-NAT) addresses and the "
                          "post-NAT zones; the zones given when a rule is evaluated must be the post-NAT zones.")
        return self.policy


def parse(text_, source_id):
    """Parse a PAN-OS XML configuration into a PolicySet."""
    return _Parser(parse_xml(text_), source_id).run()
