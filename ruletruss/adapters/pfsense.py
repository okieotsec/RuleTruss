"""pfSense and OPNsense adapter: `config.xml` (backup) with the legacy `<filter><rule>` rule list.

Reads interfaces, aliases (host, network, port; nested), filter rules in order (floating rules with `quick` first, then
interface rules), and port-forward NAT. Rules are evaluated on the interface where traffic enters, first match wins.

Not evaluated, always reported: floating rules without `quick` (last match wins), rules with `statetype none`, rule
schedules, gateway/policy routing, aliases that are URL tables or contain host names, `(self)`, DHCP-addressed
interface networks, OPNsense MVC rules (`OPNsense/Firewall/Filter`), and OPNsense automation rules.
"""
import ipaddress

from .. import limits, netutil
from ..model import AddrSet, Evidence, NatRule, PolicySet, Rule, ServiceSet, SvcEntry
from .common import cap_expansion, dedupe, spend_visit
from .xmlsafe import parse_xml, snippet, text

ICMP_NAMES = {"echoreq": 8, "echorep": 0, "unreach": 3, "squench": 4, "redir": 5, "althost": 6, "routeradv": 9,
              "routersol": 10, "timex": 11, "paramprob": 12, "timereq": 13, "timerep": 14, "inforeq": 15, "inforep": 16,
              "maskreq": 17, "maskrep": 18}
ICMP6_NAMES = {"unreach": 1, "toobig": 2, "timex": 3, "paramprob": 4, "echoreq": 128, "echorep": 129, "listenq": 130,
               "listenr": 131, "listend": 132, "routersol": 133, "routeradv": 134, "neighbrsol": 135, "neighbradv": 136,
               "redir": 137}


def detect(text_):
    head = text_[:2000]
    return "<pfsense>" in head or "<opnsense>" in head


class _Parser:
    def __init__(self, root, source_id):
        self.root = root
        self.source_id = source_id
        vendor = "opnsense" if root.tag == "opnsense" else "pfsense"
        self.policy = PolicySet(policy_id=source_id, source_id=source_id, vendor=vendor,
                                platform="OPNsense" if vendor == "opnsense" else "pfSense", stateful=True,
                                default_action="deny", default_basis="default block on interfaces", address_context="internal-real",
                                version=limits.clip(text(root, "version")), hostname=limits.clip(text(root, "system/hostname")))
        self.aliases = {}
        self.seen = set()

    def issue(self, severity, code, message, name=None):
        key = (code, message)
        if key not in self.seen:
            self.seen.add(key)
            self.policy.issue(severity, code, message, [Evidence(self.source_id, "config", name, "")] if name else [])

    def read_interfaces(self):
        ifaces = self.root.find("interfaces")
        if ifaces is None:
            return
        for node in ifaces:
            ip, prefix = text(node, "ipaddr"), text(node, "subnet")
            nets, host_ips = [], []
            if ip and netutil.is_uint(prefix):
                try:
                    interface = ipaddress.ip_interface(f"{ip}/{prefix}")
                    nets.append(str(interface.network))
                    host_ips.append(f"{interface.ip}/{interface.max_prefixlen}")
                except ValueError:
                    pass
            self.policy.interfaces[node.tag] = {
                "nets": nets, "host_ips": host_ips, "zone": node.tag, "descr": limits.clip(text(node, "descr")),
                "dynamic": ip in ("dhcp", "pppoe", "ppp")}

    def read_aliases(self):
        for node in self.root.findall("aliases/alias"):
            name = text(node, "name")
            if name:
                self.aliases[name] = (text(node, "type"), text(node, "address").split())

    def alias_nets(self, name, depth=0, seen=()):
        if not spend_visit(self, depth, name, self.issue):
            return [], [name]
        kind, values = self.aliases[name]
        if name in seen or depth > limits.MAX_OBJECT_DEPTH:
            self.issue("warning", "group-cycle", f"alias {name!r} is nested too deeply or contains itself")
            return [], [name]
        if kind in ("url", "urltable", "url_ports", "urltable_ports", "geoip", "external", "dynipv6host", "networkgroup"):
            self.issue("warning", "alias-unresolved", f"alias {name!r} has type {kind}, which cannot be resolved offline")
            return [], [f"{kind} alias {name}"]
        nets, unresolved = [], []
        for value in values:
            if value in self.aliases:
                n, u = self.alias_nets(value, depth + 1, (*seen, name))
                nets += n
                unresolved += u
                if cap_expansion(nets, unresolved, name, self.issue):
                    break
                continue
            try:
                nets.append(str(netutil.parse_ip_or_net(value)))
            except netutil.ParseProblem:
                unresolved.append(f"host name {value}")
                self.issue("warning", "alias-hostname", f"alias {name!r} contains a host name ({value[:60]}); it is not "
                           "resolved and rules using it are undecidable")
        return nets, unresolved

    def port_ranges(self, name_or_ports, depth=0, seen=()):
        """Ports from a literal or a port alias. Returns (ranges or None, unresolved)."""
        value = name_or_ports.strip()
        if not value:
            return None, []
        if value in self.aliases:
            if not spend_visit(self, depth, value, self.issue):
                return None, [f"port alias {value}"]
            kind, values = self.aliases[value]
            if value in seen:
                self.issue("warning", "group-cycle", f"port alias {value!r} contains itself")
                return None, [f"port alias {value}"]
            if depth > limits.MAX_OBJECT_DEPTH or kind not in ("port",):
                return None, [f"{kind} alias {value}"]
            ranges, unresolved = [], []
            for item in values:
                r, u = self.port_ranges(item, depth + 1, (*seen, value))
                ranges += r or []
                unresolved += u
            return netutil.merge_ranges(ranges), unresolved
        try:
            return netutil.parse_port_ranges(value.replace(":", "-").replace(" ", ",")), []
        except netutil.ParseProblem:
            return None, [f"port {value[:40]}"]

    def endpoint(self, node, ipprotocol):
        """Parse <source> or <destination>. Returns (AddrSet, port ranges or None, unresolved port names)."""
        family = {"inet": ["0.0.0.0/0"], "inet6": ["::/0"]}.get(ipprotocol)
        ports, port_unres = self.port_ranges(text(node, "port"))
        negate = node.find("not") is not None
        if node.find("any") is not None or (node.find("network") is None and node.find("address") is None):
            return (AddrSet(nets=family, refs=["any"]) if family else AddrSet(any=True)), ports, port_unres
        network = text(node, "network")
        address = text(node, "address")
        if network:
            return self.interface_network(network, negate), ports, port_unres
        if address in self.aliases:
            nets, unresolved = self.alias_nets(address)
            found = AddrSet(nets=dedupe(nets), unresolved=dedupe(unresolved), negate=negate, refs=[address])
            return found, ports, port_unres
        try:
            return AddrSet(nets=[str(netutil.parse_ip_or_net(address))], negate=negate), ports, port_unres
        except netutil.ParseProblem:
            self.issue("warning", "unresolved-object", f"address or alias {address[:60]!r} is not defined in this export")
            return AddrSet(unresolved=[address], negate=negate, refs=[address]), ports, port_unres

    def interface_network(self, label, negate):
        if label == "(self)":
            return AddrSet(unresolved=["(self): all addresses of this firewall"], negate=negate, refs=["(self)"])
        host = label.endswith("ip")
        key = label[:-2] if host else label
        iface = self.policy.interfaces.get(key)
        if iface is None:
            self.issue("warning", "unresolved-object", f"interface {label!r} is not defined in this export")
            return AddrSet(unresolved=[label], negate=negate, refs=[label])
        nets = iface["host_ips"] if host else iface["nets"]
        if not nets:
            self.issue("warning", "dynamic-interface", f"interface {key!r} has no static address in this export, so "
                       f"{'its address' if host else 'its network'} cannot be resolved")
            return AddrSet(unresolved=[f"{label} (no static address)"], negate=negate, refs=[label])
        return AddrSet(nets=list(nets), negate=negate, refs=[label])

    def icmp_entries(self, proto, node):
        names = [n for n in text(node, "icmptype").split(",") if n]
        table = ICMP6_NAMES if proto == "icmp6" else ICMP_NAMES
        if not names:
            return [SvcEntry(proto)], []
        entries, unknown = [], []
        for name in names:
            if name == "any":
                return [SvcEntry(proto)], []
            if name in table:
                entries.append(SvcEntry(proto, icmp_type=table[name]))
            else:
                unknown.append(name)
        return (entries or [SvcEntry(proto)]), unknown

    def read_rules(self):
        filt = self.root.find("filter")
        nodes = filt.findall("rule") if filt is not None else []
        floating_quick, interface_rules = [], []
        for index, node in enumerate(nodes, start=1):
            name = text(node, "descr") or text(node, "tracker") or f"rule-{index}"
            unsupported, notes = [], []
            floating = text(node, "floating") == "yes" or (node.find("floating") is not None and text(node, "floating") != "no")
            quick = node.find("quick") is not None or (self.policy.vendor == "opnsense" and not floating)
            if floating and node.find("quick") is None and self.policy.vendor == "pfsense":
                unsupported.append("floating rule without Quick (last matching rule wins; not modelled)")
            if text(node, "statetype") == "none":
                unsupported.append("rule does not keep state (stateless); replies need their own rule")
            if text(node, "sched"):
                unsupported.append(f"schedule {text(node, 'sched')}")
            if text(node, "gateway"):
                notes.append(f"policy-routing gateway {text(node, 'gateway')} is set; routing is not modelled")
            ipprotocol = text(node, "ipprotocol", "inet")
            src_node, dst_node = node.find("source"), node.find("destination")
            src, sport, sun = self.endpoint(src_node if src_node is not None else node, ipprotocol)
            dst, dport, dun = self.endpoint(dst_node if dst_node is not None else node, ipprotocol)
            protocol = text(node, "protocol", "any").lower()
            entries = []
            if protocol in ("any", ""):
                entries = [SvcEntry("ip")]
            elif protocol == "tcp/udp":
                entries = [SvcEntry("tcp", sport, dport), SvcEntry("udp", sport, dport)]
            elif protocol in ("icmp", "icmp6", "ipv6-icmp"):
                entries, unknown = self.icmp_entries("icmp6" if protocol != "icmp" else "icmp", node)
                for name in unknown:             # an ICMP type nobody here can read must not be taken as every type
                    unsupported.append(f"ICMP type {limits.clip(name, 30)!r} is not one this tool knows")
            else:
                proto = netutil.proto_name(protocol)
                if proto is None:
                    unsupported.append(f"unknown protocol {protocol!r}")
                    proto = "ip"
                with_ports = proto in ("tcp", "udp")
                entries = [SvcEntry(proto, sport if with_ports else None, dport if with_ports else None)]
            svc = ServiceSet(any=protocol in ("any", "") and not sport and not dport, entries=entries,
                             unresolved=sun + dun)
            action = text(node, "type", "pass")
            interfaces = [i for i in text(node, "interface").split(",") if i]
            direction = text(node, "direction", "any")
            if floating and direction == "out":
                unsupported.append("floating rule applied outbound (evaluated after NAT on the egress interface)")
            rule = Rule(
                rule_id=f"{self.source_id}#{index}", original_id=text(node, "tracker") or str(index), position=0,
                action="allow" if action == "pass" else "deny", original_action=action, name=name,
                enabled=node.find("disabled") is None, scope="floating" if floating else ",".join(interfaces),
                src_zones=interfaces, src=src, dst=dst, svc=svc, log=node.find("log") is not None,
                comment=limits.clip(text(node, "descr")), unsupported=unsupported, notes=notes,
                evidence=[Evidence(self.source_id, "config", f'filter rule {index} "{limits.clip(name, 60)}"', snippet(node))],
                extra={"floating": floating, "quick": quick, "direction": direction, "ipprotocol": ipprotocol})
            (floating_quick if floating else interface_rules).append(rule)
        for position, rule in enumerate(floating_quick + interface_rules, start=1):
            rule.position = position
            if len(self.policy.rules) >= limits.MAX_RULES:
                raise limits.LimitExceeded(f"more than {limits.MAX_RULES:,} rules")
            self.policy.rules.append(rule)

    def read_nat(self):
        for index, node in enumerate(self.root.findall("nat/rule"), start=1):
            target = text(node, "target")
            dst_node = node.find("destination")
            dst, _, _ = self.endpoint(dst_node if dst_node is not None else node, "inet")
            if target and self._is_ip(target):
                translated = AddrSet(nets=[str(netutil.parse_ip_or_net(target))])
            else:
                translated = AddrSet(unresolved=[target or "unknown"], refs=[target])
            self.policy.nat_rules.append(NatRule(
                nat_id=f"{self.source_id}#nat{index}", kind="destination", original_dst=dst, translated_dst=translated,
                service=f"{text(node, 'protocol')} {text(node, 'local-port')}".strip(), in_zone=text(node, "interface"),
                enabled=node.find("disabled") is None,
                notes=["port forward: the associated firewall rule matches the translated (internal) destination"],
                evidence=[Evidence(self.source_id, "config", f"port forward {index}", snippet(node))]))

    @staticmethod
    def _is_ip(value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def run(self):
        self.read_interfaces()
        self.read_aliases()
        self.read_rules()
        self.read_nat()
        if self.root.find("OPNsense/Firewall/Filter") is not None:
            self.issue("warning", "opnsense-mvc-rules", "OPNsense MVC firewall rules (OPNsense/Firewall/Filter) are present but "
                       "not read; only legacy <filter><rule> entries are parsed")
        self.policy.stats = {"rules": len(self.policy.rules), "nat_rules": len(self.policy.nat_rules),
                             "aliases": len(self.aliases), "interfaces": len(self.policy.interfaces)}
        self.policy.issue("info", "rule-order", "Rules apply on the interface where traffic enters; floating rules with Quick "
                          "come first, then interface rules in order. Evaluate with the ingress interface name as the zone.")
        if not self.policy.rules:
            self.policy.issue("warning", "no-rules", "no <filter><rule> entries were found in this export")
        return self.policy


def parse(text_, source_id):
    """Parse a pfSense or OPNsense config.xml into a PolicySet."""
    root = parse_xml(text_)
    if root.tag not in ("pfsense", "opnsense"):
        raise ValueError("this XML is not a pfSense or OPNsense configuration (the top element is not <pfsense> or <opnsense>)")
    return _Parser(root, source_id).run()
