"""UniFi Network adapter: firewall zones and policies as exported from the UniFi Network Integration API.

The input is the JSON bundle written by tools/unifi_export.py (read-only GET requests to the gateway's local API): firewall zones,
firewall policies, networks, traffic matching lists, optionally switch ACL rules. Written from Ubiquiti's published OpenAPI schema
(Network 10.3.58) and tested on synthetic exports, not on a real gateway; anything it does not recognise is kept and reported,
never guessed.

Model used (see docs/SOURCES.md): a policy applies to one source zone and one destination zone, policies of a zone pair are
evaluated in `index` order, the first match wins. A connection's first packet is in state NEW and its replies are ESTABLISHED, checked
against the policies of the reverse zone pair (so a policy for all states that blocks that direction also blocks the replies). Policies
predefined by UniFi (origin SYSTEM_DEFINED, ORCHESTRATED, DERIVED) appear in the same list and are read like any other; in a real export
every zone pair ends in a predefined Allow All / Block All policy at index 2147483647.

Not evaluated, always reported: application and application-category filters, domain filters, region (country) filters, VPN
membership, IPv6 interface identifiers, MAC filters, schedules, IPsec matching, and protocol filters in a shape this adapter does
not know. A policy that only applies to existing connections (a connection-state filter without NEW) is kept but never matches the
start of a connection. A zone pair with no listed policy at all is reported as undecidable rather than assumed. The API leaves the ICMP
message type out of predefined ICMP policies, so their type is treated as unknown.
"""
import ipaddress
import json
import re

from .. import limits
from ..model import AddrSet, Evidence, PolicySet, Rule, ServiceSet, SvcEntry
from .common import dedupe

MARK = "ruletruss_unifi_export"
SCHEMA = "UniFi Network Integration API 10.3.58"
PROTOCOL_NAMES = {"TCP": "tcp", "UDP": "udp", "ICMP": "icmp", "ICMPV4": "icmp", "ICMPV6": "icmp6", "ICMP6": "icmp6", "SCTP": "sctp",
                  "GRE": "proto:47", "ESP": "proto:50", "AH": "proto:51"}
ICMP_TYPES = {"icmp": {"ECHO_REPLY": 0, "DESTINATION_UNREACHABLE": 3, "SOURCE_QUENCH": 4, "REDIRECT": 5, "ECHO_REQUEST": 8,
                       "ROUTER_ADVERTISEMENT": 9, "ROUTER_SOLICITATION": 10, "TIME_EXCEEDED": 11, "PARAMETER_PROBLEM": 12,
                       "TIMESTAMP_REQUEST": 13, "TIMESTAMP_REPLY": 14},
              "icmp6": {"DESTINATION_UNREACHABLE": 1, "PACKET_TOO_BIG": 2, "TIME_EXCEEDED": 3, "PARAMETER_PROBLEM": 4, "ECHO_REQUEST": 128,
                        "ECHO_REPLY": 129, "ROUTER_SOLICITATION": 133, "ROUTER_ADVERTISEMENT": 134, "NEIGHBOR_SOLICITATION": 135,
                        "NEIGHBOR_ADVERTISEMENT": 136, "REDIRECT": 137}}
PORT_PROTOCOLS = {"tcp", "udp", "sctp"}
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
MAX_ITEMS = 100_000


def detect(text):
    head = text[:4096]
    return head.lstrip().startswith("{") and f'"{MARK}"' in head


def _s(value, limit=120):
    """Text from the export, safe to show: control characters removed, clipped."""
    return limits.clip(CONTROL.sub(" ", str(value)).strip(), limit)


def _list(value):
    if isinstance(value, list) and len(value) > MAX_ITEMS:       # a policy list cut short would change what the rest of the export means
        raise limits.LimitExceeded(f"a list in the export has {len(value):,} items; the limit is {MAX_ITEMS:,}")
    return value if isinstance(value, list) else []


def _dict(value):
    return value if isinstance(value, dict) else {}


MAC_TEXT = re.compile(r"[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}")


def _macs(value):
    """MAC addresses from a string, a list or the {'macAddresses': [...]} form, lower-cased and colon-separated."""
    if isinstance(value, dict):
        value = value.get("macAddresses")
    if isinstance(value, list):
        value = " ".join(str(v) for v in value[:50])
    return [m.lower().replace("-", ":") for m in MAC_TEXT.findall(str(value or ""))][:50]


def _host_net(address):
    try:
        return str(ipaddress.ip_network(address, strict=False))
    except ValueError:
        return None


def _ranges_complement(ranges):
    """Port ranges that are not in `ranges` (for 'match opposite')."""
    out, cursor = [], 1
    for low, high in sorted(ranges):
        if low > cursor:
            out.append((cursor, low - 1))
        cursor = max(cursor, high + 1)
    if cursor <= 65535:
        out.append((cursor, 65535))
    return out


class _Parser:
    def __init__(self, doc, source_id):
        self.doc, self.source_id = doc, source_id
        site = _dict(doc.get("site"))
        self.policy = PolicySet(policy_id=source_id, source_id=source_id, vendor="unifi", platform="UniFi Network (zone-based firewall)",
                                version=_s(doc.get("application_version", "")), hostname=_s(site.get("name", "")), stateful=True,
                                default_action="deny", default_mode="zone_pairs",
                                default_basis="each zone pair ends in its own predefined policy (Allow All Traffic or Block All Traffic); "
                                              "a pair with no listed policy cannot be decided",
                                address_context="unknown")
        self.zone_names, self.networks, self.lists = {}, {}, {}
        self.host_addresses = []
        self.seen = set()

    def issue(self, severity, code, message, evidence=None):
        key = (code, message)
        if key not in self.seen:
            self.seen.add(key)
            self.policy.issue(severity, code, message, evidence or [])

    # ------------------------------------------------------------ objects
    def read_networks(self):
        for item in _list(self.doc.get("networks")):
            item = _dict(item)
            ident, name = str(item.get("id", "")), _s(item.get("name", "")) or "network"
            nets = []
            ipv4 = _dict(item.get("ipv4Configuration"))
            if ipv4.get("hostIpAddress") is not None and ipv4.get("prefixLength") is not None:
                net = _host_net(f"{ipv4['hostIpAddress']}/{ipv4['prefixLength']}")
                if net:
                    nets.append(net)
                    self.host_addresses.append(str(ipv4["hostIpAddress"]))
            self.networks[ident] = {"name": name, "nets": nets, "vlan": item.get("vlanId"), "management": _s(item.get("management", ""))}
            taken = {n["key"] for n in self.networks.values() if "key" in n}
            self.networks[ident]["key"] = name if name not in taken else f"{name}-{ident[:6]}"       # the interface name when translating
            if not nets:
                self.issue("info", "network-no-subnet", f"network {name} has no gateway-managed IPv4 subnet in the export, so rules that "
                           "name it cannot be matched to addresses")

    def read_zones(self):
        for item in _list(self.doc.get("zones")):
            item = _dict(item)
            ident = str(item.get("id", ""))
            name = _s(item.get("name", "")) or f"zone-{ident[:8]}"
            if name in self.zone_names.values():
                name = f"{name} ({ident[:8]})"
            self.zone_names[ident] = name
            nets, members, network_nets, missing = [], [], {}, []
            for network_id in _list(item.get("networkIds")):
                network = self.networks.get(str(network_id))
                if network:
                    nets += network["nets"]
                    members.append(network["name"])
                    network_nets[network["key"]] = list(network["nets"])
                else:
                    missing.append(str(network_id)[:8])
            if missing:
                self.issue("warning", "zone-network-missing", f"zone {name} refers to {len(missing)} network(s) that are not in the "
                           f"export's network list ({', '.join(missing[:4])}), so their subnets are unknown and addresses in them cannot "
                           "be placed in this zone")
            origin = _s(_dict(item.get("metadata")).get("origin", ""))
            if name.lower() == "gateway" and origin == "SYSTEM_DEFINED":
                # traffic to the gateway's own addresses belongs to the Gateway zone (a host route beats the network's own subnet)
                nets += [f"{n.split('/')[0]}/{32 if ':' not in n else 128}" for n in self.host_addresses]
            self.policy.interfaces[name] = {"nets": dedupe(nets), "zone": name, "networks": members, "origin": origin,
                                            "network_nets": network_nets, "missing_networks": len(missing)}

    def read_lists(self):
        for item in _list(self.doc.get("traffic_matching_lists")):
            item = _dict(item)
            self.lists[str(item.get("id", ""))] = {"name": _s(item.get("name", "")), "type": item.get("type"),
                                                   "items": _list(item.get("items"))}

    def zone_name(self, zone_id):
        return self.zone_names.get(str(zone_id)) or f"zone-{str(zone_id)[:8]}"

    # ------------------------------------------------------------ matching pieces
    def ip_items(self, items):
        """(nets, unresolved) from 'IP matching' items."""
        nets, unresolved = [], []
        for entry in _list(items):
            entry = _dict(entry)
            kind = entry.get("type")
            try:
                if kind == "IP_ADDRESS" or kind == "SUBNET":
                    nets.append(str(ipaddress.ip_network(str(entry["value"]).strip(), strict=False)))
                elif kind == "IP_ADDRESS_RANGE":
                    nets += [str(n) for n in ipaddress.summarize_address_range(ipaddress.ip_address(str(entry["start"]).strip()),
                                                                              ipaddress.ip_address(str(entry["stop"]).strip()))]
                else:
                    unresolved.append(f"unrecognised address item {_s(kind, 40)}")
            except (KeyError, ValueError, TypeError):
                unresolved.append(f"unreadable address item {_s(kind, 40)}")
            if len(nets) > limits.MAX_EXPANSION:                          # ranges multiply: one item can be 250 networks
                self.issue("warning", "group-too-large", f"an address list expands to more than {limits.MAX_EXPANSION:,} entries; the rest "
                           "were not read")
                del nets[limits.MAX_EXPANSION:]
                unresolved.append("address list too large to read completely")
                break
        return nets, unresolved

    def address(self, flt, rule_unsupported):
        """AddrSet for an `ipAddressFilter`."""
        flt = _dict(flt)
        negate = bool(flt.get("matchOpposite"))
        if flt.get("type") == "TRAFFIC_MATCHING_LIST":
            ref = self.lists.get(str(flt.get("trafficMatchingListId", "")))
            if ref is None or ref["type"] not in ("IPV4_ADDRESSES", "IPV6_ADDRESSES"):
                return AddrSet(negate=negate, unresolved=[f"traffic matching list {_s(flt.get('trafficMatchingListId', ''), 12)}"],
                               refs=["traffic matching list"])
            nets, unresolved = self.ip_items(ref["items"])
            return AddrSet(nets=dedupe(nets), negate=negate, unresolved=unresolved, refs=[ref["name"]])
        if flt.get("type") == "IP_ADDRESSES":
            nets, unresolved = self.ip_items(flt.get("items"))
            if not nets and not unresolved:
                unresolved = ["address filter with no addresses"]
                rule_unsupported.append("an address filter with no addresses in it")
            return AddrSet(nets=dedupe(nets), negate=negate, unresolved=unresolved)
        rule_unsupported.append(f"unrecognised IP address filter {_s(flt.get('type', ''), 40)}")
        return AddrSet(negate=negate, unresolved=["unrecognised IP address filter"])

    def ports(self, flt, rule_unsupported):
        """(ranges or None, unresolved list) for a `portFilter`."""
        flt = _dict(flt)
        if not flt:
            return None, []
        items = flt.get("items")
        if flt.get("type") == "TRAFFIC_MATCHING_LIST":
            ref = self.lists.get(str(flt.get("trafficMatchingListId", "")))
            if ref is None or ref["type"] != "PORTS":
                return None, [f"port list {_s(flt.get('trafficMatchingListId', ''), 12)}"]
            items = ref["items"]
        elif flt.get("type") != "PORTS":
            rule_unsupported.append(f"unrecognised port filter {_s(flt.get('type', ''), 40)}")
            return None, ["unrecognised port filter"]
        ranges, unresolved = [], []
        for entry in _list(items):
            entry = _dict(entry)
            try:
                if entry.get("type") == "PORT_NUMBER":
                    ranges.append((int(entry["value"]), int(entry["value"])))
                elif entry.get("type") == "PORT_NUMBER_RANGE":
                    ranges.append((int(entry["start"]), int(entry["stop"])))
                else:
                    unresolved.append(f"unrecognised port item {_s(entry.get('type', ''), 40)}")
            except (KeyError, ValueError, TypeError, ArithmeticError):        # ArithmeticError: int(Infinity), which json accepts
                unresolved.append("unreadable port item")
        valid = [(lo, hi) for lo, hi in ranges if 1 <= lo <= hi <= 65535]
        if len(valid) != len(ranges):
            unresolved.append("a port outside 1-65535")                 # dropping it silently would leave the rest as the whole condition
        ranges = valid
        if not ranges and not unresolved:
            unresolved.append("port filter with no valid ports")
            rule_unsupported.append("a port filter with no valid ports in it")
        if flt.get("matchOpposite") and ranges and not unresolved:
            ranges = _ranges_complement(ranges)
            if not ranges:
                unresolved.append("a port filter that excludes every port")      # an empty list would read as 'any port'
        elif flt.get("matchOpposite"):
            unresolved.append("ports other than those listed")
        return ranges or None, unresolved

    @staticmethod
    def mac_condition(flt, rule, which):
        macs = _macs(flt.get("macAddressFilter"))
        if not macs and not flt.get("macAddressFilter"):
            return
        rule.extra[f"{which}_macs"] = macs
        listed = ", ".join(macs[:5]) + (" ..." if len(macs) > 5 else "") if macs else "(unreadable)"
        rule.unsupported.append(f"{'source' if which == 'src' else 'destination'} MAC address filter: {listed}")

    def side(self, traffic_filter, rule, which="src"):
        """(AddrSet, port ranges, unresolved port notes) for one side of a policy; adds conditions the evaluator cannot decide to `rule`.

        MAC filters are kept as a separate condition (`rule.extra[which + "_macs"]`): they are evaluated when the sender's MAC address is
        known and otherwise leave the rule undecidable. They cannot be translated to an IP-based destination.
        """
        flt = _dict(traffic_filter)
        kind = flt.get("type")
        addr = AddrSet(any=True)
        if kind == "IP_ADDRESS":
            addr = self.address(flt.get("ipAddressFilter"), rule.unsupported)
            self.mac_condition(flt, rule, which)
        elif kind == "NETWORK":
            net_filter = _dict(flt.get("networkFilter"))
            nets, unresolved = [], []
            for network_id in _list(net_filter.get("networkIds")):
                network = self.networks.get(str(network_id))
                if network and network["nets"]:
                    nets += network["nets"]
                else:
                    unresolved.append(f"network {_s(network['name'], 40) if network else str(network_id)[:8]} (no subnet)")
            if not _list(net_filter.get("networkIds")):
                unresolved.append("network filter with no networks (the network may have been deleted)")
                self.issue("warning", "empty-filter", f"policy {rule.original_id!r} has a network filter with no networks in it; UniFi "
                           "shows this as a warning. It is treated as undecidable, not as matching nothing.")
            addr = AddrSet(nets=dedupe(nets), negate=bool(net_filter.get("matchOpposite")), unresolved=unresolved,
                           refs=[self.networks.get(str(i), {}).get("name", "?") for i in _list(net_filter.get("networkIds"))])
            self.mac_condition(flt, rule, which)
        elif kind == "MAC_ADDRESS":
            self.mac_condition(flt, rule, which)
        elif kind == "PORT":
            pass
        elif kind == "REGION":
            regions = [_s(r, 4) for r in _list(_dict(flt.get("regionFilter")).get("regions"))]
            addr = AddrSet(unresolved=[f"region {r}" for r in regions] or ["region"], refs=regions)
        elif kind == "DOMAIN":
            domains = [_s(d, 100).lower() for d in _list(_dict(flt.get("domainFilter")).get("domains"))]
            addr = AddrSet(unresolved=[f"fqdn:{d}" for d in domains] or ["fqdn:"], refs=domains)
        elif kind in ("APPLICATION", "APPLICATION_CATEGORY"):
            key = "applicationFilter" if kind == "APPLICATION" else "applicationCategoryFilter"
            rule.applications.append(f"{kind.lower().replace('_', ' ')} {_s(json.dumps(_dict(flt.get(key)), sort_keys=True), 80)}")
        elif kind in ("VPN_SERVER", "SITE_TO_SITE_VPN_TUNNEL"):
            addr = AddrSet(unresolved=[kind.lower().replace("_", " ")], refs=[kind])
        elif kind == "IPV6_IID":
            addr = AddrSet(unresolved=["IPv6 interface identifier"])
        elif kind:
            addr = AddrSet(unresolved=[f"unrecognised filter {_s(kind, 40)}"])
            rule.unsupported.append(f"unrecognised traffic filter {_s(kind, 40)}")
        ranges, unresolved = self.ports(flt.get("portFilter"), rule.unsupported)
        return addr, ranges, unresolved

    def protocols(self, scope, rule, predefined=False):
        """List of (protocol, icmp type or None), or None for any protocol; and unresolved notes.

        A predefined policy named after one ICMP message (for example "Allow Neighbor Solicitations") is exported with the protocol
        ICMPv6 and no message type, so the type is unknown: that is reported instead of reading it as "every ICMP message".
        """
        flt = _dict(scope.get("protocolFilter"))
        if not flt:
            return None, []
        kind = flt.get("type")
        if kind in ("PRESET",) or "preset" in flt:
            preset = str(flt.get("preset", "")).upper()
            if preset == "TCP_UDP":
                return [("tcp", None), ("udp", None)], []
            return None, [f"protocol preset {_s(preset, 30)}"]
        protocol = _dict(flt.get("protocol"))
        name = str(protocol.get("name", "")).upper().replace("-", "")
        if not name and isinstance(flt.get("protocol"), str):
            name = str(flt["protocol"]).upper()
        if flt.get("matchOpposite"):
            return None, [f"any protocol except {_s(name, 30) or '?'}"]
        if name == "TCPUDP" or name == "TCP_UDP":
            return [("tcp", None), ("udp", None)], []
        proto = PROTOCOL_NAMES.get(name)
        if proto is None:
            rule.unsupported.append(f"protocol filter {_s(name or json.dumps(flt, sort_keys=True), 60)} is not recognised")
            return None, [f"protocol {_s(name, 30) or '?'}"]
        icmp_type = None
        type_name = protocol.get("typenameFilter")
        if proto in ICMP_TYPES and not type_name and predefined:
            rule.unsupported.append(f"{proto.upper().replace('6', 'v6')} message type is not in the export for this predefined policy")
            return [(proto, None)], [f"{proto} message type (not exported)"]
        if proto in ICMP_TYPES and type_name:
            icmp_type = ICMP_TYPES[proto].get(str(type_name).upper())
            if icmp_type is None:
                rule.unsupported.append(f"ICMP type filter {_s(type_name, 40)} is not recognised")
                return [(proto, None)], [f"ICMP type {_s(type_name, 30)}"]
        return [(proto, icmp_type)], []

    # ------------------------------------------------------------ policies
    def read_policies(self):
        rows = []
        for index, item in enumerate(_list(self.doc.get("policies"))):
            item = _dict(item)
            src_zone = self.zone_name(_dict(item.get("source")).get("zoneId", ""))
            dst_zone = self.zone_name(_dict(item.get("destination")).get("zoneId", ""))
            order = item.get("index") if isinstance(item.get("index"), int) else 10 ** 6
            rows.append((src_zone, dst_zone, order, index, item))
        rows.sort(key=lambda r: r[:4])
        for position, (src_zone, dst_zone, order, _raw, item) in enumerate(rows, start=1):
            self.policy.rules.append(self.make_rule(position, src_zone, dst_zone, order, item))
        if not rows:
            self.issue("warning", "no-policies", "the export contains no firewall policies; UniFi's built-in defaults for each zone pair "
                       "are not known, so nothing can be decided")

    def make_rule(self, position, src_zone, dst_zone, order, item):
        name = _s(item.get("name", "")) or f"policy-{position}"
        ident = str(item.get("id", ""))
        action_type = str(_dict(item.get("action")).get("type", "")).upper()
        rule = Rule(rule_id=f"{self.source_id}#{position}", original_id=name, position=position,
                    action="allow" if action_type == "ALLOW" else "deny", original_action=action_type.lower() or "unknown", name=name,
                    enabled=bool(item.get("enabled", True)), scope=f"{src_zone} to {dst_zone}", src_zones=[src_zone], dst_zones=[dst_zone],
                    log=bool(item.get("loggingEnabled")), comment=_s(item.get("description", ""), 200))
        if action_type not in ("ALLOW", "BLOCK", "REJECT"):
            rule.unsupported.append(f"unrecognised action {_s(action_type, 30) or 'none'}")
        scope = _dict(item.get("ipProtocolScope"))
        version = str(scope.get("ipVersion", "IPV4_AND_IPV6")).upper()
        src, sports, sunres = self.side(_dict(item.get("source")).get("trafficFilter"), rule, "src")
        dst, dports, dunres = self.side(_dict(item.get("destination")).get("trafficFilter"), rule, "dst")
        if version in ("IPV4", "IPV6"):
            family = "0.0.0.0/0" if version == "IPV4" else "::/0"
            for addr in (src, dst):
                if addr.any:
                    addr.any, addr.nets = False, [family]
        origin = _s(_dict(item.get("metadata")).get("origin", ""), 30)
        protocols, punres = self.protocols(scope, rule, predefined=bool(origin) and origin != "USER_DEFINED")
        rule.src, rule.dst = src, dst
        rule.svc = self.service(protocols, sports, dports, punres + sunres + dunres)
        if rule.svc.entries and rule.svc.unresolved:     # protocol AND ports: a part nobody can read leaves the whole condition open
            rule.unsupported.append("service condition not fully known: " + "; ".join(rule.svc.unresolved[:3]))
        states = [str(s).upper() for s in _list(item.get("connectionStateFilter"))]
        if states:
            rule.extra["states"] = states               # the evaluator matches a connection's state (NEW for a first packet) against these
        if states and "NEW" not in states:
            rule.extra["new_connections"] = False       # migrations and the analysis skip these: they never act on a new connection
            rule.notes.append("applies only to existing connections (" + ", ".join(states) + "); it never matches the start of one")
        elif states:
            rule.notes.append("connection states: " + ", ".join(states))
        if item.get("ipsecFilter"):
            rule.unsupported.append(f"IPsec match: {_s(item['ipsecFilter'], 30)}")
        schedule = _dict(item.get("schedule"))
        if schedule:
            rule.schedule = _s(schedule.get("mode", "scheduled"), 40)
        if action_type == "ALLOW" and _dict(item.get("action")).get("allowReturnTraffic"):
            rule.notes.append("also allows return traffic of the mirrored zone pair (this tool allows replies anyway)")
        if origin and origin != "USER_DEFINED":
            rule.notes.append(f"predefined by UniFi ({origin.lower().replace('_', ' ')})")
        rule.extra.update({"uuid": ident, "index": order, "origin": origin, "ip_version": version, "zone_pair": [src_zone, dst_zone],
                           "acl": f"{src_zone} to {dst_zone}", "default_policy": order == 2147483647})
        rule.evidence = [Evidence(self.source_id, "config", f"policy {name!r}", limits.clip(
            f"{src_zone} to {dst_zone}, index {order}, {action_type or '?'}, {'enabled' if rule.enabled else 'disabled'}", 200))]
        return rule

    @staticmethod
    def service(protocols, sports, dports, unresolved):
        if protocols is None and not sports and not dports and not unresolved:
            return ServiceSet(any=True)
        if protocols is None:
            protocols = [("tcp", None), ("udp", None)] if (sports or dports) else [(None, None)]
            if unresolved and not (sports or dports):
                return ServiceSet(unresolved=list(unresolved))
        entries = []
        for proto, icmp_type in protocols:
            has_ports = proto in PORT_PROTOCOLS
            entries.append(SvcEntry(proto or "ip", sports if has_ports else None, dports if has_ports else None, icmp_type=icmp_type))
        return ServiceSet(entries=entries, unresolved=list(unresolved))


def check_assignments(policy):
    """Report policies of yours whose addresses belong to another zone's network than the one they are assigned to.

    That can be a stale zone assignment (a network moved to a new zone) or a zone whose networks were left out of the export. Nothing is
    changed: the policy stays where the export put it, and this tool does not claim whether it has any effect on the live gateway.
    """
    owners = {z: [ipaddress.ip_network(n) for n in info.get("nets", [])] for z, info in policy.interfaces.items() if z.lower() != "gateway"}
    seen = set()
    empty = {}
    for rule in policy.rules:
        if rule.extra.get("origin") != "USER_DEFINED" or not rule.enabled:
            continue
        for zone in dict.fromkeys((*rule.src_zones, *rule.dst_zones)):
            info = policy.interfaces.get(zone, {})
            if not info.get("nets") and zone.lower() not in ("gateway", "external", "vpn"):
                empty.setdefault(zone, []).append(rule.original_id)
        for side, zone, addr in (("source", (rule.src_zones or [""])[0], rule.src), ("destination", (rule.dst_zones or [""])[0], rule.dst)):
            if addr.any or addr.unresolved or addr.negate or not addr.nets or (rule.rule_id, side) in seen:
                continue
            mine = owners.get(zone, [])
            for text in addr.nets[:6]:
                net = ipaddress.ip_network(text, strict=False)
                if any(net.version == m.version and net.subnet_of(m) for m in mine):
                    continue
                elsewhere = sorted(z for z, nets in owners.items()
                                   if z != zone and any(net.version == n.version and net.subnet_of(n) for n in nets))
                if elsewhere:
                    seen.add((rule.rule_id, side))
                    have = "has no networks in the export" if not mine else "has other networks"
                    policy.issue("warning", "zone-address-mismatch",
                                 f"Policy {rule.original_id!r} is assigned to zone {zone}, which {have}, but its {side} address "
                                 f"{text} lies in zone {elsewhere[0]}'s network. This may be a stale zone assignment or incomplete export "
                                 "context; it was left as exported and not moved.", rule.evidence[:1])
                    break
    for zone, names in empty.items():
        shown = ", ".join(repr(n) for n in names[:3]) + (" ..." if len(names) > 3 else "")
        policy.issue("warning", "zone-has-no-networks",
                     f"{len(names)} of your policies are assigned to zone {zone}, which has no networks in the export "
                     f"({shown}). They cannot be placed on any address; this may be a stale assignment or an incomplete "
                     "export. Nothing was moved.")


def parse(text, source_id):
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError) as error:
        raise ValueError("the UniFi export is not valid JSON") from error
    if not isinstance(doc, dict) or MARK not in doc:
        raise ValueError("this JSON file is not a RuleTruss UniFi export (make one with tools/unifi_export.py)")
    parser = _Parser(doc, source_id)
    parser.read_networks()
    parser.read_zones()
    parser.read_lists()
    parser.read_policies()
    policy = parser.policy
    check_assignments(policy)
    acl = len(_list(doc.get("acl_rules")))
    if acl:
        parser.issue("info", "acl-rules-not-evaluated", f"{acl} switch ACL rule(s) are in the export and are not evaluated")
    parser.issue("info", "unifi-schema", f"Read as the {SCHEMA}. One real export (Network 10.6.106) was read; other versions, and "
                 "traffic paths outside the policy table (port forwards, inspection), are not verified.")
    policy.objects_summary = {"zones": len(parser.zone_names), "networks": len(parser.networks),
                              "traffic_matching_lists": len(parser.lists)}
    policy.stats = {"policies": len(policy.rules)}
    return policy
