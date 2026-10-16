"""Zone-pair policies (UniFi) to interface ACLs (Cisco ASA, and IOS with by-hand return paths).

A zone-pair source has no interface ACLs of its own: every policy belongs to a (source zone, destination zone) pair and the pairs are
independent lists, each ending in its own default. An interface ACL has one list per interface and no destination zone, so the pairs are
combined like this, and the combination is the whole point of this module:

  * An interface is a *network* (a zone may hold several, and each is its own interface on the target), or the WAN side for External.
    Interface names are never guessed: each network shows as a placeholder until the user maps it.
  * A policy applies to the interfaces of its source zone's networks (or the ones its source addresses fall in). The address field of a
    policy means "in its zone", so an unrestricted field becomes the zone's own networks, never "any".
  * Destination zones that have networks become address sets, so zone pairs stay independent. A pair's default ("Allow All Traffic",
    "Block All Traffic") is then a catch-all for that destination only. Pairs run in index order. External has no networks of its own
    (it is "everything else"), so its pairs go last in each ACL; every other destination is already decided by then.
  * Policies with nothing the target can express or that depend on something the export does not say are never turned into a looser
    rule: they are reported as unsupported or unresolved, with the policies that would then let the traffic through, and the output is
    labelled a preview that cannot be deployed.
Every source policy ends with exactly one disposition: translated, implemented through target behaviour, unsupported, unresolved, or
not applicable.
"""
import dataclasses
import ipaddress
import re

from ..model import AddrSet
from .firewall import VPN_FILTER, OutRule, _issue, safe_id

TRANSLATED, IMPLEMENTED, UNSUPPORTED, UNRESOLVED, NOT_APPLICABLE = "translated", "implemented", "unsupported", "unresolved", "not-applicable"
DEFAULT_INDEX = 2147483647
WAN_PREFIX = "zone-"
MAX_MAC_MAP, MAX_VPN_NETWORKS, MAX_LOCAL_PIECES = 256, 16, 200
MAC_FORM = re.compile(r"^[0-9a-f]{2}([:-]?[0-9a-f]{2}){5}$")
MANAGEMENT = "the ASA offers ssh (22), http (443, HTTPS) and icmp to the box itself; it has no access list for other local services"


def _nets(addr):
    return [ipaddress.ip_network(n, strict=False) for n in addr.nets]


def _inside(net, container_nets):
    return any(net.version == c.version and net.subnet_of(c) for c in container_nets)


def _short(rule):
    return f"{rule.original_id} [{str(rule.extra.get('uuid', ''))[:8]}]"


class _Plan:
    """Collects the result for one policy: its disposition and the access-list entries it produced."""

    def __init__(self, rule):
        self.rule = rule
        self.disposition, self.reason, self.entries = None, "", []
        self.bypassed_by = []
        self.local = None                  # a policy to the gateway waiting for the pass that orders it with the rest of its pair
        self.macs = []                     # (mac, ip) replacements made in this policy

    def set(self, disposition, reason):
        self.disposition, self.reason = disposition, reason
        return self


def normalise_mac(text):
    text = str(text).strip().lower()
    if not MAC_FORM.match(text):
        raise ValueError(f"{str(text)[:40]!r} is not a MAC address (six pairs of hex digits)")
    digits = re.sub(r"[^0-9a-f]", "", text)
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def check_supplied(policy, mac_map, vpn_networks):
    """Validate what the user supplied: {mac: ip} and a list of VPN client networks. Returns them normalised; raises ValueError with a sentence."""
    if not isinstance(mac_map, dict):
        raise ValueError("mac_map must be an object of MAC address to IPv4 address")
    if len(mac_map) > MAX_MAC_MAP:
        raise ValueError(f"mac_map has more than {MAX_MAC_MAP} entries")
    macs = {}
    for mac, address in mac_map.items():
        key = normalise_mac(mac)
        try:
            ip = ipaddress.IPv4Address(str(address)) if isinstance(address, str) else None
        except ValueError:
            ip = None
        if ip is None or ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local or ip == ipaddress.IPv4Address("255.255.255.255"):
            raise ValueError(f"{str(address)[:40]!r} for {key} is not a usable IPv4 host address")
        if key in macs and macs[key] != str(ip):
            raise ValueError(f"{key} is given two different addresses")
        macs[key] = str(ip)
    if not isinstance(vpn_networks, (list, tuple)):
        raise ValueError("vpn_networks must be a list of IPv4 networks")
    if len(vpn_networks) > MAX_VPN_NETWORKS:
        raise ValueError(f"vpn_networks has more than {MAX_VPN_NETWORKS} entries")
    pool = []
    zone_nets = [ipaddress.ip_network(n) for info in policy.interfaces.values() for nets in info.get("network_nets", {}).values() for n in nets]
    for text in vpn_networks:
        try:
            net = ipaddress.IPv4Network(str(text), strict=True) if isinstance(text, str) else None
        except ValueError:
            net = None
        if net is None:
            raise ValueError(f"{str(text)[:40]!r} is not an IPv4 network written as address/length with the host bits zero")
        if net.prefixlen < 8:
            raise ValueError(f"{net} is too wide to be a VPN client pool (the longest accepted prefix to start from is /8)")
        clash = next((z for z in zone_nets if z.version == 4 and z.overlaps(net)), None)
        if clash is None:
            clash = next((p for p in pool if p.overlaps(net)), None)
        if clash is not None:
            raise ValueError(f"VPN pool {net} overlaps {clash}; a client address must not belong to a network the firewall already routes")
        pool.append(net)
    return macs, [str(n) for n in pool]


def _with_addresses(rule, mac_map):
    """The rule with each MAC address filter replaced by the addresses the user gave, when they gave every one. Otherwise the rule is
    returned as it is, with the MAC condition worded so the report says what is missing. Never a partial replacement."""
    out, notes = rule, []
    for which in ("src", "dst"):
        macs = rule.extra.get(f"{which}_macs")
        if not macs:
            continue
        label = "source" if which == "src" else "destination"
        missing = [m for m in macs if m not in mac_map]
        kept = [u for u in out.unsupported if not u.startswith(f"{label} MAC address filter")]
        if missing or not mac_map:
            kept.append(f"{label} MAC address filter: {', '.join(macs[:5])}; an ASA matches addresses, so give the IP address of each device "
                        + (f"(none given for {', '.join(missing[:3])})" if mac_map and missing else "to translate it"))
            out = dataclasses.replace(out, unsupported=kept)
            continue
        addr = AddrSet(nets=[f"{mac_map[m]}/32" for m in macs], refs=[f"MAC {m}" for m in macs])
        out = dataclasses.replace(out, unsupported=kept, **{which: addr})
        notes += [(m, mac_map[m]) for m in macs]
    return out, notes


def translate(policy, caps, t, zone_map, identity, confirmed, supplied=None):
    """Fill `t` (a Translation) with output rules, a disposition per source policy, issues and the interface table."""
    supplied = supplied or {}
    mac_map, vpn_pool = supplied.get("mac_map") or {}, [ipaddress.ip_network(n) for n in supplied.get("vpn_networks") or []]
    zones = policy.interfaces
    network_nets = {z: dict(info.get("network_nets", {})) for z, info in zones.items()}
    has_networks = {z for z, n in network_nets.items() if n}
    user_zones = {z for r in policy.rules if r.extra.get("origin") == "USER_DEFINED" for z in (*r.src_zones, *r.dst_zones)}
    t.iface_nets = {key: list(nets) for z in network_nets.values() for key, nets in z.items()}
    t.iface_zone = {key: z for z, n in network_nets.items() for key in n}
    wan = [z for z, info in zones.items() if z.lower() == "external" and info.get("origin") == "SYSTEM_DEFINED"]
    wan_zone = wan[0] if wan else None
    if wan_zone:
        t.iface_nets[WAN_PREFIX + wan_zone] = []
        t.iface_zone[WAN_PREFIX + wan_zone] = wan_zone
    incomplete = {z: sorted(key for key, nets in n.items() if not nets) for z, n in network_nets.items() if any(not nets for nets in n.values())}
    if incomplete:
        t.issues.append(_issue("blocker", "network-without-subnet", "These networks have no subnet in the export, so their zones cannot be written "
                               "completely and every policy that names those zones is unresolved: "
                               + "; ".join(f"{z}: {', '.join(keys[:3])}" for z, keys in sorted(incomplete.items())[:4]) + "."))
    plans = []
    for r in policy.rules:
        changed, replaced = _with_addresses(r, mac_map) if r.enabled else (r, [])
        plans.append(_Plan(changed))
        plans[-1].macs = replaced
    t.inputs = {"mac_filters": _mac_filters(policy, mac_map), "vpn_networks": [str(n) for n in vpn_pool]}
    unused = sorted(set(mac_map) - {f["mac"] for f in t.inputs["mac_filters"]})
    if unused:
        t.issues.append(_issue("warning", "mac-map-unused", f"These MAC addresses were given an address but no enabled policy filters on them, so "
                               f"they were ignored: {', '.join(unused[:6])}."))
    by_pair = {}
    for plan in plans:
        r = plan.rule
        by_pair.setdefault((r.src_zones[0] if r.src_zones else "", r.dst_zones[0] if r.dst_zones else ""), []).append(plan)

    for plan in plans:
        _classify(plan, policy, zones, network_nets, has_networks, user_zones, wan_zone, caps, confirmed, t, vpn_pool)
    _gateway_pass(plans, t)

    # access-list entries, interface by interface: pairs with known destination networks first, External last, each pair in index order
    per_interface = {}
    for plan in plans:
        for key, rank, dst_zone, out in plan.entries:
            per_interface.setdefault(key, []).append((rank, dst_zone, plan.rule.extra.get("index", plan.rule.position), plan.rule.position, out))
    for items in per_interface.values():
        for _rank, _zone, _index, _pos, out in sorted(items, key=lambda x: x[:4]):
            t.rules.append(out)

    _bypass(by_pair, plans)
    _pairs_without_policy(policy, zones, network_nets, has_networks, by_pair, wan_zone, t)
    _report(plans, t)
    _issues(plans, policy, caps, t, confirmed, zone_map)
    t.vpn_pool = [str(n) for n in vpn_pool] if any(out.src_zone == VPN_FILTER for out in t.rules) else []


# ------------------------------------------------------------------------------------------------ one policy

def _state_only(plan, r, states):
    """A policy that applies only to packets of connections already known (no NEW). The ASA's stateful inspection covers two of the four
    combinations; the others cannot be written as an interface ACL, so they are unsupported, not implemented."""
    names = {str(x).upper() for x in states}
    if r.action == "allow" and names <= {"ESTABLISHED", "RELATED"}:
        return plan.set(IMPLEMENTED, "replies and related traffic of permitted connections are accepted by the ASA's stateful inspection; "
                        "it does not need an entry, and it accepts them whether or not this exact policy exists")
    if r.action != "allow" and names == {"INVALID"}:
        return plan.set(IMPLEMENTED, "applies only to packets in state invalid, never to a new connection; the ASA drops packets that do not "
                        "belong to a connection it tracks, which is similar but not identical to this policy")
    if r.action == "allow":
        return plan.set(UNSUPPORTED, f"allows packets in state {', '.join(sorted(names)).lower()}; the ASA drops packets that do not belong to a "
                        "connection it tracks and cannot be told to allow them")
    return plan.set(UNSUPPORTED, f"blocks packets in state {', '.join(sorted(names)).lower()}, which are replies or related traffic of connections "
                    "that were allowed; an ASA always accepts those, so this restriction cannot be written as an interface ACL")


def _wide(addr):
    """No limit on this side: 'any', or the whole IPv4 space an IPv4-only policy writes instead of 'any'."""
    return addr.any or (not addr.unresolved and not addr.negate and set(addr.nets) == {"0.0.0.0/0"})


def _classify(plan, policy, zones, network_nets, has_networks, user_zones, wan_zone, caps, confirmed, t, vpn_pool=()):
    r = plan.rule
    if not r.enabled:
        return plan.set(NOT_APPLICABLE, "the policy is disabled in the export")
    sz, dz = (r.src_zones or [""])[0], (r.dst_zones or [""])[0]
    states = r.extra.get("states")
    if states and "NEW" not in states:
        return _state_only(plan, r, states)
    for zone in (sz, dz):
        if zone in network_nets and any(not nets for nets in network_nets[zone].values()):
            return plan.set(UNRESOLVED, f"zone {zone} has a network with no subnet in the export, so its addresses cannot be written completely")
    if sz.lower() == "gateway" and zones.get(sz, {}).get("origin") == "SYSTEM_DEFINED":
        return plan.set(IMPLEMENTED, "traffic the firewall itself starts is not filtered by interface ACLs")
    problems = list(r.unsupported)
    if r.applications and r.applications != ["any"]:
        problems.append(f"application condition ({', '.join(r.applications[:2])})")
    if r.users:
        problems.append("identity condition")
    if r.schedule:
        problems.append(f"schedule {r.schedule}")
    for label, addr in (("source", r.src), ("destination", r.dst)):
        if addr.unresolved:
            problems.append(f"{label} has members that are not IP addresses ({', '.join(addr.unresolved[:2])})")
        if addr.negate:
            problems.append(f"{label} is negated, which an ACL cannot express")
    if r.svc.unresolved:
        problems.append(f"service not resolvable ({', '.join(r.svc.unresolved[:2])})")
    if problems:
        return plan.set(UNSUPPORTED, "; ".join(problems))
    asa = t.target == "cisco-asa"
    # where does it apply
    if sz not in has_networks and sz != wan_zone:
        if sz.lower() == "vpn" and sz in user_zones:
            if asa and vpn_pool and dz in has_networks:
                return _vpn_filter(plan, r, dz, network_nets, vpn_pool, t)
            return _vpn(plan, "from VPN clients", confirmed, asa, bool(vpn_pool))
        if sz in user_zones and r.extra.get("origin") == "USER_DEFINED":
            return plan.set(UNRESOLVED, f"source zone {sz} has no networks in the export, so there is no interface to place this on "
                            "(a stale zone assignment or an incomplete export)")
        return plan.set(NOT_APPLICABLE, f"zone {sz} has no networks in the export, so nothing is attached to it")
    if dz.lower() == "gateway" and zones.get(dz, {}).get("origin") == "SYSTEM_DEFINED":
        return _gateway(plan, r, sz, wan_zone, network_nets, confirmed, asa, zones[dz].get("nets", []))
    if dz not in has_networks and dz != wan_zone:
        if dz.lower() == "vpn" and dz in user_zones:
            return _vpn(plan, "to VPN clients", confirmed, asa, bool(vpn_pool))
        if dz in user_zones and r.extra.get("origin") == "USER_DEFINED":
            return plan.set(UNRESOLVED, f"destination zone {dz} has no networks in the export, so its addresses are unknown (a stale zone "
                            "assignment or an incomplete export)")
        return plan.set(NOT_APPLICABLE, f"zone {dz} has no networks in the export, so nothing is attached to it")
    if r.extra.get("ip_version") == "IPV6":
        return plan.set(UNRESOLVED, "an IPv6 policy, and the export has no IPv6 prefixes for the zones, so its scope cannot be written")
    sources, failed = _sources(plan, r, sz, wan_zone, network_nets)
    if failed is not None:
        return failed
    # destination
    if dz == wan_zone:
        dst, rank = r.dst, 1
    else:
        zone_all = [ipaddress.ip_network(n) for nets in network_nets[dz].values() for n in nets]
        if _wide(r.dst):
            dst = AddrSet(nets=[str(n) for n in zone_all], refs=[dz])
        else:
            for net in _nets(r.dst):
                if not _inside(net, zone_all):
                    return plan.set(UNRESOLVED, f"destination address {net} is not inside any network of zone {dz} (a stale zone assignment "
                                    "or an incomplete export); it was not moved to another zone")
            dst = r.dst
        rank = 0
    if sz == dz and sz != wan_zone and len(network_nets[sz]) == 1:
        return plan.set(NOT_APPLICABLE, "both ends are in the same network, so the traffic never passes the firewall")
    for key, src in sources:
        own = [ipaddress.ip_network(n) for n in t.iface_nets.get(key, [])] if sz == dz and _wide(r.dst) else []
        this_dst = AddrSet(nets=[n for n in dst.nets if ipaddress.ip_network(n) not in own], refs=dst.refs) if own else dst
        plan.entries.append((key, rank, dz, OutRule(
            name=safe_id(r.original_id), action=r.action, src=src, dst=this_dst, svc=r.svc, src_zone=key, dst_zone=None, log=r.log,
            comment=limits_clip(_comment(r, plan)), source_rule_ids=[r.rule_id], source_ids_text=safe_id(_short(r)), evidence=r.evidence[:2])))
    notes = _mac_notes(plan)
    if r.action == "deny" and not states and r.extra.get("origin") == "USER_DEFINED":
        notes.append("this block applies to every connection state on UniFi, so it can also drop replies of connections the other side "
                     "started; the ASA always lets replies of permitted connections through, so it will not")
    return plan.set(TRANSLATED, "; ".join(notes))


def _comment(rule, plan):
    return "MAC filter replaced by the addresses you gave" if plan.macs else rule.comment


def _mac_notes(plan):
    """What was substituted for a MAC address filter, in words that also say what it costs."""
    if not plan.macs:
        return []
    pairs = ", ".join(f"{m} as {ip}" for m, ip in plan.macs[:4]) + (f" and {len(plan.macs) - 4} more" if len(plan.macs) > 4 else "")
    text = (f"an ASA matches addresses, not MAC addresses: {pairs} (the addresses you gave), so the rule follows those addresses; "
            "if a device's address changes it is no longer matched")
    if plan.rule.action == "deny":
        text += " - for this block that BROADENS access, because the device is then no longer blocked"
    return [text]


def _sources(plan, r, sz, wan_zone, network_nets):
    """([(interface key, source addresses)], None) for where a policy applies, or (None, the plan, finished) when it cannot be placed."""
    if sz == wan_zone:
        return [(WAN_PREFIX + wan_zone, r.src)], None
    zone_nets = network_nets[sz]
    if _wide(r.src):
        return [(key, AddrSet(nets=list(nets), refs=[key])) for key, nets in zone_nets.items()], None
    owned = {}
    for net in _nets(r.src):
        key = next((k for k, nets in zone_nets.items() if _inside(net, [ipaddress.ip_network(n) for n in nets])), None)
        if key is None:
            return None, plan.set(UNRESOLVED, f"source address {net} is not inside any network of zone {sz} (a stale zone assignment or an "
                                  "incomplete export); it was not moved to another zone")
        owned.setdefault(key, []).append(str(net))
    return [(key, AddrSet(nets=nets)) for key, nets in owned.items()], None


# ------------------------------------------------------------------------------------------------ the gateway itself

def _offered(svc):
    """What a service condition names of the three things an ASA offers to the box: (ssh, http, icmp, other, odd).

    icmp is None, "all" or the set of ICMP types named; `other` describes the rest (so the reason can say what has no equivalent); `odd` is a
    reason the condition cannot be read at all (a source-port limit).
    """
    if svc.any:
        return True, True, "all", ["every other service"], ""
    ssh = http = False
    icmp, other = None, []
    for e in svc.entries:
        if e.proto == "ip":
            return True, True, "all", ["every other service"], ""
        if e.proto == "tcp":
            if e.sports is not None:
                return False, False, None, [], "it limits the TCP source port, which the ASA's access to itself cannot"
            if e.established:
                return False, False, None, [], "it depends on TCP flags"
            ranges = e.dports
            ssh = ssh or ranges is None or any(lo <= 22 <= hi for lo, hi in ranges)
            http = http or ranges is None or any(lo <= 443 <= hi for lo, hi in ranges)
            rest = ranges is None or any(lo != hi or lo not in (22, 443) for lo, hi in ranges)
            if rest:
                other.append("other tcp ports" if ranges is None else "tcp " + ", ".join(
                    f"{lo}" if lo == hi else f"{lo}-{hi}" for lo, hi in ranges if lo != hi or lo not in (22, 443)))
        elif e.proto == "icmp":
            if e.icmp_type is None:
                icmp = "all"
            elif e.icmp_type == 8:
                icmp = icmp if icmp == "all" else {8}
            else:
                other.append(f"icmp type {e.icmp_type}")
        else:
            other.append(e.proto)
    return ssh, http, icmp, other, ""


def _gateway(plan, r, sz, wan_zone, network_nets, confirmed, asa, own_addresses):
    """Traffic to the firewall itself. Interface ACLs do not govern it; on an ASA, ssh, http and icmp are governed by their own commands,
    which this writes. Any other local service is left to the user (unresolved, or implemented when they say they handle it)."""
    handled = "gateway" in confirmed
    if not asa:
        if handled:
            return plan.set(IMPLEMENTED, "traffic to the firewall itself: you confirmed it is handled with the device's own access controls "
                            "(management access lists, control-plane policy), which this translation does not generate")
        return plan.set(UNRESOLVED, "traffic to the firewall itself needs explicit handling on the device (management access, DNS/DHCP service "
                        "settings, control-plane policy); interface ACLs do not govern it")
    rest = (IMPLEMENTED, "traffic to the firewall itself: you confirmed it is handled separately on the ASA (DHCP service, DNS, mDNS, IPv6 "
            "neighbour discovery), which this translation does not generate") if handled else (
        UNRESOLVED, "traffic to the firewall itself needs explicit local-service handling on the ASA (DHCP service, DNS, mDNS, IPv6 neighbour "
        "discovery, control-plane ACLs); interface ACLs do not govern it")
    if r.extra.get("ip_version") == "IPV6":
        return plan.set(rest[0], rest[1] + "; this policy is for IPv6 only")
    ssh, http, icmp, other, odd = _offered(r.svc)
    if odd:
        return plan.set(UNSUPPORTED, odd)
    if not (ssh or http or icmp):
        return plan.set(rest[0], rest[1] + f"; this policy is about {', '.join(other[:3]) or 'a service the ASA has no access list for'}, and " + MANAGEMENT)
    named = not _wide(r.dst)
    if named:
        gateway = [ipaddress.ip_network(n) for n in own_addresses]
        stray = [n for n in _nets(r.dst) if not _inside(n, gateway)]
        if stray:
            return plan.set(UNSUPPORTED, f"destination {', '.join(str(n) for n in stray[:2])} is not an address of the gateway in the export, "
                            "and the ASA's access to itself is set per interface, not per address")
    sources, failed = _sources(plan, r, sz, wan_zone, network_nets)
    if failed is not None:
        return failed
    plan.local = {"sources": sources, "ssh": ssh, "http": http, "icmp": icmp, "other": other, "named": named}
    return plan


def _pieces(nets, taken):
    """`nets` with everything in `taken` cut out, as a list of networks."""
    left = [ipaddress.ip_network(n) for n in nets]
    for cut in taken:
        nxt = []
        for net in left:
            if net.version != cut.version or not net.overlaps(cut):
                nxt.append(net)
            elif not net.subnet_of(cut):
                nxt.extend(net.address_exclude(cut))
        left = nxt
        if len(left) > MAX_LOCAL_PIECES:
            break
    return sorted(left, key=lambda n: (n.version, n.network_address, n.prefixlen))


def _gateway_pass(plans, t):
    """Order the policies to the gateway within their pair, as UniFi does, and turn them into ASA access commands.

    ssh and http only have permit lines, so a block is written by cutting its addresses out of the later permits. icmp is an ordered list, so
    its permits and denies are written in order. A policy that an earlier one already decides completely has no effect and is reported so."""
    pairs = {}
    for plan in plans:
        if plan.local is not None:
            pairs.setdefault((plan.rule.src_zones or [""])[0], []).append(plan)
    for group in pairs.values():
        group.sort(key=lambda p: (p.rule.extra.get("index", p.rule.position), p.rule.position))
        cut, icmp_decided, deciders = {}, {}, []
        for plan in group:
            r, local = plan.rule, plan.local
            allow = r.action == "allow"
            staged, effect, pieces_over = {}, False, False
            for key, src in local["sources"]:
                nets = src.nets or ["0.0.0.0/0"]
                for command in ("ssh", "http"):
                    if not local[command]:
                        continue
                    if allow:
                        earlier = cut.get((key, command), [])
                        left = _pieces(nets, earlier) if len(earlier) <= MAX_LOCAL_PIECES else []
                        if len(earlier) > MAX_LOCAL_PIECES or len(left) > MAX_LOCAL_PIECES:
                            pieces_over = True
                        if left:
                            staged.setdefault((key, command), []).extend(str(n) for n in left)
                            effect = True
                    else:
                        staged.setdefault((key, command), []).extend(nets)
                        effect = True
                if local["icmp"]:
                    done = icmp_decided.get(key, [])
                    if not all(any(ipaddress.ip_network(n).subnet_of(d) for d in done) for n in nets):
                        kind = 8 if local["icmp"] != "all" else None
                        staged.setdefault((key, "icmp"), []).extend((("permit" if allow else "deny"), n, kind) for n in nets)
                        effect = True
            if pieces_over:
                plan.set(UNSUPPORTED, f"keeping the blocks that come before it needs more than {MAX_LOCAL_PIECES} address entries on the ASA")
                continue
            if not effect:
                plan.set(NOT_APPLICABLE, "no effect: " + ", ".join(deciders[:2]) + " already decide(s) all of this traffic" if deciders else
                         "no effect: nothing is left for it to decide")
                continue
            for (key, command), items in staged.items():
                access = t.local_access.setdefault(key, {"ssh": [], "http": [], "icmp": []})
                if command == "icmp":
                    access["icmp"].extend(items)
                    if local["icmp"] == "all":
                        icmp_decided.setdefault(key, []).extend(ipaddress.ip_network(n) for _v, n, _k in items)
                elif allow:
                    access[command].extend(n for n in items if n not in access[command])
                else:
                    cut.setdefault((key, command), []).extend(ipaddress.ip_network(n) for n in items)
            if not allow:
                deciders.append(r.original_id)
            done = [c for c in ("ssh", "http", "icmp") if local[c]]
            words = ", ".join(done[:-1]) + " and " + done[-1] if len(done) > 1 else done[0]
            note = (f"traffic to the firewall itself: written as ASA access commands, so the ASA {'permits' if allow else 'does not permit'} "
                    f"{words} for the addresses of this policy")
            if local["named"]:
                note += ("; it names the gateway's addresses, and an ASA accepts management traffic only on the interface it arrives on, so it "
                         "is written for each source network's own interface")
            if local["other"]:
                note += f"; {MANAGEMENT}, so {', '.join(local['other'][:3])} has no equivalent here"
            plan.set(TRANSLATED, note)


# ------------------------------------------------------------------------------------------------ VPN

def _vpn(plan, what, confirmed, asa=False, pool=False):
    if "vpn" in confirmed:
        return plan.set(IMPLEMENTED, f"traffic {what}: you confirmed VPN is handled separately on the target, which this translation does not generate")
    if asa and not pool and what.startswith("from"):
        return plan.set(UNRESOLVED, f"traffic {what} can be written as a VPN filter once you give the VPN client address pool; without it the "
                        "addresses of the clients are not known")
    return plan.set(UNRESOLVED, f"traffic {what} needs the target's VPN topology and the interface it arrives on")


def _vpn_filter(plan, r, dz, network_nets, pool, t):
    """Traffic from VPN clients to a zone with networks, as an entry of the VPN filter access list (ASA, group-policy vpn-filter)."""
    if _wide(r.src):
        src = AddrSet(nets=[str(n) for n in pool], refs=["Vpn"])
    else:
        for net in _nets(r.src):
            if not _inside(net, pool):
                return plan.set(UNRESOLVED, f"source address {net} is not inside the VPN client address pool you gave")
        src = r.src
    zone_all = [ipaddress.ip_network(n) for nets in network_nets[dz].values() for n in nets]
    if _wide(r.dst):
        dst = AddrSet(nets=[str(n) for n in zone_all], refs=[dz])
    else:
        for net in _nets(r.dst):
            if not _inside(net, zone_all):
                return plan.set(UNRESOLVED, f"destination address {net} is not inside any network of zone {dz} (a stale zone assignment "
                                "or an incomplete export); it was not moved to another zone")
        dst = r.dst
    plan.entries.append((VPN_FILTER, 0, dz, OutRule(
        name=safe_id(r.original_id), action=r.action, src=src, dst=dst, svc=r.svc, src_zone=VPN_FILTER, dst_zone=None, log=r.log,
        comment=limits_clip(r.comment), source_rule_ids=[r.rule_id], source_ids_text=safe_id(_short(r)), evidence=r.evidence[:2])))
    return plan.set(TRANSLATED, "traffic from VPN clients: written as an entry of the VPN filter (group-policy vpn-filter) over the client pool you "
                    "gave; not yet tried on a device")


def _mac_filters(policy, mac_map):
    """Every MAC address used in an enabled policy, with the policies that use it and the address the user gave (if any)."""
    found = {}
    for r in policy.rules:
        if not r.enabled:
            continue
        for which in ("src_macs", "dst_macs"):
            for mac in r.extra.get(which) or []:
                found.setdefault(mac, [])
                if r.original_id not in found[mac] and len(found[mac]) < 5:
                    found[mac].append(r.original_id)
    return [{"mac": mac, "policies": names, "ip": mac_map.get(mac, "")} for mac, names in sorted(found.items())[:MAX_MAC_MAP]]


def limits_clip(text):
    return (text or "")[:80]


# ------------------------------------------------------------------------------------------------ consequences

def _bypass(by_pair, plans):
    """For a policy that could not be translated: the later translated policies of the same pair that would now decide its traffic."""
    for pair_plans in by_pair.values():
        pair_plans.sort(key=lambda p: p.rule.position)
        for i, plan in enumerate(pair_plans):
            if plan.disposition not in (UNSUPPORTED, UNRESOLVED):
                continue
            later = [p.rule.original_id for p in pair_plans[i + 1:] if p.disposition == TRANSLATED and p.rule.enabled]
            plan.bypassed_by = later[:3]
            if plan.rule.action == "deny":
                plan.reason += "; BROADENS access: the protection this policy gave is not in the output" + (
                    ", and later policies of its pair (" + ", ".join(later[:3]) + ") will now decide that traffic" if later else "")
            elif plan.rule.action == "allow":
                plan.reason += "; the traffic this policy allowed falls through to the later policies of its pair" + (
                    f" ({', '.join(later[:2])})" if later else "")


def _is_final_default(rule):
    """The Allow All / Block All policy that ends a zone pair: enabled, last in order, and not limited by state, address or service."""
    return (rule.enabled and rule.extra.get("default_policy") and not rule.extra.get("states")
            and rule.src.any and rule.dst.any and rule.svc.any and rule.action in ("allow", "deny"))


def _pairs_without_policy(policy, zones, network_nets, has_networks, by_pair, wan_zone, t):
    endpoints = has_networks | ({wan_zone} if wan_zone else set())              # External starts pairs as well as ending them
    for sz in sorted(endpoints):
        for dz in sorted(endpoints - {sz}):
            listed = by_pair.get((sz, dz), [])
            if any(_is_final_default(p.rule) for p in listed):
                continue
            what = "lists no policy" if not listed else "lists policies but no enabled final Allow All / Block All"
            t.issues.append(_issue("blocker", "pair-without-policy", f"The export {what} for {sz} to {dz}. UniFi's behaviour for that pair "
                                   "is not in the export, and the ASA denies anything no entry permits. Decide what it should do and add it by hand."))


def _report(plans, t):
    for plan in plans:
        r = plan.rule
        targets = sorted({out.src_zone for _k, _rk, _dz, out in plan.entries if out.src_zone})
        t.report.append({"source_rule": r.original_id, "rule_id": r.rule_id, "policy_id": str(r.extra.get("uuid", "")),
                         "index": r.extra.get("index"), "pair": r.scope, "origin": r.extra.get("origin", ""), "action": r.action,
                         "status": plan.disposition, "disposition": plan.disposition, "reason": plan.reason, "interfaces": targets,
                         "bypassed_by": plan.bypassed_by, "evidence": r.evidence[:2], "warnings": []})


def _issues(plans, policy, caps, t, confirmed, zone_map):
    mapped = [zone_map[k] for k in t.iface_nets if k in zone_map]
    twice = sorted({v for v in mapped if mapped.count(v) > 1})
    if twice:
        t.issues.append(_issue("blocker", "interface-mapping-duplicate", f"Two or more source interfaces are mapped to the same target interface "
                               f"({', '.join(twice[:3])}). Each network needs its own interface (or sub-interface) on the target."))
    unused = sorted(k for k in zone_map if k not in t.iface_nets)
    if unused:
        t.issues.append(_issue("warning", "interface-mapping-unused", f"These mapping entries match no interface of this export and were ignored: "
                               f"{', '.join(unused[:6])}. Interfaces here are named after UniFi networks (and zone-External for the Internet side)."))
    count = {}
    for p in plans:
        count[p.disposition] = count.get(p.disposition, 0) + 1
    gateway = [p for p in plans if p.disposition == UNRESOLVED and "firewall itself" in p.reason]
    if gateway:
        if t.target == "cisco-asa":
            text = (f"{len(gateway)} policies are about traffic to the firewall itself that the ASA has no access list for (DHCP service, DNS, "
                    "mDNS, IPv6 neighbour discovery, other ports). Configure those services on the ASA yourself, then tick 'I handle the other "
                    "local services' to mark them handled. ssh, http and icmp are written for you.")
        else:
            text = (f"{len(gateway)} policies are about traffic to the firewall itself. Interface ACLs do not govern it; configure management, "
                    "DNS and DHCP access on the device explicitly, then tick 'I handle the other local services' to mark them handled.")
        t.issues.append(_issue("blocker", "local-services", text))
    vpn = [p for p in plans if p.disposition == UNRESOLVED and "VPN" in p.reason]
    if vpn:
        t.issues.append(_issue("blocker", "vpn-topology", f"{len(vpn)} policies involve VPN clients. Traffic that clients start can be written "
                               "as a VPN filter on an ASA once you give the client address pool; traffic toward clients, and anything else, needs the "
                               "target's VPN design. Tick 'I handle VPN separately' once that is settled."))
    if any(out.src_zone == VPN_FILTER for out in t.rules):
        t.issues.append(_issue("blocker", "vpn-filter-untested", "The VPN filter has not been tried on a device by the authors of this tool: how a "
                               "vpn-filter list reads its source and destination for both directions of a session, and whether it also governs "
                               "traffic the clients receive, is taken from the ASA documentation and not from a test. Try it in a lab with a real "
                               "client before relying on it. The output stays a preview until then."))
        t.issues.append(_issue("warning", "vpn-filter-attach", "The filter does nothing until the group policy RT-VPN-POLICY is assigned to the "
                               "VPN connection profile that hands out the pool you gave. An ASA lets decrypted VPN traffic bypass the interface "
                               "ACLs by default (sysopt connection permit-vpn), which is why the filter is a separate list. The validation "
                               "samples through-traffic only and does not cover it."))
    if t.local_access:
        t.issues.append(_issue("warning", "management-access", "Policies to the Gateway were written as the ASA's own access commands (ssh, http, "
                               "icmp) for the networks they name: that opens management access from those networks, so check each one. ssh also "
                               "needs a key, a user and 'aaa authentication ssh console', and http needs 'http server enable'. An icmp deny is "
                               "written because an ASA answers ping on an interface until some icmp command exists for it. These lines are not "
                               "covered by the validation, which samples through-traffic; they follow the ASA documentation and have not been "
                               "tried on a device by the authors of this tool."))
    swapped = [p for p in plans if p.macs and p.disposition == TRANSLATED]
    if swapped:
        denies = sum(1 for p in swapped if p.rule.action == "deny")
        t.issues.append(_issue("warning", "mac-substituted", f"{len(swapped)} policies filter on MAC addresses and were written with the IP "
                               f"addresses you gave ({denies} deny, {len(swapped) - denies} allow). An ASA does not match MAC addresses in an "
                               "ACL: a device whose address changes (DHCP) stops matching, which for an allow fails closed and for a deny fails "
                               "open. Reserve those addresses on the DHCP server, or keep the rule by hand."))
    for p in plans:
        if p.disposition in (UNSUPPORTED, UNRESOLVED) and p.rule.extra.get("origin") == "USER_DEFINED":
            t.issues.append(_issue("blocker", "policy-not-translated", f"Policy {_short(p.rule)} ({p.rule.scope}) was not translated: "
                                   f"{p.reason}.", p.rule.evidence[:1]))
    if any(p.rule.extra.get("origin") != "USER_DEFINED" and p.disposition in (UNSUPPORTED, UNRESOLVED) for p in plans):
        names = sorted({p.rule.original_id for p in plans if p.rule.extra.get("origin") != "USER_DEFINED"
                        and p.disposition in (UNSUPPORTED, UNRESOLVED) and "firewall itself" not in p.reason and "VPN" not in p.reason})
        if names:
            t.issues.append(_issue("blocker", "predefined-not-translated", f"Predefined policies that could not be translated: "
                                   f"{', '.join(names[:6])}. Dropping one of these removes behaviour UniFi applied on its own."))
    if caps["stateful"] is False:
        t.issues.append(_issue("blocker", "stateless-returns", "The destination is stateless and this source is zone-based: return paths for "
                               "permitted traffic are not generated for zone-pair sources. Add them by hand before any use."))
    t.issues.append(_issue("warning", "ipv4-only", "Policies for both IP versions are translated for IPv4 only: the export gives no IPv6 prefixes "
                           "for the zones. IPv6-only policies are listed as unresolved."))
    t.issues.append(_issue("warning", "states-by-target", "Connection-state policies (Return Traffic, Invalid) are implemented by the ASA's stateful "
                           "inspection, not by individual entries. UniFi's all-states blocks can also drop replies, which the ASA does not do."))
    if t.target == "cisco-asa":
        t.issues.append(_issue("warning", "icmp-inspection", "An ASA does not track ICMP by default, so the replies to an allowed ping (and ICMP errors) "
                               "come back through a lower-security interface only if ICMP inspection is on (`inspect icmp` and `inspect icmp error` in "
                               "the global policy). This translation does not generate them. TCP and UDP replies need nothing extra."))
    t.issues.append(_issue("info", "order-by-pair", "Each interface ACL lists the zone pairs of its source zone one after another: pairs with known "
                           "destination networks first, External last, each pair in UniFi's index order and ending in its own default."))
    t.dispositions = count
