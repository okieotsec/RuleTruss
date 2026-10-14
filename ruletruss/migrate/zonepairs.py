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
import ipaddress

from ..model import AddrSet
from .firewall import OutRule, _issue, safe_id

TRANSLATED, IMPLEMENTED, UNSUPPORTED, UNRESOLVED, NOT_APPLICABLE = "translated", "implemented", "unsupported", "unresolved", "not-applicable"
DEFAULT_INDEX = 2147483647
WAN_PREFIX = "zone-"


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

    def set(self, disposition, reason):
        self.disposition, self.reason = disposition, reason
        return self


def translate(policy, caps, t, zone_map, identity, confirmed):
    """Fill `t` (a Translation) with output rules, a disposition per source policy, issues and the interface table."""
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
    plans = [_Plan(r) for r in policy.rules]
    by_pair = {}
    for plan in plans:
        r = plan.rule
        by_pair.setdefault((r.src_zones[0] if r.src_zones else "", r.dst_zones[0] if r.dst_zones else ""), []).append(plan)

    for plan in plans:
        _classify(plan, policy, zones, network_nets, has_networks, user_zones, wan_zone, caps, confirmed, t)

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


def _classify(plan, policy, zones, network_nets, has_networks, user_zones, wan_zone, caps, confirmed, t):
    r = plan.rule
    if not r.enabled:
        return plan.set(NOT_APPLICABLE, "the policy is disabled in the export")
    sz, dz = (r.src_zones or [""])[0], (r.dst_zones or [""])[0]
    states = r.extra.get("states")
    if states and "NEW" not in states:
        return _state_only(plan, r, states)
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
    # where does it apply
    if sz not in has_networks and sz != wan_zone:
        if sz.lower() == "vpn" and sz in user_zones:
            return _vpn(plan, "from VPN clients", confirmed)
        if sz in user_zones and r.extra.get("origin") == "USER_DEFINED":
            return plan.set(UNRESOLVED, f"source zone {sz} has no networks in the export, so there is no interface to place this on "
                            "(a stale zone assignment or an incomplete export)")
        return plan.set(NOT_APPLICABLE, f"zone {sz} has no networks in the export, so nothing is attached to it")
    if dz.lower() == "gateway" and zones.get(dz, {}).get("origin") == "SYSTEM_DEFINED":
        if "gateway" in confirmed:
            return plan.set(IMPLEMENTED, "traffic to the firewall itself: you confirmed it is handled with the ASA's own access controls "
                            "(ssh, http, icmp, control-plane ACLs), which this translation does not generate")
        return plan.set(UNRESOLVED, "traffic to the firewall itself needs explicit local-service handling on the ASA (ssh, http, icmp, "
                        "DNS/DHCP service settings, control-plane ACLs); interface ACLs do not govern it")
    if dz not in has_networks and dz != wan_zone:
        if dz.lower() == "vpn" and dz in user_zones:
            return _vpn(plan, "to VPN clients", confirmed)
        if dz in user_zones and r.extra.get("origin") == "USER_DEFINED":
            return plan.set(UNRESOLVED, f"destination zone {dz} has no networks in the export, so its addresses are unknown (a stale zone "
                            "assignment or an incomplete export)")
        return plan.set(NOT_APPLICABLE, f"zone {dz} has no networks in the export, so nothing is attached to it")
    if r.extra.get("ip_version") == "IPV6" and dz != wan_zone:
        return plan.set(UNRESOLVED, "an IPv6 policy, and the export has no IPv6 prefixes for the zones, so its scope cannot be written")
    # source interfaces and their source addresses
    sources = []
    if sz == wan_zone:
        sources.append((WAN_PREFIX + wan_zone, r.src))
    else:
        zone_nets = network_nets[sz]
        if r.src.any:
            sources = [(key, AddrSet(nets=list(nets), refs=[key])) for key, nets in zone_nets.items()]
        else:
            owned = {}
            for net in _nets(r.src):
                key = next((k for k, nets in zone_nets.items() if _inside(net, [ipaddress.ip_network(n) for n in nets])), None)
                if key is None:
                    return plan.set(UNRESOLVED, f"source address {net} is not inside any network of zone {sz} (a stale zone assignment or an "
                                    "incomplete export); it was not moved to another zone")
                owned.setdefault(key, []).append(str(net))
            sources = [(key, AddrSet(nets=nets)) for key, nets in owned.items()]
    # destination
    if dz == wan_zone:
        dst, rank = r.dst, 1
    else:
        zone_all = [ipaddress.ip_network(n) for nets in network_nets[dz].values() for n in nets]
        if r.dst.any:
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
        own = [ipaddress.ip_network(n) for n in t.iface_nets.get(key, [])] if sz == dz and r.dst.any else []
        this_dst = AddrSet(nets=[n for n in dst.nets if ipaddress.ip_network(n) not in own], refs=dst.refs) if own else dst
        plan.entries.append((key, rank, dz, OutRule(
            name=safe_id(r.original_id), action=r.action, src=src, dst=this_dst, svc=r.svc, src_zone=key, dst_zone=None, log=r.log,
            comment=limits_clip(r.comment), source_rule_ids=[r.rule_id], source_ids_text=safe_id(_short(r)), evidence=r.evidence[:2])))
    notes = []
    if r.action == "deny" and not states and r.extra.get("origin") == "USER_DEFINED":
        notes.append("this block applies to every connection state on UniFi, so it can also drop replies of connections the other side "
                     "started; the ASA always lets replies of permitted connections through, so it will not")
    return plan.set(TRANSLATED, "; ".join(notes))


def _vpn(plan, what, confirmed):
    if "vpn" in confirmed:
        return plan.set(IMPLEMENTED, f"traffic {what}: you confirmed VPN is handled separately on the target, which this translation does not generate")
    return plan.set(UNRESOLVED, f"traffic {what} needs the target's VPN topology and the interface it arrives on")


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
        t.issues.append(_issue("blocker", "local-services", f"{len(gateway)} policies are about traffic to the firewall itself. Interface ACLs "
                               "do not govern it; configure ssh/http/icmp/DNS/DHCP access on the ASA explicitly, then tick 'I handle traffic to "
                               "the firewall itself' to mark them handled."))
    vpn = [p for p in plans if p.disposition == UNRESOLVED and "VPN" in p.reason]
    if vpn:
        t.issues.append(_issue("blocker", "vpn-topology", f"{len(vpn)} policies involve VPN clients, which need the target's VPN design and the "
                               "interface they arrive on. Tick 'I handle VPN separately' once that is settled."))
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
    t.issues.append(_issue("info", "order-by-pair", "Each interface ACL lists the zone pairs of its source zone one after another: pairs with known "
                           "destination networks first, External last, each pair in UniFi's index order and ending in its own default."))
    t.dispositions = count
