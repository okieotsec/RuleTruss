"""User-defined groups of endpoints and the set arithmetic needed to reason about them.

A group member is an IP address or a CIDR. An endpoint can be in several groups. Nothing here is guessed: groups come from
the user or from an explicit, labelled suggestion the user accepts.
"""
import ipaddress

from .. import limits, netutil
from ..model import AddrSet, Group

MAX_GROUPS = 2_000
MAX_MEMBERS = 50_000


def validate_groups(raw):
    """Turn user JSON into Group objects. Raises ValueError with a message safe to show."""
    if not isinstance(raw, list):
        raise ValueError("groups must be a list")
    if len(raw) > MAX_GROUPS:
        raise ValueError(f"more than {MAX_GROUPS} groups")
    seen, out, total = set(), [], 0
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("each group must be an object with a name and members")
        name = str(item.get("name", "")).strip()
        if not name or len(name) > limits.MAX_NAME_CHARS:
            raise ValueError(f"group name is empty or longer than {limits.MAX_NAME_CHARS} characters")
        if name.lower() in seen:
            raise ValueError(f"duplicate group name {name!r}")
        seen.add(name.lower())
        members = item.get("members", [])
        if not isinstance(members, list):
            raise ValueError(f"members of {name!r} must be a list")
        clean = []
        for m in members:
            try:
                clean.append(str(netutil.parse_ip_or_net(str(m))))
            except netutil.ParseProblem as error:
                raise ValueError(f"group {name!r}: {error}") from error
        total += len(clean)
        if total > MAX_MEMBERS:
            raise ValueError(f"more than {MAX_MEMBERS} group members in total")
        out.append(Group(name=name, members=clean, gateway_isolated=bool(item.get("gateway_isolated", False)),
                         note=limits.clip(str(item.get("note", "")), 300)))
    return out


def nets(group):
    return [ipaddress.ip_network(m, strict=False) for m in group.members]


def groups_for_ip(ip, groups):
    addr = ipaddress.ip_address(ip)
    return [g for g in groups if any(n.version == addr.version and addr in n for n in nets(g))]


def address_count(group):
    return sum(n.num_addresses for n in nets(group))


def subtract(wanted, covered):
    """Networks in `wanted` that are not inside any network in `covered`."""
    remaining = list(wanted)
    for c in covered:
        nxt = []
        for r in remaining:
            if r.version != c.version or not r.overlaps(c):
                nxt.append(r)
            elif r.subnet_of(c):
                continue
            elif c.subnet_of(r):
                nxt.extend(r.address_exclude(c))
        remaining = nxt
        if len(remaining) > limits.MAX_EXPANSION:
            break
    return remaining


def cover_addrset(addr, groups):
    """Which groups can stand for an address set without granting anything outside it?

    Returns dict: exact (list of Group fully inside the set), uncovered (CIDR strings no group covers), overlapping (groups
    that only partly overlap, with the extra addresses they would add), any (the set is unrestricted), blocked (reason or '').
    """
    if addr.negate or addr.unresolved:
        reasons = []
        if addr.negate:
            reasons.append("negated address (everything except ...)")
        if addr.unresolved:
            reasons.append("unresolved members: " + ", ".join(addr.unresolved[:3]))
        return {"exact": [], "uncovered": [], "overlapping": [], "any": False, "blocked": "; ".join(reasons)}
    if addr.any:
        return {"exact": [], "uncovered": [], "overlapping": [], "any": True, "blocked": ""}
    wanted = [ipaddress.ip_network(n, strict=False) for n in addr.nets]
    exact, overlapping = [], []
    for g in groups:
        gn = nets(g)
        if not gn:
            continue
        if not subtract(gn, wanted):
            exact.append(g)
        elif any(n.overlaps(w) for n in gn for w in wanted):
            overlapping.append((g, [str(x) for x in subtract(gn, wanted)][:5]))
    covered = [n for g in exact for n in nets(g)]
    uncovered = [str(x) for x in subtract(wanted, covered)]
    return {"exact": exact, "uncovered": uncovered, "overlapping": overlapping, "any": False, "blocked": ""}


def suggest_groups(ctx, flows):
    """Explicit suggestions only: one group per user-defined subnet. Devices outside any subnet are listed, not grouped."""
    suggestions = [{"name": s.label or s.cidr, "members": [s.cidr], "gateway_isolated": False,
                    "note": "suggested from your subnet definition; edit before use"} for s in ctx.subnets]
    unassigned = sorted({ip for f in flows for ip in (f.initiator, f.responder) if ctx.subnet_of(ip) is None},
                        key=lambda x: ipaddress.ip_address(x))
    return {"groups": suggestions, "unassigned": unassigned}


def as_addrset(group):
    return AddrSet(nets=list(group.members), refs=[group.name])
