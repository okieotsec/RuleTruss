"""Compare allow/deny decisions of the source policy and the generated destination policy on representative traffic.

How it works: the generated destination configuration is rendered, parsed back with the destination adapter, and both the
source policy and that parsed result are asked about the same connections. Mismatches are classified; a destination that
allows what the source denied is reported as BROADER.

Limits (also returned in every report): only the sampled connections are compared; both sides are evaluated by this tool's own
evaluator, so a misunderstanding of vendor behaviour shared by the parser and evaluator would not be caught; application,
identity, schedule, inspection and NAT-ordering behaviour are not modelled; connections whose outcome is undecidable on either
side are counted but not compared. Passing this check does not demonstrate equivalence.
"""
import ipaddress

from .. import analysis
from ..adapters.registry import parse_config
from ..evaluate import ALLOW, DENY, INDETERMINATE, Probe, evaluate_connection
from . import firewall as fw

LIMITS = [
    "Only the sampled connections listed below were compared; other traffic may behave differently.",
    "Both sides are evaluated by this tool's evaluator. A shared misunderstanding of a vendor's behaviour would not be caught.",
    "Applications, identities, schedules, security profiles, inspection, and the order of NAT versus filtering are not modelled.",
    "Connections that cannot be decided on either side (unknown zone, unresolved object, uncertain condition) are counted but not "
    "compared.",
    "Passing this check does not show the two policies are equivalent.",
]
MAX_CASES = 3000


def _first_host(net):
    if net.prefixlen >= net.max_prefixlen - 1:
        return net.network_address
    return net.network_address + 1


def _outside(net):
    """An address just outside `net`, in the same family, or None."""
    low, high = int(net.network_address) - 1, int(net.broadcast_address) + 1
    for value in (low, high):
        try:
            ip = ipaddress.ip_address(value) if net.version == 4 else ipaddress.IPv6Address(value)
        except ValueError:
            continue
        if ip not in net:
            return ip
    return None


def _entry_probes(entry):
    """Representative (proto, sport, dport, icmp_type, icmp_code, out_of_range_dport) for an SvcEntry."""
    proto = "icmp" if entry.proto == "icmp" else "icmp6" if entry.proto == "icmp6" else entry.proto
    if proto in ("tcp", "udp", "sctp"):
        dport = entry.dports[0][0] if entry.dports else 443
        sport = entry.sports[0][0] if entry.sports else 40000
        beyond = None
        if entry.dports:
            hi = entry.dports[-1][1]
            beyond = hi + 1 if hi < 65535 else None
        return proto, sport, dport, None, None, beyond
    if proto in ("icmp", "icmp6"):
        return proto, None, None, entry.icmp_type if entry.icmp_type is not None else (8 if proto == "icmp" else 128), \
            entry.icmp_code if entry.icmp_code is not None else 0, None
    return None


def rule_cases(policy):
    """Representative connections inside each enabled rule and just outside it."""
    cases = []
    for rule in policy.rules:
        if not rule.enabled or rule.extra.get("stage") == "unbound" or rule.src.unresolved or rule.dst.unresolved or rule.src.negate \
                or rule.dst.negate or rule.extra.get("new_connections") is False:
            continue
        srcs = [ipaddress.ip_network(n, strict=False) for n in rule.src.nets] or [ipaddress.ip_network("10.255.0.0/16")]
        dsts = [ipaddress.ip_network(n, strict=False) for n in rule.dst.nets] or [ipaddress.ip_network("10.254.0.0/16")]
        if rule.src.any:
            srcs = [ipaddress.ip_network("10.255.0.0/16")]
        if rule.dst.any:
            dsts = [ipaddress.ip_network("10.254.0.0/16")]
        entries = [None] if rule.svc.any else rule.svc.entries
        s, d = srcs[0], dsts[0]
        if s.version != d.version:
            d = next((x for x in dsts if x.version == s.version), None)
            if d is None:
                continue
        for entry in entries[:6]:
            spec = _entry_probes(entry) if entry is not None else ("tcp", 40000, 443, None, None, 444)
            if spec is None:
                continue
            proto, sport, dport, it, ic, beyond = spec
            base = {"proto": proto, "sport": sport, "dport": dport, "icmp_type": it, "icmp_code": ic,
                    "src_zone": rule.src_zones[0] if rule.src_zones else None,
                    "dst_zone": rule.dst_zones[0] if rule.dst_zones else None}
            cases.append((f"inside rule {rule.original_id}", Probe(str(_first_host(s)), str(_first_host(d)), **base)))
            if beyond:
                cases.append((f"just past the ports of rule {rule.original_id}",
                              Probe(str(_first_host(s)), str(_first_host(d)), **{**base, "dport": beyond})))
            out_s = _outside(s) if not rule.src.any else None
            if out_s is not None:
                cases.append((f"source just outside rule {rule.original_id}", Probe(str(out_s), str(_first_host(d)), **base)))
            out_d = _outside(d) if not rule.dst.any else None
            if out_d is not None:
                cases.append((f"destination just outside rule {rule.original_id}", Probe(str(_first_host(s)), str(out_d), **base)))
            if proto in ("tcp", "udp", "sctp"):
                # A NEW connection started from the server side: replies are not reverse initiation.
                rev = Probe(str(_first_host(d)), str(_first_host(s)), proto, sport=dport, dport=40001, src_zone=base["dst_zone"],
                            dst_zone=base["src_zone"])
                cases.append((f"new connection from the other side of rule {rule.original_id}", rev))
    return cases


def _effective(policy, probe):
    forward, reply = evaluate_connection(policy, probe)
    if forward.outcome != ALLOW:
        return forward.outcome, forward, None
    if reply is not None and reply.outcome != ALLOW:
        return (DENY if reply.outcome == DENY else INDETERMINATE), forward, reply
    return ALLOW, forward, reply


def _map_zone(zone, translation):
    if zone is None:
        return None
    return translation.zone_map.get(zone, zone)


def _iface_for(ip, translation):
    """The target interface key an address arrives on (zone-pair sources): its network's, else the WAN side."""
    addr = ipaddress.ip_address(ip)
    for key, nets in translation.iface_nets.items():
        if any(addr.version == ipaddress.ip_network(n).version and addr in ipaddress.ip_network(n) for n in nets):
            return key
    return next((k for k, nets in translation.iface_nets.items() if not nets), None)


def _target_probe(probe, translation):
    if translation.iface_nets:                                   # an interface ACL has no destination zone
        return Probe(probe.src, probe.dst, probe.proto, probe.sport, probe.dport, probe.icmp_type, probe.icmp_code,
                     _map_zone(_iface_for(probe.src, translation), translation), None)
    return Probe(probe.src, probe.dst, probe.proto, probe.sport, probe.dport, probe.icmp_type, probe.icmp_code,
                 _map_zone(probe.src_zone, translation), _map_zone(probe.dst_zone, translation))


def zone_pair_cases(policy, translation):
    """Representative connections for a zone-pair source: every source network to every destination zone, and the inside of each policy
    you wrote."""
    zone_nets = {z: [ipaddress.ip_network(n) for nets in info.get("network_nets", {}).values() for n in nets]
                 for z, info in policy.interfaces.items() if info.get("network_nets")}
    wan = next((z for z in policy.interfaces if z.lower() == "external" and policy.interfaces[z].get("origin") == "SYSTEM_DEFINED"), None)
    services = [("tcp", 40000, 443, None, None), ("udp", 40000, 53, None, None), ("icmp", None, None, 8, 0)]
    cases = []
    sources = [(z, n) for z, nets in zone_nets.items() for n in nets] + ([(wan, ipaddress.ip_network("203.0.113.48/28"))] if wan else [])
    targets = [(z, nets[0]) for z, nets in zone_nets.items()] + ([(wan, ipaddress.ip_network("198.51.100.64/28"))] if wan else [])
    for sz, snet in sources:
        for dz, dnet in targets:
            if dnet == snet:
                continue
            for proto, sport, dport, it, ic in services:
                probe = Probe(str(_first_host(snet)), str(_first_host(dnet) + 1), proto, sport, dport, it, ic, src_zone=sz, dst_zone=dz)
                cases.append((f"{sz} to {dz} ({proto})", probe))
    for rule in policy.rules:
        state_only = bool(rule.extra.get("states")) and "NEW" not in rule.extra["states"]
        if (not rule.enabled or rule.extra.get("origin") != "USER_DEFINED" or rule.src.unresolved or rule.dst.unresolved or rule.src.negate
                or rule.dst.negate or state_only):
            continue
        sz, dz = rule.src_zones[0], rule.dst_zones[0]
        snets = [ipaddress.ip_network(n) for n in rule.src.nets] if not rule.src.any else zone_nets.get(sz, [])[:1]
        dnets = [ipaddress.ip_network(n) for n in rule.dst.nets] if not rule.dst.any else (zone_nets.get(dz, [])[:1] or (
            [ipaddress.ip_network("198.51.100.64/28")] if dz == wan else []))
        if not snets or not dnets or snets[0].version != dnets[0].version:
            continue
        for entry in ([None] if rule.svc.any else rule.svc.entries[:2]):
            spec = _entry_probes(entry) if entry is not None else ("tcp", 40000, 443, None, None, None)
            if spec is None:
                continue
            proto, sport, dport, it, ic, _beyond = spec
            probe = Probe(str(_first_host(snets[0])), str(_first_host(dnets[0])), proto, sport, dport, it, ic, src_zone=sz, dst_zone=dz)
            cases.append((f"inside rule {rule.original_id}", probe))
    return cases


def probe_text(p):
    where = f"{p.proto} {p.src}" + (f":{p.sport}" if p.sport else "") + f" -> {p.dst}" + (f":{p.dport}" if p.dport else "")
    if p.icmp_type is not None:
        where += f" type {p.icmp_type}"
    return where + (f" [{p.src_zone or '?'} to {p.dst_zone or '?'}]")


def _fill_zones(probe, source_policy, ctx):
    """Give a probe the zones the source rule did not name, from the user's subnet zones or the device's interface networks."""
    if ctx is None:
        return probe
    if probe.src_zone is None:
        probe.src_zone = analysis.zone_for(probe.src, ctx, source_policy)
    if probe.dst_zone is None:
        probe.dst_zone = analysis.zone_for(probe.dst, ctx, source_policy)
    return probe


def _result(summary):
    """The headline. It may say 'no difference' only for connections that were actually compared, and says how many were not."""
    if summary["target_broader"]:
        return "destination allows connections the source denied"
    if summary["target_narrower"]:
        return "destination blocks connections the source allowed"
    if not summary["compared"]:
        return (f"nothing could be compared ({summary['not_compared']} of {summary['cases']} sampled connections were undecidable): "
                "no agreement is claimed")
    left = f"; {summary['not_compared']} could not be compared" if summary["not_compared"] else ""
    return f"no difference found on the {summary['compared']} sampled connections that could be compared{left}"


def validate_preserve(source_policy, translation, ctx=None, extra_cases=(), max_cases=MAX_CASES):
    """Round-trip the translation and compare decisions. `translation` must already be rendered for its target.

    `ctx` (an analysis.Context) supplies the zone of addresses when a source rule does not name one.
    """
    clone = fw.Translation(target=translation.target, workflow=translation.workflow, rules=translation.rules,
                           zone_map=dict(translation.zone_map))
    text = fw.render(clone, translation.target, identity=True)
    target_policy = parse_config(text, "validation-target", translation.target if translation.target != "cisco-asa" else "cisco-asa")
    for item in target_policy.rules:                  # unlabelled rules would explain nothing; keep the source name for the report
        item.extra.setdefault("source", item.original_id)
    if translation.iface_nets:
        cases = zone_pair_cases(source_policy, translation)
    else:
        cases = [(label, _fill_zones(probe, source_policy, ctx)) for label, probe in rule_cases(source_policy)]
    cases.extend(extra_cases)
    blocked_ids = {e["source_rule"] for e in translation.report
                   if e.get("status") == "blocked" or e.get("disposition") in ("unsupported", "unresolved")}
    reply_only_ids = {e["source_rule"] for e in translation.report
                      if e.get("status") == "skipped" and "reply traffic only" in e.get("reason", "")}
    if len(cases) > max_cases:
        cases = cases[:max_cases]
    counts = {"same_allow": 0, "same_deny": 0, "target_broader": 0, "target_narrower": 0, "not_compared": 0,
              "explained_by_blocked_rule": 0, "explained_by_source_default": 0}
    mismatches, skipped = [], []
    return_rule_names = {r.name for r in translation.rules if r.kind == "return-path"}
    for label, probe in cases:
        s_out, s_fwd, s_reply = _effective(source_policy, probe)
        t_probe = _target_probe(probe, translation)
        t_out, t_fwd, _ = _effective(target_policy, t_probe)
        if s_out == INDETERMINATE or t_out == INDETERMINATE:
            counts["not_compared"] += 1
            if len(skipped) < 20:
                side = s_fwd if s_out == INDETERMINATE else t_fwd
                why = "; ".join((side.uncertain or [side.basis])[:1])
                skipped.append({"case": label, "connection": probe_text(probe), "why": why,
                                "undecidable_on": "source" if s_out == INDETERMINATE else "destination"})
            continue
        if s_out == t_out:
            counts["same_allow" if s_out == ALLOW else "same_deny"] += 1
            continue
        kind = "target_broader" if t_out == ALLOW else "target_narrower"
        counts[kind] += 1
        expected = kind == "target_broader" and bool(return_rule_names) and label.startswith("new connection from the other side")
        blocked_rule = next((rid for rid in blocked_ids if label.endswith(f"rule {rid}")), None)
        reply_entry = next((rid for rid in reply_only_ids if label.endswith(f"rule {rid}")), None)
        return_note = ("the stateless source permits the connection but not its replies, so it does not work there; the stateful "
                       "destination tracks replies and lets it work" if kind == "target_broader" and s_reply is not None
                       and s_reply.outcome == DENY and s_fwd.outcome == ALLOW else None)
        default_note = ("source relies on its security-level default, which is not translated (see the default-security-level "
                        "warning)" if kind == "target_narrower" and "security level" in s_fwd.basis else None)
        if default_note:
            counts["explained_by_source_default"] += 1
        if blocked_rule is not None:
            counts["explained_by_blocked_rule"] = counts.get("explained_by_blocked_rule", 0) + 1
        if len(mismatches) < 60:
            mismatches.append({
                "kind": kind, "case": label, "connection": probe_text(probe),
                "source": f"{s_out}: {s_fwd.basis}", "destination": f"{t_out}: {t_fwd.basis}",
                "explained_by_known_broader_rule": bool(expected),
                "explained_by_blocked_rule": blocked_rule, "explained_by_source_default": default_note,
                "explained_by_reply_entry": reply_entry, "explained_by_source_return_path": return_note,
                "source_evidence": [e.ref + ": " + e.text for e in s_fwd.evidence[:1]],
                "destination_evidence": [e.ref + ": " + e.text for e in t_fwd.evidence[:1]]})
    summary = {
        "cases": len(cases), **counts,
        "unexplained_broader": counts["target_broader"] - sum(1 for m in mismatches if m["kind"] == "target_broader" and (
            m["explained_by_known_broader_rule"] or m["explained_by_blocked_rule"] or m["explained_by_source_return_path"])),
        "explained_by_reply_entry": sum(1 for m in mismatches if m["explained_by_reply_entry"]),
        "compared": counts["same_allow"] + counts["same_deny"] + counts["target_broader"] + counts["target_narrower"],
    }
    summary["result"] = _result(summary)
    return {"summary": summary, "mismatches": mismatches, "not_compared": skipped, "limits": LIMITS,
            "rendered_for_validation": "Interface names were taken to be the zone names so decisions could be compared; the real "
                                       "interface mapping is yours to supply."}


def validate_observed(translation, comms, ctx, source_policy_for_zones=None):
    """Narrow workflow: every included observed communication must be allowed, and its reverse initiation and other ports denied."""
    clone = fw.Translation(target=translation.target, workflow=translation.workflow, rules=translation.rules,
                           zone_map=dict(translation.zone_map))
    text = fw.render(clone, translation.target, identity=True)
    target_policy = parse_config(text, "validation-target", translation.target)
    included = {e["source_rule"] for e in translation.report if e.get("status") == "translated"}
    counts = {"not_compared": 0, "observed_allowed": 0, "observed_blocked": 0, "reverse_denied": 0, "reverse_allowed": 0,
              "reverse_allowed_known_return_rule": 0,
              "other_port_denied": 0, "other_port_allowed": 0}
    problems = []
    for c in comms:
        if c.comm_id not in included or c.proto not in ("tcp", "udp"):
            continue
        zs = analysis.zone_for(c.initiator, ctx, source_policy_for_zones) if source_policy_for_zones else ctx.zone_of(c.initiator)
        zd = analysis.zone_for(c.responder, ctx, source_policy_for_zones) if source_policy_for_zones else ctx.zone_of(c.responder)
        probe = Probe(c.initiator, c.responder, c.proto, 40000, c.responder_port, src_zone=_map_zone(zs, translation),
                      dst_zone=_map_zone(zd, translation))
        out, fwd, _ = _effective(target_policy, probe)
        if out == INDETERMINATE:
            counts["not_compared"] += 1
            continue
        if out == ALLOW:
            counts["observed_allowed"] += 1
        else:
            counts["observed_blocked"] += 1
            problems.append({"kind": "observed_not_allowed", "connection": probe_text(probe), "detail": f"{out}: {fwd.basis}"})
        rev = Probe(c.responder, c.initiator, c.proto, c.responder_port, 40001, src_zone=probe.dst_zone, dst_zone=probe.src_zone)
        out, fwd, _ = _effective(target_policy, rev)
        if out == ALLOW:
            known = c.proto == "udp" and any(r.kind == "return-path" for r in translation.rules)
            counts["reverse_allowed_known_return_rule" if known else "reverse_allowed"] += 1
            problems.append({"kind": "reverse_initiation_allowed" + (" (known: stateless UDP return rule)" if known else ""),
                             "connection": probe_text(rev), "detail": fwd.basis, "expected": known})
        else:
            counts["reverse_denied"] += 1
        other = Probe(c.initiator, c.responder, c.proto, 40000, 65000 if c.responder_port != 65000 else 64999,
                      src_zone=probe.src_zone, dst_zone=probe.dst_zone)
        out, fwd, _ = _effective(target_policy, other)
        counts["other_port_allowed" if out == ALLOW else "other_port_denied"] += 1
        if out == ALLOW:
            problems.append({"kind": "other_port_allowed", "connection": probe_text(other), "detail": fwd.basis})
    unexpected = [x for x in problems if not x.get("expected")]
    return {"summary": {**counts, "result": "problems found" if unexpected else "observed traffic is allowed, reverse initiation and "
                        "unobserved ports are denied, on the sampled connections" + (
                            " (apart from the known stateless UDP return rules)" if problems else "")},
            "problems": problems[:60], "limits": LIMITS}
