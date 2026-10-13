"""Directional group policy planning: internal group policies and external egress policies, as a reviewable worksheet.

The model is defined by this application (see MODEL_FACTS), not by any vendor:

  * A policy connects one or more From groups to one or more To groups.
  * Direction is permission to INITIATE: From may start connections to To; To may not start connections to From.
  * Allowing both directions takes two policies.
  * An endpoint can be in several groups, and a group can be in several policies.
  * An external egress policy is a separate type for endpoints that sit isolated behind a gateway: it lists the external
    destinations (address prefixes, DNS names) those endpoints may reach.

The model deliberately carries no ports, protocols, deny actions, ordering, applications, users or schedules. Where a source
rule has such a condition, the plan keeps it as information, says it is not carried over, and says whether that widens access.
No native import file is produced: the output is a worksheet to apply by hand on whatever enforcement platform is used.
"""
import ipaddress
from dataclasses import dataclass, field

from .. import analysis, limits
from ..model import AddrSet, Evidence, Issue
from . import groups as grp

MODEL_FACTS = {
    "name": "Directional group policy model",
    "defined": [
        "A policy connects one or more From groups to one or more To groups.",
        "From groups may initiate connections to To groups within the policy; To groups may not initiate to From groups.",
        "Direction is about who may initiate a connection. Replies to a permitted connection are not a separate permission.",
        "Allowing both directions needs two policies.",
        "An endpoint can belong to several groups and a group can appear in several policies.",
        "An external egress policy is a separate type for endpoints isolated behind a gateway. It names the endpoint groups, the "
        "allowed external destinations (address prefixes and DNS names, optionally recursive), optional services, whether all DNS "
        "queries are allowed, and whether the policy is enabled.",
    ],
    "not_modelled": [
        "Ports and protocols as enforced conditions on a group policy (kept only as information).",
        "Deny actions, and rule ordering or precedence.",
        "Application, user-identity or schedule conditions.",
        "How a named service for an egress policy is defined on a particular platform.",
    ],
    "note": "This is a model defined by this application so that policies can be reviewed in one neutral form. It is not the "
            "policy format of any product. Check what your enforcement platform supports before relying on any row.",
}
DIRECTION_NOTE = ("Members of the From groups may initiate connections to members of the To groups. Members of the To groups "
                  "may not initiate connections to the From groups under this policy; reverse initiation needs its own policy.")
PAIR_CHECK_LIMIT = 2_000_000


@dataclass
class DGroup:
    name: str
    members: list
    gateway_isolated: bool = False
    note: str = ""


@dataclass
class DPolicy:
    name: str
    from_groups: list
    to_groups: list
    origin: str                                  # preserved or proposed
    status: str = "proposed"                     # proposed, needs_review, blocked
    services_informational: list = field(default_factory=list)   # the model does not enforce these
    source_rule_ids: list = field(default_factory=list)
    source_rules: list = field(default_factory=list)
    comm_ids: list = field(default_factory=list)
    basis: str = ""
    warnings: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    broadens: bool = False
    loses_restrictions: bool = False
    direction_note: str = DIRECTION_NOTE
    granted_pairs: int = 0
    observed_pairs: int = 0


@dataclass
class EgressPolicy:
    name: str
    endpoint_groups: list
    origin: str
    enabled: bool = True
    allowed_prefixes: list = field(default_factory=list)
    allowed_dns_names: list = field(default_factory=list)
    recursive_dns: bool = False
    allow_all_dns: bool = False
    services: list = field(default_factory=list)    # services to create or select on the platform
    status: str = "proposed"
    source_rule_ids: list = field(default_factory=list)
    comm_ids: list = field(default_factory=list)
    basis: str = ""
    warnings: list = field(default_factory=list)
    evidence: list = field(default_factory=list)


@dataclass
class Plan:
    workflow: str                                # preserve or narrow
    title: str
    groups: list = field(default_factory=list)
    policies: list = field(default_factory=list)
    egress_policies: list = field(default_factory=list)
    gaps: list = field(default_factory=list)     # Issue objects: things that did not translate, or translated with loss
    review_items: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    observation: dict = field(default_factory=dict)
    facts: dict = field(default_factory=lambda: MODEL_FACTS)
    manual_steps: list = field(default_factory=list)


def _issue(severity, code, message, evidence=None):
    return Issue(severity, code, message, list(evidence or [])[:3])


def manual_steps():
    return [
        "Create each group listed in the Groups table on your enforcement platform and add its endpoints (group membership is "
        "not imported from this worksheet).",
        "For each row of the Group policies table, create one policy from the From groups to the To groups. Create one policy "
        "per direction; a policy never grants the reverse direction.",
        "For each row of the Egress policies table, create an external egress policy for the endpoint groups with the allowed "
        "prefixes and DNS names, and decide on services and DNS handling yourself.",
        "Services (ports/protocols) in the worksheet are for reference. The directional model does not enforce them; if your "
        "platform can, apply them there, otherwise accept that the policy is broader than the source.",
        "Review every item under Review and Gaps before enabling anything. This worksheet is not proof that the result is "
        "equivalent to the source; it is a starting point.",
    ]


def _atoms(group_objs):
    seen, out = set(), []
    for g in group_objs:
        for m in g.members:
            if m not in seen:
                seen.add(m)
                out.append(m)
    return out


def _address_total(atoms):
    return sum(ipaddress.ip_network(a, strict=False).num_addresses for a in atoms)


def _addr(atom):
    return AddrSet(nets=[atom])


def _same_scope(rule):
    return (rule.extra.get("stage"), rule.extra.get("bind"), rule.extra.get("acl"))


def _is_reply_rule(rule, allow_rules):
    """True when an entry only permits replies: TCP `established`, or the port-mirror of another allowed rule."""
    if not rule.svc.entries or rule.svc.any:
        return False
    if all(e.established for e in rule.svc.entries):
        return True
    for entry in rule.svc.entries:
        if entry.sports is None or entry.dports is not None:
            return False
        mirrored = False
        for other in allow_rules:
            if other is rule or not analysis.addr_covers(other.src, rule.dst) or not analysis.addr_covers(other.dst, rule.src):
                continue
            if other.svc.any or any(o.proto in (entry.proto, "ip") and (o.dports is None or analysis._ranges_cover(entry.sports, o.dports))
                                    for o in other.svc.entries):
                mirrored = True
                break
        if not mirrored:
            return False
    return True


def _name(from_groups, to_groups):
    return limits.clip(f"{'+'.join(from_groups)} to {'+'.join(to_groups)}", 100)


def _merge(plan, key, make):
    for p in plan.policies:
        if (tuple(p.from_groups), tuple(p.to_groups)) == key:
            return p
    p = make()
    plan.policies.append(p)
    return p


# ---------------------------------------------------------------------------------------------------- preserve workflow

def plan_preserve(policy, groups):
    """Translate the *configured* permissions of a source policy to directional group policies."""
    plan = Plan(workflow="preserve", title=f"Preserve existing permissions: {policy.platform or policy.vendor} "
                                           f"{policy.hostname}".strip(), manual_steps=manual_steps())
    plan.groups = [DGroup(g.name, list(g.members), g.gateway_isolated, g.note) for g in groups]
    gateway = [g for g in groups if g.gateway_isolated]
    rules = [r for r in policy.rules if r.extra.get("stage") != "unbound"]
    allow_all = [r for r in rules if r.enabled and r.action == "allow"]
    by_scope = {}
    for r in rules:
        by_scope.setdefault(_same_scope(r), []).append(r)
    for scope_rules in by_scope.values():
        scope_rules.sort(key=lambda r: r.position)
    counts = {"translated": 0, "blocked": 0, "deny_not_translated": 0, "reply_rules": 0, "disabled": 0}
    for scope_rules in by_scope.values():
        for index, rule in enumerate(scope_rules):
            ev = rule.evidence[:1]
            if not rule.enabled:
                counts["disabled"] += 1
                plan.gaps.append(_issue("info", "rule-disabled", f"Rule {rule.original_id} is disabled and was not translated.", ev))
                continue
            if rule.action == "deny":
                counts["deny_not_translated"] += 1
                plan.gaps.append(_issue(
                    "warning", "deny-not-translated",
                    f"Deny rule {rule.original_id} has no equivalent in the directional model (it has no deny action or ordering). "
                    "Traffic not granted by a policy is not permitted, but a deny that overrode a later broader allow is lost; "
                    "see the warnings on the allow policies.", ev))
                continue
            if _is_reply_rule(rule, allow_all):
                counts["reply_rules"] += 1
                plan.review_items.append(_issue(
                    "info", "reply-rule", f"Rule {rule.original_id} appears to permit reply traffic only (TCP established, or the "
                    "port-mirror of an allowed rule). No policy was generated: policies in this model are about who may initiate. "
                    "If this entry is really meant to let those devices initiate connections, add a separate policy.", ev))
                continue
            problems = []
            if rule.unsupported:
                problems.append("conditions this tool cannot evaluate or carry over: " + "; ".join(rule.unsupported))
            for label, conditions in (("application", rule.applications), ("identity", rule.users)):
                if conditions and conditions != ["any"]:
                    problems.append(f"{label} condition ({', '.join(conditions[:4])}) has no equivalent in the "
                                    "directional model")
            if rule.schedule:
                problems.append(f"schedule {rule.schedule} has no equivalent in the directional model")
            src_cover = grp.cover_addrset(rule.src, groups)
            if src_cover["blocked"]:
                problems.append("source: " + src_cover["blocked"])
            if src_cover["any"]:
                problems.append("the source is 'any'; policies connect named groups and the model has no 'any' source, so you "
                                "must decide which group(s) should stand for it")
            # Egress candidate: gateway-isolated endpoints whose destination lies wholly outside every group
            all_group_nets = [n for g in groups for n in grp.nets(g)]
            dst_nets = [ipaddress.ip_network(n, strict=False) for n in rule.dst.nets]
            touches_a_group = any(n.version == g.version and n.overlaps(g) for n in dst_nets for g in all_group_nets)
            outside_only = (not rule.dst.negate and bool(rule.dst.fqdn_names() or dst_nets or rule.dst.any)
                            and not touches_a_group)
            if gateway and not problems and src_cover["exact"] and not src_cover["uncovered"] and \
                    all(g in gateway for g in src_cover["exact"]) and outside_only:
                _egress_from_rule(plan, rule, src_cover["exact"])
                counts["translated"] += 1
                continue
            dst_cover = grp.cover_addrset(rule.dst, groups)
            if dst_cover["blocked"]:
                problems.append("destination: " + dst_cover["blocked"])
            if dst_cover["any"]:
                problems.append("the destination is 'any'; the model has no 'any' destination for group policies. Use an egress "
                                "policy for external destinations (gateway-isolated endpoints only) or name the destination groups")
            if problems:
                counts["blocked"] += 1
                plan.policies.append(DPolicy(
                    name=limits.clip(f"BLOCKED rule {rule.original_id}", 100), from_groups=[], to_groups=[], origin="preserved",
                    status="blocked", source_rule_ids=[rule.rule_id], source_rules=[rule.original_id], evidence=list(rule.evidence),
                    basis=f"Source rule {rule.original_id} ({rule.src.text()} to {rule.dst.text()} on {rule.svc.text()})",
                    warnings=[_issue("blocker", "cannot-translate", "Not translated: " + "; ".join(problems) + ".", ev)]))
                plan.gaps.append(_issue("blocker", "rule-not-translated", f"Rule {rule.original_id} was not translated: "
                                        + "; ".join(problems) + ".", ev))
                continue
            from_names = [g.name for g in src_cover["exact"]]
            to_names = [g.name for g in dst_cover["exact"]]
            if not from_names or not to_names:
                counts["blocked"] += 1
                missing = []
                if not from_names:
                    missing.append(f"no group is wholly inside the source ({rule.src.text()})")
                if not to_names:
                    missing.append(f"no group is wholly inside the destination ({rule.dst.text()})")
                plan.gaps.append(_issue("blocker", "no-matching-group", f"Rule {rule.original_id} was not translated: "
                                        + "; ".join(missing) + ". Define groups for these addresses.", ev))
                plan.policies.append(DPolicy(name=limits.clip(f"BLOCKED rule {rule.original_id}", 100), from_groups=[], to_groups=[],
                                              origin="preserved", status="blocked", source_rule_ids=[rule.rule_id],
                                              source_rules=[rule.original_id], evidence=list(rule.evidence),
                                              warnings=[_issue("blocker", "no-matching-group", "; ".join(missing), ev)]))
                continue
            key = (tuple(from_names), tuple(to_names))
            pol = _merge(plan, key, lambda fn=from_names, tn=to_names: DPolicy(
                name=_name(fn, tn), from_groups=fn, to_groups=tn, origin="preserved",
                basis="Preserves configured permissions from the source policy; not derived from observed traffic."))
            pol.source_rule_ids.append(rule.rule_id)
            pol.source_rules.append(rule.original_id)
            pol.evidence.extend(rule.evidence[:1])
            pol.services_informational.append(f"{rule.original_id}: {rule.svc.text()}")
            counts["translated"] += 1
            if not rule.svc.any:
                pol.loses_restrictions = True
                _add_warning(pol, "services-not-enforced", "warning",
                             f"Source rule {rule.original_id} allowed only {rule.svc.text()}. The directional model "
                             "has no port or protocol condition, so this restriction is not carried over: members of the "
                             "From groups would be permitted to initiate to the To groups on any service the endpoints expose.", ev)
            if src_cover["uncovered"] or dst_cover["uncovered"]:
                uncovered = src_cover["uncovered"] + dst_cover["uncovered"]
                _add_warning(pol, "address-not-in-any-group", "warning",
                             f"Rule {rule.original_id} also covers addresses that belong to no group ({', '.join(uncovered[:5])}"
                             f"{'...' if len(uncovered) > 5 else ''}); those addresses are not represented in this policy.", ev)
            earlier_denies = [d for d in scope_rules[:index] if d.enabled and d.action == "deny" and analysis.rule_overlap(d, rule)]
            if earlier_denies:
                pol.broadens = True
                _add_warning(pol, "earlier-deny-lost", "warning",
                             f"Rule {rule.original_id} came after deny rule(s) {', '.join(d.original_id for d in earlier_denies[:4])} "
                             "that blocked part of what it allows. The directional model has no deny, so the policy grants "
                             "the whole From to To relationship including the part the source denied.", ev)
            if not policy.stateful and rule.svc.entries and not all(e.established for e in rule.svc.entries):
                _add_warning(pol, "stateless-source", "info",
                             "The source is a stateless ACL; the explicit return-path entries it needed are not translated "
                             "(policies in this model are about who may initiate).", ev)
    for p in plan.policies:
        if p.status == "blocked":
            continue
        p.status = "needs_review" if any(w.severity in ("warning", "blocker") for w in p.warnings) else "proposed"
    _check_aggregation(plan, policy, groups)
    _finish_summary(plan, counts, policy)
    return plan


def _add_warning(pol, code, severity, message, evidence=None):
    if not any(w.code == code and w.message == message for w in pol.warnings):
        pol.warnings.append(_issue(severity, code, message, evidence))


def _egress_from_rule(plan, rule, endpoint_groups):
    names = sorted(g.name for g in endpoint_groups)
    prefixes = [n for n in rule.dst.nets if n not in ("0.0.0.0/0", "::/0")] if not rule.dst.any else []
    dns = sorted(set(rule.dst.fqdn_names()))
    key = ("egress", tuple(names))
    pol = next((p for p in plan.egress_policies if p.name == limits.clip("Egress " + "+".join(names), 100)), None)
    if pol is None:
        pol = EgressPolicy(name=limits.clip("Egress " + "+".join(names), 100), endpoint_groups=names, origin="preserved",
                           basis="Preserves configured permissions to external destinations from gateway-isolated endpoint groups.")
        plan.egress_policies.append(pol)
    del key
    pol.allowed_prefixes = sorted(set(pol.allowed_prefixes) | set(prefixes))
    pol.allowed_dns_names = sorted(set(pol.allowed_dns_names) | set(dns))
    pol.source_rule_ids.append(rule.rule_id)
    pol.evidence.extend(rule.evidence[:1])
    if not rule.svc.any:
        pol.services.append(f"{rule.original_id}: {rule.svc.text()}")
    if rule.dst.any:
        pol.warnings.append(_issue("blocker", "egress-any", f"Rule {rule.original_id} allowed any destination; an egress policy "
                                   "needs explicit prefixes or DNS names, so this part is not translated.", rule.evidence[:1]))
        pol.status = "needs_review"
    if not prefixes and not dns:
        pol.warnings.append(_issue("blocker", "egress-no-destination", f"Rule {rule.original_id} produced no allowed prefix or "
                                   "DNS name.", rule.evidence[:1]))
        pol.status = "needs_review"
    if dns:
        pol.warnings.append(_issue("warning", "egress-dns-name", f"Source allowed host name(s) {', '.join(dns)}. Your platform resolves "
                                   "DNS names itself: confirm they resolve to the same addresses and whether wildcards are needed "
                                   "(wildcard support depends on the platform).", rule.evidence[:1]))
        pol.status = "needs_review"
    if not rule.svc.any:
        pol.warnings.append(_issue("warning", "egress-services", "Services were restricted in the source. Egress policies can name "
                                   "services, but how a service is defined depends on the platform: create or select matching "
                                   "services manually.", rule.evidence[:1]))
        pol.status = "needs_review"


def _check_aggregation(plan, source_policy, groups):
    """Detect access that group membership grants but the source never did."""
    allow = [r for r in source_policy.rules if r.enabled and r.action == "allow" and r.extra.get("stage") != "unbound"]
    by_name = {g.name: g for g in groups}
    budget = PAIR_CHECK_LIMIT
    truncated = False
    for p in plan.policies:
        if p.status == "blocked":
            continue
        fa = _atoms([by_name[n] for n in p.from_groups])
        ta = _atoms([by_name[n] for n in p.to_groups])
        p.granted_pairs = len(fa) * len(ta)
        unintended, partial = [], []
        for a in fa:
            for b in ta:
                if budget <= 0:
                    truncated = True
                    break
                budget -= max(1, len(allow))
                covered = any(analysis.addr_covers(r.src, _addr(a)) and analysis.addr_covers(r.dst, _addr(b)) for r in allow)
                if covered:
                    continue
                overlapping = any(analysis._overlap_addr(r.src, _addr(a)) and analysis._overlap_addr(r.dst, _addr(b)) for r in allow)
                (partial if overlapping else unintended).append((a, b))
        if unintended or partial:
            p.broadens = True
            sample = ", ".join(f"{a} to {b}" for a, b in (unintended + partial)[:4])
            _add_warning(p, "aggregation-grants-extra", "warning",
                         f"Group membership makes this policy grant {len(unintended)} member pair(s) that no source rule permitted"
                         f"{f' and {len(partial)} that the source permitted only in part' if partial else ''} (for example {sample}). "
                         "Split the groups or change membership so the policy grants only what the source did.")
        both = set(fa) & set(ta)
        if len(both) >= 2:
            p.broadens = True
            _add_warning(p, "implied-reverse-initiation", "warning",
                         f"{len(both)} member(s) ({', '.join(sorted(both)[:4])}) are in both the From and To groups, so they may "
                         "initiate to each other in both directions even though a policy is directional.")
        if p.status != "blocked" and p.warnings and any(w.severity in ("warning", "blocker") for w in p.warnings):
            p.status = "needs_review"
    if truncated:
        plan.gaps.append(_issue("info", "aggregation-truncated", "The group aggregation check stopped early because of the size of "
                                "the groups and rules; some member pairs were not compared."))


def _finish_summary(plan, counts, source_policy):
    live = [p for p in plan.policies if p.status != "blocked"]
    plan.summary = {
        "source_rules": len(source_policy.rules),
        "policies": len(live), "blocked_rules": counts["blocked"], "egress_policies": len(plan.egress_policies),
        "policies_that_broaden_access": sum(1 for p in live if p.broadens),
        "policies_that_lose_restrictions": sum(1 for p in live if p.loses_restrictions),
        "deny_rules_not_translated": counts["deny_not_translated"], "reply_rules_not_translated": counts["reply_rules"],
        "disabled_rules_skipped": counts["disabled"], "needs_review": sum(1 for p in live if p.status == "needs_review"),
        "verdict": ("This migration broadens access or drops restrictions in at least one place; read every warning before use."
                    if any(p.broadens or p.loses_restrictions for p in live) or counts["deny_not_translated"] else
                    "No broadening or lost restriction was detected by this tool's checks; that is not proof of equivalence."),
    }


# ---------------------------------------------------------------------------------------------------- narrow workflow

def plan_narrow(comms, flows_by_id, groups, ctx, observation, include_low_confidence=False):
    """Propose group policies from *observed* initiation. Every proposal needs review: a capture is only a window."""
    plan = Plan(workflow="narrow", title="Propose narrower permissions from observed communications", manual_steps=manual_steps())
    plan.groups = [DGroup(g.name, list(g.members), g.gateway_isolated, g.note) for g in groups]
    plan.observation = dict(observation)
    gateway_names = {g.name for g in groups if g.gateway_isolated}
    sizes = {g.name: grp.address_count(g) for g in groups}
    counts = {"observed": len(comms), "used": 0, "low_confidence_held_back": 0, "unassigned": 0}
    pair_observed = {}
    for c in comms:
        ev = c.evidence[:2]
        if c.direction_confidence in ("low", "unknown") and not include_low_confidence:
            counts["low_confidence_held_back"] += 1
            plan.review_items.append(_issue(
                "warning", "direction-uncertain", f"{c.initiator} and {c.responder} ({c.proto}"
                f"{' ' + str(c.responder_port) if c.responder_port else ''}): which side initiates is uncertain "
                f"({c.direction_confidence} confidence: {'; '.join(c.direction_basis[:1]) or 'no evidence'}). No policy was proposed. "
                "Decide the direction before creating one; a wrong direction would permit the opposite initiation.", ev))
            continue
        src_groups = grp.groups_for_ip(c.initiator, groups)
        dst_groups = grp.groups_for_ip(c.responder, groups)
        if gateway_names and src_groups and all(g.name in gateway_names for g in src_groups) and not dst_groups \
                and ctx.subnet_of(c.responder) is None:
            _egress_from_comm(plan, c, [g.name for g in src_groups], flows_by_id)
            counts["used"] += 1
            continue
        if not src_groups or not dst_groups:
            counts["unassigned"] += 1
            missing = []
            if not src_groups:
                missing.append(f"initiator {c.initiator}")
            if not dst_groups:
                missing.append(f"responder {c.responder}")
            verb = "is" if len(missing) == 1 else "are"
            plan.review_items.append(_issue(
                "warning", "not-in-a-group", f"{' and '.join(missing)} {verb} not in any group, so the communication was not turned "
                "into a policy. Add the address to a group.", ev))
            continue
        best = min(((fg, tg) for fg in src_groups for tg in dst_groups),
                   key=lambda pair: (sizes[pair[0].name] * sizes[pair[1].name], pair[0].name, pair[1].name))
        key = ((best[0].name,), (best[1].name,))
        pol = _merge(plan, key, lambda b=best: DPolicy(
            name=_name([b[0].name], [b[1].name]), from_groups=[b[0].name], to_groups=[b[1].name], origin="proposed",
            basis="Proposed from observed initiation in the supplied capture(s); observation is not proof of business need."))
        pol.comm_ids.append(c.comm_id)
        pol.evidence.extend(ev)
        service = f"{c.proto}{'/' + str(c.responder_port) if c.responder_port is not None else ''}"
        app = next((a for a in c.apps if a.confidence == "confirmed"), None)
        pol.services_informational.append(f"observed {service}" + (f" ({app.name}, confirmed by decoding)" if app else ""))
        pair_observed.setdefault(key, set()).add((c.initiator, c.responder))
        if c.direction_confidence == "medium":
            _add_warning(pol, "direction-medium", "info", f"Direction of {c.initiator} to {c.responder} ({service}) was inferred with "
                         f"medium confidence: {'; '.join(c.direction_basis[:1])}.", ev)
        if len(src_groups) > 1 or len(dst_groups) > 1:
            _add_warning(pol, "multiple-groups", "info", f"{c.initiator} or {c.responder} is in more than one group; the pair with the "
                         "smallest total membership was chosen to limit group aggregation.", ev)
        counts["used"] += 1
    by_name = {g.name: g for g in groups}
    for p in plan.policies:
        fa, ta = _atoms([by_name[n] for n in p.from_groups]), _atoms([by_name[n] for n in p.to_groups])
        key = (tuple(p.from_groups), tuple(p.to_groups))
        p.granted_pairs = _address_total(fa) * _address_total(ta)
        p.observed_pairs = len(pair_observed.get(key, ()))
        if p.granted_pairs > max(p.observed_pairs, 1):
            p.broadens = True
            _add_warning(p, "aggregation-grants-extra", "warning",
                         f"This policy grants {p.granted_pairs:,} address pair(s) between its groups but only {p.observed_pairs} "
                         "initiating pair(s) were observed. The rest are permitted by group membership without evidence in the "
                         "capture. Narrow the groups if that is not intended.")
        both = set(fa) & set(ta)
        if len(both) >= 2:
            _add_warning(p, "implied-reverse-initiation", "warning", f"{len(both)} member(s) are in both the From and To groups and "
                         "may initiate to each other in both directions.")
        if any(w.severity in ("warning", "blocker") for w in p.warnings):
            p.status = "needs_review"
    keys = {(tuple(p.from_groups), tuple(p.to_groups)): p for p in plan.policies}
    for (f, t), p in keys.items():
        reverse = keys.get((t, f))
        if reverse is not None and f < t:
            note = ("Both directions were observed as separate initiations, so two separate policies are proposed: "
                    f"'{p.name}' and '{reverse.name}'.")
            _add_warning(p, "reverse-initiation", "info", note)
            _add_warning(reverse, "reverse-initiation", "info", note)
    plan.review_items.insert(0, _issue(
        "warning", "observation-limits", "These proposals come only from the capture window described under Observation. Dependencies "
        "that did not occur in that window are invisible to this tool: scheduled or seasonal jobs, backup and failover paths, "
        "maintenance and vendor access, start-up sequences, rarely used engineering functions, and anything outside the "
        "observation point. Confirm each proposal with the people who run the systems before enforcing it."))
    plan.summary = {
        "communications_observed": counts["observed"], "communications_used": counts["used"],
        "held_back_low_confidence": counts["low_confidence_held_back"], "not_in_a_group": counts["unassigned"],
        "policies": len(plan.policies), "egress_policies": len(plan.egress_policies),
        "policies_that_broaden_access": sum(1 for p in plan.policies if p.broadens),
        "needs_review": sum(1 for p in plan.policies if p.status == "needs_review"),
        "verdict": "All proposals require review before use. Observed traffic is not proof of business need.",
    }
    return plan


def _egress_from_comm(plan, c, endpoint_groups, flows_by_id):
    names = sorted(endpoint_groups)
    pol_name = limits.clip("Egress " + "+".join(names), 100)
    pol = next((p for p in plan.egress_policies if p.name == pol_name), None)
    if pol is None:
        pol = EgressPolicy(name=pol_name, endpoint_groups=names, origin="proposed", status="needs_review",
                           basis="Proposed from observed connections by gateway-isolated endpoints to destinations outside every group.")
        plan.egress_policies.append(pol)
    prefix = str(ipaddress.ip_network(c.responder))
    if prefix not in pol.allowed_prefixes:
        pol.allowed_prefixes.append(prefix)
    for fid in c.flow_ids:
        for name in getattr(flows_by_id.get(fid), "hostnames", []) or []:
            if name not in pol.allowed_dns_names and c.proto == "tcp":
                pol.allowed_dns_names.append(name)
    service = f"{c.proto}{'/' + str(c.responder_port) if c.responder_port is not None else ''}"
    if service not in pol.services:
        pol.services.append(service)
    pol.comm_ids.append(c.comm_id)
    pol.evidence.extend(c.evidence[:1])
    if not pol.warnings:
        pol.warnings.append(_issue("warning", "egress-review", "Prefixes are the exact addresses observed. Cloud and CDN services change "
                                   "addresses; prefer DNS names where the destination is a named service, and review whether DNS "
                                   "resolution should be allowed (the Allow all DNS queries setting is left off).", c.evidence[:1]))
        pol.warnings.append(_issue("warning", "egress-services", "Observed services are for reference. Egress policies can name "
                                   "services, whose definition depends on the platform.", c.evidence[:1]))


def observation_summary(infos, comms):
    """Describe the capture window so a reviewer can judge what is missing."""
    first = min((i.first_ts for i in infos if i.first_ts), default=None)
    last = max((i.last_ts for i in infos if i.last_ts), default=None)
    duration = (last - first) if first and last else 0
    return {"captures": [{"filename": i.filename, "format": i.format, "first_ts": i.first_ts, "last_ts": i.last_ts,
                          "observation_point": i.observation_point or "not supplied", "packets": i.packets_read} for i in infos],
            "first_ts": first, "last_ts": last, "duration_seconds": duration, "communications": len(comms),
            "caveats": ["A capture shows only traffic that crossed the observation point during the capture window.",
                        f"Window length: {duration / 3600:.2f} hours." if duration else "Window length is unknown.",
                        *[n for i in infos for n in i.coverage_notes[:3]]]}


def evidence_text(evidence):
    return "; ".join(f"{e.kind} {e.ref}" if isinstance(e, Evidence) else str(e) for e in evidence[:4])
