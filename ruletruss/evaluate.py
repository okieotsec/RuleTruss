"""Decide what a configured policy does with one connection.

The answer is allow, deny or indeterminate. Indeterminate is a real outcome: it means a rule that would change the
answer has a condition (application, user, schedule, unresolved object, unknown zone) this tool cannot evaluate.
The evaluator never guesses a condition away.
"""
from dataclasses import dataclass, field

ALLOW, DENY, INDETERMINATE = "allow", "deny", "indeterminate"


@dataclass
class Probe:
    """One connection to test, described from the initiator's side."""
    src: str
    dst: str
    proto: str
    sport: int = None
    dport: int = None
    icmp_type: int = None
    icmp_code: int = None
    src_zone: str = None
    dst_zone: str = None

    def reply(self):
        """The server-to-client direction of the same connection (an echo request is answered by an echo reply)."""
        icmp_type = {("icmp", 8): 0, ("icmp6", 128): 129}.get((self.proto, self.icmp_type), self.icmp_type)
        return Probe(self.dst, self.src, self.proto, self.dport, self.sport, icmp_type, self.icmp_code,
                     self.dst_zone, self.src_zone)


@dataclass
class Decision:
    outcome: str
    rule_id: str = ""
    original_id: str = ""
    basis: str = ""                         # one sentence a person can read
    uncertain: list = field(default_factory=list)   # why the outcome is indeterminate, or what else could change it
    evidence: list = field(default_factory=list)


def _zone_match(rule_zones, probe_zone):
    if not rule_zones:
        return True
    if probe_zone is None:
        return None
    return probe_zone in rule_zones


def rule_matches(rule, probe, tcp_established=False):
    """True, False or None for one rule and one probe, ignoring enabled/ordering."""
    rule_type = rule.extra.get("rule_type", "universal")
    if rule_type in ("intrazone", "interzone"):
        if probe.src_zone is None or probe.dst_zone is None:
            type_result = None
        else:
            type_result = (probe.src_zone == probe.dst_zone) == (rule_type == "intrazone")
    else:
        type_result = True
    results = [
        type_result,
        _zone_match(rule.src_zones, probe.src_zone),
        _zone_match(rule.dst_zones, probe.dst_zone),
        rule.src.contains(probe.src),
        rule.dst.contains(probe.dst),
        rule.svc.match(probe.proto, probe.sport, probe.dport, probe.icmp_type, probe.icmp_code, tcp_established),
    ]
    if any(r is False for r in results):
        return False
    if any(r is None for r in results):
        return None
    return True


def default_decision(policy, probe):
    """What happens when no rule matches."""
    if policy.default_mode == "security_level" or policy.vendor == "cisco-asa":
        if probe.src_zone is not None and policy.interfaces.get(probe.src_zone, {}).get("acl_in"):
            return Decision(DENY, basis="no entry of the inbound ACL matched; an ACL ends in an implicit deny")
        a, b = policy.zone_levels.get(probe.src_zone), policy.zone_levels.get(probe.dst_zone)
        if probe.src_zone is None or probe.dst_zone is None or a is None or b is None:
            return Decision(INDETERMINATE, basis="no rule matched and the interfaces (security levels) are unknown",
                            uncertain=["ingress and egress interface are needed to apply security levels"])
        if a > b:
            return Decision(ALLOW, basis=f"no ACL is applied inbound; traffic from security level {a} to the lower "
                                         f"level {b} is allowed by default")
        return Decision(DENY, basis=f"no ACL is applied inbound; traffic from security level {a} to {b} is denied "
                                    "by default")
    if policy.default_mode == "panos":
        if probe.src_zone is None or probe.dst_zone is None:
            return Decision(INDETERMINATE, basis="no rule matched; PAN-OS default rules depend on whether the source and "
                            "destination zones are the same", uncertain=["source and destination zone are needed"])
        if probe.src_zone == probe.dst_zone:
            return Decision(ALLOW, basis="no rule matched; the intrazone-default rule allows traffic within a zone")
        return Decision(DENY, basis="no rule matched; the interzone-default rule denies traffic between zones")
    return Decision(ALLOW if policy.default_action == "allow" else DENY,
                    basis=f"no rule matched; the default action is {policy.default_action} "
                          f"({policy.default_basis or 'implicit'})")


def _first_match(rules, probe, tcp_established):
    """Walk `rules` in order. Returns (Decision or None, uncertain) where uncertain lists earlier maybe-matches."""
    uncertain = []
    for rule in sorted(rules, key=lambda r: r.position):
        if not rule.enabled:
            continue
        result = rule_matches(rule, probe, tcp_established)
        if result is False:
            continue
        unknowns = rule.condition_unknowns()
        if result is None:
            note = f"rule {rule.original_id}: a condition depends on unavailable information (zone, unresolved object)"
            unknowns = [*unknowns, note]
        if unknowns:
            # The rule might match. Remember it and keep looking: an earlier uncertain rule limits what we can claim.
            uncertain.append((rule, unknowns))
            continue
        decision = Decision(rule.action, rule.rule_id, rule.original_id,
                            f"matched {rule.original_action or rule.action} rule {rule.original_id}"
                            f"{' (' + rule.name + ')' if rule.name else ''} at position {rule.position}",
                            evidence=list(rule.evidence))
        if uncertain:
            decision.uncertain = [r for _, rs in uncertain for r in rs]
            if uncertain[0][0].action != rule.action:
                decision.outcome = INDETERMINATE
                decision.basis += (f", but earlier rule {uncertain[0][0].original_id} ({uncertain[0][0].action}) might "
                                   "also match and cannot be ruled out")
        return decision, uncertain
    return None, uncertain


def _fall_through(uncertain, fallback):
    """Combine "no rule matched" with earlier maybe-matching rules."""
    if uncertain and {r.action for r, _ in uncertain} != {fallback.outcome} and fallback.outcome != INDETERMINATE:
        fallback.uncertain = [r for _, rs in uncertain for r in rs]
        fallback.basis += "; but a rule with an undecidable condition might have matched first"
        fallback.outcome = INDETERMINATE
    return fallback


def _acl_stage(policy, probe, tcp_established, stage):
    """One ACL stage (inbound on the ingress interface, or outbound on the egress interface).

    Returns None when no ACL is applied at this stage, otherwise a Decision.
    """
    zone = probe.src_zone if stage == "in" else probe.dst_zone
    key = f"acl_{stage}" + ("6" if ":" in probe.src and policy.vendor == "cisco-ios" else "")
    if zone is None:
        bound = [n for n, i in policy.interfaces.items() if i.get(key)]
        if not bound:
            return None
        names = ", ".join(sorted(bound))
        return Decision(INDETERMINATE, basis=f"the {stage}bound interface is unknown and ACLs are applied {stage}bound "
                        f"on {names}", uncertain=[f"say which interface this traffic uses ({stage}bound)"])
    if not policy.interfaces.get(zone, {}).get(key):
        return None
    acl_name = policy.interfaces[zone][key]
    rules = [r for r in policy.rules if r.extra.get("stage") == stage and r.extra.get("bind") == zone
             and r.extra.get("acl") == acl_name]
    decision, uncertain = _first_match(rules, probe, tcp_established)
    if decision is None and stage == "in" and policy.vendor == "cisco-asa":
        decision, uncertain2 = _first_match([r for r in policy.rules if r.extra.get("stage") == "global"],
                                            probe, tcp_established)
        uncertain = uncertain + uncertain2
    if decision is None:
        decision = _fall_through(uncertain, Decision(
            DENY, basis=f"no entry of the {stage}bound ACL on {zone} matched; an ACL ends in an implicit deny"))
    return decision


def _evaluate_acl_binding(policy, probe, tcp_established):
    stage_in = _acl_stage(policy, probe, tcp_established, "in")
    stage_out = _acl_stage(policy, probe, tcp_established, "out")
    results = [d for d in (stage_in, stage_out) if d is not None]
    for decision in results:
        if decision.outcome == DENY:
            return decision
    if stage_in is None and policy.vendor == "cisco-asa":
        globals_ = [r for r in policy.rules if r.extra.get("stage") == "global"]
        if globals_:
            decision, uncertain = _first_match(globals_, probe, tcp_established)
            stage_in = decision or _fall_through(uncertain, Decision(
                DENY, basis="no entry of the global ACL matched; an ACL ends in an implicit deny"))
            results = [d for d in (stage_in, stage_out) if d is not None]
            if stage_in.outcome == DENY:
                return stage_in
        else:
            stage_in = default_decision(policy, probe)
            results = [d for d in (stage_in, stage_out) if d is not None]
            if stage_in.outcome == DENY:
                return stage_in
    for decision in results:
        if decision.outcome == INDETERMINATE:
            return decision
    if results:
        return results[0]
    return Decision(ALLOW, basis="no ACL is applied to this traffic, so the router does not filter it here")


def evaluate(policy, probe, tcp_established=False):
    """Evaluate `probe` against the policy and return a Decision."""
    if policy.default_mode == "acl_binding":
        return _evaluate_acl_binding(policy, probe, tcp_established)
    decision, uncertain = _first_match(policy.rules, probe, tcp_established)
    if decision is not None:
        return decision
    return _fall_through(uncertain, default_decision(policy, probe))


def evaluate_connection(policy, probe):
    """Decide a whole connection: the initiating direction, and what the policy does about the replies.

    Stateful policies allow replies to a permitted connection automatically. Stateless ACLs do not: the reply
    direction is evaluated as TCP-established (or UDP/ICMP reply) traffic and reported separately.
    """
    forward = evaluate(policy, probe)
    reply = None
    if forward.outcome != DENY and not policy.stateful:
        reply = evaluate(policy, probe.reply(), tcp_established=(probe.proto == "tcp"))
    return forward, reply
