"""Translate rules to another firewall through explicit destination adapters.

Rules of the translation:
  * Order is preserved within each destination ACL or rulebase.
  * A source rule that uses something the destination cannot express (applications, users, schedules, unresolved names,
    negation, a zone the destination has no concept of ...) is BLOCKED: it is listed with the reason and emitted only as a
    comment. It is never replaced by "any".
  * Stateful source to stateless destination adds explicit return rules, each marked as broader than the original.
  * Differences in address context (as-received versus real internal address) with NAT in play block the rule.
  * Interface names of the destination are never guessed: unmapped zones become visible placeholders that make the output
    invalid until replaced.
Destinations implemented: Cisco ASA, Cisco IOS / IOS-XE (extended ACLs), Fortinet FortiOS.
"""
import ipaddress
import re
from dataclasses import dataclass, field

from .. import limits, netutil
from ..model import AddrSet, Issue, ServiceSet, SvcEntry
from .directional import _is_reply_rule

MAX_EXPANSION_LINES = 2_000

TARGETS = {
    "cisco-asa": {"label": "Cisco ASA (ACLs with access-group)", "stateful": True, "negate": False, "dst_zone": False,
                  "global_acl": True, "address_context": "internal-real"},
    "cisco-ios": {"label": "Cisco IOS / IOS-XE (extended ACLs, stateless)", "stateful": False, "negate": False, "dst_zone": False,
                  "global_acl": False, "address_context": "original-packet"},
    "fortios": {"label": "Fortinet FortiOS (firewall policy)", "stateful": True, "negate": True, "dst_zone": True,
                "global_acl": False, "address_context": "original-packet"},
}


@dataclass
class OutRule:
    name: str
    action: str
    src: AddrSet
    dst: AddrSet
    svc: ServiceSet
    src_zone: str = None
    dst_zone: str = None
    log: bool = False
    comment: str = ""
    kind: str = "translated"            # translated, return-path, observed
    source_rule_ids: list = field(default_factory=list)
    source_ids_text: str = ""
    evidence: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    broader: bool = False               # known to permit more than the source rule did


@dataclass
class Translation:
    target: str
    workflow: str
    rules: list = field(default_factory=list)
    report: list = field(default_factory=list)       # one entry per source rule or observed item
    issues: list = field(default_factory=list)
    text: str = ""
    placeholders: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    zone_map: dict = field(default_factory=dict)


def _issue(sev, code, msg, ev=None):
    return Issue(sev, code, msg, list(ev or [])[:2])


def safe_id(text):
    return re.sub(r"[^A-Za-z0-9._:-]", "_", str(text))[:60]


def _zone_name(zone, zone_map, translation, identity):
    if zone is None:
        return None
    if zone in zone_map:
        return zone_map[zone]
    if identity:
        return zone
    placeholder = f"<TARGET-IF:{safe_id(zone)}>"
    if placeholder not in translation.placeholders:
        translation.placeholders.append(placeholder)
    return placeholder


# ------------------------------------------------------------------------------------------------ source rule to OutRule

def _specific_overlap(side, addr):
    """True when a specific (not 0.0.0.0/0, not 'any') address in `addr` overlaps one in `side`."""
    if side.any or addr.any:
        return False
    for x in side.nets:
        for y in addr.nets:
            nx, ny = ipaddress.ip_network(x, strict=False), ipaddress.ip_network(y, strict=False)
            if nx.prefixlen and ny.prefixlen and nx.version == ny.version and nx.overlaps(ny):
                return True
    return False


def _nat_conflicts(policy, target_ctx, rule):
    """Destination or static NAT statements that name the same specific addresses as this rule, when the address context
    of the source and destination platforms differs (as-received versus real internal address)."""
    if policy.address_context == target_ctx or not policy.nat_rules:
        return []
    out = []
    for nat in policy.nat_rules:
        if nat.kind not in ("destination", "static", "twice-static"):
            continue
        sides = (nat.original_dst, nat.translated_dst, nat.original_src, nat.translated_src)
        if any(_specific_overlap(side, addr) for side in sides for addr in (rule.src, rule.dst)):
            out.append(nat.nat_id)
    return sorted(set(out))


def _infer_zone(addr, policy, ctx=None):
    """The single zone that holds every destination address, or None. Used only to place return ACLs.

    The user's subnet definitions are consulted first, then the networks of the source device's own interfaces.
    """
    if addr.any or addr.negate or addr.unresolved or not addr.nets:
        return None
    found = set()
    for n in addr.nets:
        net = ipaddress.ip_network(n, strict=False)
        if ctx is not None:
            subnet = ctx.subnet_of(net.network_address)
            if subnet is not None and subnet.zone and net.subnet_of(ipaddress.ip_network(subnet.cidr, strict=False)):
                found.add(subnet.zone)
                continue
        hits = {name for name, info in policy.interfaces.items()
                if any(net.version == ipaddress.ip_network(i, strict=False).version and net.subnet_of(ipaddress.ip_network(i, strict=False))
                       for i in info.get("nets", []))}
        if len(hits) != 1:
            return None
        found |= hits
    return next(iter(found)) if len(found) == 1 else None


def _default_behaviour_notes(policy, caps):
    """What the source does with traffic no rule matches, when that differs from the destination's plain default deny."""
    notes = []
    if policy.vendor == "cisco-asa":
        notes.append(_issue("warning", "default-security-level", "The ASA allows traffic from a higher security level to a lower one "
                            "when no ACL is applied inbound on the source interface. That default is not translated: the destination "
                            "denies it unless a rule permits it, so such traffic stops. Add explicit rules where it must continue."))
    if policy.vendor == "panos":
        notes.append(_issue("warning", "default-intrazone", "PAN-OS allows traffic inside one zone by default (intrazone-default) unless "
                            "a rule says otherwise. That default is not translated; the destination denies it unless a rule permits it."))
    if policy.vendor in ("pfsense", "opnsense"):
        notes.append(_issue("info", "default-block", "pfSense/OPNsense block traffic that no rule on the entry interface permits; "
                            "the destination's default deny matches, but automatic rules (anti-lockout, NAT-associated) are not "
                            "in the export's rule list and are not translated."))
    if policy.default_action == "allow" and caps:
        notes.append(_issue("warning", "default-allow", "The source's default action is allow; the destination's is deny."))
    return notes


def translate_policy(policy, target, zone_map=None, identity=False, ctx=None):
    """Preserve workflow: source PolicySet to destination rules."""
    caps = TARGETS[target]
    zone_map = dict(zone_map or {})
    t = Translation(target=target, workflow="preserve", zone_map=zone_map)
    allow_all = [r for r in policy.rules if r.enabled and r.action == "allow"]
    t.issues.append(_issue("info", "order", "Rule order is preserved within each destination ACL or rulebase."))
    if policy.stateful and not caps["stateful"]:
        t.issues.append(_issue("warning", "stateful-to-stateless", "The source is stateful and the destination ACLs are stateless. "
                               "Each permitted rule gets explicit return rules (marked broader than the source) because replies "
                               "are not tracked."))
    if not policy.stateful and caps["stateful"]:
        t.issues.append(_issue("info", "stateless-to-stateful", "The source is stateless and the destination is stateful: "
                               "TCP 'established' and mirrored reply entries are not translated because replies are tracked."))
    if policy.address_context != caps["address_context"] and policy.nat_rules:
        t.issues.append(_issue("warning", "address-context", f"The source writes rule addresses as '{policy.address_context}' and "
                               f"the destination as '{caps['address_context']}'. Rules whose addresses are touched by destination "
                               "or static NAT are blocked; check the others against your NAT design."))
    n_rules = 0
    # ASA evaluates the interface ACL first and the global ACL after it, so global rules come last.
    ordered = sorted(policy.rules, key=lambda r: (r.extra.get("stage") == "global", str(r.extra.get("stage")), str(r.extra.get("bind")),
                                                  r.position))
    for note in _default_behaviour_notes(policy, caps):
        t.issues.append(note)
    for rule in ordered:
        ev = rule.evidence[:1]
        entry = {"source_rule": rule.original_id, "rule_id": rule.rule_id, "evidence": rule.evidence[:2], "warnings": []}
        t.report.append(entry)
        if not rule.enabled:
            entry.update(status="skipped", reason="rule is disabled")
            continue
        if rule.extra.get("stage") == "unbound":
            entry.update(status="skipped", reason="the ACL is not applied to any interface in the source export")
            continue
        if caps["stateful"] and rule.action == "allow" and _is_reply_rule(rule, allow_all):
            entry.update(status="skipped", reason="permits reply traffic only; the destination tracks state so it is not needed")
            continue
        problems = list(rule.unsupported)
        if rule.applications and rule.applications != ["any"]:
            problems.append(f"application condition ({', '.join(rule.applications[:3])})")
        if rule.users:
            problems.append(f"identity condition ({', '.join(rule.users[:3])})")
        if rule.schedule:
            problems.append(f"schedule {rule.schedule}")
        for label, addr in (("source", rule.src), ("destination", rule.dst)):
            if addr.unresolved:
                problems.append(f"{label} has members that are not IP addresses ({', '.join(addr.unresolved[:2])})")
            if addr.negate and not caps["negate"]:
                problems.append(f"{label} is negated, which the destination cannot express")
        if rule.svc.unresolved:
            problems.append(f"service not resolvable ({', '.join(rule.svc.unresolved[:2])})")
        if rule.extra.get("rule_type", "universal") != "universal":
            problems.append(f"rule type {rule.extra['rule_type']} (depends on zone equality)")
        nat = _nat_conflicts(policy, caps["address_context"], rule)
        if nat:
            problems.append(f"NAT ({', '.join(nat[:3])}) changes which address this rule should name in the destination")
        src_zone = rule.src_zones[0] if len(rule.src_zones) == 1 else None
        if len(rule.src_zones) > 1:
            problems.append("more than one source zone in one rule (split the rule per zone first)")
        if not rule.src_zones and target == "cisco-ios":
            problems.append("no source interface: IOS ACLs apply per interface and have no global form, so choose an interface")
        if rule.dst_zones and len(rule.dst_zones) > 1:
            problems.append("more than one destination zone in one rule")
        if problems:
            sev = "blocker"
            entry.update(status="blocked", reason="; ".join(problems))
            consequence = ("Because it is a deny rule, leaving it out BROADENS access." if rule.action == "deny"
                           else "Traffic this rule allowed will be dropped by the destination's default deny.")
            t.issues.append(_issue(sev, "rule-blocked", f"Rule {rule.original_id} was not translated: {'; '.join(problems)}. "
                                   + consequence, ev))
            t.rules.append(OutRule(name=safe_id(rule.original_id), action=rule.action, src=rule.src, dst=rule.dst, svc=rule.svc,
                                   src_zone=src_zone, comment="NOT TRANSLATED: " + "; ".join(problems), kind="blocked",
                                   source_rule_ids=[rule.rule_id], source_ids_text=safe_id(rule.original_id), evidence=rule.evidence[:1]))
            continue
        dst_zone = rule.dst_zones[0] if rule.dst_zones else None
        out = OutRule(name=safe_id(rule.original_id), action=rule.action, src=rule.src, dst=rule.dst, svc=rule.svc,
                      src_zone=src_zone, dst_zone=dst_zone, log=rule.log, comment=limits.clip(rule.comment, 80),
                      source_rule_ids=[rule.rule_id], source_ids_text=safe_id(rule.original_id), evidence=rule.evidence[:2])
        if dst_zone and not caps["dst_zone"]:
            out.broader = True
            out.warnings.append(_issue("warning", "dst-zone-dropped", f"Rule {rule.original_id} was limited to destination zone "
                                       f"{dst_zone}; the destination cannot express that, so the rule matches those addresses on "
                                       "any interface.", ev))
        entry.update(status="translated", reason="", warnings=out.warnings)
        t.rules.append(out)
        n_rules += 1
        if not caps["stateful"] and rule.action == "allow" and policy.stateful:
            return_zone = dst_zone or _infer_zone(rule.dst, policy, ctx)
            if return_zone and not dst_zone:
                out.warnings.append(_issue("info", "return-zone-inferred", f"The return ACL for rule {rule.original_id} is placed on "
                                           f"{return_zone}, the zone whose network holds the destination addresses.", ev))
            for ret in _return_rules(rule, out, return_zone):
                t.rules.append(ret)
                if ret.kind == "blocked":
                    entry["warnings"].append(ret.warnings[0])
    _finish(t, policy, zone_map, identity)
    return t


def _blocked_return(out, rule, why):
    r = OutRule(name=out.name + "-return", action="allow", src=rule.dst, dst=rule.src, svc=ServiceSet(any=True), src_zone=None,
                comment="NOT TRANSLATED: " + why, kind="blocked", source_rule_ids=out.source_rule_ids,
                source_ids_text=out.source_ids_text, evidence=out.evidence[:1])
    r.warnings.append(_issue("blocker", "return-not-generated", f"Rule {rule.original_id} needs a return path on a stateless "
                             f"destination and none could be generated safely ({why}). Replies would be dropped; add it by hand."))
    return r


def _return_rules(rule, out, dst_zone):
    """Explicit return-path rules for a stateless destination. Each is broader than a stateful reply."""
    if dst_zone is None:
        return [_blocked_return(out, rule, "the source rule has no destination zone to put the return ACL on")]
    ret = []
    entries = [SvcEntry("ip")] if rule.svc.any else rule.svc.entries
    for entry in entries:
        if entry.proto == "tcp":
            svc = ServiceSet(entries=[SvcEntry("tcp", entry.dports, None, established=True)])
            note = ("TCP return rule using 'established': it matches any segment with ACK or RST set, so the server side can send "
                    "such packets to the client side at will. This is not a stateful check.")
        elif entry.proto == "udp":
            svc = ServiceSet(entries=[SvcEntry("udp", entry.dports, None)])
            note = ("UDP return rule: it permits ANY datagram from the server port to the client side, including unsolicited ones, "
                    "because ACLs keep no state.")
        elif entry.proto in ("icmp", "icmp6") and entry.icmp_type in (8, 128):
            svc = ServiceSet(entries=[SvcEntry(entry.proto, icmp_type=0 if entry.proto == "icmp" else 129)])
            note = "ICMP echo-reply return rule."
        elif entry.proto == "ip":
            svc = ServiceSet(any=True)
            note = "The source allowed any protocol, so the return rule allows any protocol back."
        else:
            ret.append(_blocked_return(out, rule, f"no return rule is defined for {entry.proto}"))
            continue
        r = OutRule(name=out.name + "-return", action="allow", src=rule.dst, dst=rule.src, svc=svc, src_zone=dst_zone,
                    comment="return path for " + out.source_ids_text, kind="return-path", broader=True,
                    source_rule_ids=out.source_rule_ids, source_ids_text=out.source_ids_text, evidence=out.evidence[:1])
        r.warnings.append(_issue("warning", "return-rule-broader", note, out.evidence[:1]))
        ret.append(r)
    return ret


def _finish(t, policy, zone_map, identity):
    for rule in t.rules:
        if rule.kind != "blocked":
            for z in (rule.src_zone, rule.dst_zone):
                if z is not None:
                    _zone_name(z, zone_map, t, identity)
    for rule in t.rules:
        t.issues.extend(rule.warnings)
    translated = [r for r in t.rules if r.kind in ("translated", "observed")]
    blocked = [e for e in t.report if e.get("status") == "blocked"]
    t.summary = {
        "source_rules": len(policy.rules) if policy is not None else 0, "translated": len(translated),
        "blocked": len(blocked), "blocked_returns": sum(1 for r in t.rules if r.kind == "blocked" and r.name.endswith("-return")),
        "skipped": sum(1 for e in t.report if e.get("status") == "skipped"),
        "return_rules_added": sum(1 for r in t.rules if r.kind == "return-path"),
        "rules_known_broader": sum(1 for r in t.rules if r.broader and r.kind != "blocked"),
        "blocked_deny_rules": sum(1 for r in t.rules if r.kind == "blocked" and r.action == "deny"),
        "placeholders": len(t.placeholders),
    }
    t.summary["verdict"] = _verdict(t.summary)


def _verdict(s):
    bits = []
    if s["blocked_deny_rules"]:
        bits.append(f"{s['blocked_deny_rules']} deny rule(s) could not be translated, which BROADENS access")
    if s["blocked"]:
        bits.append(f"{s['blocked']} rule(s) were not translated and traffic they allowed will be dropped or must be re-created")
    if s["blocked_returns"]:
        bits.append(f"{s['blocked_returns']} return path(s) could not be generated, so replies to permitted traffic would be dropped")
    if s["rules_known_broader"]:
        bits.append(f"{s['rules_known_broader']} rule(s) are known to permit more than the source did")
    if s["placeholders"]:
        bits.append("interface placeholders must be replaced before the output is usable")
    return ("; ".join(bits) + "." if bits else
            "No translation gap was detected by this tool's checks. That is not proof of equivalence: see the validation limits.")


# ------------------------------------------------------------------------------------------------ narrow workflow

def rules_from_observation(comms, ctx, policy_zone_lookup, include_low_confidence=False):
    """Observed communications to allow rules (exact host addresses). Low-confidence direction is held back for review."""
    t = Translation(target="", workflow="narrow")
    t.issues.append(_issue("warning", "observation-limits",
                           "These rules come only from what the supplied capture(s) show. Dependencies that did not occur in the "
                           "capture window (scheduled jobs, failover, maintenance, vendor access, start-up traffic) are not covered "
                           "and would be blocked. Observed traffic is not proof of business need."))
    seen = {}
    for c in comms:
        entry = {"source_rule": c.comm_id, "rule_id": c.comm_id, "evidence": c.evidence[:2], "warnings": []}
        t.report.append(entry)
        if c.direction_confidence in ("low", "unknown") and not include_low_confidence:
            entry.update(status="skipped", reason=f"direction is {c.direction_confidence} confidence; decide it before allowing")
            continue
        if c.proto in ("icmp", "icmp6"):
            svc = ServiceSet(entries=[SvcEntry(c.proto, icmp_type=c.icmp_type)])
        elif c.proto in ("tcp", "udp", "sctp") and c.responder_port is not None:
            svc = ServiceSet(entries=[SvcEntry(c.proto, None, [(c.responder_port, c.responder_port)])])
        else:
            entry.update(status="skipped", reason="no port or ICMP type to build a rule from")
            continue
        key = (c.initiator, c.responder, c.proto, c.responder_port, c.icmp_type)
        if key in seen:
            continue
        seen[key] = True
        app = next((a for a in c.apps if a.confidence == "confirmed"), None)
        r = OutRule(name=f"obs-{len(t.rules) + 1}", action="allow", src=AddrSet(nets=[str(netutil.parse_ip_or_net(c.initiator))]),
                    dst=AddrSet(nets=[str(netutil.parse_ip_or_net(c.responder))]), svc=svc,
                    src_zone=policy_zone_lookup(c.initiator), dst_zone=policy_zone_lookup(c.responder),
                    comment=("observed " + (app.name if app else c.proto))[:60], kind="observed", source_rule_ids=[c.comm_id],
                    source_ids_text=c.comm_id, evidence=c.evidence[:2])
        if c.direction_confidence == "medium":
            r.warnings.append(_issue("info", "direction-medium", f"Direction of {c.initiator} to {c.responder} was inferred "
                                     f"with medium confidence: {'; '.join(c.direction_basis[:1])}.", c.evidence[:1]))
        t.rules.append(r)
        entry.update(status="translated", reason="", warnings=r.warnings)
    return t


# ------------------------------------------------------------------------------------------------ rendering

def _cisco_addr(net, flavour):
    """One address specification, or 'any' when net is None."""
    if net is None:
        return "any"
    if net.prefixlen == 0:
        return ("any6" if net.version == 6 else "any4") if flavour == "asa" else "any"
    if net.version == 6:
        return f"host {net.network_address}" if net.prefixlen == 128 else str(net)
    if net.prefixlen == 32:
        return f"host {net.network_address}"
    return f"{net.network_address} {net.netmask if flavour == 'asa' else net.hostmask}"


def _port_words(ranges):
    if ranges is None:
        return [""]
    return [f"eq {lo}" if lo == hi else f"range {lo} {hi}" for lo, hi in ranges]


def _proto_word(proto):
    return "icmp" if proto in ("icmp", "icmp6") else proto.split(":", 1)[1] if proto.startswith("proto:") else proto


def _cisco_lines(rule, flavour):
    """(text, is_ipv6) lines for one OutRule. Address lists and port ranges are expanded, bounded by MAX_EXPANSION_LINES."""
    verb = "permit" if rule.action == "allow" else "deny"
    srcs = [None] if rule.src.any else [ipaddress.ip_network(n, strict=False) for n in rule.src.nets]
    dsts = [None] if rule.dst.any else [ipaddress.ip_network(n, strict=False) for n in rule.dst.nets]
    entries = [SvcEntry("ip")] if rule.svc.any else rule.svc.entries
    out = []
    for s in srcs:
        for d in dsts:
            if s is not None and d is not None and s.version != d.version:
                continue
            version_net = s if s is not None else d
            v6 = version_net is not None and version_net.version == 6
            for entry in entries:
                icmp = ""
                if entry.icmp_type is not None:
                    icmp = f" {entry.icmp_type}" + (f" {entry.icmp_code}" if entry.icmp_code is not None else "")
                for sp in _port_words(entry.sports):
                    for dp in _port_words(entry.dports):
                        if len(out) >= MAX_EXPANSION_LINES:
                            out.append(("! TRUNCATED: this rule expands to too many lines", False))
                            return out
                        parts = [verb, _proto_word(entry.proto), _cisco_addr(s, flavour), sp, _cisco_addr(d, flavour), dp]
                        text = " ".join(x for x in parts if x) + icmp
                        if entry.established and flavour == "ios":
                            text += " established"
                        if rule.log:
                            text += " log"
                        out.append((text, v6))
    return out


def render_cisco(t, flavour, identity=False):
    """Text for a Cisco ASA ('asa') or IOS ('ios') destination."""
    label = TARGETS["cisco-" + flavour]["label"]
    lines = [f"! Generated by Policy Bridge ({t.workflow} workflow) for {label}.",
             "! REVIEW BEFORE USE. This is a proposal, not a verified equivalent of the source.",
             "! Rules marked NOT TRANSLATED were left out on purpose; see the translation report."]
    acls = {}
    for rule in t.rules:
        key = rule.src_zone if rule.src_zone is not None else "global"
        acls.setdefault(key, []).append(rule)
    bindings, v6_present = [], set()
    for key, rules in acls.items():
        name = "PB-GLOBAL" if key == "global" else f"PB-{safe_id(key)}-IN"
        if key == "global" and flavour == "ios":
            for rule in rules:
                why = rule.comment[16:200] if rule.kind == "blocked" else "IOS ACLs need an interface; choose one for this rule"
                lines.append(f"! NOT PLACED {rule.source_ids_text}: {why}")
            continue
        v4_lines, v6_lines = [], []
        for rule in rules:
            if rule.kind == "blocked":
                v4_lines.append(("!", f"NOT TRANSLATED {rule.source_ids_text}: {rule.comment[16:200]}"))
                continue
            remark = f"source rule {rule.source_ids_text} ({rule.kind}){': ' + rule.comment if rule.comment else ''}"[:100]
            produced = _cisco_lines(rule, flavour)
            for lst, wanted in ((v4_lines, False), (v6_lines, True)):
                chosen = [text for text, v6 in produced if (v6 and flavour == "ios") == wanted]
                if chosen:
                    lst.append(("remark", remark))
                    lst.extend(("ace", text) for text in chosen)
        if flavour == "asa":
            for kind, text in v4_lines:
                if kind == "!":
                    lines.append(f"! {text}")
                elif kind == "remark":
                    lines.append(f"access-list {name} remark {text}")
                else:
                    lines.append(f"access-list {name} extended {text}")
        else:
            lines.append(f"ip access-list extended {name}")
            for kind, text in v4_lines:
                lines.append(f" ! {text}" if kind == "!" else f" remark {text}" if kind == "remark" else f" {text}")
            if v6_lines:
                v6_present.add(name)
                lines.append(f"ipv6 access-list {name}-V6")
                lines.extend(f" remark {text}" if kind == "remark" else f" {text}" for kind, text in v6_lines)
        if key != "global":
            bindings.append((name, _zone_name(key, t.zone_map, t, identity)))
    for name, iface in bindings:
        if flavour == "asa":
            lines.append(f"access-group {name} in interface {iface}")
        else:
            lines.extend([f"interface {iface}", f" ip access-group {name} in"])
            if name in v6_present:
                lines.append(f" ipv6 traffic-filter {name}-V6 in")
    if flavour == "asa" and any(r.kind != "blocked" for r in acls.get("global", [])):
        lines.append("access-group PB-GLOBAL global")
    if flavour == "ios" and any(r.src.any and r.dst.any for r in t.rules if r.kind != "blocked"):
        lines.append("! NOTE: rules with 'any' on both sides were written for IPv4 only; IPv6 needs its own ACL")
    return "\n".join(lines) + "\n"


def _forti_addr_name(net):
    return "PB-" + str(net).replace("/", "_").replace(":", "-")


def _forti_service(entry):
    """(name, lines) for a custom service, or ('ALL', None)."""
    if entry.proto == "ip":
        return "ALL", None
    if entry.proto in ("tcp", "udp", "sctp"):
        d = netutil.ranges_text(entry.dports).replace(",", " ") if entry.dports else "1-65535"
        if entry.sports:
            d = " ".join(f"{x}:{netutil.ranges_text(entry.sports).replace(',', ' ')}" for x in d.split())
        name = f"PB-{entry.proto}-{d.replace(' ', '_').replace(':', '-s')}"
        return name, [f"set {entry.proto}-portrange {d}"]
    if entry.proto in ("icmp", "icmp6"):
        name = f"PB-{entry.proto}-{entry.icmp_type if entry.icmp_type is not None else 'all'}"
        body = [f"set protocol {'ICMP' if entry.proto == 'icmp' else 'ICMP6'}"]
        if entry.icmp_type is not None:
            body.append(f"set icmptype {entry.icmp_type}")
        if entry.icmp_code is not None:
            body.append(f"set icmpcode {entry.icmp_code}")
        return name, body
    number = entry.proto.split(":", 1)[1] if entry.proto.startswith("proto:") else {"gre": "47", "esp": "50", "ah": "51"}.get(entry.proto)
    if number:
        return f"PB-proto-{number}", ["set protocol IP", f"set protocol-number {number}"]
    return None, None


def render_fortios(t, identity=False, first_id=1):
    lines = ["# Generated by Policy Bridge (" + t.workflow + " workflow) for Fortinet FortiOS.",
             "# REVIEW BEFORE USE. This is a proposal, not a verified equivalent of the source.",
             "# Rules marked NOT TRANSLATED were left out on purpose; see the translation report."]
    live = [r for r in t.rules if r.kind != "blocked"]
    nets4, nets6, services = {}, {}, {}
    for r in live:
        for addr in (r.src, r.dst):
            for n in addr.nets:
                net = ipaddress.ip_network(n, strict=False)
                if net.prefixlen == 0:
                    continue
                (nets4 if net.version == 4 else nets6)[str(net)] = net
        for entry in ([SvcEntry("ip")] if r.svc.any else r.svc.entries):
            name, body = _forti_service(entry)
            if body is not None:
                services[name] = body
    if nets4:
        lines.append("config firewall address")
        for net in nets4.values():
            lines += [f'    edit "{_forti_addr_name(net)}"', f"        set subnet {net.network_address} {net.netmask}", "    next"]
        lines.append("end")
    if nets6:
        lines.append("config firewall address6")
        for net in nets6.values():
            lines += [f'    edit "{_forti_addr_name(net)}"', f"        set ip6 {net}", "    next"]
        lines.append("end")
    if services:
        lines.append("config firewall service custom")
        for name, body in services.items():
            lines.append(f'    edit "{name}"')
            lines += [f"        {b}" for b in body]
            lines.append("    next")
        lines.append("end")
    policies = {4: [], 6: []}
    counter = first_id
    for r in t.rules:
        if r.kind == "blocked":
            lines.append(f"# NOT TRANSLATED {r.source_ids_text}: {r.comment[16:200]}")
            continue
        families = [4, 6] if (r.src.any and r.dst.any) else sorted({ipaddress.ip_network(n).version for n in r.src.nets + r.dst.nets})
        for fam in families:
            def side(addr, fam=fam):
                if addr.any:
                    return ["all"]
                chosen = [n for n in addr.nets if ipaddress.ip_network(n, strict=False).version == fam]
                return [("all" if ipaddress.ip_network(n).prefixlen == 0 else _forti_addr_name(ipaddress.ip_network(n, strict=False)))
                        for n in chosen]
            src_names, dst_names = side(r.src), side(r.dst)
            if not src_names or not dst_names:
                continue
            svc_names = []
            for entry in ([SvcEntry("ip")] if r.svc.any else r.svc.entries):
                name, _ = _forti_service(entry)
                if name and name not in svc_names:
                    svc_names.append(name)
            body = [f"    edit {counter}", f'        set name "PB-{counter}"',
                    f'        set srcintf "{_zone_name(r.src_zone, t.zone_map, t, identity) or "any"}"',
                    f'        set dstintf "{_zone_name(r.dst_zone, t.zone_map, t, identity) or "any"}"',
                    f"        set action {'accept' if r.action == 'allow' else 'deny'}"]
            suffix = "" if fam == 4 else "6"
            body.append(f"        set srcaddr{suffix} " + " ".join(f'"{x}"' for x in src_names))
            body.append(f"        set dstaddr{suffix} " + " ".join(f'"{x}"' for x in dst_names))
            if r.src.negate:
                body.append("        set srcaddr-negate enable")
            if r.dst.negate:
                body.append("        set dstaddr-negate enable")
            body += ['        set schedule "always"', "        set service " + " ".join(f'"{x}"' for x in svc_names),
                     f"        set logtraffic {'all' if r.log else 'disable'}",
                     f'        set comments "{safe_id(r.source_ids_text)} {r.kind}"', "    next"]
            policies[fam].append(body)
            counter += 1
    for fam, key in ((4, "firewall policy"), (6, "firewall policy6")):
        if policies[fam]:
            lines.append(f"config {key}")
            for body in policies[fam]:
                lines.extend(body)
            lines.append("end")
    return "\n".join(lines) + "\n"


def render(t, target, identity=False):
    """Render Translation `t` for `target` and store the text on it."""
    t.target = target
    if target == "cisco-asa":
        t.text = render_cisco(t, "asa", identity)
    elif target == "cisco-ios":
        t.text = render_cisco(t, "ios", identity)
    elif target == "fortios":
        t.text = render_fortios(t, identity)
    else:
        raise ValueError(f"unknown destination {target!r}")
    return t.text
