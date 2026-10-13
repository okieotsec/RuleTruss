"""Reviewable exports: CSV tables, Markdown worksheets and JSON. Everything is labelled with what it is.

Any text that came from an uploaded file or capture is treated as untrusted: CSV cells that a spreadsheet would run as a
formula are neutralised, and Markdown control characters are escaped.
"""
import csv
import io
import json
import re
import time

from .model import to_plain

FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def csv_safe(value):
    """A CSV cell that cannot run as a spreadsheet formula."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, float)):
        return value
    text = CONTROL.sub("", str(value))
    if text.startswith(FORMULA_START):
        text = "'" + text
    return text


def to_csv(headers, rows):
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow([csv_safe(h) for h in headers])
    for row in rows:
        writer.writerow([csv_safe(c) for c in row])
    return out.getvalue()


def md(text):
    """Escape untrusted text for use inside a Markdown table cell or paragraph."""
    text = CONTROL.sub("", str(text if text is not None else ""))
    text = text.replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("[", "\\[").replace("]", "\\]").replace("\r", " ").replace("\n", " ")
    return text


def _evidence(evidence):
    return "; ".join(f"{e.kind} {e.ref}" for e in evidence[:4]) if evidence else ""


def _warnings(warnings):
    return " | ".join(f"[{w.severity}] {w.message}" for w in warnings)


# ---------------------------------------------------------------------------------------------------- directional plan

def plan_tables(plan):
    groups = (["Group", "Members", "Isolated behind a gateway", "Note"],
              [[g.name, " ".join(g.members), g.gateway_isolated, g.note] for g in plan.groups])
    policies = (["Policy", "Status", "Origin", "From groups", "To groups", "Direction", "Services (information only)", "Source rules",
                 "Broadens access", "Loses restrictions", "Granted address pairs", "Observed pairs", "Basis", "Warnings", "Evidence"],
                [[p.name, p.status, p.origin, ", ".join(p.from_groups), ", ".join(p.to_groups),
                  "From may initiate to To; To may not initiate to From" if p.status != "blocked" else "not generated",
                  "; ".join(p.services_informational), ", ".join(p.source_rules), p.broadens, p.loses_restrictions, p.granted_pairs,
                  p.observed_pairs, p.basis, _warnings(p.warnings), _evidence(p.evidence)] for p in plan.policies])
    egress = (["Egress policy", "Status", "Enabled", "Endpoint groups", "Allowed prefixes", "Allowed DNS names", "Recursive DNS",
               "Allow all DNS queries", "Services (information only)", "Basis", "Warnings", "Evidence"],
              [[e.name, e.status, e.enabled, ", ".join(e.endpoint_groups), " ".join(e.allowed_prefixes), " ".join(e.allowed_dns_names),
                e.recursive_dns, e.allow_all_dns, "; ".join(e.services), e.basis, _warnings(e.warnings), _evidence(e.evidence)]
               for e in plan.egress_policies])
    gaps = (["Severity", "Code", "Message", "Evidence"], [[g.severity, g.code, g.message, _evidence(g.evidence)] for g in plan.gaps])
    review = (["Severity", "Code", "Message", "Evidence"],
              [[g.severity, g.code, g.message, _evidence(g.evidence)] for g in plan.review_items])
    return {"groups": groups, "group-policies": policies, "egress-policies": egress, "gaps": gaps, "review": review}


def plan_markdown(plan, project_name=""):
    title = {"preserve": "Preserved configured permissions", "narrow": "Proposed narrower permissions from observation"}[plan.workflow]
    lines = [f"# {md(title)}", "",
             "> **PROPOSED. This is an implementation worksheet, not a configuration file and not an import file.** It was produced "
             "by Policy Bridge from the inputs named below. It has not been applied to any system and its equivalence to the "
             "source has not been proven.", ""]
    if project_name:
        lines += [f"Project: {md(project_name)}", ""]
    lines += [f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}", "",
              "## Result", "", md(plan.summary.get("verdict", "")), ""]
    lines += ["| Measure | Value |", "| --- | --- |"] + [f"| {md(k.replace('_', ' '))} | {md(v)} |" for k, v in plan.summary.items()
                                                       if k != "verdict"] + [""]
    if plan.workflow == "narrow":
        o = plan.observation
        lines += ["## Observation period (read before using any proposal)", ""]
        if o.get("first_ts"):
            lines.append(f"- From {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(o['first_ts']))} to "
                         f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(o['last_ts']))} "
                         f"({o.get('duration_seconds', 0) / 3600:.2f} hours).")
        for c in o.get("captures", []):
            lines.append(f"- {md(c['filename'])} ({md(c['format'])}), observation point: {md(c['observation_point'])}")
        lines += [f"- {md(x)}" for x in o.get("caveats", [])] + [""]
    lines += ["## The directional model", ""]
    lines += [f"- {md(x)}" for x in plan.facts["defined"]] + ["", "Not carried by this model:", ""]
    lines += [f"- {md(x)}" for x in plan.facts["not_modelled"]] + ["", md(plan.facts["note"]), ""]
    lines += ["## Groups", "", "| Group | Members | Isolated behind a gateway |", "| --- | --- | --- |"]
    lines += [f"| {md(g.name)} | {md(' '.join(g.members))} | {'yes' if g.gateway_isolated else 'no'} |" for g in plan.groups] + [""]
    blocked = [p for p in plan.policies if p.status == "blocked"]
    lines += ["## Group policies (From may initiate to To; the reverse needs its own policy)", ""]
    for p in [x for x in plan.policies if x.status != "blocked"]:
        lines += [f"### {md(p.name)} ({md(p.status)})", "",
                  f"- From: {md(', '.join(p.from_groups) or '-')}   To: {md(', '.join(p.to_groups) or '-')}",
                  f"- Origin: {md(p.origin)}. {md(p.basis)}",
                  f"- Services (information only, not enforced by the model): {md('; '.join(p.services_informational) or '-')}",
                  f"- Source rules: {md(', '.join(p.source_rules) or '-')}   Evidence: {md(_evidence(p.evidence)) or '-'}"]
        if p.granted_pairs:
            lines.append(f"- Address pairs granted by group membership: {p.granted_pairs:,}; observed or source-permitted: "
                         f"{p.observed_pairs}")
        lines += [f"- **{md(w.severity.upper())}** {md(w.message)}" for w in p.warnings] + [""]
    if blocked:
        lines += ["## Source rules that could not be translated", "", "| Source rule | Why | Evidence |", "| --- | --- | --- |"]
        lines += [f"| {md(', '.join(p.source_rules))} | {md(' '.join(w.message for w in p.warnings))} | {md(_evidence(p.evidence[:1]))} |"
                  for p in blocked] + [""]
    if plan.egress_policies:
        lines += ["## External egress policies", ""]
        for e in plan.egress_policies:
            lines += [f"### {md(e.name)} ({md(e.status)})", "",
                      f"- Endpoint groups: {md(', '.join(e.endpoint_groups))}   Enabled: {'yes' if e.enabled else 'no'}",
                      f"- Allowed prefixes: {md(' '.join(e.allowed_prefixes) or '-')}",
                      f"- Allowed DNS names: {md(' '.join(e.allowed_dns_names) or '-')}   Recursive: {'yes' if e.recursive_dns else 'no'}",
                      f"- Allow all DNS queries: {'yes' if e.allow_all_dns else 'no'}",
                      f"- Services (information only): {md('; '.join(e.services) or '-')}",
                      f"- Evidence: {md(_evidence(e.evidence)) or '-'}"]
            lines += [f"- **{md(w.severity.upper())}** {md(w.message)}" for w in e.warnings] + [""]
    for heading, items in (("Gaps: what did not translate or translated with loss", plan.gaps), ("Review items", plan.review_items)):
        lines += [f"## {heading}", ""]
        lines += [f"- **{md(g.severity.upper())}** {md(g.message)} {md(_evidence(g.evidence))}" for g in items] or ["- none"]
        lines.append("")
    lines += ["## Manual steps", ""] + [f"{i}. {md(s)}" for i, s in enumerate(plan.manual_steps, start=1)] + [""]
    lines += ["## Limits", "", "- Directional rules alone are not a complete zero trust architecture: identity, device posture, "
              "encryption, monitoring and change control are outside this worksheet.",
              "- Observed traffic is not proof of business need, and absence from a capture is not proof of absence.", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------------- firewall translation

def translation_markdown(t, validation=None, project_name=""):
    lines = ["# Firewall translation report", "",
             "> **PROPOSED. The configuration text is for review, not for direct deployment.** It was generated by Policy Bridge and "
             "has not been tested on a device.", ""]
    if project_name:
        lines += [f"Project: {md(project_name)}", ""]
    lines += [f"Destination: {md(t.target)}   Workflow: {md(t.workflow)}", "", "## Result", "", md(t.summary.get("verdict", "")), "",
              "| Measure | Value |", "| --- | --- |"]
    lines += [f"| {md(k.replace('_', ' '))} | {md(v)} |" for k, v in t.summary.items() if k != "verdict"] + [""]
    lines += ["## Per-rule report", "", "| Source rule | Status | Reason | Evidence |", "| --- | --- | --- | --- |"]
    lines += [f"| {md(e['source_rule'])} | {md(e['status'])} | {md(e.get('reason', ''))} | {md(_evidence(e.get('evidence', [])))} |"
              for e in t.report] + [""]
    lines += ["## Issues", ""] + [f"- **{md(i.severity.upper())}** {md(i.message)}" for i in t.issues] + [""]
    if validation:
        s = validation["summary"]
        lines += ["## Validation (sampled connections)", "", f"Result: {md(s.get('result', ''))}", "",
                  "| Measure | Value |", "| --- | --- |"]
        lines += [f"| {md(k.replace('_', ' '))} | {md(v)} |" for k, v in s.items() if k != "result"] + [""]
        lines += ["Limits of this comparison:", ""] + [f"- {md(x)}" for x in validation["limits"]] + [""]
        for m in validation.get("mismatches", [])[:40]:
            why = []
            if m.get("explained_by_known_broader_rule"):
                why.append("a known broader stateless return rule")
            if m.get("explained_by_blocked_rule"):
                why.append(f"source rule {m['explained_by_blocked_rule']} was not translated")
            if m.get("explained_by_source_default"):
                why.append(m["explained_by_source_default"])
            note = f"Explained: {md('; '.join(why))}." if why else "Not explained by a known cause."
            lines.append(f"- {md(m['kind'])}: {md(m['connection'])} ({md(m['case'])}). Source: {md(m['source'])}. "
                         f"Destination: {md(m['destination'])}. {note}")
        lines.append("")
    lines += ["## Generated configuration (review before use)", "", "```text", t.text.replace("```", "'''"), "```", ""]
    return "\n".join(lines)


def communications_markdown(rows, coverage, project_name=""):
    lines = ["# Observed communications", "",
             "> **OBSERVED.** These are statements about what the supplied captures show, with the confidence of each inference. "
             "They are not statements about what is permitted or needed.", ""]
    if project_name:
        lines += [f"Project: {md(project_name)}", ""]
    lines += ["## Coverage and limits", ""] + [f"- {md(n)}" for n in coverage] + ["", "## Communications", ""]
    for r in rows:
        lines += [f"- {md(r['explanation'])} (direction confidence: {md(r['direction_confidence'])}; evidence: {md(r['evidence_text'])})"]
    return "\n".join(lines) + "\n"


def json_bytes(obj):
    return json.dumps(to_plain(obj), indent=2, ensure_ascii=True, sort_keys=False).encode("ascii")
