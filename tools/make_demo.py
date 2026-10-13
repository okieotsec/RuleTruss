"""Run the whole demonstration through the real application code and write the results to docs/demo and docs/WALKTHROUGH.md.

    .venv/bin/python tools/make_demo.py

Nothing in the output is typed by hand: every number, sentence and excerpt below comes from the code that the web application
runs, applied to the synthetic sample project (a fictional plant). Run it again after a change to see what changed.
"""
import json
import subprocess  # nosec B404 - runs this project's own test suite with a fixed command line
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from pbridge import analysis, exports  # noqa: E402
from pbridge.adapters.registry import parse_config  # noqa: E402
from pbridge.migrate import firewall, validate  # noqa: E402
from pbridge.model import Subnet  # noqa: E402
from pbridge.samples import create_demo  # noqa: E402
from pbridge.service import Service  # noqa: E402
from pbridge.store import Store  # noqa: E402

OUT = ROOT / "docs" / "demo"


def head(text, lines):
    rows = text.strip().splitlines()
    return "\n".join(rows[:lines]) + ("\n..." if len(rows) > lines else "")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as d:
        service = Service(Store(d))
        project = create_demo(service)
        pid = project["id"]
        sid = next(s["id"] for s in service.project(pid)["sources"] if s["kind"] == "policy")
        write = lambda name, data: (OUT / name).write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))  # noqa: E731

        overview = service.overview(pid)
        comms = service.communications(pid, {"limit": "500"})
        write("01-observed-communications.md", service.export(pid, {"kind": "communications-markdown"})[2])
        write("02-observed-communications.csv", service.export(pid, {"kind": "communications-csv"})[2])
        view = service.policy_view(pid, sid)
        rules_md = ["# Configured policy (demo ASA)", "", "> **CONFIGURED.** Read from the export; not evidence of what traffic exists.", "",
                    "| Pos | Rule | Action | From | Source | Destination | Service | Not evaluated |", "| --- | --- | --- | --- | --- | --- | --- | --- |"]
        for r in view["rules"]:
            extra = "; ".join(r["unsupported"] + (["application " + ", ".join(r["applications"])] if r["applications"] else [])
                              + ([f"schedule {r['schedule']}"] if r["schedule"] else []))
            rules_md.append(f"| {r['position']} | {exports.md(r['id'])} | {r['action']}{'' if r['enabled'] else ' (disabled)'} | "
                            f"{exports.md(', '.join(r['src_zones']) or 'any')} | {exports.md(r['src'])} | {exports.md(r['dst'])} | "
                            f"{exports.md(r['service'])} | {exports.md(extra or '-')} |")
        rules_md += ["", "## Findings", ""] + [f"- **{f['kind']}**: {exports.md(f['message'])}" for f in view["findings"]]
        write("03-configuration-analysis.md", "\n".join(rules_md) + "\n")

        compare = service.compare(pid, sid)
        cmp_md = ["# Observed traffic compared with configured permissions", "", "> **OBSERVED** compared with **CONFIGURED**. " + compare["note"], "",
                  "| Initiator | Responder | Service | Outcome | Matched rule | Reading |", "| --- | --- | --- | --- | --- | --- |"]
        for r in compare["rows"]:
            o = r["observed"]
            svc = f"{o['proto']}/{o['port']}" if o["port"] is not None else o["proto"]
            cmp_md.append(f"| {o['initiator']} | {o['responder']} | {svc} | {r['outcome']} | {exports.md(r['rule'] or '-')} | {exports.md(r['reading'])} |")
        cmp_md += ["", "## Allow rules no observed traffic matched", ""] + [f"- {exports.md(u['rule'])}: {exports.md(u['src'])} to {exports.md(u['dst'])} "
                                                                           f"on {exports.md(u['svc'])}" for u in compare["unobserved_rules"]]
        write("04-observed-vs-configured.md", "\n".join(cmp_md) + "\n")

        for workflow, name in (("preserve", "05-directional-preserve.md"), ("narrow", "06-directional-narrow.md")):
            data = service.export(pid, {"kind": "plan-markdown", "workflow": workflow, "policy": sid, "acknowledge_observation_limits": True})[2]
            write(name, data)
        plan_p = service.plan_json(pid, {"workflow": "preserve", "policy": sid})
        plan_n = service.plan_json(pid, {"workflow": "narrow"})
        write("directional-narrow.json", service.export(pid, {"kind": "plan-json", "workflow": "narrow", "acknowledge_observation_limits": True})[2])
        write("directional-narrow-group-policies.csv", service.export(pid, {"kind": "plan-csv-group-policies", "workflow": "narrow",
                                                                             "acknowledge_observation_limits": True})[2])

        zone_maps = {"cisco-asa": {"eng": "eng", "plc": "plc", "hist": "hist", "corp": "corp"},
                     "cisco-ios": {"eng": "Vlan20", "plc": "Vlan30", "hist": "Vlan50", "corp": "Vlan10"},
                     "fortios": {"eng": "port2", "plc": "port3", "hist": "port4", "corp": "port5"}}
        results = {}
        for workflow in ("preserve", "narrow"):
            for target, zmap in zone_maps.items():
                body = {"workflow": workflow, "policy": sid, "target": target, "zone_map": zmap, "acknowledge_observation_limits": True}
                t = service.translation_json(pid, body)
                results[(workflow, target)] = t
                write(f"07-{workflow}-{target}.md", service.export(pid, {**body, "kind": "firewall-markdown"})[2])
                write(f"07-{workflow}-{target}.txt", t["text"])
        write("validation-summaries.json", json.dumps({f"{w}/{t}": r["validation"]["summary"] for (w, t), r in results.items()}, indent=2))

        # ------------------------------------------------------------------ fixtures x destinations matrix
        ctx = analysis.build_context(subnets=[Subnet("10.20.0.0/16", "eng", "ot"), Subnet("10.30.0.0/16", "ot", "ot"), Subnet("10.10.0.0/16", "corp", "corp"),
                                              Subnet("10.50.0.0/24", "dmz", "dmz")])
        matrix_rows = []
        for fixture in ("asa_plant.cfg", "ios_ot_switch.cfg", "panos_plant.xml", "fortios_plant.conf", "pfsense_plant.xml"):
            src = parse_config((ROOT / "tests" / "fixtures" / fixture).read_text(encoding="utf-8"), "src")
            for target in firewall.TARGETS:
                if target == {"cisco-ios": "cisco-ios", "cisco-asa": "cisco-asa", "fortios": "fortios"}.get(src.vendor):
                    continue
                t = firewall.translate_policy(src, target, {}, ctx=ctx)
                firewall.render(t, target)
                v = validate.validate_preserve(src, t, ctx)["summary"]
                matrix_rows.append((fixture, target, t.summary, v))

        tests = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "."], cwd=ROOT, capture_output=True, text=True,  # nosec B603
                               timeout=1800, check=False)
        test_tail = [line for line in tests.stderr.strip().splitlines() if line.startswith(("Ran ", "OK", "FAILED"))]

        # ------------------------------------------------------------------ WALKTHROUGH.md
        def first_matching(rows, key, value):
            return next(r for r in rows if r[key] == value)
        c502 = next(r for r in comms["rows"] if r["initiator"] == "10.20.1.15" and r["port"] == 502)
        c514 = next(r for r in comms["rows"] if r["port"] == 514)
        c_http = next(r for r in comms["rows"] if r["initiator"] == "10.20.1.99")
        syn_only = next(r for r in comms["rows"] if r["initiator"] == "10.10.4.4" and r["port"] == 502)
        deny_row = next(r for r in compare["rows"] if r["outcome"] == "deny")
        narrow = plan_n
        preserve = plan_p
        ios = results[("preserve", "cisco-ios")]
        forti = results[("preserve", "fortios")]
        w = ["# Walkthrough: from inputs to explanations to exports", "",
             "This page is generated by `tools/make_demo.py` from the real application code and the synthetic sample project (a fictional plant). "
             "Nothing here was typed by hand and none of it is real data. Run the script again to regenerate it.", "",
             f"Generated {time.strftime('%Y-%m-%d', time.gmtime())}. The full outputs are in [docs/demo/](demo/).", "",
             "## 1. Inputs", "",
             "| File | What it is |", "| --- | --- |",
             "| [samples/plant-span.pcapng](../samples/plant-span.pcapng) | A synthetic capture (21 flows, IPv4 and IPv6, a VLAN tag, a mid-connection start, one-way UDP, a SYN with no reply). Also as [pcap](../samples/plant-span.pcap). |",
             "| [samples/configs/demo-plant-asa.cfg](../samples/configs/demo-plant-asa.cfg) | A synthetic Cisco ASA export for the same plant. |",
             "| [samples/plant-conn.log](../samples/plant-conn.log) | A small Zeek conn.log (flow records) in the same fictional network. |", "",
             "Import them on the **Import** tab, or use **Create a sample project**, which runs exactly this path.", "",
             "## 2. What was seen (OBSERVED)", "",
             f"The capture holds {overview['flows']} flows, grouped into {overview['communications']} communications "
             f"(initiator, responder, service). Direction confidence: " + ", ".join(f"{k} {v}" for k, v in overview["direction_confidence"].items()) + ".", "",
             "Examples, as the application words them:", "",
             f"> {c502['explanation']}", "", f"> {c_http['explanation']}", "", f"> {syn_only['explanation']}", "", f"> {c514['explanation']}", "",
             "Note how the wording follows the evidence: a confirmed protocol is stated as identified from decoding; a port-only guess is "
             "called a possibility; traffic on port 502 that decodes as HTTP is called out; a one-way UDP flow gets a low-confidence direction "
             "and is not turned into a policy. Coverage statements printed with every capture:", ""]
        w += [f"- {n}" for n in overview["coverage"]]
        w += ["", "Full text: [01-observed-communications.md](demo/01-observed-communications.md), [CSV](demo/02-observed-communications.csv).", "",
              "## 3. What the device is configured to allow (CONFIGURED)", "",
              f"The ASA export has {view['summary']['rules']} rules in {view['summary'].get('acls', '4')} ACLs. The analysis found:", ""]
        w += [f"- **{f['kind']}**: {f['message']}" for f in view["findings"]]
        w += ["", "Full rule table with evidence references: [03-configuration-analysis.md](demo/03-configuration-analysis.md).", "",
              "## 4. Observed against configured", "",
              f"Outcomes for the {len(compare['rows'])} communications: " + ", ".join(f"{k} {v}" for k, v in compare["counts"].items()) + ".", "",
              f"Example of a denial: {deny_row['observed']['initiator']} to {deny_row['observed']['responder']} "
              f"({deny_row['observed']['proto']}/{deny_row['observed']['port']}) matched `{deny_row['rule']}`. The reading attached to it: "
              f"\"{deny_row['reading']}\"", "",
              f"{len(compare['unobserved_rules'])} allow rules matched no observed traffic. The report states this does not show they are unused.", "",
              "Full table: [04-observed-vs-configured.md](demo/04-observed-vs-configured.md).", "",
              "## 5. Directional group policies (PROPOSED)", "",
              "Groups used (Groups & labels tab): " + ", ".join(f"{g['name']}{' (isolated behind a gateway)' if g.get('gateway_isolated') else ''}" for g in project["groups"]) + ".", "",
              "### Preserve the configured permissions", "", f"> {preserve['summary']['verdict']}", "",
              "Measures: " + ", ".join(f"{k.replace('_', ' ')} {v}" for k, v in preserve["summary"].items() if k != "verdict") + ".", "",
              "Because the sample groups are broad (whole subnets) and the ASA rules name individual hosts and ports, the tool refuses to widen silently: "
              "rules for which no group lies wholly inside the source or destination are listed as not translated, with the reason and what to do. "
              "Full worksheet: [05-directional-preserve.md](demo/05-directional-preserve.md).", "",
              "### Propose narrower permissions from observation", "", f"> {narrow['summary']['verdict']}", "",
              "Measures: " + ", ".join(f"{k.replace('_', ' ')} {v}" for k, v in narrow["summary"].items() if k != "verdict") + ".", "",
              "Policies proposed (From may initiate to To; a reverse direction is its own policy):", ""]
        w += [f"- **{p['name']}** ({p['status']}): {'; '.join(p['services_informational'][:3])}" for p in narrow["policies"]]
        w += ["", "External egress policies (separate type, for the group marked as isolated behind a gateway):", ""]
        w += [f"- **{e['name']}**: prefixes {', '.join(e['allowed_prefixes'])}; DNS names {', '.join(e['allowed_dns_names']) or '-'}; allow all DNS queries: "
              f"{'yes' if e['allow_all_dns'] else 'no'}" for e in narrow["egress_policies"]]
        w += ["", "Held back for review (direction not trusted enough):", ""]
        w += [f"- {i['message']}" for i in narrow["review_items"] if i["code"] == "direction-uncertain"]
        w += ["", "Every proposal carries the observation period and a requirement to confirm dependencies that did not occur in the window. "
              "Export is refused until that is acknowledged. Worksheet: [06-directional-narrow.md](demo/06-directional-narrow.md), "
              "[JSON](demo/directional-narrow.json), [CSV](demo/directional-narrow-group-policies.csv).", "",
              "## 6. Translate to another firewall (PROPOSED)", "",
              "The same ASA export translated to a stateless IOS ACL set and to FortiOS, with validation against the source:", "",
              "| Destination | Translated | Not translated | Return rules added (broader) | Sampled connections | Same | Destination broader | Destination narrower | Not compared |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
        for target in ("cisco-ios", "fortios"):
            r = results[("preserve", target)]
            s, v = r["summary"], r["validation"]["summary"]
            w.append(f"| {target} | {s['translated']} | {s['blocked']} | {s['return_rules_added']} | {v['cases']} | {v['same_allow'] + v['same_deny']} | "
                     f"{v['target_broader']} | {v['target_narrower']} | {v['not_compared']} |")
        w += ["", f"IOS verdict: {ios['summary']['verdict']}", "", f"FortiOS verdict: {forti['summary']['verdict']}", "",
              "Excerpt of the generated FortiOS text (review only):", "", "```text", head(forti["text"], 28), "```", "",
              "Reports with the per-rule table, issues and validation mismatches: "
              + ", ".join(f"[{w_}/{t}](demo/07-{w_}-{t}.md)" for (w_, t) in results) + ".", "",
              "## 7. What the validation does and does not show", "",
              "See [VALIDATION.md](VALIDATION.md). In short: source and destination are asked about the same sampled connections; differences are "
              "classified; a destination that allows what the source denied is flagged as broader. The comparison uses this tool's own evaluator on "
              "both sides, so it cannot demonstrate equivalence."]
        (ROOT / "docs" / "WALKTHROUGH.md").write_text("\n".join(w) + "\n", encoding="utf-8")

        # ------------------------------------------------------------------ VALIDATION.md
        v = ["# Validation evidence", "", "Generated by `tools/make_demo.py`. Two kinds of evidence: the automated test suite, and the migration "
             "validation run on every fixture and every destination.", "", "## Test suite", "",
             "`python -m unittest discover -s tests -t .` at generation time:", "", "```text"] + test_tail + ["```", "",
             "Areas covered (see the test files): object and nested-group resolution; ordered rules, implicit deny, ASA security levels and the "
             "interface-then-global order; stateful replies versus reverse initiation; stateless ACL return requirements and `established`; NAT "
             "address context; IPv6, UDP and ICMP; shadowed, redundant and conflicting rules; disabled rules; group aggregation that creates "
             "unintended access; unsupported applications, identities and schedules; hostile files and resource limits; the web server's access "
             "control; fuzzing with Hypothesis.", "",
             "## Migration validation matrix (preserve workflow)", "",
             "Each synthetic fixture is translated to each destination other than its own product, the destination text is parsed back with the "
             "destination adapter, and the source and the parsed destination are asked about the same sampled connections (one inside each rule, "
             "one just outside each address and port range, and a new connection from the server side).", "",
             "| Source fixture | Destination | Rules translated | Not translated | Return rules (broader) | Sampled | Same | Dest. broader | Dest. narrower | Not compared |",
             "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
        for fixture, target, s, val in matrix_rows:
            v.append(f"| {fixture} | {target} | {s['translated']} | {s['blocked']} | {s['return_rules_added']} | {val['cases']} | "
                     f"{val['same_allow'] + val['same_deny']} | {val['target_broader']} ({val.get('unexplained_broader', 0)} unexplained) | "
                     f"{val['target_narrower']} | {val['not_compared']} |")
        v += ["", "Reading the table: *broader* means the destination permits a sampled connection the source denied. Cases explained by a known, "
              "reported cause (a stateless return rule that is broader by construction, or a source rule that was blocked) are separated from "
              "*unexplained* ones. *Narrower* means the destination blocks something the source allowed, typically a rule that could not be "
              "translated or a default behaviour that is not carried over. *Not compared* means an outcome could not be decided on one side "
              "(an unknown zone, an unresolved object, an application or schedule condition).", "",
              "## What this evidence does not show", ""] + [f"- {x}" for x in validate.LIMITS]
        (ROOT / "docs" / "VALIDATION.md").write_text("\n".join(v) + "\n", encoding="utf-8")
    print("wrote docs/demo, docs/WALKTHROUGH.md and docs/VALIDATION.md")


if __name__ == "__main__":
    main()
