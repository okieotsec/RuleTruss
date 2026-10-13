"""Regenerate the synthetic sample inputs in samples/. Everything is fictional and reproducible.

    .venv/bin/python tools/make_samples.py

samples/small/      one capture, one Zeek log and one config per format: quick to read
samples/riverbend/  the larger example (a fictional water-treatment plant) with GUIDE.md, written from live results
"""
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from ruletruss import riverbend  # noqa: E402
from ruletruss.samples import create_riverbend, riverbend_files  # noqa: E402
from ruletruss.service import Service  # noqa: E402
from ruletruss.store import Store  # noqa: E402
from ruletruss.synthetic import plant_capture  # noqa: E402

ZEEK = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes"
        "\tconn_state\thistory\torig_pkts\tresp_pkts\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring\tcount\tcount\n"
        "1700000000.0\tCa1\t10.20.1.15\t50000\t10.30.2.40\t502\ttcp\tmodbus\t1.5\t12\t23\tSF\tShADadFf\t6\t5\n"
        "1700000010.0\tCa2\t10.20.1.15\t50001\t10.30.2.40\t502\ttcp\tmodbus\t1.2\t12\t23\tSF\tShADadFf\t6\t5\n"
        "1700000020.0\tCa3\t10.30.2.40\t49500\t10.30.5.10\t4840\ttcp\t-\t0.4\t36\t0\tSF\tShADadFf\t5\t4\n"
        "1700000030.0\tCa4\t10.20.1.50\t41000\t10.30.2.40\t161\tudp\tsnmp\t0.1\t60\t70\tSF\tDd\t1\t1\n"
        "1700000040.0\tCa5\t10.20.1.15\t51500\t10.30.2.40\t502\ttcp\t-\t3.0\t10\t10\tOTH\tDd\t2\t2\n")


def small():
    out = ROOT / "samples" / "small"
    (out / "configs").mkdir(parents=True, exist_ok=True)
    builder = plant_capture()
    builder.write(str(out / "plant-span.pcap"), "pcap")
    builder.write(str(out / "plant-span.pcapng"), "pcapng")
    (out / "plant-conn.log").write_text(ZEEK, encoding="utf-8")
    shutil.copy(ROOT / "ruletruss" / "samples" / "demo_asa.cfg", out / "configs" / "demo-plant-asa.cfg")
    for src, dst in (("asa_plant.cfg", "asa-firewall.cfg"), ("ios_ot_switch.cfg", "ios-switch-acls.cfg"), ("panos_plant.xml", "panos-firewall.xml"),
                     ("fortios_plant.conf", "fortios-firewall.conf"), ("pfsense_plant.xml", "pfsense-config.xml")):
        shutil.copy(ROOT / "tests" / "fixtures" / src, out / "configs" / dst)


def riverbend_files_on_disk():
    out = ROOT / "samples" / "riverbend"
    for sub in ("captures", "flow-logs", "configs"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    folders = {"pcap": "captures", "pcapng": "captures", "log": "flow-logs"}
    for name, data in riverbend_files().items():
        (out / folders.get(name.rsplit(".", 1)[-1], "configs") / name).write_bytes(data)
    import json
    (out / "context.json").write_text(json.dumps(riverbend.context(), indent=2) + "\n", encoding="utf-8")
    return out


def guide(out):
    """GUIDE.md from live results: every number below comes from running the application on these very files."""
    with tempfile.TemporaryDirectory() as d:
        svc = Service(Store(d))
        project = create_riverbend(svc)
        pid = project["id"]
        ov = svc.overview(pid)
        policy_ids = {s["filename"]: s["id"] for s in project["sources"] if s["kind"] == "policy"}
        cmp_ = {name: svc.compare(pid, sid) for name, sid in policy_ids.items()}
        narrow = svc.plan_json(pid, {"workflow": "narrow"})
        preserve = svc.plan_json(pid, {"workflow": "preserve", "policy": policy_ids["perimeter-asa.cfg"]})
        ios = svc.translation_json(pid, {"workflow": "preserve", "policy": policy_ids["ops-field-fortios.conf"], "target": "cisco-ios",
                                         "zone_map": {"ops": "Vlan20", "cell1": "Vlan11", "cell2": "Vlan12", "field": "Vlan11"}})
        asa_to_forti = svc.translation_json(pid, {"workflow": "preserve", "policy": policy_ids["perimeter-asa.cfg"], "target": "fortios", "zone_map": {}})
        conf = ov["direction_confidence"]
    cross = {n: (c["crossing"], len(c["rows"]), c["crossing_counts"]) for n, c in cmp_.items()}
    L = []
    w = L.append
    w("# Riverbend: a guided tour of RuleTruss")
    w("")
    w("**Everything here is fictional.** Riverbend Water Treatment is an invented plant. The captures are generated, not recorded; the addresses are private "
      "ranges or the reserved documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); the device configurations are written, not exported. "
      "Nothing is real, so nothing needs protecting. The files were built so that, together, they show every idea in the application, including the places "
      "where the tool says *I cannot tell*.")
    w("")
    w("Regenerate everything, including this page, with `python tools/make_samples.py`. Each teaching point below is also an automated test "
      "(`tests/test_riverbend.py`, named by the same id), so this guide cannot describe something the data does not show.")
    w("")
    w("## Load it")
    w("")
    w("**Quickest:** start RuleTruss, open the Import tab, press **Create the Riverbend example**. It imports every file below and sets up the subnets, labels and groups.")
    w("")
    w("**By hand** (to see each step): create a project; import the three captures, the flow log and the five configurations (drag them in; set the "
      "*observation point* text for each capture, as in the table); then on **Groups & labels** use *Load from a JSON file* with `context.json` and press Save.")
    w("")
    w("## The plant")
    w("")
    w("```text")
    w("  Internet / vendor --------+")
    w("   198.51.100.0/24          |   vendor access (pfSense)            perimeter (Cisco ASA)")
    w("   203.0.113.0/24, 192.0.2.0/24                                          |")
    w("                            +--------------------------+------------+")
    w("                                                       |")
    w("   corp 10.10.0.0/16 ---- ASA ---- dmz 10.40.0.0/24   (jump host .10, historian replica .20, patch .30, file transfer .40)")
    w("                                      |")
    w("                                   PAN-OS  (IT/OT boundary)")
    w("                                      |")
    w("   ops 10.20.0.0/24  (SCADA .10 .11, historian .20, engineering .50 .51, HMIs .60 .61, monitor .70, backup .80, services .2)")
    w("        |                             |")
    w("      FortiOS (ops-field)          IOS router (ACLs)")
    w("        |        |                    |")
    w("   cell1 10.30.1.0/24   cell2 10.30.2.0/24    cell3 10.30.3.0/24")
    w("   Modbus/TCP PLCs      S7comm PLCs + EtherNet/IP   DNP3 RTUs + IEC 104 gateway")
    w("```")
    w("")
    w("## The files")
    w("")
    w("| File | What it is | Where it was 'taken' |")
    w("| --- | --- | --- |")
    for name, kind, where in (
            ("captures/ops-field-span.pcapng", "5 minutes of steady control traffic", riverbend_point("ops-field-span.pcapng")),
            ("captures/dmz-tap.pcap", "30 minutes of sparse, human-driven traffic", riverbend_point("dmz-tap.pcap")),
            ("captures/cell-switch-late-start.pcapng", "90 seconds, started in the middle of conversations", riverbend_point("cell-switch-late-start.pcapng")),
            ("flow-logs/corp-edge-conn.log", "Zeek connection summaries (no packets)", riverbend_point("corp-edge-conn.log")),
            ("configs/perimeter-asa.cfg", "Cisco ASA 9.16 running-config", "the corporate/DMZ/Internet firewall"),
            ("configs/it-ot-boundary-panos.xml", "PAN-OS 10.2 XML", "the DMZ-to-operations firewall"),
            ("configs/ops-field-fortios.conf", "FortiOS 7.2 CLI", "the operations-to-cells firewall (cells 1 and 2)"),
            ("configs/cell3-router-ios.cfg", "IOS-XE 17.9 ACLs (stateless)", "the router in front of cell 3"),
            ("configs/vendor-access-pfsense.xml", "pfSense 23.09 config.xml", "the vendor remote-access appliance"),
            ("context.json", "subnets, labels and groups", "what you, the engineer, know")):
        w(f"| `{name}` | {kind} | {where} |")
    w("")
    w(f"In total the three captures and the log hold **{ov['flows']} flows** that group into **{ov['communications']} communications** between **{len(ov['inventory']['devices'])} devices**. "
      f"Direction confidence across the flows: " + ", ".join(f"{k} {v}" for k, v in conf.items()) + ".")
    w("")
    w("## How to read the application (a suggested order)")
    w("")
    w("1. **Inventory** shows what was seen and, before anything else, the *coverage and limits* box: three capture points, none of which sees everything. Read the matrix as *row initiated to column*; an empty cell means nothing was seen, not that nothing happens. No device is given a role; the labels are yours (from `context.json`).")
    w("2. **Communications** is where the explanations live. Click any row for the plain-language sentence, why the direction was chosen, how the application was identified, and the evidence (packet numbers).")
    w("3. **Graph** draws the same facts: arrows run from the side that initiated. Switch to *Devices*.")
    w("4. **Configuration** shows one device's rules in order, with the analysis (shadowed, redundant, conflicting, broad rules) and the things the tool did *not* evaluate.")
    w("5. **Compare** sets observed traffic against one configuration. By default it shows only traffic that **crosses that device** (both ends in zones it knows), because a configuration cannot be judged by traffic that never reaches it. "
      + "; ".join(f"{n}: {c} of {t}" for n, (c, t, _) in cross.items()) + ".")
    w("6. **Groups & labels**, then **Migrate** (the two workflows, then translation), then **Export & AI**.")
    w("")
    w("## What to look for: observed traffic")
    w("")
    w("| Id | Where to look | What you should see | Why it matters for the design |")
    w("| --- | --- | --- | --- |")
    w("| T01 | Communications, port 502 | SCADA-1 to the intake PLCs is **Modbus/TCP, confirmed** (the payload was decoded). Engineering WS-2 to PLC 3 on port 502 is only **possible**, and the basis says the payload did *not* decode as Modbus. | A port number is never proof of a protocol. |")
    w("| T02 | Historian to its replica, port 1433 | *Microsoft SQL Server*, **possible**: this tool does not decode that protocol, so it offers the port's usual meaning and says so. | The tool shows the limit of its own evidence. |")
    w("| T03 | Engineering WS-2 to PLC 4 on port 4000 | No application at all. | Unknown stays unknown. |")
    w("| T04 | Ports 102, 20000, 2404 | S7comm, DNP3 are confirmed from their headers (DNP3's CRC is checked); IEC 104 is only **probable** (a weak signature). | Three levels: confirmed, probable, possible. |")
    w("| T05 | RTU 32 to SCADA-1, port 20000 | **The RTU initiated**: its SYN is in the capture. SCADA servers also poll RTUs on the same port. | Two directions between the same groups are two separate policies. |")
    w("| T06 | SCADA-1 to treatment PLC 1, port 102 | Direction is only **medium**: one of the captures started after the connection was set up, and the notes say the initiator is not proven. | Mid-stream captures cannot prove who connected. |")
    w("| T07 | SCADA-1 to RTU 33, port 20000 | A note that only one direction was captured. | Asymmetric capture is reported, not hidden. |")
    w("| T08 | PLCs to the ops services host, port 514 | Syslog datagrams one way only: direction **low**, and no policy is proposed from them in the *narrow* workflow (listed under review). | UDP gives no handshake, so it never earns more than medium. |")
    w("| T09 | PLCs to Engineering WS-1, port 44818 | Replies to a discovery broadcast, but a one-direction flow cannot show that, so each looks like an initiation with **low** confidence. | Replies are not reverse initiation; the tool says when it cannot tell them apart. |")
    w("| T10 | Review items in the narrow plan | DHCP from 0.0.0.0, SSDP, mDNS and the ENIP broadcast are not turned into policy. | Discovery noise is not a relationship between endpoints. |")
    w("| T11 | HMI-2 to RTU 31 port 23; BI server to the jump host; contractor laptop to the file server (SMB) | SYN packets with no reply. The explanation says no reply was captured. | An attempt is not a connection, and not proof of a need. |")
    w("| T12 | Treatment PLC 1 to 203.0.113.10:443 | A TLS connection with the server name `telemetry.vendor.example`. The *Treatment PLCs* group is marked isolated behind a gateway, so the narrow plan proposes an **external egress policy** with that prefix and DNS name. | The egress policy type is separate from group policies. |")
    w("| T13 | SCADA-1 to intake PLC 1, port 502 | Two flows, from two captures, merged; the communication takes the **weakest** direction confidence. | Several observation points combine conservatively. |")
    w("| T14 | Corporate DNS to 9.9.9.9 | From the Zeek log: direction **low** and labelled as Zeek's own inference. | A summary is not packet evidence. |")
    w("")
    w("## What to look for: configurations")
    w("")
    w("| Id | Where to look | What you should see | Why it matters |")
    w("| --- | --- | --- | --- |")
    w("| C01 | ASA, Configuration and Compare | `CORP-IN:4` is a temporary \"all of corporate to the whole DMZ\" rule. It **allows** the BI server's and the contractor laptop's unanswered attempts, and the later `deny` for the BI server is reported as **shadowed**. | One broad rule hides the specific ones; the comparison shows who it really admits. |")
    w("| C02 | ASA, Compare | The vendor's RDP is **indeterminate** (an identity condition); the patch server's HTTPS to the Internet is **indeterminate** (an FQDN object); `OUTSIDE-IN:3`, an old vendor range, matched nothing observed. | Conditions the tool cannot evaluate are reported, not guessed. 'Matched nothing' is not 'unused'. |")
    w("| C03 | ASA, translate to FortiOS | The jump-host rules are **blocked**: the ASA writes rules with the real address while FortiOS writes them as received, and a static NAT touches that address. Identity, schedule and FQDN rules are blocked too. | Address context and NAT are where translations silently go wrong. |")
    w("| C04 | PAN-OS | `application-default` and App-ID rules are **indeterminate**; a dynamic address group cannot be resolved; one rule is negated; one is `intrazone`; one is disabled; there is a destination NAT. | The model keeps what it cannot evaluate. |")
    w("| C05 | FortiOS, Compare | Engineering WS-2's odd traffic (the non-Modbus on 502, port 4000, a PLC web page) is **allowed by rule 5**, a leftover commissioning rule that permits everything from engineering to the cells. Rule 6 is redundant behind it. A virtual IP is flagged because FortiOS gives such policies priority over list order. Rule 15 has no action set, which FortiOS treats as deny. | A permissive rule makes observed traffic look fine. |")
    w("| C06 | IOS | The ACLs are **stateless**: `CELL3-IN:2` only lets replies back (TCP `established`). One entry has a wildcard mask that cannot be expressed as a network, one uses a reflexive option; both make nearby answers **indeterminate** (including the IEC 104 gateway, which has no visible permit). | Stateless ACLs need return rules; unreadable entries are surfaced, not skipped. |")
    w("| C07 | pfSense | An alias that is a URL table and one that is a host name cannot be resolved; a rule keeps no state; one is scheduled; a floating Quick rule comes first. Its rules use the translated (internal) address after the port forward. | Same ideas, different vocabulary. |")
    w("| C08 | Compare, the checkbox | Each device 'sees' only part of the traffic. Tick *also show traffic that does not cross this device* to see the rest. | Judge a rule base only by traffic that reaches it. |")
    w("")
    w("## What to look for: migration")
    w("")
    w("| Id | Where to look | What you should see | Why it matters |")
    w("| --- | --- | --- | --- |")
    w(f"| M01 | Migrate, *Preserve*, source = the ASA | {preserve['summary']['blocked_rules']} of its {preserve['summary']['source_rules']} rules cannot be turned into group policies (no group lies wholly inside the addresses, or an identity/schedule/FQDN condition), {preserve['summary']['deny_rules_not_translated']} deny rules have no equivalent, and services are listed as information only. The verdict line says access is broadened or restrictions dropped. | The directional model is simpler than a firewall; the loss is counted. |")
    w(f"| M02 | Migrate, *Narrower* | {narrow['summary']['policies']} policies are proposed from {narrow['summary']['communications_used']} communications, and {narrow['summary']['policies_that_broaden_access']} of them are flagged because group membership grants more address pairs than were observed (the *Corporate IT* group is a whole /16). Open the worksheet to see granted against observed. | Coarse groups are the main way a directional policy over-grants. Edit the groups and rebuild. |")
    w(f"| M03 | Migrate, translate the FortiOS config to Cisco IOS | {ios['summary']['return_rules_added']} return rules are added and marked **broader** (a stateless ACL cannot track replies); an IPv6 default-deny ACL is added because an IPv4 ACL does not filter IPv6; the report explains that `established` matches any packet with ACK or RST set. | Stateful to stateless always costs something. |")
    w(f"| M04 | Translate the ASA to FortiOS | {asa_to_forti['summary']['translated']} rules translated, {asa_to_forti['summary']['blocked']} blocked, each with the reason. Validation: {asa_to_forti['validation']['summary']['same_allow'] + asa_to_forti['validation']['summary']['same_deny']} sampled connections agree, {asa_to_forti['validation']['summary']['not_compared']} could not be compared, and the limits of the comparison are printed. | The tool never turns a rule it cannot express into 'any'. |")
    w("| M05 | Any source, any destination | `tests/test_riverbend.py` translates all five configurations to all three destinations and fails if the destination allows something the source denied for a reason the report does not explain. | The migration check is part of the test suite. |")
    w("")
    w("## Exercises")
    w("")
    w("1. **Shrink a group, rebuild a plan.** In Groups & labels delete the *Corporate IT* group (a whole /16) and rebuild *Narrower*. Communications that used it now fall back to a smaller group, or are listed as *not in a group*; watch the granted-pair numbers fall.")
    w("2. **Find the leak.** Compare the FortiOS configuration, tick the *does not cross* box, and ask which rule admitted Engineering WS-2's port-4000 traffic. Then build the narrow plan and see that no such policy is proposed unless the traffic was seen.")
    w("3. **Two directions.** In the narrow plan find *Distribution RTUs to SCADA servers* and *SCADA servers to Distribution RTUs*. Open the evidence of each. Explain why one policy cannot cover both.")
    w("4. **Undo the egress.** Untick *isolated behind a gateway* on *Treatment PLCs* and rebuild. What happens to the 203.0.113.10 connection?")
    w("5. **Read a blocked rule.** Translate the ASA to FortiOS and read why the jump-host rules are blocked. What would you need to know about the NAT to translate them by hand?")
    w("6. **Make it fail.** Import `perimeter-asa.cfg` without `context.json`. Which comparisons become indeterminate, and why?")
    w("")
    w("## What this example does not claim")
    w("")
    w("It is not a model of any real plant, a benchmark of the application, or evidence that the parsers handle every real export; it only shows how the tool reasons. The captures contain no real protocol conversations beyond the headers the tool checks.")
    (out / "GUIDE.md").write_text("\n".join(L) + "\n", encoding="utf-8")


def riverbend_point(name):
    from ruletruss.samples import RIVERBEND_POINTS
    return RIVERBEND_POINTS[name]


def main():
    small()
    out = riverbend_files_on_disk()
    guide(out)
    print("wrote samples/small and samples/riverbend (with GUIDE.md)")


if __name__ == "__main__":
    main()
