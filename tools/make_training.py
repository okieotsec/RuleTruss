"""Write docs/TRAINING.md, the training guide, from live results of the example projects.

    .venv/bin/python tools/make_training.py            write the guide
    .venv/bin/python tools/make_training.py --check    exit 1 if docs/TRAINING.md is out of date (used by the tests)

Every number and every sentence about what the examples show comes from running the application on them, so the guide cannot describe
something the application does not do. Everything in the examples is invented.
"""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from ruletruss.samples import create_riverbend, create_unifi, vendor_names  # noqa: E402
from ruletruss.service import Service  # noqa: E402
from ruletruss.store import Store  # noqa: E402
from ruletruss.version import __version__  # noqa: E402

OUT = ROOT / "docs" / "TRAINING.md"


def facts():
    with tempfile.TemporaryDirectory() as d:
        svc = Service(Store(d))
        vendor_names.install(svc.vendor_path)
        project = create_riverbend(svc)
        pid = project["id"]
        ov = svc.overview(pid)
        rows = svc.communications(pid, {"limit": "500"})["rows"]
        policies = {s["filename"]: s["id"] for s in project["sources"] if s["kind"] == "policy"}
        compare = {n: svc.compare(pid, sid) for n, sid in policies.items()}
        narrow = svc.plan_json(pid, {"workflow": "narrow"})
        preserve = svc.plan_json(pid, {"workflow": "preserve", "policy": policies["perimeter-asa.cfg"]})
        ios = svc.translation_json(pid, {"workflow": "preserve", "policy": policies["ops-field-fortios.conf"], "target": "cisco-ios",
                                         "zone_map": {"ops": "Vlan20", "cell1": "Vlan11", "cell2": "Vlan12", "field": "Vlan11"}})
        asa_forti = svc.translation_json(pid, {"workflow": "preserve", "policy": policies["perimeter-asa.cfg"], "target": "fortios", "zone_map": {}})
        devs = {x["ip"]: x for x in ov["inventory"]["devices"]}
        unifi_project = create_unifi(svc)
        unifi_policy = next(s for s in unifi_project["sources"] if s["kind"] == "policy")
        unifi_view = svc.policy_view(unifi_project["id"], unifi_policy["id"])
        unifi_cmp = svc.compare(unifi_project["id"], unifi_policy["id"])
    def find(src, dst, port):
        return next(r for r in rows if r["initiator"] == src and r["responder"] == dst and r["port"] == port)
    cells = {(c["src"], c["dst"]): c for c in unifi_view["zone_matrix"]["cells"]}
    return {"ov": ov, "rows": rows, "compare": compare, "narrow": narrow, "preserve": preserve, "ios": ios, "asa_forti": asa_forti, "devs": devs,
            "find": find, "unifi_view": unifi_view, "unifi_cmp": unifi_cmp, "cells": cells, "unifi_rules": unifi_policy["rules"]}


def build():
    f = facts()
    ov, devs, find = f["ov"], f["devs"], f["find"]
    conf = ov["direction_confidence"]
    cross = {n: (c["crossing"], len(c["rows"])) for n, c in f["compare"].items()}
    telnet = find("10.20.0.61", "10.30.3.31", 23)
    rtu = find("10.30.3.32", "10.20.0.10", 20000)
    s7 = find("10.20.0.10", "10.30.2.21", 102)
    modbus = find("10.20.0.10", "10.30.1.11", 502)
    pitfall = f["cells"][("Internal", "Internal")]
    L = []
    w = L.append

    w("# RuleTruss training guide")
    w("")
    w(f"For network and security engineers who want to understand what is on a network and what a firewall allows, and to turn that into reviewed policy. "
      f"Written for RuleTruss {__version__}. **Everything in the examples is invented**, so you can click anything.")
    w("")
    w("| | |")
    w("| --- | --- |")
    w("| Time | about 3 hours for everything; each lab stands alone and takes 10 to 20 minutes |")
    w("| You need | Python 3.12 or newer, a browser, and this repository. A real capture or firewall export is optional (section 4) |")
    w("| You will be able to | read a capture and say who started what, with how much certainty; read a firewall export and find what is wrong with it; set one against the other; produce a reviewable policy proposal; explain every one of those results to someone else |")
    w("| Reference | the [README](../README.md), [what the tool can read](SUPPORT_MATRIX.md), [its limits](LIMITATIONS_AND_ROADMAP.md), [UniFi export guide](EXPORT_UNIFI.md) |")
    w("")
    w("How to use this guide: do the labs in order the first time. After each lab there are *check yourself* questions; the answers are in appendix D. "
      "Numbers in this guide come from the examples as they are shipped; if you see different ones, you are probably looking at a different file.")
    w("")

    w("## 1. Ideas that make everything else easier")
    w("")
    w("RuleTruss keeps three kinds of statement apart, and labels them everywhere:")
    w("")
    w("| Label | Means | Comes from |")
    w("| --- | --- | --- |")
    w("| **OBSERVED** | something seen in a capture or flow log | packets and logs |")
    w("| **CONFIGURED** | something a device is set to do | a firewall, router or switch export |")
    w("| **PROPOSED** | something this tool suggests | its own analysis; never applied to any device |")
    w("")
    w("Three habits of the tool explain most of what you will see:")
    w("")
    w("1. **It says how sure it is.** A TCP handshake proves who started a connection (*high*). A capture that begins mid-conversation, or one-way UDP, "
      "cannot prove it (*medium*, *low*, *unknown*). Application names have three levels: *confirmed* (the payload decoded), *probable* (a weak signature), "
      "*possible* (only the port number suggests it).")
    w("2. **Unknown stays unknown.** When a rule depends on something the tool cannot evaluate (an application, a user, a schedule, a domain, a region), "
      "the answer is *cannot decide*, never a guess. \"Would be allowed\" and \"would be blocked\" are only said when they are certain.")
    w("3. **Silence is not absence.** A capture shows one place for one period. A device that never appears may simply not be visible from there.")
    w("")
    w("Everything is local: nothing leaves your computer, the server only answers your own browser, and the tool never changes a live device.")
    w("")

    w("## 2. Setting up")
    w("")
    w("```bash")
    w(".venv/bin/python -m ruletruss")
    w("```")
    w("")
    w("It prints an address ending in `#token=...`. Open **that** address; the token changes every time the server starts, so an old browser tab stops "
      "working after a restart. After updating the program, stop it with Ctrl+C and start it again.")
    w("")
    w("Useful options (see the README for all): `--port N` if 8765 is busy; `--data-dir PATH` for where projects are stored; `--max-capture-mb`, "
      "`--max-packets`, `--parse-minutes` for big captures (section 4). The top-right buttons switch the colour theme (system, light, dark) and "
      "**Show explanations**, which opens every long explanation at once.")
    w("")
    w("**Tabs that are not ready.** The tabs run left to right in the order you work: *Import*, then the three views of traffic, then the "
      "configuration views, then the planning tabs. A tab that has nothing to show yet has a small padlock. Click it and the page tells you what is missing "
      "(a project, a capture, a device export) and offers a button to fix it. *Import*, *Groups & labels* (needs a project only) and *Data & privacy* never lock.")
    w("")

    w("## 3. Lab 1: load an example and find your way around (10 minutes)")
    w("")
    w("Goal: see every tab with real content and learn where things are.")
    w("")
    w("1. Open the address from step 2. On **Import**, press **Load the Riverbend example**. It is a fictional water-treatment plant: "
      f"{len(ov['captures'])} captures, a flow log and five firewall exports ({ov['flows']} flows between {len(ov['inventory']['devices'])} devices).")
    w("2. Click **Inventory**. Read the *coverage and limits* line first: it says where each capture was taken.")
    w("3. Click **Communications**, then a row. The first line is the plain-language sentence; the rest is why.")
    w("4. Click **Graph**, then a circle, then **Fit**.")
    w("5. Click **Configuration** and pick `perimeter-asa.cfg`. Look at *Rule analysis*.")
    w("")
    w("You should see: " + f"{ov['flows']} flows, {ov['communications']} communications; direction confidence high {conf.get('high', 0)}, medium {conf.get('medium', 0)}, "
      f"low {conf.get('low', 0)}, unknown {conf.get('unknown', 0)}.")
    w("")
    w("*Check yourself:* 1. What does the padlock on a tab mean? 2. What are the three labels, and which one means \"nothing was changed anywhere\"?")
    w("")

    w("## 4. Importing your own data")
    w("")
    w("**What you can import.** Captures: PCAP and PCAPNG (Ethernet, raw IP, Linux cooked, loopback; IPv4, IPv6, VLAN tags). Flow logs: Zeek `conn.log` "
      "(TSV or JSON lines). Device exports: Cisco ASA, Cisco IOS/IOS-XE ACLs, Palo Alto PAN-OS XML, Fortinet FortiOS, pfSense/OPNsense, and UniFi "
      "(a JSON file made with `tools/unifi_export.py`, section 11). The type is recognised from the content, not the file name.")
    w("")
    w("**Say where a capture was taken** in *Capture point*. The tool never guesses it, and it matters: traffic that does not pass that point is not seen.")
    w("")
    w("**Big captures.** The defaults protect against hostile or broken files: 512 MB, 5,000,000 packets, 200,000 flows, 10 minutes and 2 GB of memory per "
      "file. For a capture you trust, raise them when you start the server, for example "
      "`--max-capture-mb 4096 --max-packets 60000000 --parse-minutes 90 --parse-memory-gb 4`. Files over 32 MB are analysed in the background with a progress "
      "line and a **Stop** button; you can keep using other tabs. A measured 810 MB capture took about two minutes. Keep free disk space for the file and its analysis.")
    w("")
    w("**Vendor names (optional).** A MAC address's first half names the maker of the network card. RuleTruss does not ship that list; on "
      "**Data & privacy**, the *Vendor names* card has one button that downloads it from the IEEE (the only time the tool uses the network). Without it, "
      "MAC addresses still work and the *Card maker* column is empty.")
    w("")
    w("**Your own files carry real addresses.** Imported files are stored in the data folder (readable only by you), and nothing is deleted until you delete it "
      "(section 10). Do not put real exports into an example or a shared project.")
    w("")

    w("## 5. Reading what was seen")
    w("")
    w("### Lab 2: Inventory and who started what (15 minutes)")
    w("")
    w("1. On **Inventory**, read the matrix: *row initiated to column*. An empty cell means nothing was seen, not that nothing is allowed.")
    w("2. In *Devices*, click the SCADA-1 row (`10.20.0.10`). Its detail says what it said about itself.")
    w(f"3. Find `10.30.1.11`: its MAC address is **{devs['10.30.1.11']['mac_confidence']}** (it answered ARP) and its identity reads *{devs['10.30.1.11']['identity_short']}* "
      "(from a Modbus identification reply). Find `10.20.0.70`: its MAC is only **probable**. Why the difference? (answer 3)")
    w("4. Open *MACs shared by several addresses*: one MAC carries many addresses because it belongs to a router in front of them. RuleTruss never gives such a MAC to one of them.")
    w("")
    w("A MAC names the card, not the device. It is shown with how it was learned (**confirmed**: the device announced it with ARP or DHCP; **probable**: only seen as the "
      "sender of its own frames), and a randomised or locally set MAC has no maker at all. Text a device sends about itself (LLDP, DHCP host name, SNMP, HTTP "
      "and SSH banners, Modbus and EtherNet/IP identity) is shown as what the device *said*; it can be wrong or forged. A TTL guess is shown apart as a weak hint.")
    w("")
    w("### Lab 3: Communications and certainty (20 minutes)")
    w("")
    w("1. On **Communications**, filter *Port* = `502`. Open the SCADA-1 to intake PLC 1 row.")
    w(f"   > {modbus['explanation_short']}")
    w("2. Open the unanswered Telnet attempt (filter *Port* = `23`):")
    w(f"   > {telnet['explanation_short']}")
    w("3. Open the DNP3 row from RTU 32 to SCADA-1 (port `20000`). The RTU started this one: its SYN is in the capture " + f"(direction **{rtu['direction_confidence']}**).")
    w("4. Open the S7 row from SCADA-1 to treatment PLC 1 (port `102`). Its direction is only " + f"**{s7['direction_confidence']}**. Read the note on why.")
    w("")
    w("*Check yourself:* What is the difference between a SYN with no reply and a closed connection? Why is a mid-stream capture never *high*? (answer 4)")
    w("")
    w("### Lab 4: The graph (15 minutes)")
    w("")
    w("1. Open **Graph**. Circles are subnets (colours match the legend); arrows point from the side that started. Dashed red means some starters are uncertain.")
    w("2. **Resize** the box by dragging its bottom-right corner, or use *Size*. **Scroll** to zoom, drag the background to pan, drag a circle to move it, "
      "**Fit** to start over. *Labels* chooses how many names to show.")
    w("3. **Click** a circle: the panel on the right says how many conversations it started and answered, who it talks to, which services it offers and uses, and "
      "a small sample of the traffic with how sure each statement is. **Click an arrow** for one direction between two circles.")
    w("4. **Double-click** *Cell 1: intake* (or press *Open its devices*). You now see its three PLCs and the machines that talk to them. *Back to subnets* returns.")
    w("5. Click one of the PLCs, then press *See all its communications*: you land on **Communications** already filtered to that address.")
    w("")
    w("*Check yourself:* A circle is large and its arrows are thick. Does that mean it is important? (answer 5)")
    w("")

    w("## 6. Reading what is configured")
    w("")
    w("### Lab 5: Configuration and rule analysis (20 minutes)")
    w("")
    w("1. **Configuration**, pick `perimeter-asa.cfg`. Read *Notes*: they list what could not be read or evaluated.")
    w("2. In the rules table click a row for its plain-language sentence and the line it came from.")
    w("3. Read *Rule analysis*. Terms: **shadowed** (a later rule can never match because an earlier one already covers it), **redundant** (same, same action), "
      "**conflict** (overlap with different actions; the earlier rule wins), **broad** (any source to any destination), **unevaluated** (a condition the tool cannot decide).")
    w("4. Switch to the PAN-OS file and look at the *NAT* card: NAT statements are recorded, not applied.")
    w("")
    w("*Check yourself:* A rule is marked *unevaluated* because it uses an application. Is it safe to assume it allows everything? (answer 6)")
    w("")

    w("## 7. Observed against configured")
    w("")
    w("### Lab 6: Compare (20 minutes)")
    w("")
    w("1. **Compare**, pick each firewall in turn. The counts at the top say how many observed conversations *cross this device*: "
      + "; ".join(f"`{n}`: {c} of {t}" for n, (c, t) in cross.items()) + ".")
    w("2. Why only some? A firewall can only judge traffic that passes through it. Tick *show the rest* to see the others; treat their results with care.")
    w("3. Open an *allow* row and a *deny* row. The detail says which rule matched, in what position, and anything that makes the answer uncertain.")
    w("4. Read *Allow rules no observed traffic matched*. It is **not** a list of unused rules: a capture covers one window and one place.")
    w("")
    w("*Check yourself:* Compare says \"would be denied\" for a flow that clearly works in real life. List three reasons that are not a bug. (answer 7)")
    w("")

    w("## 8. Your names and groups")
    w("")
    w("### Lab 7: Groups & labels (15 minutes)")
    w("")
    w("1. **Groups & labels** shows your *networks* (with the zone or interface name a firewall rule would use), *device labels* and *groups*. "
      "Zone names matter: Compare and Migrate use them to know which zone an address is in.")
    w("2. A device can be in several groups. Mark a group **isolated behind a gateway** if its members may only reach the outside through one controlled path.")
    w("3. *Download as JSON* and *Load from a JSON file* move all of this between projects.")
    w("")
    w("Labels are yours; the tool never decides what a device is.")
    w("")

    w("## 9. Proposals")
    w("")
    w("### The directional model")
    w("")
    w("RuleTruss's own policy form: a policy says **From** groups may **start** connections to **To** groups. The reverse direction is a separate policy. Replies need no "
      "policy. Policies have no ports, no deny and no order (those are shown as information). A separate *external egress* policy covers endpoints that may only "
      "reach named outside addresses. The model is the tool's own, not any product's format: the output is a worksheet you apply by hand.")
    w("")
    w("### Lab 8: Preserve and narrow (25 minutes)")
    w("")
    w(f"1. **Migrate**, *Preserve what is configured*, source `perimeter-asa.cfg`, then *Build directional policies*. The summary says {f['preserve']['summary']['blocked_rules']} of "
      f"{f['preserve']['summary']['source_rules']} rules could not be turned into group policies. Read each reason under *Gaps*.")
    w(f"2. Choose *Propose narrower from observation*. It proposes {f['narrow']['summary']['policies']} policies from {f['narrow']['summary']['communications_used']} observed "
      f"communications; {f['narrow']['summary']['policies_that_broaden_access']} are flagged because group membership grants more address pairs than were seen.")
    w("3. Open a flagged policy's detail: *granted* against *observed* address pairs shows exactly where a group is too coarse.")
    w("4. Uncertain directions are held back for review, not turned into policy. Observation-based proposals need you to tick that you have read the observation limits before you can export them.")
    w("")
    w("*Check yourself:* Why can a proposal from observation never be a complete policy? (answer 8)")
    w("")
    w("### Lab 9: Translate to another firewall (25 minutes)")
    w("")
    w(f"1. Under *Translate to another firewall*, take the FortiOS export to **Cisco IOS**. {f['ios']['summary']['return_rules_added']} return rules are added and marked "
      "**broader**: a stateless ACL cannot track replies. An IPv6 default-deny is added, because an IPv4 ACL does not filter IPv6.")
    w(f"2. Take the ASA export to **FortiOS**: {f['asa_forti']['summary']['translated']} rules translated, {f['asa_forti']['summary']['blocked']} blocked, each with its reason.")
    w("3. Read the generated text: blocked rules are **comments**, never \"any\". Interface names are placeholders such as `<TARGET-IF:zone>`; you map them.")
    w("4. Look at the top of the result. If it says **Diagnostic preview: not deployable**, something is unsupported, unresolved or still a placeholder; "
      "the generated text carries the same banner and exporting it needs your acknowledgement. Open *Every source policy and what became of it*: "
      "each policy has an id and exactly one of *translated*, *implemented* (by the target's own behaviour), *unsupported*, *unresolved* or *not-applicable*.")
    w("5. Read *Validation on sampled connections*, especially *Limits of this comparison*. The tool parses its own output back and compares decisions on sample connections. "
      "That catches mistakes in translation; it is not a proof of equivalence.")
    w("")
    w("The rule of the translator: if a condition cannot be expressed on the destination, the rule is **blocked** and explained, never widened.")
    w("")

    w("## 10. Exporting and cleaning up")
    w("")
    w("**Export & AI** produces Markdown and JSON worksheets, CSV tables, firewall text, a communications table and a devices table. CSV cells that a spreadsheet could "
      "run as formulas are neutralised, and text from files is escaped. The AI feature is off unless the server was started with `--ai-endpoint`, and then it only "
      "sends parsed statements, never raw files.")
    w("")
    w("**Delete.** *Data & privacy* has *Delete this project* and *Delete all data*. Deletion overwrites file contents first as a best effort; that cannot be guaranteed on "
      "SSDs, snapshots or backups. Treat the data folder like the exports themselves.")
    w("")

    w("## 11. UniFi gateways")
    w("")
    w("UniFi shows a zone matrix and a policy table, and its policies work differently from a classic rule list. Real exports come from `tools/unifi_export.py` "
      "(steps in [EXPORT_UNIFI.md](EXPORT_UNIFI.md)); for practice use the example.")
    w("")
    w("### Lab 10: the UniFi example (25 minutes)")
    w("")
    w("1. On **Import**, press **Load the UniFi example**, then open **Configuration**. The first card after the summary is the **Zone matrix**: rows start a connection, "
      "columns receive it. Click *IoT* to *Internal*.")
    w(f"   Its cell reads **{f['cells'][('IoT', 'Internal')]['label']}**: the pair ends in UniFi's predefined *Block All Traffic*, one of your policies allows something first, "
      "and replies are let in by the predefined *Allow Return Traffic*.")
    w("2. In the cell's list, find *Block IoT to LAN*. It is limited to the connection state **New**, so it blocks new connections but not replies.")
    w(f"3. Now click *Internal* to *Internal*: **{pitfall['label']}**. *Block Servers to LAN* is on purpose set for **all** states.")
    w("4. Open **Compare**. Find the Laptop to NAS conversation and read its reply line: a policy for the reverse direction matches the replies and blocks them, so the "
      "connection would not work. This is a real UniFi mistake: a block for all states also blocks the replies of connections the other side started, unless an earlier "
      "policy lets them through. The fix is to limit the block to *New* (and *Invalid*), or to put a return-traffic allow written in the replies' direction above it.")
    w("5. Open **Compare** rows for the camera and the TV. One is *permitted*, one *would be denied* by *Block IoT to LAN*, and one *cannot be decided* because a policy "
      "depends on a domain name. Read why in the detail.")
    w("")
    w("Things to remember: the gateway's own addresses are the *Gateway* zone, any other public address is *External*, and an unknown private address has no zone, so it is "
      "undecidable. Predefined policies (*Allow All*, *Block All*, *Allow Return Traffic*, *Block Invalid Traffic*, *Isolated Networks*) are marked as UniFi's own and never "
      "reported as broad or conflicting. UniFi's behaviour for traffic outside the policy table (port forwards, inspection) is not modelled.")
    w("")
    w("*Check yourself:* A policy allows WIRELESS to CAMERAS with the connection state *Return Traffic*. Does that let a phone on WIRELESS open a connection to a camera? (answer 9)")
    w("")

    w("## 12. A method for a real review")
    w("")
    w("1. **Write the question** (\"can the vendor reach X?\", \"what must stay open when we replace this firewall?\"). Tools answer questions.")
    w("2. **Import traffic** from the right places and record each capture point. One capture is one view.")
    w("3. **Label and group** what you know; leave what you do not know unlabelled.")
    w("4. **Read the Inventory and Graph** for surprises before reading any rules.")
    w("5. **Import the configuration** and read *Notes* and *Rule analysis* first; they say how far to trust the rest.")
    w("6. **Compare**, and treat *cannot decide* as a to-do list, not noise.")
    w("7. **Propose** (preserve first, then narrow) and read every warning. A proposal built from observation covers only what was seen.")
    w("8. **Have a person approve** each proposed change, apply it by hand, and keep the exports from before and after.")
    w("9. **Delete** the project when the review is over.")
    w("")
    w("What not to conclude: that a rule is unused because nothing matched it; that a device is what it says it is; that a flow is needed because it was seen; "
      "that a translated rule set is equivalent because validation passed.")
    w("")

    w("## Appendix A: tab by tab")
    w("")
    w("| Tab | Needs | What it gives you |")
    w("| --- | --- | --- |")
    w("| Import | nothing | add captures, logs and exports; load an example; background progress for big files |")
    w("| Inventory | traffic | devices, subnets, direction confidence, MAC and identity, who initiated to whom |")
    w("| Communications | traffic | every conversation in plain words, with filters and evidence |")
    w("| Graph | traffic | the relationships, resizable, with drill-down and a sample of the traffic |")
    w("| Configuration | a device export | rules in order, notes, rule analysis, zone matrix (UniFi), NAT |")
    w("| Compare | traffic and an export | what each rule would do with each observed conversation |")
    w("| Groups & labels | a project | your networks, labels and groups |")
    w("| Migrate | traffic or an export | directional policies (preserve or narrow) and firewall translation with validation |")
    w("| Export & AI | traffic or an export | downloads; the optional, off-by-default AI helper |")
    w("| Data & privacy | nothing | where data is kept, deletion, vendor names, the network statement |")
    w("")

    w("## Appendix B: glossary")
    w("")
    w("| Term | Meaning |")
    w("| --- | --- |")
    w("| Initiator / responder | the side that started a conversation / the side that answered |")
    w("| Flow / communication | one connection / all flows between the same two endpoints on the same service |")
    w("| Capture point | where a capture was taken (SPAN port, tap, host) |")
    w("| Confidence | high, medium, low, unknown: how sure the tool is about who started a flow |")
    w("| Indeterminate / cannot decide | the answer depends on something the tool cannot evaluate |")
    w("| Shadowed / redundant / conflict | rule analysis terms (section 6) |")
    w("| Stateful / stateless | whether replies to allowed connections are allowed automatically |")
    w("| Zone | a named security area a rule refers to (an interface on some products) |")
    w("| OUI | the part of a MAC address that names the card's maker |")
    w("| Egress policy | a directional policy for endpoints that may only reach named outside addresses |")
    w("| Evidence | the packet numbers or config lines behind a statement |")
    w("")

    w("## Appendix C: when something does not work")
    w("")
    w("| Symptom | Likely cause and fix |")
    w("| --- | --- |")
    w("| \"missing or wrong access token\" | open the address printed when the server started; the token changes on every start |")
    w("| Port already in use | another copy is running; stop it, or start with `--port 8766` |")
    w("| A tab has a padlock | it is waiting for something; click it to see what |")
    w("| Import says the file is too large | raise `--max-capture-mb` and restart (section 4) |")
    w("| Import stops at the time limit | raise `--parse-minutes`; the progress line shows how far it got |")
    w("| \"format not recognised\" | check it is a full export (for ASA `show running-config`; for PAN-OS the XML; for UniFi the file made by the export tool) |")
    w("| Everything is *cannot decide* | zones missing: on Groups & labels give each subnet the zone name the firewall uses |")
    w("| Compare shows few rows | most traffic does not cross that device; tick *show the rest* |")
    w("| No card makers shown | download the vendor names on Data & privacy (optional) |")
    w("| The graph is crowded | choose *Devices*, open one subnet, or set *Labels* to *hover only* |")
    w("")

    w("## Appendix D: answers")
    w("")
    w("1. (Lab 1) The tab has nothing to show yet; click it to see what is missing. 2. OBSERVED, CONFIGURED, PROPOSED. PROPOSED only means a suggestion; no label means a device was changed.")
    w("3. (Lab 2) `10.30.1.11` answered ARP, so its own announcement ties the MAC to the address (confirmed). `10.20.0.70` was only seen sending frames, which is also what a router in front of it would look like, so it is probable.")
    w("4. (Lab 3) A SYN with no reply means the target did not answer (blocked, refused, or the reply path was not visible); a closed connection had a reply. A capture that starts mid-conversation has no SYN, so who started it is inferred from weaker evidence.")
    w("5. (Lab 4) No. Size and thickness show how many flows were seen, which depends on what the capture could see and for how long; importance is your judgement.")
    w("6. (Lab 5) No. It means the tool cannot tell; the rule might allow far less. The finding exists so you check it.")
    w("7. (Lab 6) The traffic does not pass through that device; the capture was taken before enforcement or at another point; the export is not what is running; the zones or subnets you defined do not match.")
    w("8. (Lab 8) Observation shows what happened in a window at a place. It cannot show rare jobs, failover paths or traffic that was blocked.")
    w("9. (Lab 10) No. *Return Traffic* matches only replies in the direction written. Starting a connection from WIRELESS needs the default or an allow for new connections, and the cameras' replies need a return-traffic allow written from CAMERAS to WIRELESS above any all-states block.")
    w("")
    return "\n".join(L) + "\n"


def main():
    text = build()
    if "--check" in sys.argv:
        return 0 if OUT.exists() and OUT.read_text(encoding="utf-8") == text else 1
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(text.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
