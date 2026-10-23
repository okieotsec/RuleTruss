# RuleTruss training guide

For network and security engineers who want to understand what is on a network and what a firewall allows, and to turn that into reviewed policy. Written for RuleTruss 0.1.1. **Everything in the examples is invented**, so you can click anything.

| | |
| --- | --- |
| Time | about 3 hours for everything; each lab stands alone and takes 10 to 20 minutes |
| You need | Python 3.12 or newer, a browser, and this repository. A real capture or firewall export is optional (section 4) |
| You will be able to | read a capture and say who started what, with how much certainty; read a firewall export and find what is wrong with it; set one against the other; produce a reviewable policy proposal; explain every one of those results to someone else |
| Reference | the [README](../README.md), [what the tool can read](SUPPORT_MATRIX.md), [its limits](LIMITATIONS_AND_ROADMAP.md), [UniFi export guide](EXPORT_UNIFI.md) |

How to use this guide: do the labs in order the first time. After each lab there are *check yourself* questions; the answers are in appendix D. Numbers in this guide come from the examples as they are shipped; if you see different ones, you are probably looking at a different file.

## 1. Ideas that make everything else easier

RuleTruss keeps three kinds of statement apart, and labels them everywhere:

| Label | Means | Comes from |
| --- | --- | --- |
| **OBSERVED** | something seen in a capture or flow log | packets and logs |
| **CONFIGURED** | something a device is set to do | a firewall, router or switch export |
| **PROPOSED** | something this tool suggests | its own analysis; never applied to any device |

Three habits of the tool explain most of what you will see:

1. **It says how sure it is.** A TCP handshake proves who started a connection (*high*). A capture that begins mid-conversation, or one-way UDP, cannot prove it (*medium*, *low*, *unknown*). Application names have three levels: *confirmed* (the payload decoded), *probable* (a weak signature), *possible* (only the port number suggests it).
2. **Unknown stays unknown.** When a rule depends on something the tool cannot evaluate (an application, a user, a schedule, a domain, a region), the answer is *cannot decide*, never a guess. "Would be allowed" and "would be blocked" are only said when they are certain.
3. **Silence is not absence.** A capture shows one place for one period. A device that never appears may simply not be visible from there.

Everything is local: nothing leaves your computer, the server only answers your own browser, and the tool never changes a live device.

## 2. Setting up

```bash
.venv/bin/python -m ruletruss
```

It prints an address ending in `#token=...`. Open **that** address; the token changes every time the server starts, so an old browser tab stops working after a restart. After updating the program, stop it with Ctrl+C and start it again.

Useful options (see the README for all): `--port N` if 8765 is busy; `--data-dir PATH` for where projects are stored; `--max-capture-mb`, `--max-packets`, `--parse-minutes` for big captures (section 4). The top-right buttons switch the colour theme (system, light, dark) and **Show explanations**, which opens every long explanation at once.

**Tabs that are not ready.** The tabs run left to right in the order you work: *Import*, then the three views of traffic, then the configuration views, then the planning tabs. A tab that has nothing to show yet has a small padlock. Click it and the page tells you what is missing (a project, a capture, a device export) and offers a button to fix it. *Import*, *Groups & labels* (needs a project only) and *Data & privacy* never lock.

## 3. Lab 1: load an example and find your way around (10 minutes)

Goal: see every tab with real content and learn where things are.

1. Open the address from step 2. On **Import**, press **Load the Riverbend example**. It is a fictional water-treatment plant: 4 captures, a flow log and five firewall exports (198 flows between 47 devices).
2. Click **Inventory**. Read the *coverage and limits* line first: it says where each capture was taken.
3. Click **Communications**, then a row. The first line is the plain-language sentence; the rest is why.
4. Click **Graph**, then a circle, then **Fit**.
5. Click **Configuration** and pick `perimeter-asa.cfg`. Look at *Rule analysis*.

You should see: 198 flows, 82 communications; direction confidence high 117, medium 33, low 47, unknown 1.

*Check yourself:* 1. What does the padlock on a tab mean? 2. What are the three labels, and which one means "nothing was changed anywhere"?

## 4. Importing your own data

**What you can import.** Captures: PCAP and PCAPNG (Ethernet, raw IP, Linux cooked, loopback; IPv4, IPv6, VLAN tags). Flow logs: Zeek `conn.log` (TSV or JSON lines). Device exports: Cisco ASA, Cisco IOS/IOS-XE ACLs, Palo Alto PAN-OS XML, Fortinet FortiOS, pfSense/OPNsense, and UniFi (a JSON file made with `tools/unifi_export.py`, section 11). The type is recognised from the content, not the file name.

**Say where a capture was taken** in *Capture point*. The tool never guesses it, and it matters: traffic that does not pass that point is not seen.

**Big captures.** The defaults protect against hostile or broken files: 512 MB, 5,000,000 packets, 200,000 flows, 10 minutes and 2 GB of memory per file. For a capture you trust, raise them when you start the server, for example `--max-capture-mb 4096 --max-packets 60000000 --parse-minutes 90 --parse-memory-gb 4`. Files over 32 MB are analysed in the background with a progress line and a **Stop** button; you can keep using other tabs. A measured 810 MB capture took about two minutes. Keep free disk space for the file and its analysis.

**Vendor names (optional).** A MAC address's first half names the maker of the network card. RuleTruss does not ship that list; on **Data & privacy**, the *Vendor names* card has one button that downloads it from the IEEE (the only time the tool uses the network). Without it, MAC addresses still work and the *Card maker* column is empty.

**Your own files carry real addresses.** Imported files are stored in the data folder (readable only by you), and nothing is deleted until you delete it (section 10). Do not put real exports into an example or a shared project.

## 5. Reading what was seen

### Lab 2: Inventory and who started what (15 minutes)

1. On **Inventory**, read the matrix: *row initiated to column*. An empty cell means nothing was seen, not that nothing is allowed.
2. In *Devices*, click the SCADA-1 row (`10.20.0.10`). Its detail says what it said about itself.
3. Find `10.30.1.11`: its MAC address is **confirmed** (it answered ARP) and its identity reads *Pump controller (Example Controls; EC-100; revision V3.1)* (from a Modbus identification reply). Find `10.20.0.70`: its MAC is only **probable**. Why the difference? (answer 3)
4. Open *MACs shared by several addresses*: one MAC carries many addresses because it belongs to a router in front of them. RuleTruss never gives such a MAC to one of them.

A MAC names the card, not the device. It is shown with how it was learned (**confirmed**: the device announced it with ARP or DHCP; **probable**: only seen as the sender of its own frames), and a randomised or locally set MAC has no maker at all. Text a device sends about itself (LLDP, DHCP host name, SNMP, HTTP and SSH banners, Modbus and EtherNet/IP identity) is shown as what the device *said*; it can be wrong or forged. A TTL guess is shown apart as a weak hint.

### Lab 3: Communications and certainty (20 minutes)

1. On **Communications**, filter *Port* = `502`. Open the SCADA-1 to intake PLC 1 row.
   > SCADA-1 10.20.0.10 most likely initiated 2 TCP connections to Intake pump PLC 1 10.30.1.11 on port 502 · Modbus/TCP identified by decoding · direction medium confidence.
2. Open the unanswered Telnet attempt (filter *Port* = `23`):
   > HMI-2 10.20.0.61 initiated 1 TCP connection to RTU 31 10.30.3.31 on port 23 · Telnet possible (port number only) · no reply seen.
3. Open the DNP3 row from RTU 32 to SCADA-1 (port `20000`). The RTU started this one: its SYN is in the capture (direction **high**).
4. Open the S7 row from SCADA-1 to treatment PLC 1 (port `102`). Its direction is only **medium**. Read the note on why.

*Check yourself:* What is the difference between a SYN with no reply and a closed connection? Why is a mid-stream capture never *high*? (answer 4)

### Lab 4: The graph (15 minutes)

1. Open **Graph**. Circles are subnets (colours match the legend); arrows point from the side that started. Dashed red means some starters are uncertain.
2. **Resize** the box by dragging its bottom-right corner, or use *Size*. **Scroll** to zoom, drag the background to pan, drag a circle to move it, **Fit** to start over. *Labels* chooses how many names to show.
3. **Click** a circle: the panel on the right says how many conversations it started and answered, who it talks to, which services it offers and uses, and a small sample of the traffic with how sure each statement is. **Click an arrow** for one direction between two circles.
4. **Double-click** *Cell 1: intake* (or press *Open its devices*). You now see its three PLCs and the machines that talk to them. *Back to subnets* returns.
5. Click one of the PLCs, then press *See all its communications*: you land on **Communications** already filtered to that address.

*Check yourself:* A circle is large and its arrows are thick. Does that mean it is important? (answer 5)

## 6. Reading what is configured

### Lab 5: Configuration and rule analysis (20 minutes)

1. **Configuration**, pick `perimeter-asa.cfg`. Read *Notes*: they list what could not be read or evaluated.
2. In the rules table click a row for its plain-language sentence and the line it came from.
3. Read *Rule analysis*. Terms: **shadowed** (a later rule can never match because an earlier one already covers it), **redundant** (same, same action), **conflict** (overlap with different actions; the earlier rule wins), **broad** (any source to any destination), **unevaluated** (a condition the tool cannot decide).
4. Switch to the PAN-OS file and look at the *NAT* card: NAT statements are recorded, not applied.

*Check yourself:* A rule is marked *unevaluated* because it uses an application. Is it safe to assume it allows everything? (answer 6)

## 7. Observed against configured

### Lab 6: Compare (20 minutes)

1. **Compare**, pick each firewall in turn. The counts at the top say how many observed conversations *cross this device*: `perimeter-asa.cfg`: 13 of 82; `it-ot-boundary-panos.xml`: 9 of 82; `ops-field-fortios.conf`: 44 of 82; `cell3-router-ios.cfg`: 10 of 82; `vendor-access-pfsense.xml`: 3 of 82.
2. Why only some? A firewall can only judge traffic that passes through it. Tick *show the rest* to see the others; treat their results with care.
3. Open an *allow* row and a *deny* row. The detail says which rule matched, in what position, and anything that makes the answer uncertain.
4. Read *Allow rules no observed traffic matched*. It is **not** a list of unused rules: a capture covers one window and one place.

*Check yourself:* Compare says "would be denied" for a flow that clearly works in real life. List three reasons that are not a bug. (answer 7)

## 8. Your names and groups

### Lab 7: Groups & labels (15 minutes)

1. **Groups & labels** shows your *networks* (with the zone or interface name a firewall rule would use), *device labels* and *groups*. Zone names matter: Compare and Migrate use them to know which zone an address is in.
2. A device can be in several groups. Mark a group **isolated behind a gateway** if its members may only reach the outside through one controlled path.
3. *Download as JSON* and *Load from a JSON file* move all of this between projects.

Labels are yours; the tool never decides what a device is.

## 9. Proposals

### The directional model

RuleTruss's own policy form: a policy says **From** groups may **start** connections to **To** groups. The reverse direction is a separate policy. Replies need no policy. Policies have no ports, no deny and no order (those are shown as information). A separate *external egress* policy covers endpoints that may only reach named outside addresses. The model is the tool's own, not any product's format: the output is a worksheet you apply by hand.

### Lab 8: Preserve and narrow (25 minutes)

1. **Migrate**, *Preserve what is configured*, source `perimeter-asa.cfg`, then *Build directional policies*. The summary says 7 of 15 rules could not be turned into group policies. Read each reason under *Gaps*.
2. Choose *Propose narrower from observation*. It proposes 26 policies from 67 observed communications; 24 are flagged because group membership grants more address pairs than were seen.
3. Open a flagged policy's detail: *granted* against *observed* address pairs shows exactly where a group is too coarse.
4. Uncertain directions are held back for review, not turned into policy. Observation-based proposals need you to tick that you have read the observation limits before you can export them.

*Check yourself:* Why can a proposal from observation never be a complete policy? (answer 8)

### Lab 9: Translate to another firewall (25 minutes)

1. Under *Translate to another firewall*, take the FortiOS export to **Cisco IOS**. 8 return rules are added and marked **broader**: a stateless ACL cannot track replies. An IPv6 default-deny is added, because an IPv4 ACL does not filter IPv6.
2. Take the ASA export to **FortiOS**: 6 rules translated, 9 blocked, each with its reason.
3. Read the generated text: blocked rules are **comments**, never "any". Interface names are placeholders such as `<TARGET-IF:zone>`; you map them.
4. Look at the top of the result. If it says **Diagnostic preview: not deployable**, something is unsupported, unresolved or still a placeholder; the generated text carries the same banner and exporting it needs your acknowledgement. Open *Every source policy and what became of it*: each policy has an id and exactly one of *translated*, *implemented* (by the target's own behaviour), *unsupported*, *unresolved* or *not-applicable*.
5. Read *Validation on sampled connections*, especially *Limits of this comparison*. The tool parses its own output back and compares decisions on sample connections. That catches mistakes in translation; it is not a proof of equivalence.

The rule of the translator: if a condition cannot be expressed on the destination, the rule is **blocked** and explained, never widened.

## 10. Exporting and cleaning up

**Export & AI** produces Markdown and JSON worksheets, CSV tables, firewall text, a communications table and a devices table. CSV cells that a spreadsheet could run as formulas are neutralised, and text from files is escaped. The AI feature is off unless the server was started with `--ai-endpoint`, and then it only sends parsed statements, never raw files.

**Delete.** *Data & privacy* has *Delete this project* and *Delete all data*. Deletion overwrites file contents first as a best effort; that cannot be guaranteed on SSDs, snapshots or backups. Treat the data folder like the exports themselves.

## 11. UniFi gateways

UniFi shows a zone matrix and a policy table, and its policies work differently from a classic rule list. Real exports come from `tools/unifi_export.py` (steps in [EXPORT_UNIFI.md](EXPORT_UNIFI.md)); for practice use the example.

### Lab 10: the UniFi example (25 minutes)

1. On **Import**, press **Load the UniFi example**, then open **Configuration**. The first card after the summary is the **Zone matrix**: rows start a connection, columns receive it. Click *IoT* to *Internal*.
   Its cell reads **Block, 1 allowed**: the pair ends in UniFi's predefined *Block All Traffic*, one of your policies allows something first, and replies are let in by the predefined *Allow Return Traffic*.
2. In the cell's list, find *Block IoT to LAN*. It is limited to the connection state **New**, so it blocks new connections but not replies.
3. Now click *Internal* to *Internal*: **Allow, 1 blocked**. *Block Servers to LAN* is on purpose set for **all** states.
4. Open **Compare**. Find the Laptop to NAS conversation and read its reply line: a policy for the reverse direction matches the replies and blocks them, so the connection would not work. This is a real UniFi mistake: a block for all states also blocks the replies of connections the other side started, unless an earlier policy lets them through. The fix is to limit the block to *New* (and *Invalid*), or to put a return-traffic allow written in the replies' direction above it.
5. Open **Compare** rows for the camera and the TV. One is *permitted*, one *would be denied* by *Block IoT to LAN*, and one *cannot be decided* because a policy depends on a domain name. Read why in the detail.

Things to remember: the gateway's own addresses are the *Gateway* zone, any other public address is *External*, and an unknown private address has no zone, so it is undecidable. Predefined policies (*Allow All*, *Block All*, *Allow Return Traffic*, *Block Invalid Traffic*, *Isolated Networks*) are marked as UniFi's own and never reported as broad or conflicting. UniFi's behaviour for traffic outside the policy table (port forwards, inspection) is not modelled.

*Check yourself:* A policy allows WIRELESS to CAMERAS with the connection state *Return Traffic*. Does that let a phone on WIRELESS open a connection to a camera? (answer 9)

## 12. A method for a real review

1. **Write the question** ("can the vendor reach X?", "what must stay open when we replace this firewall?"). Tools answer questions.
2. **Import traffic** from the right places and record each capture point. One capture is one view.
3. **Label and group** what you know; leave what you do not know unlabelled.
4. **Read the Inventory and Graph** for surprises before reading any rules.
5. **Import the configuration** and read *Notes* and *Rule analysis* first; they say how far to trust the rest.
6. **Compare**, and treat *cannot decide* as a to-do list, not noise.
7. **Propose** (preserve first, then narrow) and read every warning. A proposal built from observation covers only what was seen.
8. **Have a person approve** each proposed change, apply it by hand, and keep the exports from before and after.
9. **Delete** the project when the review is over.

What not to conclude: that a rule is unused because nothing matched it; that a device is what it says it is; that a flow is needed because it was seen; that a translated rule set is equivalent because validation passed.

## Appendix A: tab by tab

| Tab | Needs | What it gives you |
| --- | --- | --- |
| Import | nothing | add captures, logs and exports; load an example; background progress for big files |
| Inventory | traffic | devices, subnets, direction confidence, MAC and identity, who initiated to whom |
| Communications | traffic | every conversation in plain words, with filters and evidence |
| Graph | traffic | the relationships, resizable, with drill-down and a sample of the traffic |
| Configuration | a device export | rules in order, notes, rule analysis, zone matrix (UniFi), NAT |
| Compare | traffic and an export | what each rule would do with each observed conversation |
| Groups & labels | a project | your networks, labels and groups |
| Migrate | traffic or an export | directional policies (preserve or narrow) and firewall translation with validation |
| Export & AI | traffic or an export | downloads; the optional, off-by-default AI helper |
| Data & privacy | nothing | where data is kept, deletion, vendor names, the network statement |

## Appendix B: glossary

| Term | Meaning |
| --- | --- |
| Initiator / responder | the side that started a conversation / the side that answered |
| Flow / communication | one connection / all flows between the same two endpoints on the same service |
| Capture point | where a capture was taken (SPAN port, tap, host) |
| Confidence | high, medium, low, unknown: how sure the tool is about who started a flow |
| Indeterminate / cannot decide | the answer depends on something the tool cannot evaluate |
| Shadowed / redundant / conflict | rule analysis terms (section 6) |
| Stateful / stateless | whether replies to allowed connections are allowed automatically |
| Zone | a named security area a rule refers to (an interface on some products) |
| OUI | the part of a MAC address that names the card's maker |
| Egress policy | a directional policy for endpoints that may only reach named outside addresses |
| Evidence | the packet numbers or config lines behind a statement |

## Appendix C: when something does not work

| Symptom | Likely cause and fix |
| --- | --- |
| "missing or wrong access token" | open the address printed when the server started; the token changes on every start |
| Port already in use | another copy is running; stop it, or start with `--port 8766` |
| A tab has a padlock | it is waiting for something; click it to see what |
| Import says the file is too large | raise `--max-capture-mb` and restart (section 4) |
| Import stops at the time limit | raise `--parse-minutes`; the progress line shows how far it got |
| "format not recognised" | check it is a full export (for ASA `show running-config`; for PAN-OS the XML; for UniFi the file made by the export tool) |
| Everything is *cannot decide* | zones missing: on Groups & labels give each subnet the zone name the firewall uses |
| Compare shows few rows | most traffic does not cross that device; tick *show the rest* |
| No card makers shown | download the vendor names on Data & privacy (optional) |
| The graph is crowded | choose *Devices*, open one subnet, or set *Labels* to *hover only* |

## Appendix D: answers

1. (Lab 1) The tab has nothing to show yet; click it to see what is missing. 2. OBSERVED, CONFIGURED, PROPOSED. PROPOSED only means a suggestion; no label means a device was changed.
3. (Lab 2) `10.30.1.11` answered ARP, so its own announcement ties the MAC to the address (confirmed). `10.20.0.70` was only seen sending frames, which is also what a router in front of it would look like, so it is probable.
4. (Lab 3) A SYN with no reply means the target did not answer (blocked, refused, or the reply path was not visible); a closed connection had a reply. A capture that starts mid-conversation has no SYN, so who started it is inferred from weaker evidence.
5. (Lab 4) No. Size and thickness show how many flows were seen, which depends on what the capture could see and for how long; importance is your judgement.
6. (Lab 5) No. It means the tool cannot tell; the rule might allow far less. The finding exists so you check it.
7. (Lab 6) The traffic does not pass through that device; the capture was taken before enforcement or at another point; the export is not what is running; the zones or subnets you defined do not match.
8. (Lab 8) Observation shows what happened in a window at a place. It cannot show rare jobs, failover paths or traffic that was blocked.
9. (Lab 10) No. *Return Traffic* matches only replies in the direction written. Starting a connection from WIRELESS needs the default or an allow for new connections, and the cameras' replies need a return-traffic allow written from CAMERAS to WIRELESS above any all-states block.

