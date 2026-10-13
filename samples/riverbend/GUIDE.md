# Riverbend: a guided tour of RuleTruss

**Everything here is fictional.** Riverbend Water Treatment is an invented plant. The captures are generated, not recorded; the addresses are private ranges or the reserved documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); the device configurations are written, not exported. Nothing is real, so nothing needs protecting. The files were built so that, together, they show every idea in the application, including the places where the tool says *I cannot tell*.

Regenerate everything, including this page, with `python tools/make_samples.py`. Each teaching point below is also an automated test (`tests/test_riverbend.py`, named by the same id), so this guide cannot describe something the data does not show.

## Load it

**Quickest:** start RuleTruss, open the Import tab, press **Create the Riverbend example**. It imports every file below and sets up the subnets, labels and groups.

**By hand** (to see each step): create a project; import the three captures, the flow log and the five configurations (drag them in; set the *observation point* text for each capture, as in the table); then on **Groups & labels** use *Load from a JSON file* with `context.json` and press Save.

## The plant

```text
  Internet / vendor --------+
   198.51.100.0/24          |   vendor access (pfSense)            perimeter (Cisco ASA)
   203.0.113.0/24, 192.0.2.0/24                                          |
                            +--------------------------+------------+
                                                       |
   corp 10.10.0.0/16 ---- ASA ---- dmz 10.40.0.0/24   (jump host .10, historian replica .20, patch .30, file transfer .40)
                                      |
                                   PAN-OS  (IT/OT boundary)
                                      |
   ops 10.20.0.0/24  (SCADA .10 .11, historian .20, engineering .50 .51, HMIs .60 .61, monitor .70, backup .80, services .2)
        |                             |
      FortiOS (ops-field)          IOS router (ACLs)
        |        |                    |
   cell1 10.30.1.0/24   cell2 10.30.2.0/24    cell3 10.30.3.0/24
   Modbus/TCP PLCs      S7comm PLCs + EtherNet/IP   DNP3 RTUs + IEC 104 gateway
```

## The files

| File | What it is | Where it was 'taken' |
| --- | --- | --- |
| `captures/ops-field-span.pcapng` | 5 minutes of steady control traffic | SPAN of the trunk between operations and the field cells (fictional) |
| `captures/dmz-tap.pcap` | 30 minutes of sparse, human-driven traffic | Tap on the DMZ firewall links (fictional) |
| `captures/cell-switch-late-start.pcapng` | 90 seconds, started in the middle of conversations | Laptop on a cell switch port, started late (fictional) |
| `flow-logs/corp-edge-conn.log` | Zeek connection summaries (no packets) | Zeek at the corporate edge (fictional) |
| `configs/perimeter-asa.cfg` | Cisco ASA 9.16 running-config | the corporate/DMZ/Internet firewall |
| `configs/it-ot-boundary-panos.xml` | PAN-OS 10.2 XML | the DMZ-to-operations firewall |
| `configs/ops-field-fortios.conf` | FortiOS 7.2 CLI | the operations-to-cells firewall (cells 1 and 2) |
| `configs/cell3-router-ios.cfg` | IOS-XE 17.9 ACLs (stateless) | the router in front of cell 3 |
| `configs/vendor-access-pfsense.xml` | pfSense 23.09 config.xml | the vendor remote-access appliance |
| `context.json` | subnets, labels and groups | what you, the engineer, know |

In total the three captures and the log hold **197 flows** that group into **81 communications** between **43 devices**. Direction confidence across the flows: high 117, medium 32, low 47, unknown 1.

## How to read the application (a suggested order)

1. **Inventory** shows what was seen and, before anything else, the *coverage and limits* box: three capture points, none of which sees everything. Read the matrix as *row initiated to column*; an empty cell means nothing was seen, not that nothing happens. No device is given a role; the labels are yours (from `context.json`).
2. **Communications** is where the explanations live. Click any row for the plain-language sentence, why the direction was chosen, how the application was identified, and the evidence (packet numbers).
3. **Graph** draws the same facts: arrows run from the side that initiated. Switch to *Devices*.
4. **Configuration** shows one device's rules in order, with the analysis (shadowed, redundant, conflicting, broad rules) and the things the tool did *not* evaluate.
5. **Compare** sets observed traffic against one configuration. By default it shows only traffic that **crosses that device** (both ends in zones it knows), because a configuration cannot be judged by traffic that never reaches it. perimeter-asa.cfg: 13 of 81; it-ot-boundary-panos.xml: 9 of 81; ops-field-fortios.conf: 44 of 81; cell3-router-ios.cfg: 10 of 81; vendor-access-pfsense.xml: 3 of 81.
6. **Groups & labels**, then **Migrate** (the two workflows, then translation), then **Export & AI**.

## What to look for: observed traffic

| Id | Where to look | What you should see | Why it matters for the design |
| --- | --- | --- | --- |
| T01 | Communications, port 502 | SCADA-1 to the intake PLCs is **Modbus/TCP, confirmed** (the payload was decoded). Engineering WS-2 to PLC 3 on port 502 is only **possible**, and the basis says the payload did *not* decode as Modbus. | A port number is never proof of a protocol. |
| T02 | Historian to its replica, port 1433 | *Microsoft SQL Server*, **possible**: this tool does not decode that protocol, so it offers the port's usual meaning and says so. | The tool shows the limit of its own evidence. |
| T03 | Engineering WS-2 to PLC 4 on port 4000 | No application at all. | Unknown stays unknown. |
| T04 | Ports 102, 20000, 2404 | S7comm, DNP3 are confirmed from their headers (DNP3's CRC is checked); IEC 104 is only **probable** (a weak signature). | Three levels: confirmed, probable, possible. |
| T05 | RTU 32 to SCADA-1, port 20000 | **The RTU initiated**: its SYN is in the capture. SCADA servers also poll RTUs on the same port. | Two directions between the same groups are two separate policies. |
| T06 | SCADA-1 to treatment PLC 1, port 102 | Direction is only **medium**: one of the captures started after the connection was set up, and the notes say the initiator is not proven. | Mid-stream captures cannot prove who connected. |
| T07 | SCADA-1 to RTU 33, port 20000 | A note that only one direction was captured. | Asymmetric capture is reported, not hidden. |
| T08 | PLCs to the ops services host, port 514 | Syslog datagrams one way only: direction **low**, and no policy is proposed from them in the *narrow* workflow (listed under review). | UDP gives no handshake, so it never earns more than medium. |
| T09 | PLCs to Engineering WS-1, port 44818 | Replies to a discovery broadcast, but a one-direction flow cannot show that, so each looks like an initiation with **low** confidence. | Replies are not reverse initiation; the tool says when it cannot tell them apart. |
| T10 | Review items in the narrow plan | DHCP from 0.0.0.0, SSDP, mDNS and the ENIP broadcast are not turned into policy. | Discovery noise is not a relationship between endpoints. |
| T11 | HMI-2 to RTU 31 port 23; BI server to the jump host; contractor laptop to the file server (SMB) | SYN packets with no reply. The explanation says no reply was captured. | An attempt is not a connection, and not proof of a need. |
| T12 | Treatment PLC 1 to 203.0.113.10:443 | A TLS connection with the server name `telemetry.vendor.example`. The *Treatment PLCs* group is marked isolated behind a gateway, so the narrow plan proposes an **external egress policy** with that prefix and DNS name. | The egress policy type is separate from group policies. |
| T13 | SCADA-1 to intake PLC 1, port 502 | Two flows, from two captures, merged; the communication takes the **weakest** direction confidence. | Several observation points combine conservatively. |
| T14 | Corporate DNS to 9.9.9.9 | From the Zeek log: direction **low** and labelled as Zeek's own inference. | A summary is not packet evidence. |

## What to look for: configurations

| Id | Where to look | What you should see | Why it matters |
| --- | --- | --- | --- |
| C01 | ASA, Configuration and Compare | `CORP-IN:4` is a temporary "all of corporate to the whole DMZ" rule. It **allows** the BI server's and the contractor laptop's unanswered attempts, and the later `deny` for the BI server is reported as **shadowed**. | One broad rule hides the specific ones; the comparison shows who it really admits. |
| C02 | ASA, Compare | The vendor's RDP is **indeterminate** (an identity condition); the patch server's HTTPS to the Internet is **indeterminate** (an FQDN object); `OUTSIDE-IN:3`, an old vendor range, matched nothing observed. | Conditions the tool cannot evaluate are reported, not guessed. 'Matched nothing' is not 'unused'. |
| C03 | ASA, translate to FortiOS | The jump-host rules are **blocked**: the ASA writes rules with the real address while FortiOS writes them as received, and a static NAT touches that address. Identity, schedule and FQDN rules are blocked too. | Address context and NAT are where translations silently go wrong. |
| C04 | PAN-OS | `application-default` and App-ID rules are **indeterminate**; a dynamic address group cannot be resolved; one rule is negated; one is `intrazone`; one is disabled; there is a destination NAT. | The model keeps what it cannot evaluate. |
| C05 | FortiOS, Compare | Engineering WS-2's odd traffic (the non-Modbus on 502, port 4000, a PLC web page) is **allowed by rule 5**, a leftover commissioning rule that permits everything from engineering to the cells. Rule 6 is redundant behind it. A virtual IP is flagged because FortiOS gives such policies priority over list order. Rule 15 has no action set, which FortiOS treats as deny. | A permissive rule makes observed traffic look fine. |
| C06 | IOS | The ACLs are **stateless**: `CELL3-IN:2` only lets replies back (TCP `established`). One entry has a wildcard mask that cannot be expressed as a network, one uses a reflexive option; both make nearby answers **indeterminate** (including the IEC 104 gateway, which has no visible permit). | Stateless ACLs need return rules; unreadable entries are surfaced, not skipped. |
| C07 | pfSense | An alias that is a URL table and one that is a host name cannot be resolved; a rule keeps no state; one is scheduled; a floating Quick rule comes first. Its rules use the translated (internal) address after the port forward. | Same ideas, different vocabulary. |
| C08 | Compare, the checkbox | Each device 'sees' only part of the traffic. Tick *also show traffic that does not cross this device* to see the rest. | Judge a rule base only by traffic that reaches it. |

## What to look for: migration

| Id | Where to look | What you should see | Why it matters |
| --- | --- | --- | --- |
| M01 | Migrate, *Preserve*, source = the ASA | 7 of its 15 rules cannot be turned into group policies (no group lies wholly inside the addresses, or an identity/schedule/FQDN condition), 4 deny rules have no equivalent, and services are listed as information only. The verdict line says access is broadened or restrictions dropped. | The directional model is simpler than a firewall; the loss is counted. |
| M02 | Migrate, *Narrower* | 26 policies are proposed from 67 communications, and 24 of them are flagged because group membership grants more address pairs than were observed (the *Corporate IT* group is a whole /16). Open the worksheet to see granted against observed. | Coarse groups are the main way a directional policy over-grants. Edit the groups and rebuild. |
| M03 | Migrate, translate the FortiOS config to Cisco IOS | 8 return rules are added and marked **broader** (a stateless ACL cannot track replies); an IPv6 default-deny ACL is added because an IPv4 ACL does not filter IPv6; the report explains that `established` matches any packet with ACK or RST set. | Stateful to stateless always costs something. |
| M04 | Translate the ASA to FortiOS | 6 rules translated, 9 blocked, each with the reason. Validation: 36 sampled connections agree, 6 could not be compared, and the limits of the comparison are printed. | The tool never turns a rule it cannot express into 'any'. |
| M05 | Any source, any destination | `tests/test_riverbend.py` translates all five configurations to all three destinations and fails if the destination allows something the source denied for a reason the report does not explain. | The migration check is part of the test suite. |

## Exercises

1. **Shrink a group, rebuild a plan.** In Groups & labels delete the *Corporate IT* group (a whole /16) and rebuild *Narrower*. Communications that used it now fall back to a smaller group, or are listed as *not in a group*; watch the granted-pair numbers fall.
2. **Find the leak.** Compare the FortiOS configuration, tick the *does not cross* box, and ask which rule admitted Engineering WS-2's port-4000 traffic. Then build the narrow plan and see that no such policy is proposed unless the traffic was seen.
3. **Two directions.** In the narrow plan find *Distribution RTUs to SCADA servers* and *SCADA servers to Distribution RTUs*. Open the evidence of each. Explain why one policy cannot cover both.
4. **Undo the egress.** Untick *isolated behind a gateway* on *Treatment PLCs* and rebuild. What happens to the 203.0.113.10 connection?
5. **Read a blocked rule.** Translate the ASA to FortiOS and read why the jump-host rules are blocked. What would you need to know about the NAT to translate them by hand?
6. **Make it fail.** Import `perimeter-asa.cfg` without `context.json`. Which comparisons become indeterminate, and why?

## What this example does not claim

It is not a model of any real plant, a benchmark of the application, or evidence that the parsers handle every real export; it only shows how the tool reasons. The captures contain no real protocol conversations beyond the headers the tool checks.
