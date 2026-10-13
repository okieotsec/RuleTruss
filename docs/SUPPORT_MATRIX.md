# Support matrix

"Supported" means an adapter exists in this repository **and** has automated tests against synthetic fixtures. It does not mean
validated on every product version, and nothing here is endorsed by, or certified with, any vendor. See
[SOURCES.md](SOURCES.md) for what each behaviour rests on, and the end of this page for the exact fixture versions.

## Candidates evaluated

| Platform | Config export | Policy-only export | Traffic logs / flows | Source import | Destination export | Decision |
| --- | --- | --- | --- | --- | --- | --- |
| Cisco ASA | `show running-config` text | `show running-config access-list` is a subset | syslog 302013/302015 (not read) | **Supported** | **Supported** (ACLs and `access-group`) | In the MVP: very common in OT perimeters, plain text, documented evaluation order. |
| Cisco IOS / IOS-XE ACLs | `show running-config` text | `show access-lists` (counters only; not read) | NetFlow (not read) | **Supported** (IPv4 and IPv6 ACLs, bindings) | **Supported** (stateless; return rules generated) | In the MVP: the clearest example of stateless behaviour. Zone-based firewall is not modelled. |
| Cisco FTD | Managed from FMC; no equivalent plain config export | FMC JSON export | FMC logs | Not supported | Not supported | Needs FMC export or API JSON; roadmap. |
| Palo Alto PAN-OS | Full config XML (`show config running`, Export named configuration snapshot) | Rulebase XML | Traffic log CSV (not read) | **Supported** (firewall config; not Panorama device groups) | Not yet | Source in the MVP; destination needs `set`-command generation and is on the roadmap. |
| Fortinet FortiOS | `show full-configuration` CLI text | `show firewall policy` | Traffic log (not read) | **Supported** (first VDOM) | **Supported** (address, service, policy, policy6) | In the MVP: widely used in OT; CLI text is easy to read and generate. |
| Juniper SRX | `show configuration` (hierarchy or `set` format) | `show security policies` | Session logs | Not supported | Not supported | Roadmap: from-zone/to-zone policies map well to the model. |
| Check Point | Management API or SmartConsole export | `show-access-rulebase` JSON | SmartLog export | Not supported | Not supported | Roadmap: needs the JSON rulebase export; layers and inline layers need care. |
| pfSense | `config.xml` | same | Filter log (not read) | **Supported** (legacy `<filter><rule>`) | Not supported | Source in the MVP; generating a config.xml that is safe to import is risky. |
| OPNsense | `config.xml` | same | Filter log (not read) | **Supported** for legacy rules only; MVC rules are reported, not read | Not supported | As above. |

## Traffic sources

| Source | Status | Notes |
| --- | --- | --- |
| PCAP | **Supported** | Ethernet, raw IP, Linux cooked (v1 and v2), loopback. IPv4 and IPv6, VLAN tags. |
| PCAPNG | **Supported** | Link type of the first interface is used; files with several interfaces of different link types are not handled separately. |
| Zeek conn.log (TSV or JSON lines) | **Supported** | Treated as a summary: direction and application are Zeek's, with lower confidence than packet evidence. |
| NetFlow / IPFIX, firewall traffic logs, syslog | Not supported | Roadmap. |

## What is evaluated, and what is reported but not evaluated

| Evaluated | Reported as unsupported (the rule becomes undecidable and cannot be translated) |
| --- | --- |
| Addresses, nested object and address groups, ranges, negation (where the source has it) | Application conditions (App-ID, application control), `application-default` services |
| TCP/UDP/ICMP/other protocol numbers, port ranges, ICMP type and code | Users, groups and identity conditions; security-group tags |
| Order, enabled/disabled, implicit and explicit default actions | Schedules and time ranges |
| Zones and interfaces; ACL bindings (in/out/global); ASA security levels | FQDN, geography, dynamic and URL-table objects; URL categories; internet-service objects |
| Stateful or stateless behaviour; TCP `established` | Reflexive ACLs, TCP flag matches, DSCP/TTL/fragment matches |
| NAT statements (recorded, used to warn about address context) | Central NAT, twice-NAT detail, security profiles and inspection |

## Versions the fixtures stand for

The fixtures in `tests/fixtures/` and `samples/configs/` are synthetic. They are written in the syntax of: Cisco ASA 9.16, IOS-XE 17.9, PAN-OS
10.2, FortiOS 7.2 and pfSense 22.3. Other versions often produce the same syntax, but that is not claimed.
