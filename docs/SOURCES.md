# Sources and what was verified

Product-specific statements in RuleTruss's behaviour, documentation and warnings are tied to the public documents below. They
were retrieved on 2026-10-13. Vendors change behaviour between versions, so each row says what the tool relies on, and the last
section lists what could **not** be verified.

## The directional group policy model is this project's own

The From-group, To-group, initiation-direction and external-egress concepts are defined by this application (see
[MODEL.md](MODEL.md)). They are not the policy format of any product and the tool does not claim compatibility with, or
certification for, any product. Output is a worksheet to apply by hand on whatever enforcement platform is in use.

## Source and destination behaviour

| Topic | What the tool relies on | Document |
| --- | --- | --- |
| Cisco ASA rule order | Interface access rule, then global access rule, then implicit deny; the first match wins. Global rules apply inbound only. | [ASA firewall CLI guide 9.20: Access Rules](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config/access-rules.html) |
| Cisco ASA security-level default | Traffic from a higher to a lower security level is allowed by default; an ACL ends in an implicit deny. | same page |
| Cisco ASA and NAT addresses | From 8.3, access rules use the real (untranslated) address of a host, not the mapped one. This is the `internal-real` address context. | [ASDM 7.20 Access Control Lists](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/asdm720/firewall/asdm-720-firewall-config/access-acls.html); [NAT and ACLs on an ASA (115904)](https://www.cisco.com/c/en/us/support/docs/security/asa-5500-x-series-next-generation-firewalls/115904-asa-config-dmz-00.html) |
| Cisco IOS ACLs | Every ACL ends in an implicit deny; ACLs are stateless; `established` is TCP-only and matches segments with ACK or RST set (it is not a state table). | [Configure IP Access Lists](https://www.cisco.com/c/en/us/support/docs/security/ios-firewall/23602-confaccesslists.html); [Creating an IP Access List and Applying It to an Interface](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_data_acl/configuration/xe-3s/sec-data-acl-xe-3s-book/sec-create-ip-apply.html) |
| PAN-OS NAT context | Security rules match the original (pre-NAT) addresses and the post-NAT zones. This is the `original-packet` address context. | [NAT policy overview](https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-networking-admin/nat/nat-policy-rules/nat-policy-overview); [Packet flow sequence in PAN-OS](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClVHCA0) |
| PAN-OS default rules and rule types | `intrazone-default` allows traffic inside a zone, `interzone-default` denies between zones; rule types are universal, intrazone and interzone. | [Components of a security policy rule](https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/policy/security-policy/components-of-a-security-policy-rule) |
| FortiOS evaluation | Policies are checked from top to bottom for the interface pair and the first match applies; traffic that matches nothing hits the implicit deny. Policies that use a virtual IP take priority over other policies. | [Firewall policy (7.4)](https://docs.fortinet.com/document/fortigate/7.4.1/administration-guide/656084/firewall-policy); [Policies, best practices (7.4)](https://docs.fortinet.com/document/fortigate/7.4.0/best-practices/862226/policies); [Technical Tip: How policy order works on FortiGate](https://community.fortinet.com/t5/FortiGate/Technical-Tip-How-policy-order-works-on-FortiGate/ta-p/207381) |
| pfSense rule order | Rules on an interface tab apply inbound on that interface; floating rules, then interface group rules, then interface rules; Quick makes the first match final, and a floating rule without Quick is last-match-wins. | [Rule methodology](https://docs.netgate.com/pfsense/en/latest/firewall/rule-methodology.html); [Floating rules](https://docs.netgate.com/pfsense/en/latest/firewall/floating-rules.html) |
| pfSense NAT and rules | Port-forward NAT happens before firewall rules, so inbound rules name the translated (internal) destination: the `internal-real` context. | [Ordering of NAT and firewall processing](https://docs.netgate.com/pfsense/en/latest/nat/process-order.html) |
| OPNsense rule order | Floating rules, then interface groups, then interface rules; first match with Quick (the default); filter inbound on the receiving interface; default block. | [OPNsense firewall rules](https://docs.opnsense.org/manual/firewall.html) |

## Traffic sources

| Topic | What the tool relies on | Document |
| --- | --- | --- |
| Zeek conn.log | `id.orig_h`/`id.resp_h` are Zeek's originator and responder; in `history`, uppercase letters are from the originator and lowercase from the responder (`S` originator SYN, `h` responder SYN-ACK). conn.log is a summary written by Zeek, so its originator is Zeek's inference. | [conn.log](https://docs.zeek.org/en/lts/logs/conn.html); [base/protocols/conn/main.zeek](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html) |
| PCAP and PCAPNG | File structure is read by the dpkt library (BSD-licensed, pure Python). | [pcap](https://www.tcpdump.org/pcap/pcap.html); [PCAPNG draft](https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcapng-05) |
| UniFi zone-based firewall | Policies belong to a source zone and a destination zone and carry an `index`; actions ALLOW, BLOCK, REJECT; traffic filters (IP address, network, port, domain, application, region, VPN, MAC); connection-state filters (NEW, INVALID, ESTABLISHED, RELATED); policies defined by the system, derived or orchestrated appear in the same list with their origin. Read through the local Integration API (`/proxy/network/integration/v1`, header `X-API-KEY`). | [UniFi Network API reference (OpenAPI 10.3.58)](https://developer.ui.com/network/v10.3.58/openapi.json); [List Firewall Policies](https://developer.ui.com/network/v10.4.57/getfirewallpolicies) |
| Protocol structure checks | DNS (RFC 1035), NTP (RFC 5905), TLS (RFC 8446), TPKT (RFC 1006), SNMP (RFC 3416 with BER) and the public descriptions of Modbus/TCP, EtherNet/IP encapsulation, DNP3 link layer, BACnet/IP, OPC UA binary and IEC 60870-5-104. Checks are structural (magic values, length consistency, enumerations), not full decoders. | [rfc-editor.org](https://www.rfc-editor.org/); [modbus.org specifications](https://modbus.org/specs.php) |
| MAC addresses and OUIs | A MAC's first 24 bits (MA-L), 28 bits (MA-M) or 36 bits (MA-S) name the organisation that registered that block with the IEEE; the longest registered prefix wins. Bit 0x02 of the first byte marks a locally administered address (the prefix then names no maker) and bit 0x01 a group address. RuleTruss does not ship the listings. On request it downloads them into the user's data folder (`ruletruss/oui_build.py`), keeps only the prefix and the organisation name, and shows the retrieval date wherever a name is shown. | [IEEE Registration Authority](https://standards.ieee.org/products-programs/regauth/); public listings [MA-L](https://standards-oui.ieee.org/oui/oui.csv), [MA-M](https://standards-oui.ieee.org/oui28/mam.csv), [MA-S](https://standards-oui.ieee.org/oui36/oui36.csv) |
| ARP, DHCP, LLDP | ARP sender fields announce the sender's own pairing (RFC 826). A DHCP ACK gives the client hardware address and the address assigned; the client's request may carry host name (option 12) and vendor class (option 60) (RFC 2131, RFC 2132). LLDP carries chassis and port IDs, system name and description, capabilities and a management address as TLVs (IEEE 802.1AB). | [RFC 826](https://www.rfc-editor.org/rfc/rfc826); [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131); [RFC 2132](https://www.rfc-editor.org/rfc/rfc2132); [IEEE 802.1AB](https://standards.ieee.org/ieee/802.1AB/6047/) |
| Self-reported identity | SNMP `sysDescr.0`, `sysName.0` and `sysObjectID.0` (RFC 3418); Modbus function 0x2B, MEI type 0x0E "Read Device Identification" objects 0 to 6 (Modbus application protocol specification); EtherNet/IP ListIdentity reply (vendor ID, device type, product code, revision, serial, product name); HTTP `Server` and `User-Agent` (RFC 9110); the SSH identification string (RFC 4253). | [RFC 3418](https://www.rfc-editor.org/rfc/rfc3418); [modbus.org specifications](https://modbus.org/specs.php); [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110); [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253) |

## Not verified against official documentation

Be sceptical of these until you have checked them against your own equipment:

- **Adapter syntax coverage.** The parsers handle the constructs listed in the adapter docstrings, written from the vendors' documented
  command syntax and typical exports, and tested against synthetic fixtures. They have **not** been run against real exports from
  every software version. Anything a parser does not recognise is reported (never ignored), but unusual real-world syntax may be
  reported as unsupported.
- **FortiOS and PAN-OS predefined services** (`HTTP`, `HTTPS`, `SSH`, `DNS`, `service-http` and so on) use a small table in this project. A
  name that is not in the table is reported as unresolved rather than guessed.
- **ICMP type and code names**, `any4`/`any6`, and the numeric ICMP forms used when generating Cisco text.
- **Generated destination text.** It is round-tripped through this project's own parsers, not loaded onto a device.
- **IEEE registry redistribution terms (unresolved, so nothing is shipped).** The IEEE's pages state no licence for the listings. The only direct statement found is a 2013 [debian-legal post](https://lists.debian.org/debian-legal/2013/08/msg00003.html) quoting the IEEE: it "does not issue licenses for the use of the public listing" and "does not authorize" distribution of the listing by anyone but the IEEE ("third party extrapolation"); that is secondhand and old. The [Free Software Directory](https://directory.fsf.org/wiki/Ieee-data) reads the listing as unrestricted. Wireshark's `manuf` file is built from the same IEEE listings and is GPL-2.0-or-later code, so it does not avoid the question and would add a GPL problem to an MIT project. RuleTruss therefore downloads the listings on the user's request rather than redistributing them. Checked 2026-10-13; this is not legal advice.
- **EtherNet/IP details.** The ListIdentity layout was written from public descriptions of the CIP encapsulation, not from the ODVA specification (which is not freely available). Only vendor ID 1 is translated to a name; every other ID is shown as a number.
- **TTL conventions.** The initial values 32, 64, 128 and 255 and the operating systems usually associated with them are common knowledge, not a cited standard, and they vary by version and configuration.
- **LLDP.** IEEE 802.1AB itself was not read; the TLV layout comes from public descriptions.
- **UniFi ordering and defaults.** From one real export (Network 10.6.106): indexes (user policies from 10000, predefined and derived from 30000,
  each pair's final policy 2147483647), a final Allow All / Block All policy in every listed pair, connection-state filters on the predefined
  policies, and the ICMPv6 message type missing from the predefined ICMPv6 policies. From documentation and third-party guides ([Wundertech](https://www.wundertech.net/how-to-configure-unifi-firewall-rules/),
  [Demarc](https://demarcnetworks.com/guides/unifi-zone-firewall), [LazyAdmin](https://lazyadmin.nl/home-network/unifi-zone-based-firewall/), [vNinja](https://vninja.net/2026/08/13/unifi-zone-based-firewall-changes-the-iot-vlan-rule/)):
  custom policies run before predefined ones, first match wins, and a block for all states also blocks return traffic (confirmed on one gateway, Network 10.6.106, with ping: replies from a network with such a block were dropped, and a return-traffic allow written in the replies' direction above the block let them through). Ubiquiti's own help articles
  ([Zone-Based Firewalls in UniFi](https://help.ui.com/hc/en-us/articles/115003173168-Zone-Based-Firewalls-in-UniFi)) refused automated access (HTTP 403) and were
  not read; the API reference gives no description for `index`, `beforeSystemDefined` or `afterSystemDefined`. That `index` is the exact evaluation order in
  every case, and which hidden rules exist outside the policy table, are not verified.
- **UniFi.** The adapter follows the OpenAPI schema (10.3.58) as far as I could read it; several nested parts (protocol filters, the exact
  shape of presets and ICMP type names, application filter contents) were only partly visible, so unrecognised shapes are reported, not
  guessed. One real export (Network 10.6.106) was read successfully and matched the schema; decisions were not yet compared with real traffic. Which UniFi versions serve the firewall policy endpoints (documentation says 10.1.84
  onward) and what the gateway does for a zone pair with no listed policy are not verified. The menu names for creating an API key vary by
  version.
- **Application identification.** The structural checks have not been compared with a commercial deep-packet-inspection engine.
