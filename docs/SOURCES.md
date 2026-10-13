# Sources and what was verified

Product-specific statements in Policy Bridge's behaviour, documentation and warnings are tied to the public documents below. They
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
| Protocol structure checks | DNS (RFC 1035), NTP (RFC 5905), TLS (RFC 8446), TPKT (RFC 1006), SNMP (RFC 3416 with BER) and the public descriptions of Modbus/TCP, EtherNet/IP encapsulation, DNP3 link layer, BACnet/IP, OPC UA binary and IEC 60870-5-104. Checks are structural (magic values, length consistency, enumerations), not full decoders. | [rfc-editor.org](https://www.rfc-editor.org/); [modbus.org specifications](https://modbus.org/specs.php) |

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
- **Application identification.** The structural checks have not been compared with a commercial deep-packet-inspection engine.
