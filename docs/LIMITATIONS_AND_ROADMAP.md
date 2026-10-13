# Compatibility limitations, known gaps and roadmap

## What this tool does not do

* **It does not deploy anything.** No call is ever made to a firewall, switch or controller. Outputs are for review.
* **It is not a proof of equivalence.** The validation compares sampled connections with this tool's own evaluator on both sides (see [VALIDATION.md](VALIDATION.md)).
* **Observed traffic is not business need, and silence is not absence.** A capture is a window at one place. Proposals built from it require acknowledgement of that, and they
  can only ever add what was seen.
* **It does not decide what a device is.** Roles are not inferred from traffic; labels are yours.
* **Directional rules are not zero trust.** Identity, device posture, encryption, monitoring and change control are outside the worksheets.

## Parsing and evaluation limits

* Application, identity, schedule, URL-category, security-profile and inspection conditions are recognised and reported, **not evaluated**. A rule that has one is undecidable
  where it could change the answer, and cannot be translated.
* FQDN, geography, dynamic and URL-table objects cannot be resolved offline; rules using them are undecidable and not translated.
* PAN-OS: Panorama device-group pre/post rulebases are not merged; only the first virtual system is read; `application-default` services need the App-ID database.
* FortiOS: first VDOM only; central NAT and local-in policies are not read; the order rule for virtual IPs is reported but not modelled.
* Cisco ASA: Modular Policy Framework and twice-NAT detail are not modelled; interface access rules are modelled with the global rule as a fall-through; same-security-level and
  intra-interface traffic rules are reported, not applied. IOS: zone-based firewall and reflexive/CBAC are reported, not modelled; IPv4 and IPv6 ACLs are evaluated per family.
* pfSense/OPNsense: floating rules without Quick (last match wins) and stateless rules are reported as undecidable; OPNsense MVC rules are not read.
* NAT is recorded and used to warn and to block mismatched address contexts; filtering is not re-evaluated after translation.

## Capture limits

* TCP initiator inference needs the handshake. Mid-stream flows get a medium or low confidence from payload semantics or port heuristics, and say so. UDP direction is never better than
  medium. Asymmetric capture (only one direction visible) is reported on each flow.
* IP fragments are counted, not reassembled. Encapsulation other than VLAN tags (GRE, VXLAN, MPLS, IPsec) is not unwrapped. 802.11 captures are refused.
* Application identification is structural and covers a small set of OT and common protocols: Modbus/TCP, EtherNet/IP, DNP3, S7comm/ISO-on-TCP, BACnet/IP, OPC UA, IEC 60870-5-104, DNS, HTTP, TLS,
  SSH, NTP, SNMP, DHCP, SMB, RDP, Telnet, FTP/SMTP banners, SSDP, syslog. Anything else is "not identified"; a well-known port alone is only ever "possible".
* Performance is about 18,000 packets per second in pure Python; the default limits are 512 MB, 5,000,000 packets, 200,000 flows and 10 minutes per file.

## Platform

* Linux and macOS are the supported platforms for the server (it uses POSIX file modes and resource limits). Windows has not been tested; resource limits do not apply there.
* The interface needs a current browser. The graph is a simple radial drawing, suitable for tens of nodes, not hundreds.

## Roadmap

| Phase | Work |
| --- | --- |
| Next | PAN-OS destination (`set` commands); Juniper SRX source and destination; Check Point rulebase JSON source; firewall traffic-log import (PAN-OS and FortiGate CSV, ASA syslog); NetFlow/IPFIX import |
| Then | Panorama device groups; FortiOS VDOMs and central NAT; ASA twice-NAT; FQDN object resolution with a user-supplied name list; per-application mapping from vendor application names to decoded protocols; optional use of `tshark` for deeper decoding when installed |
| Later | A command-line mode; signed release bundles; side-by-side diff of two exports; per-flow timeline view; group suggestions from clustering of observed behaviour (always as suggestions) |
| Not planned | Pushing configuration to live equipment; claiming vendor certification |
