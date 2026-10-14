# Compatibility limitations, known gaps and roadmap

## What this tool does not do

* **It does not deploy anything.** No call is ever made to a firewall, switch or controller. Outputs are for review.
* **It is not a proof of equivalence.** The validation compares sampled connections with this tool's own evaluator on both sides (see [VALIDATION.md](VALIDATION.md)).
* **Observed traffic is not business need, and silence is not absence.** A capture is a window at one place. Proposals built from it require acknowledgement of that, and they
  can only ever add what was seen.
* **It does not decide what a device is.** Roles are not inferred from traffic; labels are yours. Device identification (MAC, card maker, text a device sends about itself) is shown with its source and confidence, and is passive: nothing is ever sent to a device.
* **Directional rules are not zero trust.** Identity, device posture, encryption, monitoring and change control are outside the worksheets.

## UniFi

Zone-based firewall only (Network 10.1 or later, through the API export); connection states are matched (replies are checked in the reverse zone pair), but traffic paths outside the policy table (port-forward rules, IPS, content filtering) are not modelled; legacy pre-zone firewall rules, port forwards (NAT), DNS and VPN
settings are not read, and the encrypted backup file is not read. Written from the published schema; one real export was read successfully, and decisions have not yet been compared with real traffic.
See [EXPORT_UNIFI.md](EXPORT_UNIFI.md).

## UniFi to Cisco ASA

IPv4 only; no IPv6 prefixes for zones in the export. Gateway (local services) and VPN are left to you and stay unresolved until you say so. MAC filters,
applications, domains, regions and schedules are unsupported. The ASA allows replies of every permitted connection, which UniFi's all-states blocks do not.
The result is a reviewable preview until every placeholder, unsupported and unresolved item is dealt with. See [EXPORT_UNIFI.md](EXPORT_UNIFI.md).

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
* **Size limits and how to raise them.** The defaults are 512 MB, 5,000,000 packets, 200,000 flows, 10 minutes and 2 GB of memory per file. They guard against hostile or broken files, so each can be changed only at start-up (`--max-capture-mb`, `--max-packets`, `--max-flows`, `--parse-minutes`, `--parse-memory-gb`), and each has a ceiling that no setting can pass (256 GB, 2 billion packets, 500,000 flows, 24 hours, 128 GB). Packets beyond the packet limit and flows beyond the flow limit are not analysed, and the coverage notes say so.
* **Measured** on a generated capture of 3,000,000 packets (810 MB, almost every packet its own flow, the worst case for memory): the analysis took about two minutes (roughly 26,000 packets per second) and the analysis process peaked at about 0.9 GB; with the 200,000-flow limit reached, the stored analysis was about 240 MB and opening it took the main process about 1.7 GB and 15 seconds. Real captures with few flows are lighter. Time grows with the packet count, so a 3 GB capture of small packets (tens of millions) may need an hour or more; the progress line shows how far it has got.
* **Result size.** One file's stored analysis may not exceed 512 MB, which is about what 400,000 flows would need; raise `--max-flows` with that in mind, and expect the main process to need several GB when such a project is opened.
* **Disk.** The original upload is kept next to its analysis, and the server refuses an upload that would leave less than 1 GB free. Deleting a file overwrites it first (best effort), which takes time for a multi-gigabyte capture.

* A MAC address is the device's only on the same network segment. Behind a router the MAC is the router's, so a MAC is attributed to an IP only when ARP or DHCP confirmed it, or (as *probable*) when it carried that one IP alone. The OUI names the card's maker, not necessarily the device's, and is meaningless for randomised addresses (phones, laptops, virtual machines). Self-reported strings can be forged. The downloaded registry ages: its date is shown, and you refresh it yourself.

## Platform

* Linux and macOS are the supported platforms for the server (it uses POSIX file modes and resource limits). Windows has not been tested; resource limits do not apply there.
* The interface needs a current browser. The graph is a simple radial drawing, suitable for tens of nodes, not hundreds.

## Roadmap

| Phase | Work |
| --- | --- |
| Next | PAN-OS destination (`set` commands); Juniper SRX source and destination; Check Point rulebase JSON source; firewall traffic-log import (PAN-OS and FortiGate CSV, ASA syslog); NetFlow/IPFIX import |
| Then | More passive identification: CDP, PROFINET DCP, TLS client fingerprints, DHCP option-55 fingerprints, mDNS/SSDP/NetBIOS names, the ODVA vendor table; Panorama device groups; FortiOS VDOMs and central NAT; ASA twice-NAT; FQDN object resolution with a user-supplied name list; per-application mapping from vendor application names to decoded protocols; optional use of `tshark` for deeper decoding when installed |
| Later | A command-line mode; signed release bundles; side-by-side diff of two exports; per-flow timeline view; group suggestions from clustering of observed behaviour (always as suggestions) |
| Not planned | Pushing configuration to live equipment; claiming vendor certification |
