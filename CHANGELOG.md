# Changelog

## 0.1.0 (unreleased)

First working version.

* Ingest: PCAP and PCAPNG (dpkt), Zeek conn.log; flows with initiation inference, confidence and evidence; application identification from payload structure with confirmed, probable and possible levels.
* Configuration adapters: Cisco ASA, Cisco IOS/IOS-XE ACLs, Palo Alto PAN-OS XML, Fortinet FortiOS CLI, pfSense/OPNsense config.xml.
* Vendor-neutral model with three kept-apart layers (observed, configured, proposed); three-valued evaluation; stateful and stateless behaviour; ASA interface, global and security-level behaviour; PAN-OS defaults.
* Explanations, inventory, subnet matrix, directional graph, observed-versus-configured comparison, shadowed/redundant/conflicting/broad rule analysis.
* Directional group policy worksheets (preserve and narrow workflows) with group aggregation, broadening and lost-restriction detection, and a separate external egress policy type.
* Firewall translation to Cisco ASA, Cisco IOS and FortiOS with blocked-not-widened semantics, return rules for stateless destinations, and round-trip validation on sampled connections.
* Local web application with a hardened loopback server, isolated parsing, private storage, deletion controls, CSV/Markdown/JSON exports, and an optional, off-by-default AI path.
* Security tooling and tests: hostile inputs, resource limits, fuzzing, server access control, SBOM, scan runner.
