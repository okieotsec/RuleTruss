# Checkpoint 17: a test pack for trying the generated ASA configuration on a real ASAv (Cisco Modeling Labs)

Commit: the one that adds this report. No review finding is being fixed here; this prepares the first test of the ASA output on real ASA software.

## What was added

* `tools/make_cml_pack.py` builds, from a cut-down version of the invented clean UniFi example (three networks plus External), `docs/CML_TEST.md` (steps), `samples/cml-test/asa-config.txt`
  (the whole configuration to paste into an ASAv: interfaces, ICMP inspection, the generated access lists and bindings) and `samples/cml-test/expected.csv` (24 connections: ping and TCP 443
  between four hosts, with what the UniFi policy says and an empty column for what the ASA does).
* Tests in `tests/test_cml_pack.py`: the example is deployable and every expected answer is decided; phones reach cameras and cameras cannot start the reverse (the owner's own scenario);
  nothing from outside reaches the inside; the security levels differ; ICMP inspection is in the configuration.
* A new warning on every ASA translation from a zone-pair source: **an ASA does not track ICMP by default**, so the replies to an allowed ping need `inspect icmp` and `inspect icmp error` in
  the global policy, which the translation does not generate. Found while writing the pack, from general knowledge of ASA behaviour; the lab will confirm or correct it. Documented in `docs/EXPORT_UNIFI.md`.

## The lab file (added after the owner's first CML export)

The owner built one ASAv and one Alpine node in their own CML 2.10 server and sent the exported lab file (schema version 0.3.1). It is kept as `tests/fixtures/cml-lab-export-0.3.1.yaml`.
`tools/make_cml_pack.py` now also writes `samples/cml-test/rt-asa-test-lab.yaml`: one ASAv (`rtasa`) and four Alpine hosts linked to `GigabitEthernet0/0` to `0/3`, in the same format, so it can be imported
instead of built by hand. A test checks that its keys are exactly the keys of the real export and that each host is linked to the ASA port its address is configured on. The owner also showed the Config tab of an Alpine node: a boot script, `node.cfg`, that CML sources at boot (it holds the hostname and the default login). The lab file now
carries one per host, setting its name, address, default route and a TCP 443 listener, in CML's `configuration: [name, content]` form; a second file, `rt-asa-test-lab-topology-only.yaml`,
has the same lab without them, as a fallback if CML refuses the first. Neither has been imported into CML yet, and no YAML library was available to parse them independently. The ASAv's own
configuration file name is not known yet (the owner can read it from the ASAv's Config tab), so the ASA configuration is still pasted into its console.

## Two points about CML-Free from Cisco's page (seen by the owner)

* The free reference image includes ASAv. A Cisco account with a complete profile (company details, address) is needed to download; the telemetry of a CML-Free instance (feature lists and counts of nodes, node types,
  interfaces and links, not configurations or traffic, according to Cisco) is always on and cannot be switched off without a paid licence.

## Tests and tools

* Full suite: 559 tests, all passing. ruff clean. `tools/security_checks.py`: all six scanners 0 findings; suppression gate 0 findings (70, all in the baseline). No suppression added.

## Result of the first run (2026-10-15)

The owner built the lab in their own Proxmox and CML-Free 2.10.1 (imported the OVA and the reference images, then the lab file from this checkpoint), pasted `samples/cml-test/asa-config.txt`
into the ASAv, ran the per-host test scripts on the four Alpine hosts, and sent screenshots. **All 24 connections behaved as the UniFi policy says: 24 of 24 matched** (recorded in
`samples/cml-test/results-2026-10-15.csv`). That includes the owner's own scenario: the phones' network reaches the cameras' network (ping and TCP 443) and the cameras cannot reach the phones' network,
nothing from outside reaches the inside, and the inside reaches out. The ASAv's `show access-list` hit counts agree with the test results (hits on the expected deny and permit lines, none on the lines
that should not have been hit).

Along the way: one host's test script was pasted on the wrong host (the output was labelled with the other host's name); the results were re-collected from the right hosts, and a test now ties
the recorded results to the configuration that was tried. The first listener design depended on the exit status of Alpine's `nc`; it was changed to a banner the listener sends, which does not.

Not yet done: the ASAv's software version was not recorded, and the ICMP-inspection question (does the ASAv drop ping replies without `inspect icmp`, as the new warning says) has not been tested in the lab.
The warning stays, but is unconfirmed, until it is.

## Limits

* Nothing has been run on an ASA yet. The CML steps in the pack are from general knowledge and may differ on screen. A pass covers 24 connections of one small example and does not cover NAT, routing, VPN, traffic to the
  firewall itself or other configurations. The expected column is this tool's evaluation of the source policy, not an independent oracle.
