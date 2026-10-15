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

## Two points about CML-Free from Cisco's page (seen by the owner)

* The free reference image includes ASAv. A Cisco account with a complete profile (company details, address) is needed to download; the telemetry of a CML-Free instance (feature lists and counts of nodes, node types,
  interfaces and links, not configurations or traffic, according to Cisco) is always on and cannot be switched off without a paid licence.

## Tests and tools

* Full suite: 559 tests, all passing. ruff clean. `tools/security_checks.py`: all six scanners 0 findings; suppression gate 0 findings (70, all in the baseline). No suppression added.

## Limits

* Nothing has been run on an ASA yet. The CML steps in the pack are from general knowledge and may differ on screen. A pass covers 24 connections of one small example and does not cover NAT, routing, VPN, traffic to the
  firewall itself or other configurations. The expected column is this tool's evaluation of the source policy, not an independent oracle.
