# Checkpoint 12: independent cross-check of the ASA translation with Batfish

Commit under test: the tree at `7249a51`. No application code changed in this checkpoint.

## Why

Until now the only check on the UniFi to ASA translation used this project's own evaluator on both sides. A defect in the evaluator and a
matching defect in the translator could cancel out. Batfish is a separate, open-source implementation that parses Cisco ASA configurations
and answers "is this packet permitted by this ACL" with its own model.

## Method

* Input: the clean synthetic export (`tests/unifi_zones.py`, no problem policies), every network mapped to its own interface name, gateway and VPN
  confirmed, so the translation is deployable. No real export and no data from the owner's network was used.
* RuleTruss writes the generated ASA text, preceded by a small scaffold (an `ASA Version` line, hostname, one interface per network with `nameif` and an address).
  It also lists 176 connections (every source network to every destination zone for tcp 443, udp 53 and icmp echo, plus the inside of each user
  policy) with RuleTruss's decision from the **source** policy.
* Batfish `testFilters` is asked, for each connection, what the ACL bound to the source network's interface does. The two decisions are compared.
* Scope: new connections in the initiating direction. Replies and state tracking are not modelled by `testFilters`, so they are not covered.

## Result

| Check | Result |
|---|---|
| Batfish parse warnings, init issues, undefined references, unused structures | 0, 0, 0, 0 |
| Source says deny, ASA denies | 138 of 138 |
| Source says allow, ASA permits | 35 of 35 |
| Source indeterminate | 3 (External to External: the export has no built-in default for that pair; the ASA denies by default) |
| Disagreements on a definite decision | **0** |
| Mutation check: delete one allow line from the config | caught: exactly the 3 connections it governs changed to deny |

Only one mutation kind was tried (removing an allow). Removing a deny and reordering were not.

## Harness fault found on the way (not a product defect)

The first run returned "deny, no match" for every case. Batfish had read the file as Cisco IOS because the scaffold had no `ASA Version` line,
so it did not recognise `nameif` and `security-level`. Adding the line fixed it, and the parse-warning count went from 24 to 0. Prevention: the
harness now reads Batfish's parse warnings first, and a run with warnings must not be read as a result.

## How it was run (safety)

* Image `batfish/allinone`, pinned by digest `sha256:54cb0ed94fd9a3c1ca0985f73e5be479e955cee9b9f6a6799b66be3364fd8e5c` (the release tag `latest` of 2026-08-27,
  not the CI `test-` tags). pybatfish 2026.08.27.3685, OpenJDK 25.0.4, Podman 6.1.1 (rootless).
* Container: no network (`--network none`), read-only root filesystem, tmpfs for scratch, `--cap-drop all`, `no-new-privileges`, 4 GB memory and swap
  limit, 512 processes, 15 minute timeout. The input folder was mounted read-only, one output folder read-write. Jupyter in the image was not started.
* Nothing was added to this project's dependencies or its `.venv`. The four harness scripts are kept in `harness/` as `.txt` files (reference copies, deliberately not importable or linted; remove the `.txt` to use them). They are not part of the application.
* Not done: reading the Batfish source, checking the image signature (none was verified), a vulnerability scan of the image.

## What this does and does not show

It shows that, for 173 sampled new connections on a synthetic gateway, an independent ASA parser agrees with the source policy's decisions, and that the
generated text is syntactically accepted by that parser. **It is not proof of equivalence.** It does not cover replies and connection state, NAT, routing,
VPN, traffic to the firewall itself, `object-group` forms, the owner's real export (which has unresolved and unsupported policies by design), or a real ASA's
behaviour. The output stays a preview until it has been loaded on a device.

## Suppressions added / removed, SSDF practices touched

None added or removed. PW.8 (testing): an independent tool was used against the translator. No status in `docs/SECURITY_FRAMEWORKS.md` changes.
