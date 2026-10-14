# Checkpoint 5: device identification (MAC, OUI, self-reported identity)

Reviewer: Claude (same session that wrote the code, so this is a self-review, not an independent one).

## What changed
`capture/fingerprint.py` (bounded decoders: ARP, LLDP, DHCP, SNMP response, Modbus device ID, EtherNet/IP ListIdentity, HTTP, SSH, initial TTL),
`oui.py` (IEEE prefix lookup over a bundled snapshot), `devices.py` (merge and MAC-to-IP attribution), reader/flows/worker/service/exports/UI wiring,
`tools/update_oui.py` (the only code that can download the registry; developer step), Riverbend captures and guide points D01-D07.

## New untrusted input and what was done about it
| Surface | Risk | Control | Test |
| --- | --- | --- | --- |
| Layer-2 frames (ARP, LLDP, any sender MAC) | malformed lengths, truncated frames, forged broadcast sender | every length checked before reading; group-address senders dropped; all inside the parsing subprocess | `HostileFrameTests`, prefix-truncation test |
| Strings from devices (names, banners, headers) | terminal/HTML/CSV/Markdown injection, oversized text | printable ASCII only, hard length cut, text-only rendering, CSV neutralised, Markdown escaped | `test_text_is_plain_bounded_ascii`, Hypothesis `test_text_is_always_bounded_printable_ascii`, formula test |
| SNMP messages | BER length tricks, secret in community string | bounded TLV reader (lengths of 2 bytes at most, inside parent), community skipped and never stored | prefix-truncation, random-byte tests, community test |
| Memory growth | many MACs/IPs/strings | `MAX_DEVICE_ITEMS` caps each table; the limit is reported to the user | `LimitTests` |
| IEEE registry file | untrusted download | downloaded and parsed only by `tools/update_oui.py`, row format validated, names cleaned and clipped, minimum-size sanity check; the app reads only the bundled file and makes no request | review |
| Wrong attribution | a router's MAC shown as a device's | shared MACs never attributed; frame-only attribution labelled probable with its caveat; randomised MACs show no maker | `AttributionTests`, Riverbend D01-D05 |

## Results
* 330 tests pass (39 new in `tests/test_devices.py`, 7 new Riverbend guide points, 2 new Hypothesis properties). Fuzz at `RT_FUZZ_SCALE=20`: pass.
* Headless UI check: pass (4 new checks for the devices table, detail row and shared-MAC list).
* Tools: ruff, bandit, semgrep, gitleaks, pip-audit, osv-scanner all 0. First run had three false positives (bandit B104 on the string `"0.0.0.0"` used as a packet source address and a comparison constant; semgrep dynamic-urllib in the developer download tool, whose URLs are a fixed https table). Each is annotated with its reason in the source.
* No new runtime dependency; SBOM unchanged.

## Open items (for the owner)
1. (Superseded by cp6: the snapshot was removed and is now downloaded on request.) **IEEE redistribution terms were not found.** The bundled `ruletruss/data/oui.tsv.gz` is a reduced copy (prefix + organisation name). Confirm the terms before publishing, or switch to download-on-first-use.
2. The ListIdentity layout, the CIP vendor mapping (only ID 1 is named), LLDP and TTL conventions come from public descriptions, not the paid specifications. Listed in `docs/SOURCES.md`.
3. Zeek logs and non-Ethernet captures carry no MACs here.
4. Self-review only; an independent review is still open.
