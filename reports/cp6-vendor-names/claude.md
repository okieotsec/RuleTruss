# Checkpoint 6: vendor names are downloaded on request, not shipped

Reviewer: Claude (self-review; independent review still open).

## Why
The IEEE states no licence for its OUI listings, and the one direct statement found (debian-legal, 2013, secondhand) says it does not authorise
redistribution by others. Wireshark's `manuf` file is derived from the same listings and is GPL. So the bundled `oui.tsv.gz` was removed and the
vendor-name table is fetched by the user, on request, into their own data folder. See `docs/SOURCES.md`.

## What changed
`oui.py` (pure MAC helpers + a `Registry` that reads one optional file, re-reads on change, and treats a missing, corrupt or oversized file as "no names"),
`oui_build.py` (the only networking code; downloads and builds, in its own process), `isolate.build_vendor_names`, `Service` (status, update with a
five-minute hold-off, remove), three routes (`GET/POST/DELETE /api/vendor-names`), a "Vendor names (optional)" card on Data & privacy with a confirm
dialog, a notice on the Devices table when no names are loaded, `samples/vendor_names.py` (a fictional table for tests and the guide). Riverbend no longer
attributes invented devices to real companies (neutral keys, a vendor ID that is only a number).

## New network surface and its controls
| Risk | Control | Test |
| --- | --- | --- |
| Surprise outbound traffic | only the button (with a confirm dialog) or `python -m ruletruss.oui_build`; a full analysis, imports and exports make no connection | `test_a_full_analysis_opens_no_network_connection`, `test_only_the_download_module_and_the_ai_path_import_network_code` |
| Fetch from the wrong host or a downgrade | fixed URL table; HTTPS only; host must be `ieee.org` or a subdomain; redirects re-checked; no credentials or ports in URLs | `test_only_https_on_the_ieee_host_is_allowed`, `test_a_redirect_off_the_ieee_host_is_refused` |
| Large or hostile download | 20 MB per file, 60 s timeout, 240 s overall, kernel limits in the worker, whole process killed on timeout | worker tests |
| Hostile CSV content | every row validated (registry kind, hex prefix of the right length); names stripped of control characters, ASCII, 80 characters; a minimum entry count rejects error pages | `BuilderTests` |
| A tampered or damaged stored table | size and line caps on read; any error means "no names" | `RegistryFileTests` |
| Use as a request amplifier or by a web page | token, Host and Origin checks as for every route; one request per five minutes | `ServerRouteTests`, `test_repeated_requests_are_held_back...` |
| Names appearing in output | rendered as text, CSV neutralised, Markdown escaped (unchanged paths) | existing export tests |
| Redistribution of IEEE data | none shipped; a test fails if an `oui*`/`manuf` data file appears in the repo | `test_no_ieee_data_is_shipped_in_the_repository` |

## Results
352 tests pass (22 new in `tests/test_vendor_names.py`); fuzz at `RT_FUZZ_SCALE=20` passes; headless UI check passes. ruff, bandit, semgrep, gitleaks,
pip-audit and osv-scanner: 0 findings. One real download was run once into a scratch folder to confirm the live path works (54,181 entries, 5 seconds).

## Open items for the owner
1. A written answer from the IEEE would still be good if you ever want to bundle the names.
2. The decompression and parsing of the downloaded file happens in the isolated process; the application then reads the resulting table in the main process
   with the caps above.
3. Self-review only.
