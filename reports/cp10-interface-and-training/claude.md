# Checkpoint 10: graph drill-down, interface refresh, tabs that say when they are not ready, training guide

Reviewer: Claude (self-review; independent review still open). The raw tool output was not stored in the repository this time: the security
framework that another session added writes absolute paths into its reports, which the repository's hygiene test rightly refuses.

## What changed
* **Graph** (`web/graph.js`): force layout with subnet clusters, drag, pan, zoom, fit, a box the user can resize (CSS `resize`, size presets), label modes, hover
  highlighting, keyboard access, and a drill-down panel for a device, a subnet or one direction (counts, busiest peers and services, a small sample of the
  traffic and of recent connections, with evidence). Double-click opens a subnet's devices. New API: `GET /graph/detail`, `graph?focus=`; the observed data is cached
  per project state. Links from the panel pre-filter Communications.
* **Interface**: sticky header with icons, theme switch (system, light, dark), cards accented by what they describe, stat tiles, zebra tables, loading skeletons,
  a getting-started checklist, a neutral chip for "nothing listed".
* **Tabs that are not ready** carry a padlock and a tooltip saying what they need; opening one shows what is missing with a button that fixes it.
* **Examples**: a UniFi example project (invented export and capture) with a deliberate all-states-block mistake; `samples/unifi/`.
* **Training guide** (`docs/TRAINING.md`), generated from live results, with a test that it is current and that every button and tab it names exists.
* Fixes found on the way: "broad" no longer fires for service-limited zone-pair policies; addresses in documentation ranges count as Internet in UniFi
  zone lookup; a block with policies before it is labelled "Block, n allowed"; reply wording is "uncertain" when the answer is undecidable.

## Security notes
| Risk | Control | Test |
| --- | --- | --- |
| Script injection through names shown in the graph or its panel | every string is placed with `textContent`; no HTML assignment, `eval` or inline script anywhere in the scripts | `StaticPageTests` (source scan), `test_a_hostile_label_comes_back_as_plain_text` |
| The page's CSP (`style-src 'self'`) | no style attributes: the graph's size is set through the CSSOM; a test scans for style attributes | `StaticPageTests`, headless browser run (no console errors) |
| New API accepting arbitrary ids | device ids must be IP addresses, subnet ids valid networks, edges validated the same way; unknown ones are clean 404/400 | `tests/test_graph.py` |
| Large responses | samples are capped (6 communications, 5 flows, 6 peers, 8 services); the graph keeps its 120-device cap | `test_samples_are_small_and_carry_evidence` |
| Colours as the only cue | each graph colour is at least 3:1 against the panel in both themes; subnets are also named in a legend and in each node's label and title | `test_graph_colours_are_visible...` |
| Theme switch stored in the browser | wrapped in try/catch; the page works without storage | browser run |

## Results
469 tests; the only failure is `test_no_personal_name_or_home_folder_path_...`, caused by `reports/cp9-security-framework/hdf/semgrep.hdf.json` (created by another session) containing a home-folder path. ruff, bandit, semgrep, gitleaks, pip-audit and osv-scanner: 0 findings (run to a scratch folder). The headless browser check now has 70+ checks, including real mouse clicks, drag, double-click, resize,
theme switch and the not-ready pages.

## Open items
1. The `cp9-security-framework` folder and the changes to `tools/security_checks.py`, `tests/test_security_checks.py`, `.gitignore`, `requirements-dev.txt` and
   `security/` were not made in this session; the folder contains home-folder paths and must be cleaned or ignored before anything is committed.
2. The graph is drawn in one pass; a few hundred devices in one subnet would need the layout moved to a worker thread.
3. Self-review only.
