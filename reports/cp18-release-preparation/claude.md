# Checkpoint 18: preparing a first release

Commit: the one that adds this report. No new feature. This checkpoint looks for what would go wrong the first time someone else gets the code, and adds the way to verify a download.

## Findings

| ID | Sev | Finding | Root cause | Fix and prevention |
|---|---|---|---|---|
| CP18-01 | **High** | A project analysed by an older version was read as if it were current. On the owner's own project, an old stored parse of a UniFi export made the ASA translation say 1 policy translated and 157 not applicable; a fresh parse says 68 and 76. Nothing said the analysis was out of date. Anyone upgrading RuleTruss would have hit it. | A stored analysis had no version, and the code used whatever was stored. Parsers had changed since (zones now keep their networks). | Every analysed file carries a parse-format stamp (`PARSE_FORMAT` in `store.py`, to be raised whenever what is stored changes). A stored configuration with an older or missing stamp is re-read from its kept original in the same isolated worker before use; if that fails the old analysis stays and the file is marked. Captures (large, so re-reading is the user's choice) are flagged in the Files list. Four tests, including the old-parse scenario. |
| CP18-02 | **High** | A clean checkout failed two test modules: `tests/fixtures/unifi-export.json` was not in the repository. | The ignore rule that keeps real UniFi exports out (`unifi-export*.json`) also matched the invented test fixture. The CP15 review had pointed at this missing file; I put it down to its sandbox, which was wrong. | The fixture (invented: older API version, private addresses only) is un-ignored by name; the rule still ignores a real export anywhere else. Found by running the whole suite from an extracted copy of the committed bundle: 567 tests, OK. The CI test job and the release workflow run on a clean checkout, so this class of fault fails there first. A local rehearsal (`git archive`, extract, run) belongs in the release checklist. |

## Release workflow

`.github/workflows/release.yml` runs on a pushed version tag: it checks that the tag equals the version in the code, installs the one runtime dependency with hashes, runs the tests,
builds `ruletruss-<version>.tar.gz` with `git archive`, writes a SHA-256 file, attaches the SBOM, attests build provenance (`actions/attest-build-provenance`, pinned to a full commit), and uploads the result as a
workflow artifact. It does **not** create or publish a release; the owner does that by hand after reading the artifact. Permissions are empty at the top and `contents: read`, `id-token: write`
and `attestations: write` on the one job; every action is pinned to a commit; credentials are not persisted; a concurrency group keeps two runs of one tag from overlapping.

* zizmor 1.30.1, strictest setting (`--persona pedantic`), over all three workflows: no findings (one finding on the first draft, a missing concurrency setting, was fixed).
* The build steps were rehearsed locally with the same commands: the bundle has 481 files and none of a virtual environment, caches, keys or environment files.
* **It has never run on GitHub.** The attestation and `gh attestation verify` are therefore untested. PS.2 in `docs/SECURITY_FRAMEWORKS.md` says "Partly" until a tagged run has been verified, and `SECURITY.md` has a "How to verify a download" section that says no release has been built yet.

## Other changes

* The generated CML test document and this project's CP17 report describe the CML lab-file layout without saying where a sample of it came from; the fixture is a neutral two-node example of the layout (`tests/fixtures/cml-lab-layout-0.3.1.yaml`).
* The owner checklist gains tag protection (only the owner may create `v*` tags, since they start the release workflow).

## Tests and tools on the final tree

* Full suite: 567 tests, all passing, both in the working tree and from an extracted copy of the committed bundle. ruff clean.
* `tools/security_checks.py` (output beside this report): ruff, bandit, semgrep, gitleaks, pip-audit and osv-scanner all 0 findings; suppression gate 0 findings (70, all in the baseline). SAF CLI not run.

## Suppressions added / removed, SSDF practices touched

None added or removed. PS.1, PS.2, PS.3, PW.7, RV.1 (a defect found by a rehearsal, with its cause).

## Root causes and what keeps them from coming back

* **Stored results without a version** (CP18-01): the stamp, the refresh and the file-list marker. Anyone who changes what is stored must raise `PARSE_FORMAT`; the test for the old-parse scenario shows what happens if they forget the other half.
* **A broad ignore rule hiding a needed file** (CP18-02): the narrow exception, and CI on a clean checkout.

## Limits

* Nothing here has run on GitHub. The release workflow, CodeQL, Scorecard, dependency review and Dependabot are untested until the repository is published.
* Only a person who reads the code, or who runs these firewalls, can review what AI and scanners cannot; the README says no one has.
* The first release will be experimental (0.x). The owner decides whether and when to publish.
