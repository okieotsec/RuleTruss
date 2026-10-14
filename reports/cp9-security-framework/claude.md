Reviewer: Claude Code (developer and reviewer). No independent review.
Checkpoint / commit: CP9 (security process: NIST SSDF and MITRE SAF alignment) / working tree on top of a1938bb, before commit. The working tree also holds unfinished, uncommitted work from other changes (UniFi, device identification, large captures, training samples); the scanners ran over it as it was, and the tree changed while this checkpoint was being run.
Scope: no change to the application. New or changed: tools/security_checks.py (suppression inventory and gate, SARIF output, optional SAF conversion), tests/test_security_checks.py, security/suppressions.baseline.json, .github/workflows (ci.yml changed; security.yml new), .github/dependabot.yml, requirements-dev.txt (bandit with its SARIF extra), SECURITY.md, SECURITY_TEST_PLAN.md, docs/SECURITY_FRAMEWORKS.md, README.md, CHANGELOG.md, reports/README.md.
Tools run (with versions): ruff 0.16.10, bandit 1.9.4, semgrep 1.180.0, gitleaks (full history), pip-audit 2.10.1, osv-scanner 2.5.1, MITRE SAF CLI 1.7.0, zizmor 1.30.1 (including `--persona pedantic`), the full suite (469 tests), 8 mutation checks of the new gate
Tools not run (and why): atheris and a dynamic scan of the local server with OWASP ZAP (not part of this change; both are open items in docs/SECURITY_FRAMEWORKS.md); the new GitHub workflows (the repository is not published); Heimdall (not opened)

Tool results (attached under reports/cp9-security-framework/)
- ruff, bandit, semgrep, gitleaks, pip-audit, osv-scanner: 0 findings each. Suppressions: 71, all in the reviewed baseline. SAF: 0 failed results after 5 suppressed semgrep results are left out (listed in suppressions.json).
- Full suite: 468 of 469 pass. The one failure is `test_source_hygiene` rejecting `tests/test_training.py`, a file from other in-progress work that spells the forbidden name and path strings out in full; it is not part of this checkpoint and needs that file to build them from pieces, as the hygiene test itself does. An earlier run in the same hour also failed a rule-count assertion in code that was being edited at the time; it passed on the next run.

What was checked
- Suppression review: the inventory found 65 suppression comments when first run, and the number grew to 71 as other work continued during this checkpoint. All were read. They are fixed-argument subprocess calls (the parse worker, the test certificate, the headless browser against loopback), URL opens restricted to http and https or to the IEEE host, an XML loader used only after DTDs and entities are refused, packet addresses in generated data that are never bound, and module-path setup in tools. Each has a stated reason or an obvious one. A new or additional one now fails the run until it is accepted; the gate was seen to fail on 14 and then on 2 suppressions that arrived during the checkpoint, and each was read before it was accepted.
- The gate fails when it should: the same 8 deliberate breakages as in OT Triage's CP21 were each caught by the new tests.
- SAF behaviour: observed on this project's real output (see OT Triage CP21 for the details of the threshold exit code and the compliance percentage).
- Workflows: zizmor reports no findings (pedantic persona included); every action is pinned to a full commit resolved from the upstream tag; the OSV job passes `--lockfile=requirements.txt`. None has run on GitHub.
- Archived output is trimmed and path-scrubbed; the repository-wide hygiene test found the untrimmed version of this output during the checkpoint (finding CP9-01).

Findings

Finding CP9-01
- Title: Archived tool output embedded third-party rule text and a home-folder path
- Severity: Low
- Location: tools/security_checks.py (first version of the SARIF step)
- Description: see OT Triage CP21-03. The same runner is used here.
- Evidence: `tests.test_source_hygiene` failed on the home-folder check on `reports/cp9-security-framework/hdf/semgrep.hdf.json`. Nothing was committed.
- Root cause and prevention: tool output was archived verbatim; the runner now archives a trimmed, scrubbed copy and has tests for it.
- Status: fixed. Confidence: Confirmed.

Finding CP9-02
- Title: CI had no OSV scan, and nothing ran on a schedule
- Severity: Info
- Location: .github/workflows
- Description: the plan lists osv-scanner, but it ran only at a checkpoint; CI had pip-audit only. Nothing ran weekly, so a new advisory against dpkt would be noticed only at the next change. Dependabot watched only GitHub Actions.
- Root cause and prevention: the checkpoint tools and the CI tools had drifted apart. security.yml adds osv-scanner on `requirements.txt`; both workflows run weekly; Dependabot now also watches the pip files, with a seven-day cooldown.
- Status: fixed (untested until the repository is published). Confidence: Confirmed.

Finding CP9-03
- Title: No independent review and no dynamic test of the local server
- Severity: Info (already a release-gate item)
- Location: SECURITY_TEST_PLAN.md section 9
- Description: both are required before a public release and neither has happened. The plan now names the atheris and ZAP runs explicitly instead of leaving fuzzing and server testing implied.
- Status: open, tracked in docs/SECURITY_FRAMEWORKS.md. Confidence: Confirmed.

Release gate for this change
| Gate | Evidence | Pass |
| --- | --- | --- |
| No change to the application | only documents, tools, tests and CI changed | Yes |
| Scanners clean | all six report 0 findings | Yes |
| Full suite passes | 468 of 469; the one failure is another change's new test | No: fix `tests/test_training.py` before committing |
| New gate tested | 8 tests, 8 mutation checks caught | Yes |
| Workflows audited | zizmor clean (pedantic) | Yes |
| Workflows proven on GitHub | not published | No |
| Independent review, atheris, ZAP | none done | No (release-gate items, open) |
