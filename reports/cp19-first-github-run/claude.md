# Checkpoint 19: the first run on GitHub

Commit: the one that adds this report. The repository was pushed on 2026-10-15 and its workflows ran for the first time. Nothing had run there before, so this is what the local checks could not show.

## What ran

| Workflow | Result | Notes |
|---|---|---|
| Security (CodeQL, OSV dependency scan, zizmor, Scorecard) | passed | CodeQL found nothing in the application code. Scorecard and CodeQL together raised 11 code-scanning alerts; see below. |
| CI (tests on Python 3.12 and 3.14, lint, secret scan) | **failed**: one test in each of the two test jobs | Lint, bandit, semgrep, pip-audit and gitleaks passed. |
| Dependabot (pip, GitHub Actions) | passed, no pull requests | |

## CI failures

| ID | Job | Failure | Cause | Fix |
|---|---|---|---|---|
| CP19-01 | Python 3.14 | `test_deeply_nested_json_is_a_clean_error`: a UniFi file nested 100,000 deep was read without any error | The code already turns Python's own recursion error into a clean error (and so do the other JSON readers). Whether Python's JSON reader raises at that depth depends on the Python build: this machine's 3.14.7 does, the runner's 3.14 does not. My test required one outcome. | The test now accepts a clean `ValueError` or a normal result and rejects any other exception, which is the actual requirement. No change to the code. |
| CP19-02 | Python 3.12 | The headless browser test said "browser did not start" after 20 s (the same test passed in the 3.14 job) | A slow start of Chromium on a loaded shared runner. | The start-up wait is 90 s. If it recurs I will look at the runner's own log, not widen it further. |

## The 11 code-scanning alerts

| Alert | What | Decision |
|---|---|---|
| 3, 4, 5, 6 Pinned-Dependencies (medium) | `pip install` of the test library (CI and release), the lint and audit tools, and zizmor was not pinned by hash. | **Fixed.** `requirements-test.txt`, `-lint.txt` and `-workflow.txt` are generated with `pip-compile --generate-hashes` and installed with `--require-hashes`; each was installed that way in a clean environment. CI's pip-audit now covers all four requirement files. |
| 11 `py/insecure-protocol` (high) | A test's throwaway local TLS server did not set a minimum protocol version. | **Fixed:** `minimum_version = TLSv1_2`. |
| 2 Security-Policy (medium) | `SECURITY.md` has "no linked content". | **Fixed:** it now links GitHub's private vulnerability reporting page and says what to do if that is not enabled. (Reporting must be switched on in the repository settings: owner checklist.) |
| 1 Branch-Protection (high) | No rules on `main`. | **Owner action:** a branch ruleset (settings). Listed in the owner checklist. |
| 8 Code-Review (high) | Changes were not reviewed by another person. | **Not fixable by this project.** One maintainer; the README says no person has reviewed the code. To be dismissed with that reason, by the owner. |
| 9 Maintained (high) | The repository is less than 90 days old. | Time. Closes by itself. |
| 7 Fuzzing (medium) | No continuous fuzzing service is integrated. | Open. The parsers were fuzzed by hand (CP13); integrating a continuous service is a later option. |
| 10 CII-Best-Practices (low) | No best-practices badge. | Optional self-assessment; owner's choice. |

## A vulnerable package in the new lint list, accepted on purpose

Hash-pinning the lint tools made their whole dependency tree visible to the audit, and `pip-audit` flagged `mcp` 1.29.0 (GHSA-84m7-p3x7-pcfv, memory growth in its stateful HTTP server transport).
It is not RuleTruss's dependency: it comes in only through `semgrep`, which pins it to exactly 1.29.0 (the newest `semgrep`, 1.181.0, still does). The flaw is in running an MCP server over HTTP; CI runs `semgrep scan`
once and never starts one. CI's audit therefore carries one named exception, with this reason written next to it in `ci.yml`, to be removed when `semgrep` allows `mcp` 1.30.0 or later. It does not touch the runtime
dependency, which is audited with no exceptions.

## Tests and tools on the final tree

* Full suite: 567 tests, all passing locally. ruff clean. zizmor (strictest setting) reports nothing. `tools/security_checks.py` output is beside this report.
* Not yet seen: the CI run on the fixed code. That needs the owner to push.

## Suppressions added / removed, SSDF practices touched

None added or removed in code (the single audit exception is a CI option, recorded above). PS.1, PW.7, PW.8, RV.1.

## Root causes and what keeps them from coming back

* **A test that pinned an interpreter detail** (CP19-01): it demanded one specific outcome from behaviour that varies by Python build. Prevention: test the requirement (no other exception), not the implementation; CI runs two Python versions for exactly this reason.
* **Unpinned installs in workflows** (alerts 3-6): the runtime dependency was pinned and the tools were not. Prevention: every `pip install` in a workflow reads a hashed file; Scorecard will flag a new unpinned one.

## Limits

* The Scorecard alerts about process (branch rules, review, age, fuzzing, badge) describe the repository as it is; most are settings or time, not code.
* A first run catches what a local rehearsal misses, but the release workflow has still never run. It will run for the first time on the first version tag.
