# Checkpoint 19: what the first GitHub run found

Commit pushed and checked: `624ff4d`. The repository went public with that push. The fixes below are committed after this report and have not run on GitHub yet.

## Workflow results of the first push

| Workflow | Result | Why |
|---|---|---|
| Security (CodeQL, OSV scan, workflow audit, Scorecard) | passed | Dependency review is skipped on pushes by design (it needs a pull request). |
| CI: lint and static analysis, secret scan | passed | |
| CI: tests on Python 3.14 | **failed** | One test, `test_deeply_nested_json_is_a_clean_error`, expected an error for a JSON file nested 100,000 levels. This runner's Python reads such a file without error; the local one raises `RecursionError`. The code was right (every JSON reader accepts either outcome); the test demanded one. It now accepts a clean `ValueError` or a normal result and rejects any other exception. |
| CI: tests on Python 3.12 | **failed** | The headless-browser test: "browser did not start" within its 20 seconds (the same test passed on the 3.14 job, and the browser is started with `--no-sandbox`, so this is a slow start on a shared runner). The wait is now 90 seconds. |
| Dependabot (pip, github_actions) | passed | No pull requests opened. |

## The 11 code-scanning alerts

| Alert | What it is | Decision |
|---|---|---|
| 3, 4, 5, 6 (Pinned-Dependencies, medium) | `pip install` lines in the workflows not pinned by hash (the test library, the lint and audit tools, the workflow auditor). | **Fixed.** `requirements-test.txt`, `requirements-lint.txt` and `requirements-workflow.txt` (from `.in` files, via pip-compile with hashes) and every workflow installs with `--require-hashes`. Each file was installed in a clean environment with hash checking to prove it works. |
| 11 (py/insecure-protocol, high) | A test's throwaway local TLS server set no minimum TLS version. | **Fixed:** the minimum is TLS 1.2. Test code only. |
| 2 (Security-Policy, medium) | `SECURITY.md` had "no linked content". | **Fixed:** it now links GitHub's private vulnerability reporting page and says what to do if that is not enabled. The owner must enable private vulnerability reporting in the repository settings for the link to work. |
| 1 (Branch-Protection, high) | No branch rules on `main`. | **Owner setting** (checklist in `docs/SECURITY_FRAMEWORKS.md`). |
| 8 (Code-Review, high) | No change has been reviewed on GitHub; the project has one maintainer. | **Accepted.** A second reviewer does not exist. Not dismissed in GitHub; the README says no person has reviewed the code. |
| 9 (Maintained, high) | The repository is less than 90 days old. | Passes with time. |
| 7 (Fuzzing, medium) | No continuous fuzzing service (such as ClusterFuzzLite). | **Open, optional.** The parsers were fuzzed by hand (CP13); a continuous service is a later decision. |
| 10 (CII-Best-Practices, low) | No OpenSSF Best Practices badge. | **Optional** self-assessment, the owner's choice. |

## A known vulnerability accepted on purpose

Auditing the new hash-pinned lists found `mcp` 1.29.0 with GHSA-84m7-p3x7-pcfv (memory grows without limit in the stateful Streamable HTTP server transport, fixed in 1.30.0). `mcp` is a requirement of
`semgrep` only, pinned there to exactly 1.29.0 (semgrep 1.181.0 requires the same). CI runs `semgrep scan` once and never starts an MCP server, so the vulnerable code is not reached. The CI audit step
names this one vulnerability as an exception, with the reason next to it. Remove the exception when semgrep allows `mcp` 1.30.0 or later.

## Tests and tools

* Full suite: 567 tests passing locally; ruff clean; zizmor (strictest setting) no findings; `tools/security_checks.py` output beside this report.
* Not yet seen on GitHub: the fixes above. The first run after pushing them is the real test, particularly the hash-pinned installs of about 90 packages in the lint job.

## Root causes

* A test that fixed one Python's behaviour instead of the property that matters. Prevention: test the property (a clean error or a normal result).
* Installing tools without hashes while the policy said everything is pinned. Prevention: every `pip install` in the workflows now uses a hash file.
