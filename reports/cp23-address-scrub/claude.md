# Checkpoint 23: replace addresses that matched the maintainer's private list

## Findings

* **CP23-01 (privacy, fixed in the current tree).** A scan with the maintainer's private deny-list (a file kept outside every repository, checked by the new `privacy_check.py` of the shared security tooling) found 101 lines in 14 files whose invented-looking addresses followed a layout the maintainer treats as private: the UniFi and ASA test fixtures, the CML test pack and its generator, one UI check and a few tests. Nothing in `reports/`, in commit messages, in author data or in file names matched.
* **What changed.** The second octet of six subnets was replaced by an invented range (`10.77.x.y`), leaving the other octets, prefix lengths and every relationship between hosts and networks as they were. The addresses are test data only; no code path depends on the old values.
* **Deliberately not changed.** `10.0.0.0/24` and the other generic example addresses (`10.0.0.1`, `10.200.0.0` and so on) stay: they are common defaults and are not on the private list.
* **Not changed: history.** The earlier values remain in 7 earlier commits and in the `v0.1.0` tag. Rewriting public history would break the verified release files and their attestation for no practical gain on a private-range address, so it was not done.

## What is and is not proven

* The scan with the deny-list now reports no problems in the tree. Every other scanner result is unchanged.
* The CML pack (`samples/cml-test/`) has the same topology and the same rules with different numbers. It was **not re-run in CML**: the 24 of 24 result in CP17 was obtained with the earlier addresses. The results file contains no addresses, and the test that ties it to `asa-config.txt` still passes.

## Tests and tools on the final tree

* Full suite: 612 tests, all passing (`-X dev -W error::ResourceWarning`). The first run after the rename had one failure: `tests/test_unifi_translation.py` held a regular expression, written with escaped dots, that assumed every network started with `10.0`; it now accepts `10.0` and `10.77`. The text scan had not found it because the dots were escaped.
* `tools/security_checks.py` (output beside this report): ruff, bandit, semgrep, gitleaks, pip-audit and osv-scanner all 0 findings; suppression gate 0 findings (70, all in the baseline). SAF CLI not run.

## Suppressions added / removed, SSDF practices touched

None added or removed. PS.1 (protect repository content from unintended disclosure) and PW.8 (tests and the gate re-run on the final tree).

## Root causes and what keeps them from coming back

* **Test fixtures modelled on a real layout with no check on what was published** (CP23-01). Prevention: a privacy check now runs on the maintainer's machine before every push (a pre-push hook) and will run again in CI, against a private deny-list that never enters a repository. It reports only the file and line, never the text that matched.
* **A pattern the text scan could not see** (escaped dots in a regular expression). Prevention: the change was verified by the full test suite, not by the scan alone.

## Limits

* Earlier commits and the `v0.1.0` tag still contain the old values.
* The check can be skipped with `git push --no-verify`; the CI run is the backstop.
* No human has reviewed this change.
