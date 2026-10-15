# Checkpoint 13: coverage-guided fuzzing of the parsers (Atheris)

Commit under test: `9328065` plus the fixes in this checkpoint (uncommitted when the runs were made, committed afterwards).

## What was run

Atheris 3.1.0 on Python 3.14.7, in a throwaway virtual environment outside the repository (nothing was added to the project's dependencies). The project's own
pinned runtime dependency was installed into it with `--require-hashes`. In-process, instrumented, with libFuzzer's 30 second per-input timeout and a 1 GB memory
limit. Reference copies of the harness are in `harness/` as `.txt` files.

Only `ValueError` and `OSError` count as expected (the parsers raise them on purpose with user-safe messages). Any other exception is a finding.

| Target | Entry point | Input | Seeds |
|---|---|---|---|
| config | `parse_config`, every format and auto-detection | random text | the six fixture configurations |
| unifi | UniFi parse, then translation to ASA, IOS and FortiOS and rendering | the sample export with 1 to 6 values replaced (structure-aware) | none (the mutation starts from the sample export) |
| capture | `analyze_capture_full` | random bytes in a file | the sample PCAP and PCAPNG |
| zeek | `parse_conn_log` | random bytes in a file | the sample conn.log |

## Findings

All four were unhandled exceptions on malformed text, not memory-safety or resource problems. In production the isolated worker catches them and the user sees
"the file could not be processed", so the effect is a worse error message and a failed import, not a crash of the server or a data leak. Severity: Low.

| ID | Where | Input | Root cause | Fix and prevention |
|---|---|---|---|---|
| CP13-01 | `adapters/fortios.py` (tokenizer, read at `read_policies`) | `set logtraffic` with no value | The tokenizer stored an empty list for a `set` with no value; about thirty readers index the first value of any key they find. | A `set` with no value is dropped like `unset`, in one place. Test `test_a_set_line_with_no_value_is_ignored_not_a_crash`. |
| CP13-02 | `adapters/cisco.py` `add_ace` | `access-list NAME extended` with nothing after the type | The reader strips the type keyword and assumed a rule body was left. | `add_ace` returns when nothing is left. Test `EmptyRuleBodyTests`. |
| CP13-03 | `adapters/cisco.py` `read_object` | `object network` with `subnet 10.0.0.0` and no mask | The mask form indexed a third token without checking it exists. | Guard on the token count. Test `test_a_network_object_subnet_with_no_mask_is_skipped_not_a_crash`. |
| CP13-04 | `capture/zeek.py` `_int` and timestamp | `inf` or `1e999` as a port or timestamp | `float()` accepts them, `int()` raises `OverflowError`, which was not caught; an infinite timestamp would have been read as a time. | `OverflowError` handled, non-finite timestamps rejected and counted as skipped rows. Test `test_infinite_numbers_in_a_row_do_not_crash_the_parser`. |

Each regression test was run against the unfixed code and failed there, and passes with the fix.

The common cause of three of the four is an unchecked index into a token list. A review of all remaining `[n]` accesses in the adapters was **not** done; fuzzing is the
check, and it covers only what it reached. Prevention for the class: the fuzz targets above are the regression net, and should be re-run after any parser change.

## Runs and results on the fixed code

| Target | Executions on the final code | Time | Crashes |
|---|---|---|---|
| config | about 108,000 (a 20 minute run of about 100,000, and the last 15 minute round of about 8,000) | 35 min | 0 |
| unifi | about 25,700 | 15 min | 0 |
| capture | about 185,000 | 15 min | 0 |
| zeek | about 1,760,000 | 15 min | 0 |

The unifi and capture runs started before the fixes above. Neither could have hit those bugs (they do not reach the ASA/IOS/FortiOS readers or the Zeek reader), so
they were not repeated.

## Harness faults on the way (not product defects)

* Two restarts used libFuzzer's fork mode, which re-launches the interpreter by a relative path. Every child died at start-up and the log read as
  hundreds of thousands of "crashes" with zero coverage. Those runs were discarded and counted as nothing; a plain restart-after-crash loop was used instead.
* One round after a fix started before the fix was written and so re-found the same crash; it is a duplicate, not a fifth bug.

## Tools and tests on the final tree

* Full suite: 504 tests, all passing. ruff clean.
* `tools/security_checks.py` (output beside this report): ruff, bandit, semgrep, gitleaks, pip-audit and osv-scanner all 0 findings; suppression gate 0 findings (71, all in the baseline).
  SAF CLI not run (optional, not installed).

## Suppressions added / removed, SSDF practices touched

None added or removed. PW.8 (test executable code) and PW.5 (secure coding): documented in `docs/SECURITY_FRAMEWORKS.md` and `SECURITY_TEST_PLAN.md`; the PW.8 row now says Atheris was run once.

## Limits of this evidence

Fuzzing shows that these inputs, mutations and run lengths found nothing more; it does not show the absence of bugs. The runs were short (15 to 20 minutes per target), with small
seed sets and one Python version, and the time each of the six configuration formats received was not measured. Not covered: the local web server (no
ZAP scan yet), the PCAPNG options and link-layer decoders beyond the sample seeds' reach, and the translation code on hostile inputs other than the mutated UniFi export.
The Atheris run must be repeated on the release candidate.

## Re-run after the CP15 fixes (2026-10-14)

The CP15 review changed the parsers a good deal (line and list limits, bounded groups, strict Zeek values, float timestamps, mixed-version ranges), so the four targets were run again
for 15 minutes each on commit `697f046`, in the same throwaway environment, with the same harness.

| Target | Executions | Crashes |
|---|---|---|
| config | about 82,000 | 0 |
| unifi | about 25,000 | 0 |
| capture | about 585,000 | 0 |
| zeek | about 1,473,000 | 0 |

Same limits as above: short runs, small seed sets, one Python version; no crash is evidence, not proof. The run must be repeated on any release candidate.

## Second re-run, after the CP16 fixes (2026-10-14)

The Copilot review (CP16) changed the parsers again (lookup budgets, unreadable services, Zeek checks, FortiOS tree handling), so each target was run once more, 10 minutes each, on commit `0b73b17`.

| Target | Executions | Crashes |
|---|---|---|
| config | about 25,000 | 0 |
| unifi | about 14,000 | 0 |
| capture | about 177,000 | 0 |
| zeek | about 360,000 | 0 |

Shorter than the earlier runs and with fewer executions (the machine was also running other work); the same limits apply. No crash is evidence, not proof.
