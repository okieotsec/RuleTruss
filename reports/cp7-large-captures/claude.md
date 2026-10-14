# Checkpoint 7: large captures

Reviewer: Claude (self-review; independent review still open).

## What changed
* The five size limits (file size, packets, flows, time, memory) can be raised at start-up with `--max-capture-mb`, `--max-packets`, `--max-flows`,
  `--parse-minutes`, `--parse-memory-gb`. Each has a hard ceiling (`limits.CEILINGS`); values are validated (whole numbers, 1..ceiling, no booleans or
  unknown names). They cannot be changed through the API or by a file. The server sends its limits to the analysis process in the options, so the two
  always agree.
* Imports over 32 MB run as background jobs (`jobs.py`): upload, then poll progress (packets, percent, elapsed), with a Stop button that kills the worker.
  Two at a time; finished jobs are pruned; error text is only what the parsers raise on purpose.
* `isolate.parse_file` now uses `Popen`, polls for cancel and the deadline before waiting, and always kills the worker on any exit.
* Uploads are refused when less than the file size plus 1 GB would be free.
* Found and fixed while measuring: stored analyses were capped at 64 MB on read while the worker could return 256 MB, so a large import succeeded and then
  could not be opened. Both caps are now one value (512 MB) and the worker's file-size rlimit follows it.
* Default arguments that froze limits at import time (`max_packets`, `max_flows`, `timeout`) now read the current value.

## Security notes
| Risk | Control | Test |
| --- | --- | --- |
| Raised limits widen the denial-of-service surface | start-up only, ceilings, documented in SECURITY.md and printed at start-up | `AdjustableLimitTests` |
| Hostile limit values | strict validation; nothing changes on a refusal | `test_nonsense_and_over_ceiling_values_are_refused_and_change_nothing` |
| Progress file written by the worker is untrusted | parent reads 512 bytes, accepts three integers, anything else is ignored | `test_the_worker_writes_progress_atomically_and_the_parent_reads_only_numbers` |
| A job that cannot be stopped | cancel checked before every wait; worker killed in `finally`; timeout enforced | `CancelTests` |
| Piling up jobs or disk | two running at once, 40 finished kept, disk check | `JobTests`, `test_a_full_disk_is_refused_before_anything_is_written` |
| Job ids | 64-bit random, behind the access token like every other route | `test_unknown_jobs_and_bad_ids` |

## Measurements (generated capture, 3,000,000 packets, 810 MB, ~3 million distinct flows: worst case for memory)
Analysis 115 to 139 s (about 26,000 packets per second); analysis process peak 0.9 GB; with the 200,000-flow limit reached the stored analysis was 239 MB and
the main process needed 1.7 GB and about 15 s to open it. End to end through the real server: upload 0.6 s, progress reported every 20% from the first
poll, finished with the source listed. A real 3 GB capture was not available, so its packet count and flow count are unknown; the documentation gives the
rule of thumb (time scales with packets).

## Results
375 tests pass (23 new in `tests/test_large_captures.py`); fuzz at `RT_FUZZ_SCALE=10` for properties and malicious inputs passes; the headless UI check now
also imports a 35 MB capture through the real file input. ruff, bandit, semgrep, gitleaks, pip-audit and osv-scanner: 0 findings.

## Open items
1. A real multi-gigabyte capture has not been run; the flow count of the owner's file decides whether the 200,000-flow default is enough.
2. Self-review only.
