# Checkpoint 14: dynamic scan of the local web server (OWASP ZAP)

Commit under test: `8417e94` plus the fix in this checkpoint (uncommitted when the runs were made, committed afterwards).

## What was run

OWASP ZAP (stable image, pinned by digest `sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2`) scanning the RuleTruss server.
Both ran in one rootless Podman pod created with **no network** (`--network none`): the pod has only its own loopback, so neither process could reach
anything else, and nothing outside could reach them. The server ran in `python:3.14-slim` (digest `sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170`)
with a read-only root filesystem and tmpfs for data. All containers dropped every capability, set `no-new-privileges`, and had memory and process
limits. ZAP ran with `-silent` (no update or telemetry calls). The access token and ZAP key were random per run and used only inside the pod.
The data was the synthetic UniFi example. Nothing from the owner's network was used.

Method: a scripted driver walked the application through ZAP's proxy (static files, status, creating the example project, every GET route, the plan,
translate, export, suggest-groups and AI-package routes, and a few malformed requests) so ZAP recorded real requests with the token. Then ZAP's spider,
a passive scan and a **10 minute active scan** (SQL injection, XSS, path traversal, command injection, the Spring4Shell probe and the rest of the default
rule set) ran against what was recorded. Two full runs: one before the fix and one after. Reference copies of the harness are in `harness/` as `.txt` files.
The raw ZAP report and alert files are not archived (they contain the throwaway token and request detail).

## Findings

| ID | Risk | What ZAP reported | Verdict |
|---|---|---|---|
| CP14-01 | Medium | Content Security Policy header not set (on the response to a `PATCH`) | **Real, fixed.** See below. |
| CP14-02 | High (run 2 only) | Spring4Shell, on `POST /api/projects/<id>/ai` | **False positive, accepted.** See below. |
| CP14-03 | Low | Cross-site scripting weakness (persistent in JSON response): ZAP stored `<script>alert(1);</script>` as a project name | **False positive, accepted.** See below. |
| CP14-04 | Low (12) | Private IP disclosure | Expected: the application's job is to show addresses from the user's own data. |
| CP14-05 | Low (42 to 43) | Timestamp disclosure (Unix) | Expected: capture and flow times are data the user imported. |
| CP14-06 | Informational | Suspicious comments (3); User Agent Fuzzer (48) | Comments matched the words "from" and "where" in code comments; the fuzzer reported no difference. No action. |

### CP14-01 (fixed)

Root cause: when the HTTP library refuses a request before our code runs (an unsupported method such as `PATCH` or `TRACE`, a malformed or over-long request line), it writes
its own HTML error page. That path bypassed the one function that adds the security headers, so those responses had no CSP, `nosniff`, `no-store` and so on. It was not
exploitable (the page contains no user input and the app serves no cookies), but a response without the headers is inconsistent with the rest of the server.

Fix: `send_error` is overridden so these refusals answer as JSON with the full header set and close the connection. Tests `RefusalHeaderTests` (two) fail without the fix and pass with it.
After the fix, the second run no longer reports the Medium alert and a direct request confirms the headers on `PATCH` and `TRACE`.

### CP14-02 (false positive, with the check)

ZAP's Spring4Shell rule sends a normal request, then one carrying `class.module.classLoader.DefaultAssertionStatus=nonsense`, and flags a difference between the answers (a
vulnerable Spring application answers 400 to the nonsense value). This server is plain Python with no Java; it answers `400 the request body is not valid JSON` to **any** non-JSON
body on that route. Replayed by hand: the same answer for the values `nonsense`, `true`, `false` and `1`, and for an unrelated `foo=bar`. The alert did not appear in the first run, which
is consistent with a heuristic that depends on the baseline request it happened to make.

### CP14-03 (false positive, with the reason)

Project names are stored as given. They come back in JSON served as `application/json` with `X-Content-Type-Options: nosniff` and a CSP of `default-src 'none'`, and the page
puts every such string on screen with `textContent` (never as markup); `tests/test_server.py` checks that the page scripts contain no `innerHTML` and the headless interface check exercises it. ZAP's rule raised it with low confidence because the content type is not HTML.

## Tests and tools on the final tree

* Full suite: 506 tests, all passing. ruff clean.
* `tools/security_checks.py` (output beside this report): ruff, bandit, semgrep, gitleaks, pip-audit and osv-scanner all 0 findings; suppression gate 0 findings (71, all in the baseline).
  SAF CLI not run (optional, not installed).

## Suppressions added / removed, SSDF practices touched

None added or removed. PW.8 (test executable code): dynamic testing now has evidence; PW.5 (secure defaults): the server's own refusals now match the rest. Documents updated: `SECURITY.md`,
`SECURITY_TEST_PLAN.md`, `docs/SECURITY_FRAMEWORKS.md`.

## Limits of this evidence

* ZAP can attack only requests it has seen. The driver walked the main routes with valid and a few malformed requests. Routes and bodies not in that walk (uploading a real capture or
  configuration, background import jobs, `DELETE` routes, the vendor-name download, `/api/data`) were **not** attacked; they are covered by the project's own hostile-input and server tests, not by this scan.
  `DELETE` routes were left out on purpose so the scan would not delete its own data; the vendor-name download needs a network, which the pod does not have.
* One 10 minute active scan, default rules, one run after the fix. A scan finding nothing is not a proof of nothing there.
* Authentication is a single bearer token; ZAP cannot test token guessing meaningfully, and the token check is covered by `tests/test_server.py`.
* Not done: reading Podman or ZAP source, checking image signatures (none verified), a vulnerability scan of the two images.
* The scan must be repeated on the release candidate.
