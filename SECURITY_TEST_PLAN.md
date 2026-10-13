# Security Test Plan: Policy Bridge

**Owner:** okieotsec (project lead, final approver)
**Reviewers:** Claude Code (developer and reviewer). Independent review by another reviewer is recommended before any public release and has **not** been done.
**Applies to:** every checkpoint below. The method follows the sibling project's plan (OT Triage); the threat model is new because this application reads untrusted
packet captures and configuration exports and serves a local web page.

---

## 1. Purpose and rules of engagement

1. **Work from a recorded commit.** Record the commit hash in the report.
2. **Evidence over opinion.** Every finding needs a file and line, a reproduction or tool output, and a severity from section 7.
3. **Run the tools; don't simulate them.** Output comes from a real run (`tools/security_checks.py`). A tool that cannot run is reported as NOT RUN with the reason.
4. **Don't fix while reviewing.** Findings are reported, then fixed in a separate change and re-tested (section 8).
5. **No sensitive data.** Only synthetic inputs (`pbridge/synthetic.py`, `tests/fixtures/`, `samples/`) are used. Never real captures, customer or employer configurations.

## 2. Scope

**In scope:** all of `pbridge/` (parsers, evaluator, storage, isolation, server, web page), `tools/`, third-party packages, packaging.
**Out of scope:** the host operating system, the Python interpreter and the browser, except where this application uses them unsafely.

## 3. Threat model (summary)

| Entry point / asset | Threat | Examples tested |
| --- | --- | --- |
| Uploaded capture (PCAP, PCAPNG) | Malformed or hostile packets; resource exhaustion | Random bytes after a valid header, truncation, absurd packet lengths, IP header length 0 or lying, TCP offset garbage, IPv6 extension-header chains, DNS compression loops, TLS length overflows, huge SNI, Modbus length mismatch, bogus PCAPNG blocks, many flows |
| Uploaded configuration (text and XML) | Entity expansion, DTD/XXE, deep nesting, huge files and lines, NUL/UTF-16, group cycles, exponential group fan-out, 100,000-rule files, non-ASCII digits, credentials | See `tests/malicious_cases.py` |
| Zeek logs | Giant lines, binary, NaN and huge numbers, JSON nesting | `flow_logs()` |
| Credentials inside exports | Disclosure through the screen, stored files, exports, errors, logs, AI prompts | `tests/test_server.py`, `tests/test_malicious.py`, `redact.py` properties |
| Strings from uploads shown or exported | HTML/script injection in the page, Markdown links, CSV/spreadsheet formulas, configuration-line injection in generated text | Labels, rule names, host names |
| Local web server | Other local users, cross-site requests, DNS rebinding, oversized or chunked bodies, path traversal, CORS | Token, Host and Origin checks, size limits, id validation, strict CSP |
| Data at rest | Over-permissive files, partial writes, lost updates, leftover uploads, incomplete deletion | Modes 0700/0600, atomic writes, lock around project updates, deletion tests |
| Optional AI path | Data leaving the machine, prompt injection from uploaded text, SSRF-style endpoints | Off by default, scheme/host checks, grounded prompt with untrusted markers |
| Dependencies | Vulnerable or malicious packages | One runtime dependency, pinned with hashes; pip-audit, osv-scanner, SBOM |
| Decisions | A wrong or silently altered result | Three-valued evaluation, blocked-not-widened translation, validation against the source |

## 4. Checkpoints

| ID | When | Focus |
| --- | --- | --- |
| CP0 | After the core engine, adapters, server and interface exist | Baseline: full toolchain, first SBOM, record accepted findings |
| CP1 | After the core-engine fixes from CP0 | Re-run; hostile-input, fuzz and server tests green |
| CP2 | Release candidate | Full regression, deeper fuzz run, final SBOM, release gate |

Later changes (a new adapter or parser) get their own checkpoint report before merging.

## 5. Static analysis and supply chain

Run `python tools/security_checks.py reports/<checkpoint>`; it writes each tool's raw output and prints one line per tool.

* `ruff check .` (includes the `S` rules that mirror bandit)
* `bandit` on `pbridge/` and `tools/` (tests excluded)
* `semgrep scan --config p/python --config p/security-audit --metrics off`
* `gitleaks detect` over the full git history
* `pip-audit -r requirements.txt --require-hashes` and `osv-scanner --lockfile=requirements.txt`
* SBOM: `python tools/make_sbom.py` builds a clean environment from `requirements.txt` with `--require-hashes` and writes `sbom/sbom.cdx.json`; it fails if the SBOM and the
  requirements disagree.
* Every new dependency needs a one-line justification in the report. Current runtime dependencies: **dpkt 1.9.8** (BSD; reads PCAP/PCAPNG and decodes link, IP and
  transport headers; pure Python; no network or shell code).

## 6. Manual review checklist and dynamic testing

**Input handling:** file type is decided by content, not name; every parser has size, line, depth and expansion limits; errors are readable and contain no stack trace or path; no `eval`,
`exec`, `pickle`, `shell=True`; the XML loader refuses DOCTYPE and entities; parsers import no networking modules (tested).
**Isolation:** each upload is parsed in a subprocess with a clean environment, an empty working folder, a wall-clock timeout and RLIMIT memory, CPU, file size, open files and core.
**Server:** loopback only unless explicitly overridden; bearer token on every API call; Host and Origin checks; no CORS; streamed uploads with a size limit; chunked uploads refused; strict CSP; `no-store`.
**Storage:** data folder 0700, files 0600; atomic writes; project updates serialised; deletion overwrites then unlinks and says what it cannot guarantee.
**Output:** CSV cells neutralised; Markdown escaped; no `innerHTML` for upload-derived text; generated configuration text cannot be injected into through rule names; credentials redacted before storage.
**Honesty of results:** unknown is never treated as false; blocked rules are never widened; every broadening or lost restriction is reported; validation limits are printed with every report.

**Dynamic testing** is automated: `tests/test_malicious.py` (hostile files through the real isolation path, resource-limit mechanisms, no-network and no-dynamic-code scans),
`tests/test_properties.py` (Hypothesis; `PB_FUZZ_SCALE=30` for the checkpoint run), `tests/test_server.py` (access control, limits, workflows, exports, deletion, AI path).

## 7. Severity rubric

| Severity | Meaning | Example |
| --- | --- | --- |
| Critical | Code execution, or a silent wrong decision on real data | Executing text from a file; a blocked deny rule silently dropped |
| High | Bypass of a security control, or injection into a downstream tool | API reachable without the token; working CSV formula injection |
| Medium | Denial of service or an integrity problem with a visible symptom | Crash or hang on a malformed file; lost update of project data |
| Low | Hardening gap with limited impact | Missing size cap on a small local file |
| Info | Best-practice note | Missing docstring on a security-relevant function |

Dependency CVEs are rated by actual reachability, with the reasoning stated.

## 8. Reporting and triage

One report per checkpoint at `reports/<checkpoint>/<reviewer>.md` in this format:

```
Reviewer:
Checkpoint / commit:
Tools run (with versions):
Tools not run (and why):

Finding <ID>
- Title / Severity / Location (file:line) / Description / Evidence / Recommended fix / Confidence (Confirmed, Likely, Needs verification)
```

The project lead merges findings, verifies each by reproducing it, and assigns: fix now, fix before release, or accept with documented reasoning. After a fix the finding is re-tested and marked
verified. AI-written findings can be plausible but wrong: nothing is fixed or accepted until it is reproduced.

## 9. Exit criteria

**Each checkpoint:** every tool in section 5 ran with output attached; no open Critical or High finding; each Medium fixed or accepted with reasoning; the full test suite passes; SBOM generated.
**Release additionally requires:** no known dependency vulnerability or each documented as unreachable; `SECURITY.md` current; an independent review by someone other than the developer.
