# Checkpoint 15: review of the code by a different AI model (OpenAI Codex)

Commit reviewed: `5e704df` (the snapshot was `git archive` of that commit with reports, images and demo output removed). Fixes were made on top of it and are
committed afterwards.

**What this is, and what it is not.** The owner asked for an independent review and has one available: the Codex command line tool, installed locally. It is a
different model from the one that wrote the code, which gives some independence, but it is **an AI review, not a review by a person**. It does not
satisfy the release gate's requirement for a review by someone other than the developer; that item stays open.

## How the review was run

* Three separate read-only passes, in parallel, each with a written brief (scope, threat model pointer, required format: severity, file and line,
  a trigger, reproduced or reasoned, a suggested fix, "Not reviewed", an overall assessment). The briefs gave no conclusions of mine.
  Scopes: (A) server, isolation, storage, exports, web page, helper tools; (B) the parsers and capture readers under hostile input; (C) the
  decision logic and the UniFi to ASA translation.
* Codex 0.162.0, the model set in the owner's own configuration, reasoning effort high. Started with a read-only sandbox, no session files kept, and the owner's
  personal Codex configuration ignored (so none of their other projects' tools or memory were loaded). It saw only the snapshot: code, tests, documents and
  sample data, all synthetic. The snapshot was sent to the service the owner is signed in to; that was the owner's explicit choice.
* Its sandbox could not write temporary files, so it could not run the project's test suite; it ran isolated in-memory reproductions instead.
* Every finding was then **checked by me**: a regression test was written for each, run against the code as reviewed (with only the application code reverted,
  tests kept) and it failed there; then fixed, and the test passes. The reviewer's own words ("REPRODUCED") were not taken as proof. Raw review text is not
  archived (it contains file paths from the review environment).

## Findings: 17 distinct issues, all confirmed, all fixed

Severities are the reviewer's, adjusted where my reading differs.

### Translation and validation (review C)

| ID | Sev | Finding | Root cause | Fix and prevention |
|---|---|---|---|---|
| CP15-01 | High | A UniFi block on `ESTABLISHED`/`RELATED` traffic was marked "implemented by the target" and the result stayed deployable. | The classifier treated every policy with no `NEW` state as the ASA's own state handling. | Classified by action **and** state set: only a return-traffic allow and an `INVALID`-only block are implemented; the others are *unsupported* (and make it a preview). Tests for both directions. |
| CP15-02 | High | A rule needing more than 2,000 access-list lines was cut off and still marked deployable; the marker line was written after `access-list ... extended`. | `deployable` was decided before rendering found the cut. | The size is computed in translation; an over-limit rule is a blocker and *unsupported*, and is never partly written. |
| CP15-03 | High | A pair with some policies but no final Allow All / Block All, and every pair that starts at External, were not flagged. | The check was only "does the pair have any policy", and only for sources that have networks. | Every pair, with External as a source too, needs an enabled, unrestricted final default; otherwise a blocker. Tests for both cases. |
| CP15-04 | **High** | **With interfaces mapped, validation compared zero connections and still said "no difference found on the sampled connections."** | The check-the-output step used unmapped interface names while the generated text used the mapped ones, so every case was undecidable; the headline ignored how many were compared. | The mapping is applied; the headline now says how many were compared and "nothing could be compared" claims no agreement. Test: on the clean example 173 are compared (35 allow, 138 deny), 3 not. |
| CP15-05 | Medium | The evaluator could return a definite answer past an earlier maybe-matching rule of the other action when a different earlier rule was the first. | Only the first uncertain rule's action was compared. | Any earlier maybe-match of a different action keeps the answer open. |
| CP15-06 | Medium | Observed ICMP codes were thrown away and replaced by 0 in comparisons and in the narrow workflow. | `Communication` had no code. | The code is kept in the aggregate key, the comparison and the generated entry. |
| CP15-07 | Medium | A known source MAC settled an unresolved destination-MAC condition. | Both MAC conditions shared one text prefix and one "known" test. | Source and destination are separate conditions; only the source one is settled. Test goes through the UniFi adapter. |

### Server and output (review A)

| ID | Sev | Finding | Fix |
|---|---|---|---|
| CP15-08 | High | A line break in a PAN-OS `description` (and a blocked-rule reason, and a typed interface name) added real command lines to the generated Cisco/FortiOS text. | Comments are cleaned to one plain line when a configuration is parsed and again where they are written; typed interface names must match a strict pattern. Test over all three targets. |
| CP15-09 | Medium | Credentials written in administrator comments were copied unredacted into the parsed policy, API and export. | Comments are redacted at parse time. |
| CP15-10 | Medium | Slow or unfinished connections could use every server thread (token and Host checks happen after headers). | At most 64 open connections (excess closed at once) and a 15 second deadline for the request line and headers. Tests. |
| CP15-11 | Medium | The optional AI endpoint's redirects were followed, bypassing the host and scheme checks. | Redirects are refused. Test with a redirecting local server. |
| CP15-12 | Medium | The UniFi export helper limited each response, not the run (up to tens of gigabytes, no overall deadline). | Total byte, request, item and time budgets; oversized pages refused. Tests. |

### Parsers (review B)

| ID | Sev | Finding | Fix |
|---|---|---|---|
| CP15-13 | Medium | A configuration line over 20,000 characters was cut short, silently dropping a trailing `inactive` and leaving an enabled permit-any. | Over-long lines are refused. |
| CP15-14 | Medium | A UniFi list over 100,000 items was cut before sorting, silently losing policies. | Refused instead. (An older test asserted the cut; it now asserts the refusal.) |
| CP15-15 | Medium | Group expansion was unbounded in the Cisco service, FortiOS, PAN-OS and pfSense resolvers; the rule limit was not enforced in three adapters. | One bounded helper; a group that is too large is also reported unresolved so no rule relies on part of it; rule limit enforced everywhere. |
| CP15-16 | Medium | A range from an IPv4 to an IPv6 address raised an uncaught `TypeError` (three adapters). Zeek ports and durations were not validated (`-1`, `65536`, `nan`). A nanosecond PCAP failed after parsing because dpkt returns a `Decimal`. | Caught and left unresolved; strict port and duration parsing; timestamps converted to float at the reader; the worker now turns an unstorable value into an error message. The nanosecond-PCAP defect meant a valid, supported capture variant could not be imported. |
| CP15-17 | Medium | pfSense IPv6 interface host got `/32` instead of `/128`; an unknown pfSense ICMP type became "all ICMP". | Correct prefix length; an unknown type makes the rule undecidable. |

## A correction to what I said earlier

Until CP15-04 was fixed, the validation of any **mapped** UniFi translation compared nothing and printed "no difference found". Earlier in this project I reported
that a clean, fully mapped example was "deployable with no sampled differences"; that was true and meaningless. The first real comparison of the translation
was the independent Batfish run in CP12, whose result (173 of 173 decisions agree, 3 undecidable) the fixed validation now reproduces exactly. The CP12 report's conclusion stands; the in-product
validation claim did not, until now. The demo documents had also been failing to regenerate since the preview acknowledgement was added; `tools/make_demo.py` now acknowledges previews, and the committed demo files show the banner.

## Tests and tools on the final tree

* Full suite: 535 tests, all passing. Run against the application code as reviewed (tests kept), the new tests reported 28 failures and 6 errors, counting each failing sub-case,
  and every new test failed; that is the reproduction of each finding. ruff clean.
* `tools/security_checks.py` (output beside this report): ruff, bandit, semgrep, gitleaks, pip-audit and osv-scanner all 0 findings; the suppression gate 0 findings.
  SAF CLI not run (optional, not installed).

## Suppressions added / removed, SSDF practices touched

Added: none (two `noqa` markers I wrote in a new test were replaced by functions before they reached the baseline). Removed: one (`ruletruss/service.py`, `noqa S310`,
no longer needed once the AI request uses an opener that refuses redirects); the baseline count was lowered from 71 to 70 so that slot cannot be reused silently.
PW.1, PW.5, PW.7, PW.8 and RV.1/RV.2 (finding and fixing vulnerabilities, with root cause) are touched. `docs/SECURITY_FRAMEWORKS.md` and `SECURITY.md` now say what kind of review this was.

## Root causes and what keeps them from coming back

* **Silent truncation and silent defaults** (CP15-02, 13, 14, 15, 17): code that handled "too much" or "unknown" by quietly doing something plausible. Prevention: each case is now an
  error or an explicit unresolved state, with a test; the limits document says so.
* **A summary that could say yes when nothing was checked** (CP15-04): a headline derived from "no mismatches" instead of "N matches". Prevention: the headline is computed from counts that
  include how many were compared, and a test asserts it never claims agreement over zero.
* **Text from uploads placed into output without a single choke point** (CP15-08, 09): Prevention: one helper, used at parse time and write time; a test that checks the first
  characters of every generated line.
* **Classification by absence** (CP15-01, 03): "no NEW state" and "has some policy" were treated as proof of a property. Prevention: positive definitions (action plus exact states; an enabled unrestricted final default).

## Limits of this review

* One model, three passes, read-only and without the ability to run the test suite or the isolation layer. Its "Not reviewed" lists: real firewall behaviour, real UniFi/AI/IEEE endpoints,
  live browser CSP enforcement, `dpkt` internals, Windows and macOS resource limits, and the part of review A and B scopes that overlapped with each other only lightly.
* Findings of model reviews tend to cluster where the model looked first; a clean area is not a proof. The reviewers said where they checked and found nothing: access-control, CSP against the page, storage permissions,
  CSV and Markdown neutralisation, the vendor-name downloader, the payload decoders and the fingerprint loops.
* I verified each finding I fixed. I did not independently audit the areas where the reviewer reported nothing.
* A review by a person other than the developer is still required before any public release. The Atheris and ZAP runs should be repeated on the release candidate, since the fixes changed parser code.
