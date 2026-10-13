Reviewer: Claude Code (developer and reviewer)
Checkpoint / commit: CP1, after the CP0 annotations; the working tree that became commit 937f3fb
Tools run (with versions): ruff 0.16.10, bandit 1.9.4, semgrep 1.180.0, gitleaks, pip-audit 2.10.1, osv-scanner 2.5.1 (raw output in this folder)
Tools not run (and why): as CP0.

Tool results: all six tools report 0 findings (the three CP0 semgrep results are annotated with their reasons).

Issues found by the project's own tests, smoke runs and fuzzing while building (all fixed and covered by a regression test). They are listed because the plan asks for evidence, and because several would not have been found by static analysis.

Finding D-01
- Title: Lost update of project data under concurrent uploads
- Severity: Medium (integrity)
- Location: pbridge/store.py (add_source, delete_source, update_context)
- Evidence: tests/test_server.py::test_concurrent_uploads_do_not_interfere: four uploads returned 201 but only two sources were recorded.
- Fix: a lock around every read-modify-write of project.json. Verified: the test passes.

Finding D-02
- Title: Non-ASCII digit crashed the parsers with an unhandled ValueError
- Severity: Medium (denial of service of one upload; contained by process isolation)
- Location: pbridge/netutil.py and the Cisco, FortiOS and pfSense adapters (str.isdigit accepts characters int() rejects, for example a superscript two)
- Evidence: Hypothesis found the input; regression test test_unicode_digits_that_int_rejects_are_a_parse_problem_not_a_crash.
- Fix: netutil.is_uint (ASCII only) used everywhere.

Finding D-03
- Title: Credential redaction missed a bare "community" or "psk" keyword
- Severity: Low
- Location: pbridge/redact.py
- Evidence: property test test_a_secret_after_a_credential_keyword_is_always_removed.
- Fix: patterns added; "send-community" is deliberately left alone.

Finding D-04
- Title: Request handler could drop the connection on an unexpected error
- Severity: Low
- Location: pbridge/server.py (query parsing was outside the guarded section)
- Evidence: found by a smoke run (an incorrect parse_qs argument); regression test test_a_failure_outside_any_route_returns_a_clean_500_not_a_dropped_connection.
- Fix: the whole handler is guarded; the message sent to the client is generic and the details go to the operator's console.

Finding D-05
- Title: Stateless return rules were placed after a catch-all deny
- Severity: High (integrity: replies to permitted traffic would be dropped on the destination)
- Location: pbridge/migrate/firewall.py (render_cisco)
- Evidence: the migration validation reported two "destination narrower" cases on the demo ASA to IOS translation; test ReturnPathPlacementTests.
- Fix: return-path entries are placed first in their ACL, as a stateful device would treat replies; validation now shows no narrower case.

Finding D-06
- Title: A repeated ASA "object network" stanza replaced the earlier members
- Severity: Medium (a rule resolved to an empty address set)
- Location: pbridge/adapters/cisco.py
- Evidence: the demo worksheet showed "(empty)" for an object defined twice.
- Fix: repeated definitions are merged.

Finding D-07
- Title: An IPv4 ACL on IOS leaves IPv6 unfiltered
- Severity: High (integrity: a default-deny source becomes default-allow for IPv6 on the destination)
- Location: pbridge/migrate/firewall.py (render_cisco)
- Evidence: validate_observed reported IPv6 reverse initiation and extra ports allowed on the IOS destination.
- Fix: every interface that gets an IPv4 ACL also gets an IPv6 ACL with an explicit default deny.

Finding D-08
- Title: Sorting mixed IPv4 and IPv6 addresses raised TypeError
- Severity: Medium
- Location: pbridge/analysis.py, pbridge/migrate/groups.py
- Evidence: the overview request failed on the sample capture; regression test MixedFamilyTests.
- Fix: netutil.ip_sort_key.
