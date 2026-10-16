# Checkpoint 22: layer 3 switch ACLs as the source of a move to a firewall

Commit: the one that adds this report. The owner's stated main use: an environment that controls east/west traffic with switch ACLs only and is upgrading to a firewall. So the switch is the **source**; the firewall is the destination. RuleTruss already read IOS ACLs and bindings and evaluated them as stateless filters (`tests/test_cisco.py`); this checkpoint finds and closes what that reading was missing when the result is turned into firewall rules.

## Findings

| ID | Sev | Finding | Root cause | Fix and prevention |
|---|---|---|---|---|
| CP22-01 | **High** | A routed interface with **no inbound ACL** permits everything on a switch. The translation said nothing: the firewall output simply had no entry for it, so on cut-over all traffic from that VLAN would have stopped (or, if the interface had only an IPv6 ACL, all its IPv4). No policy of the source exists to attach a disposition to. | The translator reports what is *configured*; here the behaviour is the absence of configuration. | Every routed, IPv4-carrying, up interface without an inbound ACL that has entries (an ACL named but empty or undefined also filters nothing) is listed as an *unresolved* item in the report, with a blocker. The user decides each one: add rules, or name it to **keep it open** (one labelled `permit ip any4 any4`, counted as broader than the source). `keep_open` is checked against the real list; unknown or shut-down names are refused. |
| CP22-02 | **High** | A **VLAN-interface ACL bound outbound** was turned into a *global* rule (ASA) or blocked (IOS), with a "destination zone dropped" warning: its scope widened from "what leaves toward this VLAN" to "any interface". | Cisco targets were given no concept of an outbound ACL. | The rule keeps its direction: `access-group NAME out interface ...` (ASA), `ip access-group NAME out` (IOS); FortiOS already named the destination interface. Tests fail on the old code. |
| CP22-03 | Medium | **Layer 2 filters were invisible**: VLAN access maps and ACLs on switch ports (which also filter traffic inside a VLAN) were not mentioned, and a port ACL's entries were translated as if the switch port were a firewall interface. | The adapter treated every interface alike. | `routed` is recorded per interface (addressed and not a switch port). VLAN access maps and port ACLs are reported as warnings; port-ACL entries are listed as not applicable (they stay on the switch). |
| CP22-04 | Low | A switch with VLAN interfaces but no `ip routing` does not route between them; its SVI ACLs would filter nothing. A truncated export would look fine. | Not checked. | Warning `ip-routing-missing`. |

`PARSE_FORMAT` was raised to 6 because the stored configuration now carries the `routed` flag, so files read by an earlier version are read again before use (CP18's mechanism).

Interface: after a translation of a switch configuration, a table lists the open interfaces with a checkbox each and a "Translate again" button; the VLAN-interface ACL bindings are shown as before. Guide: [docs/MIGRATE_SWITCH_ACLS.md](../../docs/MIGRATE_SWITCH_ACLS.md) (what a switch does that is easy to miss, the steps from export to cut-over planning, limits).

## What is and is not proven

* **Not tried on a device.** The outbound `access-group ... out` binding and the open-interface permit follow the ASA documentation and the existing parser's reading of them (the validation re-reads the generated text and compares sampled connections); they have not been loaded onto an ASA or a switch by the authors.
* The validation's own differences on the new example are the known one: a stateless switch drops a reply that the stateful firewall lets through (flagged `explained_by_source_return_path`). The test asserts that nothing else differs.
* Cut-over items are out of scope and are listed in the guide as not read or generated: gateway move, `ip helper-address` (DHCP relay), routing protocols, multicast, NAT, high availability.
* A lab test is the way to turn this into evidence: CML-Free has a virtual layer 3 switch (IOSvL2) and the ASAv already used in CP17; a pack in the style of `tools/make_cml_pack.py` could configure the invented switch of the test fixture, send the sampled connections through it, and compare with RuleTruss's reading of the same config. Proposed, not done.

## Tests and tools on the final tree

* `tests/test_switch_migration.py`: 13 new tests on an invented switch configuration (`tests/fixtures/ios_l3_switch.cfg`). Run against the application code as it was before this checkpoint, 10 fail (8 assertions, 2 errors from missing fields) and 3 pass; the 3 are guards (an ASA source gets no open-interface entries, the inbound binding is unchanged, FortiOS already names the destination interface).
* The headless browser check now imports the switch configuration, sees the open-interface table, ticks one and translates again (no window was opened).
* Full suite: 612 tests, all passing. ruff clean.
* `tools/security_checks.py` (output beside this report): ruff, bandit, semgrep, gitleaks, pip-audit and osv-scanner all 0 findings; suppression gate 0 findings (70, all in the baseline). SAF CLI not run.
* `docs/VALIDATION.md` and `docs/demo/` were regenerated by `tools/make_demo.py`; most of the diff is timestamps and generated ids. The one substantive change is the existing sample switch translating with one more "not translated" item: its VLAN 40 has only an IPv6 ACL, so its IPv4 is open, which is now reported.

## Suppressions added / removed, SSDF practices touched

None added or removed. PW.1 (the design now states a source behaviour the old model left implicit), PW.5 and PW.7 (new input validated and bounded: names must be among the open interfaces), PW.8 (tests), RV.1 (CP22-01 to 04, each with a test that fails on the old code).

## Root causes and what keeps them from coming back

* **Behaviour that is the absence of configuration** (CP22-01): a translator driven by the list of source rules cannot see "no rule". Prevention: the open-interface list is computed from the interfaces, not from the rules, and the test names the pattern; any other source with an implicit permit (for example the ASA's security levels) needs the same treatment and is listed in the guide as a limit, not assumed away.
* **A direction dropped by a target with no word for it** (CP22-02): the target capability table now has `out_acl`, so the missing capability is a decision, not an omission.
* **Treating every interface as a firewall interface** (CP22-03): `routed` is stored and used where it matters.

## Limits

* IPv4 only for open interfaces. IOS and IOS-XE running-config text only; NX-OS and other vendors' switches are not read.
* The "keep open" permit is deliberately blunt; it exists so that a first translation can be complete and then tightened, and the output labels it as broader than the source and than a firewall should allow.
* No human has reviewed this change; the earlier AI reviews (CP15, CP16) did not see this code.
