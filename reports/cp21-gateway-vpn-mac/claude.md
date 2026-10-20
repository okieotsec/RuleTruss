# Checkpoint 21: translating Gateway, VPN and MAC-filter policies (UniFi to ASA)

Commit: the one that adds this report. New behaviour in the UniFi zone-pair to Cisco ASA translation. Until now these three kinds of policy were left unresolved or unsupported, so on the owner's own export most of the "not translated" list came from them.

## What was added

| Area | Before | Now |
|---|---|---|
| Policies whose destination is the **Gateway** | All unresolved (or "handled by you") | Written as the ASA's own `ssh`, `http` and `icmp permit/deny` commands for the networks the policies name, in UniFi's order. `ssh`/`http` only have permit lines, so a block that comes first is cut out of the later permits (address arithmetic, not a guess). Other local services (DHCP service, DNS, mDNS, IPv6 neighbour discovery, other ports) stay unresolved until the user says they handle them. ASA only; IOS keeps the old behaviour. |
| **VPN** policies | Unresolved | With a user-supplied **VPN client address pool**, traffic that VPN clients start (Vpn to a zone with networks) becomes an access list `RT-VPN-FILTER` and a group policy `RT-VPN-POLICY` (`vpn-filter`). Traffic toward clients, and VPN to the Gateway or the Internet, stay unresolved. |
| **MAC filters** | Always unsupported | With a user-supplied IPv4 address for every MAC a policy names, the policy is written for those addresses and the report says what that costs. One missing MAC leaves the whole policy unsupported (no partial rule). Addresses outside the policy's zone are unresolved, not moved. Capture-derived ARP/DHCP bindings are shown as *suggestions* beside the input and never applied. |

Interface: a VPN-pool field, a table of MAC filters with an address box and a "use the suggestion" button, and a re-translate button. The "I handle traffic to the firewall itself" box now says "the other local services", because ssh, http and icmp are written for the user.

## Findings along the way

| ID | Sev | Finding | Fix |
|---|---|---|---|
| CP21-01 | Medium | An **IPv4-only UniFi policy with no address limit** (the export writes 0.0.0.0/0 instead of "any") was reported as lying outside its zone's networks, so it was unresolved instead of translated. Found while writing the gateway tests; it affects every translation, not only these three kinds. | `_wide()` reads "the whole IPv4 space" as no limit for the zone-scoped sides. A test fails on the old code. |
| CP21-02 | Low | In the interface, choosing another source configuration did not redraw the page, so the VPN field and the "I handle ..." boxes showed the previous file's state (the boxes had the same fault before). The old translation also stayed on screen. | The change handler redraws and clears the old translation. The headless browser check now covers it. |
| CP21-03 | Info | The generic (non-zone-pair) translation path still reports MAC filters as unsupported. | Not changed; stated in `docs/EXPORT_UNIFI.md`. |

## What is and is not proven

* **Not tried on a device.** The `ssh`/`http`/`icmp` lines and the VPN filter follow the ASA documentation as I know it. Nothing here was run on an ASAv. Two points in particular are assumed: that an ASA answers ping on an interface until some `icmp` command exists for it (so a block writes `icmp deny`), and how a `vpn-filter` list reads source and destination for both directions of a session. For the VPN part this is a **blocker** in the output (`vpn-filter-untested`), so a translation that contains it stays a preview; for the gateway commands it is a **warning** (`management-access`), because the lines are ordinary and the user reviews them, but the warning says plainly they are untested.
* **The validation does not cover these lines.** It samples through-traffic; management access and VPN-filtered traffic are not through-traffic. The new tests check the generated text and the dispositions, not device behaviour.
* The ASA-side behaviour could be tested in the CML lab the same way as CP17 (a management client on each network: ssh/https/ping to the ASAv's interface address, a VPN client for the filter). That is a good next use of the lab and is the way to turn the two assumptions above into evidence; it is listed here, not done.
* On the owner's real export (read locally, nothing written, aggregate counts only): of the enabled policies whose destination is the Gateway, 8 are now translated (they were all unresolved before), 4 are state-only and implemented by the ASA, 3 are ICMPv6 with no message type in the export (unsupported, as before) and 10 are other local services (DHCP, mDNS) or VPN-origin, unresolved until the user says they handle them (with that box ticked: 13 implemented, 1 unresolved). The 4 MAC filters are listed as inputs; VPN stays unresolved until a pool is given.
* A first run on that export showed 7 system policies marked "unsupported" for a wrong reason: they name the gateway's own address or limit a UDP source port (DHCP), which made the translator reject them before it noticed they are not ssh, http or icmp at all. The order of the checks was changed (service first) and a destination that is an address of the gateway is now accepted for ssh/http/icmp; four tests were added for this. The three of them that fail on the first version of the change are the two gateway-address cases and the DHCP source-port case.

## Tests and tools on the final tree

* `tests/test_unifi_local_access.py`: 32 new tests. The first 28, run against the application code as it was before this checkpoint, fail 25 (20 assertion failures, 5 errors from missing fields) and pass 3; the 3 are guards for behaviour that was already right (IOS gets no ssh lines, other targets get no VPN filter, one missing MAC leaves the policy whole). One existing test (`test_gateway_and_vpn_stay_unresolved...`) described the old behaviour and was rewritten.
* Full suite: 599 tests, all passing (including the headless browser check, which now imports a zone-pair export, asks for MAC addresses, translates again and checks the page; no window was opened). ruff clean.
* `tools/security_checks.py` (output beside this report): ruff, bandit, semgrep, gitleaks, pip-audit and osv-scanner all 0 findings; suppression gate 0 findings (70, all in the baseline). SAF CLI not run.

## Suppressions added / removed, SSDF practices touched

None added or removed (a test literal that tripped a lint rule was built from pieces instead of suppressed). PW.1 (the design states what is assumed), PW.5 and PW.7 (new input is validated and bounded: at most 256 MAC entries, 16 pool networks, IPv4 only, no overlap with the zones, at most 200 address pieces per list), PW.8 (tests), RV.1 (the CP21-01 and 02 defects, found by writing the tests).

## Root causes and what keeps them from coming back

* **"Everything" written as a network** (CP21-01): UniFi writes an IPv4-only "any" as 0.0.0.0/0 and the translator compared it with the zone's networks. Prevention: the test names the pattern; any new place that reads "no address limit" must use `_wide()`.
* **UI state kept outside the redraw** (CP21-02): a handler changed state and did not redraw. Prevention: the headless check changes the source and looks at the page.
* **Untested assumptions presented as output**: the answer here is labelling, not code: the untested parts carry a warning or a blocker in the output and in this report, and the lab test that would remove them is described above.

## Limits

* IPv4 only. IOS gets MAC substitution but no gateway or VPN lines.
* MAC to IP is the user's statement (or a suggestion they accepted); DHCP changes make a deny rule fail open, and the report says so for each deny.
* No human has reviewed this change; it has had the tests and scanners above only. The earlier AI reviews (CP15, CP16) did not see this code.
