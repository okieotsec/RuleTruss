# Checkpoint 8: UniFi zone-based firewall import

Reviewer: Claude (self-review; independent review still open).

## What was added
`adapters/unifi.py` (reads the JSON bundle), `tools/unifi_export.py` (separate, read-only helper that calls the gateway's local Integration API),
`docs/EXPORT_UNIFI.md`, format registration (content-detected, and kept out of the Zeek-JSON path in the worker), evaluator support for
policies that only cover existing connections and for a zone pair with no matching policy ("cannot be decided", never "denied"), migration
handling, and tests (`tests/test_unifi.py`, a fuzz property, a schema-based fixture).

## Honest status
Written from Ubiquiti's published OpenAPI schema (10.3.58), read in pieces through a summarising fetch, so some nested shapes (protocol
filters, presets, ICMP type names, application filters) were only partly visible. Unrecognised shapes are reported and make a rule
undecidable. **Update:** the owner's real export (Network 10.6.106, 81 policies) later parsed cleanly with matching field shapes; decisions are still unchecked against real traffic. The fixture was written by me from the schema. Which Network versions serve the
endpoints, and what the gateway does for a zone pair with no listed policy, are unverified.

## Findings fixed during the work
* A UniFi "Allow Return Traffic" policy (allow any to any, connection states ESTABLISHED/RELATED only) would have been translated to another
  firewall as an allow-any rule. It is now treated as a reply-only policy in every migration path (translation to stateful and stateless
  targets, directional plan, aggregation check, validation sampling) and never matches the start of a connection when evaluating. Tested.
* The shadow/redundancy analysis ignores such policies, so they cannot hide later policies.

## Security notes
| Risk | Control | Test |
| --- | --- | --- |
| Hostile JSON (types, depth, size, names) | defensive readers for every field, `_s()` strips control characters and clips, lists cut at 100,000, recursion errors become a clean message | `RobustnessTests`, Hypothesis property |
| API key exposure | read from the environment or a file, never from argv; sent only in the X-API-KEY header to the named host; not in the output; output file 0600 | `ExporterTests` |
| Man in the middle on a self-signed gateway | default verifies; `--show-fingerprint` then `--fingerprint` pins and refuses a different certificate before any request is sent; `--insecure` is explicit | `TlsPinningTests` (a real local TLS server with a throw-away certificate) |
| Tool does more than read | only GET requests to a fixed set of read paths | `test_every_request_is_a_get_of_a_known_read_path` |
| The server contacting the gateway | it never does; the helper is a separate command | the existing "only these modules import network code" test |

## Results
409 tests pass; fuzz at `RT_FUZZ_SCALE=20` passes; ruff, bandit, semgrep, gitleaks, pip-audit, osv-scanner: 0 findings (two semgrep advisories about
`HTTPSConnection` were annotated: an explicit SSL context is passed).

## Follow-up: semantics checked against the structure of a real export
Studying the owner's export (Network 10.6.106, 81 policies) and the available documentation found four errors in the first version:
1. Replies were assumed always allowed. UniFi matches connection states, so an all-states block can block replies; replies are now evaluated in the
   reverse zone pair as ESTABLISHED.
2. The rule analysis produced 52 findings, mostly noise (35 "broad" and 13 "conflict" on predefined Allow/Block policies, two false "redundant"
   between predefined ICMPv6 policies whose message type the API omits). It now produces 9, all meaningful, and a one-line summary of the pairs
   that end in Allow All.
3. States and ICMP types were ignored when deciding whether a policy shadows another; they are now compared.
4. The default for a zone pair was reported as unknown; real data shows every pair ends in a predefined policy at index 2147483647.
Unverified still: that `index` is the exact evaluation order in all cases, and rules outside the policy table. Ubiquiti's help-center pages could
not be fetched (HTTP 403), so the documented behaviour rests on third-party guides.

## Zone matrix and empty filters
`analysis.zone_matrix` builds a source-by-destination table from the export (counts only, nothing inferred) and the Configuration tab shows it with a
click-through to each pair's policies. An empty network, address or port filter (seen in the owner's export: a deleted network) is now undecidable and
raises a warning; an empty port list was previously read as "any port". Tests: `ZoneMatrixTests`, `test_empty_filters_...`, and a browser check that imports
the fixture through the file input and clicks a cell.

## Reply handling verified on a real gateway
The owner's gateway confirmed the connection-state model: pinging a camera from another VLAN failed while the camera's own VLAN's all-states block applied,
and succeeded after the return-traffic allow policy was corrected (source and destination swapped, above the block), as the in-memory simulation had
predicted. One gateway, ICMP only. A mid-way softening of the wording (reply blocks reported as undecidable) was reverted after the ping test.

## Open items
1. A real export from a gateway is needed to confirm the field shapes; a sanitised sample would let me replace the hand-written fixture.
2. The encrypted `.unf`/`.unifi` backup is not read. It is the only thing the web interface offers, and it needs a key-based decrypt and a database
   reader; the collection names holding firewall data could not be confirmed.
3. Legacy (pre-zone) firewall rules, port forwards, VPN and DNS policies are not read.
