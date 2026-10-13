# The intermediate model and the directional group policy model

## Three things that are never mixed

| Layer | Meaning | Where it lives | How it is labelled |
| --- | --- | --- | --- |
| **Observed** | What a capture or flow log showed, with how sure the tool is | `Flow`, `CaptureInfo`, `Communication` (aggregates) | `OBSERVED` |
| **Configured** | What a device export says it permits or denies | `PolicySet`, `Rule`, `NatRule` | `CONFIGURED` |
| **Proposed** | What this tool suggests: group policies, egress policies, destination rules | `Plan`, `DPolicy`, `EgressPolicy`, `Translation`, `OutRule` | `PROPOSED` |

They live in separate stored files and separate API responses. Comparisons (`observed vs configured`) say which is which, and a
proposal always carries its basis (`preserved` from a configuration, or `proposed` from observation), its evidence and its warnings.

## Provenance on everything

`Evidence(source_id, kind, ref, text)` points back to the input: `config` evidence names the line numbers (CLI text) or the rule
element (XML) and carries a redacted, clipped excerpt; `packet` evidence lists packet numbers; `flow` evidence names a log line.
Rules, flows, policies, NAT rules, issues and proposals all hold a list of evidence. `Issue(severity, code, message, evidence)` is how
unsupported conditions, unresolved objects, assumptions and translation gaps are recorded (`info`, `warning`, `blocker`).

## Configured policy: `PolicySet` and `Rule`

| Field | Meaning |
| --- | --- |
| `vendor`, `platform`, `version`, `hostname` | What the export is |
| `stateful` | Replies to a permitted connection are allowed without a rule (false for IOS ACLs) |
| `default_action`, `default_basis`, `default_mode` | What happens when nothing matches: `implicit_deny`, `acl_binding` (Cisco: per-interface ACLs), `panos` (intrazone/interzone defaults) |
| `address_context` | `original-packet` (rule addresses are those in the packet as received), `internal-real` (the real internal host after destination NAT is undone), or `unknown` |
| `zone_levels`, `interfaces` | ASA security levels; interface and zone networks, used to place traffic in a zone |
| `rules` | Ordered `Rule` list |
| `nat_rules` | `NatRule` list (original and translated source and destination, zones) |
| `issues`, `unresolved`, `stats` | Warnings, unresolved names, counts |

`Rule`: `rule_id` (unique in the policy), `original_id` (the vendor's name or `ACL:index`), `position`, `action` (`allow`/`deny`), `original_action`, `enabled`,
`scope` (ACL or rulebase), `src_zones`/`dst_zones` (empty means any; interfaces for ACL platforms), `src`/`dst` (`AddrSet`), `svc` (`ServiceSet`),
`applications`, `users`, `schedule`, `log`, `unsupported` (conditions this tool cannot evaluate or translate), `notes`, `evidence`, `extra` (vendor
values such as the ACL stage and binding).

`AddrSet`: `any`, `nets` (CIDR strings), `negate`, `unresolved` (names that are not IP addresses), `refs` (original object names). `ServiceSet`: `any`, `entries`
of `SvcEntry(proto, sports, dports, icmp_type, icmp_code, established)`, `unresolved`.

### Matching is three-valued

`contains`, `match` and rule matching return **True**, **False** or **None** (cannot be decided: an unresolved FQDN, an unknown zone, a missing port).
`evaluate()` returns `allow`, `deny` or `indeterminate`. A rule with an application, identity, schedule or other unsupported condition that would
otherwise match makes the decision indeterminate if it could change the answer; it is never assumed away. Unknown is never treated as false.

### Statefulness

`evaluate_connection()` decides the initiating direction and, for stateless policies, evaluates the reply direction as TCP-established (or the matching
reply for UDP and ICMP echo) and reports it separately. A stateful policy does not need a rule for replies, and a reply is not a reverse initiation.

## Observed: `Flow`

`initiator`/`responder` with ports, protocol, packet and byte counts both ways, first and last time, `apps` (`AppGuess(name, confidence, basis)` with
`confirmed` = decoded payload, `probable` = weak signature or a request and response that both match, `possible` = port only), `hostnames`
(TLS server name, HTTP Host, DNS query; sanitised), and:

| `direction_confidence` | Evidence |
| --- | --- |
| high | A pure SYN seen from that side (TCP); an ICMP echo request |
| medium | A SYN-ACK seen without the SYN; payload semantics (a DNS query, an NTP client packet, a Modbus read request); a multicast sender; SYNs from both sides |
| low | No handshake and only a port-number heuristic; UDP where the first datagram seen is all there is; one-way traffic |
| unknown | ICMP control messages; no evidence either way |

`direction_basis` lists the reasons and `notes` the caveats (mid-stream capture, no reply seen, truncated packets). `CaptureInfo` holds the time range, link types,
packets read, decoded and skipped, the **user-supplied** observation point, limits that were hit and the coverage notes.

## The directional group policy model (defined by this application)

* A **policy** connects one or more **From** groups to one or more **To** groups.
* Direction means permission to **initiate**. From may start connections to To; To may not start connections to From.
* Replies to a permitted connection are not a separate permission. A required reverse initiation is a separate policy.
* An endpoint may be in several groups, and a group in several policies. Because membership is by group, a policy grants every From member access to every
  To member: the tool measures that against what the source or the observation supports (`granted_pairs` against `observed_pairs`) and warns
  about "group aggregation" that grants pairs nothing supported, and about endpoints in both From and To, which makes them bidirectional.
* An **external egress policy** is a separate type, for endpoints marked as isolated behind a gateway: endpoint groups, an enabled flag, allowed prefixes,
  allowed DNS names (optionally recursive), optional services, and whether all DNS queries are allowed.
* The model carries **no** ports, protocols, deny actions, ordering, applications, users or schedules. They are kept as information (`services_informational`).
  A source rule that had them is reported as "restriction not carried over", and a deny rule that preceded a broader allow is reported as an access
  broadening.

Not carried does not mean ignored: every such loss appears in the plan's gaps and in the summary line (`policies that broaden access`, `policies that lose
restrictions`, `deny rules not translated`).

## Proposed destination rules: `OutRule`

Source rules are translated one by one (order preserved). A rule that uses something the destination cannot express is **blocked**: kept as a comment with its
reason, never replaced by `any`. Stateful-to-stateless translation adds return rules marked `broader`. Differences in address context combined with
destination or static NAT block the affected rules. Interface names are never guessed: unmapped zones become `<TARGET-IF:zone>` placeholders.
