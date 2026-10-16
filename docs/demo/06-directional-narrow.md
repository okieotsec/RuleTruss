# Proposed narrower permissions from observation

> **PROPOSED. This is an implementation worksheet, not a configuration file and not an import file.** It was produced by RuleTruss from the inputs named below. It has not been applied to any system and its equivalence to the source has not been proven.

Project: Sample plant (synthetic)

Generated: 2026-10-16 13:39:49 UTC

## Result

All proposals require review before use. Observed traffic is not proof of business need.

| Measure | Value |
| --- | --- |
| communications observed | 16 |
| communications used | 14 |
| held back low confidence | 1 |
| broadcast or multicast | 0 |
| not in a group | 1 |
| policies | 7 |
| egress policies | 1 |
| policies that broaden access | 7 |
| needs review | 7 |

## Observation period (read before using any proposal)

- From 2023-11-14 22:13 UTC to 2023-11-14 22:15 UTC (0.04 hours).
- plant-span.pcapng (pcapng), observation point: SPAN of the controller-facing switch ports (fictional)
- A capture shows only traffic that crossed the observation point during the capture window.
- Window length: 0.04 hours.
- Absence from this capture is not evidence of absence: devices, subnets, ports and protocols that never appear may simply not have been visible to the capture point or active during this period.
- Observation point (as supplied by the user): SPAN of the controller-facing switch ports (fictional). Traffic that does not pass that point is not seen, for example traffic between two devices on a switch port that is not mirrored.
- 1 non-IP frame(s) were not analysed as traffic; ARP and LLDP among them were read for device identification.

## The directional model

- A policy connects one or more From groups to one or more To groups.
- From groups may initiate connections to To groups within the policy; To groups may not initiate to From groups.
- Direction is about who may initiate a connection. Replies to a permitted connection are not a separate permission.
- Allowing both directions needs two policies.
- An endpoint can belong to several groups and a group can appear in several policies.
- An external egress policy is a separate type for endpoints isolated behind a gateway. It names the endpoint groups, the allowed external destinations (address prefixes and DNS names, optionally recursive), optional services, whether all DNS queries are allowed, and whether the policy is enabled.

Not carried by this model:

- Ports and protocols as enforced conditions on a group policy (kept only as information).
- Deny actions, and rule ordering or precedence.
- Application, user-identity or schedule conditions.
- How a named service for an egress policy is defined on a particular platform.

This is a model defined by this application so that policies can be reviewed in one neutral form. It is not the policy format of any product. Check what your enforcement platform supports before relying on any row.

## Groups

| Group | Members | Isolated behind a gateway |
| --- | --- | --- |
| Engineering | 10.20.0.0/16 | no |
| Controllers | 10.30.2.0/24 | yes |
| Historian | 10.30.5.10/32 | no |
| Services | 10.30.5.1/32 | no |
| Corporate | 10.10.0.0/16 | no |

## Group policies (From may initiate to To; the reverse needs its own policy)

### Corporate to Controllers (needs_review)

- From: Corporate   To: Controllers
- Origin: proposed. Proposed from observed initiation in the supplied capture(s); observation is not proof of business need.
- Services (information only, not enforced by the model): observed tcp/502
- Source rules: -   Evidence: packet 58,59,60
- Address pairs granted by group membership: 16,777,216; observed or source-permitted: 1
- **WARNING** This policy grants 16,777,216 address pair(s) between its groups but only 1 initiating pair(s) were observed. The rest are permitted by group membership without evidence in the capture. Narrow the groups if that is not intended.

### Corporate to Historian (needs_review)

- From: Corporate   To: Historian
- Origin: proposed. Proposed from observed initiation in the supplied capture(s); observation is not proof of business need.
- Services (information only, not enforced by the model): observed tcp/443 (TLS, confirmed by decoding)
- Source rules: -   Evidence: packet 45,46,47,48,49,50
- Address pairs granted by group membership: 65,536; observed or source-permitted: 1
- **WARNING** This policy grants 65,536 address pair(s) between its groups but only 1 initiating pair(s) were observed. The rest are permitted by group membership without evidence in the capture. Narrow the groups if that is not intended.

### Engineering to Engineering (needs_review)

- From: Engineering   To: Engineering
- Origin: proposed. Proposed from observed initiation in the supplied capture(s); observation is not proof of business need.
- Services (information only, not enforced by the model): observed udp/53 (DNS, confirmed by decoding)
- Source rules: -   Evidence: packet 51,52
- Address pairs granted by group membership: 4,294,967,296; observed or source-permitted: 1
- **INFO** Direction of 10.20.1.15 to 10.20.1.2 (udp/53) was inferred with medium confidence: payload semantics: 10.20.1.15:40001 sent a DNS request-type message.
- **WARNING** This policy grants 4,294,967,296 address pair(s) between its groups but only 1 initiating pair(s) were observed. The rest are permitted by group membership without evidence in the capture. Narrow the groups if that is not intended.

### Engineering to Controllers (needs_review)

- From: Engineering   To: Controllers
- Origin: proposed. Proposed from observed initiation in the supplied capture(s); observation is not proof of business need.
- Services (information only, not enforced by the model): observed icmp; observed tcp/502 (Modbus/TCP, confirmed by decoding); observed tcp/44818 (EtherNet/IP, confirmed by decoding); observed tcp/8888; observed tcp/502 (Modbus/TCP, confirmed by decoding); observed udp/161 (SNMP, confirmed by decoding); observed tcp/502 (HTTP, confirmed by decoding)
- Source rules: -   Evidence: packet 75,76; packet 91,92,93,94,95,96,97; packet 1,3,4,5,6,7,8; packet 25,26,27,28,29,30,31
- Address pairs granted by group membership: 16,777,216; observed or source-permitted: 5
- **INFO** Direction of 10.20.1.15 to 10.30.2.40 (tcp/502) was inferred with medium confidence: payload semantics: 10.20.1.15:51500 sent a Modbus/TCP request-type message.
- **INFO** Direction of 10.20.1.50 to 10.30.2.40 (udp/161) was inferred with medium confidence: payload semantics: 10.20.1.50:41000 sent a SNMP request-type message.
- **WARNING** This policy grants 16,777,216 address pair(s) between its groups but only 5 initiating pair(s) were observed. The rest are permitted by group membership without evidence in the capture. Narrow the groups if that is not intended.

### Controllers to Services (needs_review)

- From: Controllers   To: Services
- Origin: proposed. Proposed from observed initiation in the supplied capture(s); observation is not proof of business need.
- Services (information only, not enforced by the model): observed udp/123 (NTP, confirmed by decoding)
- Source rules: -   Evidence: packet 53,54
- Address pairs granted by group membership: 256; observed or source-permitted: 1
- **INFO** Direction of 10.30.2.40 to 10.30.5.1 (udp/123) was inferred with medium confidence: payload semantics: 10.30.2.40:123 sent a NTP request-type message.
- **WARNING** This policy grants 256 address pair(s) between its groups but only 1 initiating pair(s) were observed. The rest are permitted by group membership without evidence in the capture. Narrow the groups if that is not intended.

### Controllers to Historian (needs_review)

- From: Controllers   To: Historian
- Origin: proposed. Proposed from observed initiation in the supplied capture(s); observation is not proof of business need.
- Services (information only, not enforced by the model): observed tcp/4840 (OPC UA, confirmed by decoding)
- Source rules: -   Evidence: packet 39,40,41,42,43,44
- Address pairs granted by group membership: 256; observed or source-permitted: 1
- **WARNING** This policy grants 256 address pair(s) between its groups but only 1 initiating pair(s) were observed. The rest are permitted by group membership without evidence in the capture. Narrow the groups if that is not intended.
- **INFO** Both directions were observed as separate initiations, so two separate policies are proposed: 'Controllers to Historian' and 'Historian to Controllers'.

### Historian to Controllers (needs_review)

- From: Historian   To: Controllers
- Origin: proposed. Proposed from observed initiation in the supplied capture(s); observation is not proof of business need.
- Services (information only, not enforced by the model): observed tcp/502 (Modbus/TCP, confirmed by decoding)
- Source rules: -   Evidence: packet 32,33,34,35,36,37,38
- Address pairs granted by group membership: 256; observed or source-permitted: 1
- **WARNING** This policy grants 256 address pair(s) between its groups but only 1 initiating pair(s) were observed. The rest are permitted by group membership without evidence in the capture. Narrow the groups if that is not intended.
- **INFO** Both directions were observed as separate initiations, so two separate policies are proposed: 'Controllers to Historian' and 'Historian to Controllers'.

## External egress policies

### Egress Controllers (needs_review)

- Endpoint groups: Controllers   Enabled: yes
- Allowed prefixes: 198.51.100.7/32
- Allowed DNS names: updates.vendor.example   Recursive: no
- Allow all DNS queries: no
- Services (information only): tcp/443
- Evidence: packet 98,99,100,101,102,103
- **WARNING** Prefixes are the exact addresses observed. Cloud and CDN services change addresses; prefer DNS names where the destination is a named service, and review whether DNS resolution should be allowed (the Allow all DNS queries setting is left off).
- **WARNING** Observed services are for reference. Egress policies can name services, whose definition depends on the platform.

## Gaps: what did not translate or translated with loss

- none

## Review items

- **WARNING** These proposals come only from the capture window described under Observation. Dependencies that did not occur in that window are invisible to this tool: scheduled or seasonal jobs, backup and failover paths, maintenance and vendor access, start-up sequences, rarely used engineering functions, and anything outside the observation point. Confirm each proposal with the people who run the systems before enforcing it. 
- **WARNING** 10.30.2.40 and 10.20.1.60 (udp 514): which side initiates is uncertain (low confidence: only datagrams from 10.30.2.40:514 were seen). No policy was proposed. Decide the direction before creating one; a wrong direction would permit the opposite initiation. packet 57
- **WARNING** initiator 2001:db8:20::15 and responder 2001:db8:30::40 are not in any group, so the communication was not turned into a policy. Add the address to a group. packet 77,78,79,80,81,82,83

## Manual steps

1. Create each group listed in the Groups table on your enforcement platform and add its endpoints (group membership is not imported from this worksheet).
2. For each row of the Group policies table, create one policy from the From groups to the To groups. Create one policy per direction; a policy never grants the reverse direction.
3. For each row of the Egress policies table, create an external egress policy for the endpoint groups with the allowed prefixes and DNS names, and decide on services and DNS handling yourself.
4. Services (ports/protocols) in the worksheet are for reference. The directional model does not enforce them; if your platform can, apply them there, otherwise accept that the policy is broader than the source.
5. Review every item under Review and Gaps before enabling anything. This worksheet is not proof that the result is equivalent to the source; it is a starting point.

## Limits

- Directional rules alone are not a complete zero trust architecture: identity, device posture, encryption, monitoring and change control are outside this worksheet.
- Observed traffic is not proof of business need, and absence from a capture is not proof of absence.
