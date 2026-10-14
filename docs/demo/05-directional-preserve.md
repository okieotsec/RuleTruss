# Preserved configured permissions

> **PROPOSED. This is an implementation worksheet, not a configuration file and not an import file.** It was produced by RuleTruss from the inputs named below. It has not been applied to any system and its equivalence to the source has not been proven.

Project: Sample plant (synthetic)

Generated: 2026-10-14 14:16:24 UTC

## Result

This migration broadens access or drops restrictions in at least one place; read every warning before use.

| Measure | Value |
| --- | --- |
| source rules | 16 |
| policies | 3 |
| blocked rules | 8 |
| egress policies | 0 |
| policies that broaden access | 0 |
| policies that lose restrictions | 3 |
| deny rules not translated | 4 |
| reply rules not translated | 0 |
| disabled rules skipped | 0 |
| needs review | 3 |

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

### Engineering to Controllers (needs_review)

- From: Engineering   To: Controllers
- Origin: preserved. Preserves configured permissions from the source policy; not derived from observed traffic.
- Services (information only, not enforced by the model): ENG-IN:5: tcp
- Source rules: ENG-IN:5   Evidence: config line 57
- Address pairs granted by group membership: 1; observed or source-permitted: 0
- **WARNING** Source rule ENG-IN:5 allowed only tcp. The directional model has no port or protocol condition, so this restriction is not carried over: members of the From groups would be permitted to initiate to the To groups on any service the endpoints expose.

### Historian to Controllers (needs_review)

- From: Historian   To: Controllers
- Origin: preserved. Preserves configured permissions from the source policy; not derived from observed traffic.
- Services (information only, not enforced by the model): HIST-IN:1: tcp dport 502; HIST-IN:2: tcp dport 44818
- Source rules: HIST-IN:1, HIST-IN:2   Evidence: config line 63; config line 64
- Address pairs granted by group membership: 1; observed or source-permitted: 0
- **WARNING** Source rule HIST-IN:1 allowed only tcp dport 502. The directional model has no port or protocol condition, so this restriction is not carried over: members of the From groups would be permitted to initiate to the To groups on any service the endpoints expose.
- **WARNING** Source rule HIST-IN:2 allowed only tcp dport 44818. The directional model has no port or protocol condition, so this restriction is not carried over: members of the From groups would be permitted to initiate to the To groups on any service the endpoints expose.

### Corporate to Historian (needs_review)

- From: Corporate   To: Historian
- Origin: preserved. Preserves configured permissions from the source policy; not derived from observed traffic.
- Services (information only, not enforced by the model): CORP-IN:1: tcp dport 443
- Source rules: CORP-IN:1   Evidence: config line 66
- Address pairs granted by group membership: 1; observed or source-permitted: 0
- **WARNING** Source rule CORP-IN:1 allowed only tcp dport 443. The directional model has no port or protocol condition, so this restriction is not carried over: members of the From groups would be permitted to initiate to the To groups on any service the endpoints expose.

## Source rules that could not be translated

| Source rule | Why | Evidence |
| --- | --- | --- |
| ENG-IN:1 | no group is wholly inside the source (10.20.1.15/32, 10.20.1.16/32); define a group holding exactly these addresses, or accept a wider group knowingly | config line 50 |
| ENG-IN:2 | no group is wholly inside the source (10.20.1.50/32); define a group holding exactly these addresses, or accept a wider group knowingly; no group is wholly inside the destination (10.30.2.40/32); define a group holding exactly these addresses, or accept a wider group knowingly | config line 52 |
| ENG-IN:3 | no group is wholly inside the source (10.20.1.15/32); define a group holding exactly these addresses, or accept a wider group knowingly | config line 53 |
| ENG-IN:4 | no group is wholly inside the source (10.20.1.20/32); define a group holding exactly these addresses, or accept a wider group knowingly | config line 55 |
| ENG-IN:6 | no group is wholly inside the source (10.20.1.99/32); define a group holding exactly these addresses, or accept a wider group knowingly; no group is wholly inside the destination (10.30.2.41/32); define a group holding exactly these addresses, or accept a wider group knowingly | config line 58 |
| PLC-IN:1 | no group is wholly inside the source (10.30.2.40/32); define a group holding exactly these addresses, or accept a wider group knowingly | config line 60 |
| PLC-IN:2 | no group is wholly inside the source (10.30.2.40/32); define a group holding exactly these addresses, or accept a wider group knowingly | config line 61 |
| CORP-IN:2 | Not translated: schedule MAINTENANCE-WINDOW has no equivalent in the directional model; the source is 'any'; policies connect named groups and the model has no 'any' source, so you must decide which group(s) should stand for it; the destination is 'any'; the model has no 'any' destination for group policies. Use an egress policy for external destinations (gateway-isolated endpoints only) or name the destination groups. | config line 67 |

## Gaps: what did not translate or translated with loss

- **BLOCKER** Rule ENG-IN:1 was not translated: no group is wholly inside the source (10.20.1.15/32, 10.20.1.16/32); define a group holding exactly these addresses, or accept a wider group knowingly. Define groups for these addresses. config line 50
- **BLOCKER** Rule ENG-IN:2 was not translated: no group is wholly inside the source (10.20.1.50/32); define a group holding exactly these addresses, or accept a wider group knowingly; no group is wholly inside the destination (10.30.2.40/32); define a group holding exactly these addresses, or accept a wider group knowingly. Define groups for these addresses. config line 52
- **BLOCKER** Rule ENG-IN:3 was not translated: no group is wholly inside the source (10.20.1.15/32); define a group holding exactly these addresses, or accept a wider group knowingly. Define groups for these addresses. config line 53
- **BLOCKER** Rule ENG-IN:4 was not translated: no group is wholly inside the source (10.20.1.20/32); define a group holding exactly these addresses, or accept a wider group knowingly. Define groups for these addresses. config line 55
- **BLOCKER** Rule ENG-IN:6 was not translated: no group is wholly inside the source (10.20.1.99/32); define a group holding exactly these addresses, or accept a wider group knowingly; no group is wholly inside the destination (10.30.2.41/32); define a group holding exactly these addresses, or accept a wider group knowingly. Define groups for these addresses. config line 58
- **WARNING** Deny rule ENG-IN:7 has no equivalent in the directional model (it has no deny action or ordering). Traffic not granted by a policy is not permitted, but a deny that overrode a later broader allow is lost; see the warnings on the allow policies. config line 59
- **BLOCKER** Rule PLC-IN:1 was not translated: no group is wholly inside the source (10.30.2.40/32); define a group holding exactly these addresses, or accept a wider group knowingly. Define groups for these addresses. config line 60
- **BLOCKER** Rule PLC-IN:2 was not translated: no group is wholly inside the source (10.30.2.40/32); define a group holding exactly these addresses, or accept a wider group knowingly. Define groups for these addresses. config line 61
- **WARNING** Deny rule PLC-IN:3 has no equivalent in the directional model (it has no deny action or ordering). Traffic not granted by a policy is not permitted, but a deny that overrode a later broader allow is lost; see the warnings on the allow policies. config line 62
- **WARNING** Deny rule HIST-IN:3 has no equivalent in the directional model (it has no deny action or ordering). Traffic not granted by a policy is not permitted, but a deny that overrode a later broader allow is lost; see the warnings on the allow policies. config line 65
- **BLOCKER** Rule CORP-IN:2 was not translated: schedule MAINTENANCE-WINDOW has no equivalent in the directional model; the source is 'any'; policies connect named groups and the model has no 'any' source, so you must decide which group(s) should stand for it; the destination is 'any'; the model has no 'any' destination for group policies. Use an egress policy for external destinations (gateway-isolated endpoints only) or name the destination groups. config line 67
- **WARNING** Deny rule CORP-IN:3 has no equivalent in the directional model (it has no deny action or ordering). Traffic not granted by a policy is not permitted, but a deny that overrode a later broader allow is lost; see the warnings on the allow policies. config line 68

## Review items

- none

## Manual steps

1. Create each group listed in the Groups table on your enforcement platform and add its endpoints (group membership is not imported from this worksheet).
2. For each row of the Group policies table, create one policy from the From groups to the To groups. Create one policy per direction; a policy never grants the reverse direction.
3. For each row of the Egress policies table, create an external egress policy for the endpoint groups with the allowed prefixes and DNS names, and decide on services and DNS handling yourself.
4. Services (ports/protocols) in the worksheet are for reference. The directional model does not enforce them; if your platform can, apply them there, otherwise accept that the policy is broader than the source.
5. Review every item under Review and Gaps before enabling anything. This worksheet is not proof that the result is equivalent to the source; it is a starting point.

## Limits

- Directional rules alone are not a complete zero trust architecture: identity, device posture, encryption, monitoring and change control are outside this worksheet.
- Observed traffic is not proof of business need, and absence from a capture is not proof of absence.
