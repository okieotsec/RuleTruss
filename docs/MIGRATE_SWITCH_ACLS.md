# Moving from layer 3 switch ACLs to a firewall (east/west)

A common starting point in a plant or a campus: a layer 3 switch routes between VLANs and a few ACLs on the VLAN interfaces (SVIs) are the only
control between them. The upgrade is a firewall that carries the east/west traffic. RuleTruss helps with the part that is about *knowing what the
switch does today* and *writing the firewall's rules from it*. It does not do the cut-over, and nothing here has been loaded onto a device by the
authors (the Cisco IOS side is read from configuration text; the ASA output follows the ASA test in [CML_TEST.md](CML_TEST.md) for through-traffic only).

## What a switch does that is easy to miss

* **A routed interface with no inbound ACL permits everything.** On an SVI, a missing ACL is "allow", the opposite of a firewall's default. RuleTruss
  lists every routed interface with no inbound ACL (or an ACL with no entries, which also filters nothing) as an *unresolved* item, and the output
  stays a preview until each is decided: add rules, or tick the interface to **keep it open** (one broad IPv4 `permit ip any4 any4`, labelled, to be
  replaced with specific rules). Shut-down interfaces are left out. IPv6 is not translated and is said so.
* **An ACL applied outbound on an SVI filters what leaves toward that VLAN.** It stays an outbound ACL (`access-group NAME out interface ...` on an
  ASA, `ip access-group NAME out` on IOS, a destination interface on FortiOS); it is never widened into a global rule.
* **IOS ACLs are stateless.** `permit tcp ... established` entries and reply-only entries exist because the switch does not track connections. A
  stateful firewall tracks them, so those entries are reported as *implemented by the target* instead of becoming rules. The validation lists the
  cases where the switch itself would have dropped a reply that the firewall lets through.
* **Layer 2 filters stay on the switch.** VLAN access maps (VACLs) and ACLs on switch ports (port ACLs) filter traffic inside a VLAN too. They are not
  modelled, are reported as warnings, and a port ACL's entries are listed as *not applicable*: they keep working on the switch after the move.
* **`ip routing` must be on.** A switch without it does not route between VLANs, and its SVI ACLs filter nothing between them. If the export has VLAN
  interfaces but no `ip routing` line, RuleTruss warns that the export may be incomplete.
* **Traffic inside one VLAN never reaches the firewall.** A firewall in the middle sees only traffic between VLANs it routes (or between ports it bridges).

## Steps

1. **Export** `show running-config` from the switch (remove passwords and keys; RuleTruss also redacts secrets on import) and import it. Read the
   Configuration tab's findings: shadowed entries, broad permits, undecidable entries (non-contiguous wildcard masks, `reflect`, `dscp`).
2. **Capture** the east/west traffic (a SPAN port or a tap on the switch uplink) and import it. *Compare* shows which observed connections the
   switch's ACLs permit, deny or cannot decide, and lists the allow entries that no observed traffic matched (which is not the same as unused: a capture covers only its own window).
3. **Narrow** (optional): *Propose narrower from observation* turns what was seen into specific rules, each with its evidence and an observation-limit
   warning (anything that did not happen in the window is invisible).
4. **Translate** the switch configuration (*Preserve what is configured*) to the firewall. Name the mapping from each VLAN interface to a firewall
   interface or sub-interface; names are never guessed. Decide each open interface. Read the report: every ACL entry has one disposition.
5. **Validate**: the comparison on sampled connections. It is this tool's own evaluator on both sides, not proof; see [VALIDATION.md](VALIDATION.md).
6. **Plan the cut-over by hand**: the firewall becomes the gateway of each VLAN (the switch SVIs go away or stay for the VLANs you keep routed), DHCP
   relay (`ip helper-address`), routing protocols, multicast, NAT, high availability and rollback are not read or generated.

## Limits

* IPv4 only for the open-interface handling; IPv6 ACLs are translated entry by entry as before.
* Only Cisco IOS / IOS-XE running-config text is read for switches. NX-OS and other vendors' switches are not.
* Time ranges, `reflect`/`evaluate`, DSCP and TCP-flag matches other than `established` are reported as not evaluated and the entry is left untranslated.
* A switch with the firewall's own policy (zone-based firewall on IOS) is reported, not modelled.
