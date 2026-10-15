# Getting a UniFi gateway's firewall into RuleTruss

Covers UniFi gateways that run the UniFi Network application with **zone-based firewall** (for example the Cloud Gateway Max).
Written from Ubiquiti's published API documentation. One real export (a Cloud Gateway Max on Network 10.6.106, 81 policies, 6 zones, 7
networks) has been read successfully: its field shapes matched, 56 policies were fully evaluable, 24 applied only to existing connections
and one used a MAC filter. Decisions have not yet been checked against real traffic on that gateway. If a step or a field differs on your
version, RuleTruss reports what it could not read rather than guessing, and the export tool says so when an endpoint is missing.

## What the web interface offers, and what it does not

* **Backups** (Settings, Control Plane, Backups in current versions; older versions have it under System): downloads a `.unf` or `.unifi`
  file. That is the controller's whole database, encrypted with a key that is the same for everyone, and it also contains secrets
  (Wi-Fi keys, device credentials). It is **not** a readable list of firewall rules, and RuleTruss does not read it. Keep such files private.
* **I did not find a button that exports the firewall policies as text or CSV.** The policy table can be read on screen, not saved.
* **The Network application's own API can.** It is documented by Ubiquiti, local to your gateway, and read-only when you only make GET
  requests. The export tool below does exactly that.

## Steps

1. **Check the version.** The firewall policy and zone endpoints need Network application **10.1 or later** (Ubiquiti's documentation lists
   policies from 10.1.84). On the gateway, open the UniFi Network application, then its *About* or *Settings* page, and read the version.
   Older versions use the legacy firewall rules, which RuleTruss does not read yet.
2. **Create an API key.** In the Network application: Settings, Control Plane, Integrations, create a new API key and copy it when it is
   shown (it is shown once). Menu names differ between versions; Ubiquiti's help article is "Getting started with the Official UniFi API".
   Delete the key from the same page when you are done.
3. **Find the gateway's certificate fingerprint** (the gateway uses a self-signed certificate):

   ```bash
   .venv/bin/python tools/unifi_export.py --host 192.168.1.1 --show-fingerprint
   ```

   It prints a SHA-256 value. If you can, compare it with the certificate your browser shows for the gateway's address.
4. **Export.** Run this and paste the API key when it asks (nothing is shown as you paste, and the key is not saved anywhere):

   ```bash
   .venv/bin/python tools/unifi_export.py --host 192.168.1.1 --fingerprint <the value from step 3> --out unifi-export.json
   ```

   If you prefer not to be prompted, put the key in the `UNIFI_API_KEY` environment variable, or in a file you create yourself (for
   example `~/unifi-key.txt`, outside the project folder, deleted afterwards) and pass `--api-key-file ~/unifi-key.txt`. There is no key
   file in the repository; you never need one.

   Use `--insecure` only if you accept that anyone on the path could answer instead of the gateway. A gateway with several sites needs
   `--site NAME`.
5. **Import** `unifi-export.json` on RuleTruss's Import tab. Then define your subnets or labels as usual: zone membership is taken from
   the UniFi networks, so traffic between your devices is placed in UniFi zones automatically.

## What the tool does and does not do

* Only GET requests, only to the host you name, with the key in the `X-API-KEY` header. It reads the site list, firewall zones, firewall
  policies, networks (each one in detail, for its subnet), traffic matching lists and, if present, switch ACL rules. The key is never written
  to the output file, and the output file is created readable by you only.
* It does **not** read port forwards (NAT), VPN settings, DNS policies, Wi-Fi, clients or devices. Without the port-forward list RuleTruss
  cannot tell how destination NAT changes which address a policy sees.
* The RuleTruss server never contacts your gateway; only this separate command, run by you, does.

## The zone matrix

On the Configuration tab, a UniFi export gets a **Zone matrix** like UniFi's own: rows are source zones, columns are destination zones, and each
cell says what the pair ends in (*Allow all*, *Block all*, *Block (replies allowed)*) and, when policies come first, how many (*Allow, 4
blocked*; *Block, 5 allowed*). Click a cell to read that pair's policies in order, with the predefined ones, the disabled ones and the
replies-only ones marked. Counts are policies in the export; a policy that only applies to existing connections is not counted as a block or an
allow. *No policy listed* and *No default listed* mean the export has nothing there, not that the gateway does nothing.

## Translating a UniFi export to a Cisco ASA

UniFi keeps one list of policies per pair of zones, each pair ending in its own default. An ASA has one ACL per interface and no
destination zone, so RuleTruss combines the pairs on purpose rather than flattening them:

* **An interface is a network, not a zone.** A zone can hold several networks (VLANs) and each is its own interface on the ASA. The mapping
  box takes lines like `SOC_SERVICES = GigabitEthernet0/1.100`, one per UniFi network, plus `zone-External` for the Internet side. Names are
  never guessed; two networks mapped to one interface are refused.
* **A zone's address field means "in that zone".** An unrestricted field becomes the zone's own networks, never `any`. So *Block All Traffic*
  from SOC Services to OT Lab becomes `deny ip <SOC network> <OT network>`, and *Allow SOC to Default LAN* stays scoped to the Default LAN
  network. A policy whose addresses fall outside its zone's networks is reported, not moved.
* **Order is rebuilt per interface.** Each ACL lists the pairs of its source zone one after another: pairs whose destination zone has networks
  first (they cannot overlap, each default names only its own destination), External last, every pair in UniFi's index order and ending in its own
  default. A pair needs an enabled final Allow All / Block All policy, including the pairs that start at External; a pair with none (or with only some policies) is a blocker: the ASA would deny it and UniFi's behaviour is not in the export.
* **Connection-state policies are implemented by the ASA's stateful inspection**, not by entries: *Allow Return Traffic* (replies are always
  accepted for permitted connections) and *Block Invalid Traffic* (the ASA drops packets of unknown connections; similar, not identical). UniFi's
  all-states blocks can also drop replies, which the ASA does not do; those policies are flagged. A block on established or related
  traffic, and an allow of invalid traffic, cannot be written as an interface ACL and are marked *unsupported*, not implemented.
* **Traffic to the firewall itself** (the Gateway zone) is not governed by interface ACLs and needs explicit ssh/http/icmp/DNS/DHCP/control-plane
  configuration. **VPN** needs the target's VPN design. Both stay *unresolved* until you tick that you handle them; then they are marked as handled by you.
* **Every source policy ends with one disposition:** translated, implemented through target behaviour, unsupported, unresolved or not applicable
  (for example a zone with no networks in the export, a disabled policy, or traffic inside one network). The generated text ends with one comment line
  per policy and the report has the full table with each policy's id.
* **Impact is stated.** Leaving out a block says that its protection is gone and which later policies now decide the traffic; leaving out an allow says
  its traffic falls through to the pair's later policies. MAC filters are never turned into IP addresses (the identity semantics would change, and the
  mapping would need verifying); ICMPv6 policies whose message type the API omits are unsupported.
* **Preview, not deployable.** While anything is unsupported, unresolved or still a placeholder the output carries a banner, its file name says
  `PREVIEW-NOT-DEPLOYABLE`, and exporting it needs your acknowledgement. IPv4 only: the export has no IPv6 prefixes for the zones. IOS (stateless) is
  also a preview because return paths are not generated for zone-pair sources. For an ASA, replies to an allowed ping come back only if ICMP inspection
  (`inspect icmp`, `inspect icmp error`) is on (confirmed on an ASAv, software 9.24(1): without it an allowed ping got no replies); RuleTruss warns about it and does not write it. TCP and UDP replies need nothing extra.

Validation compares sampled connections (every source network to every destination zone, and the inside of each policy you wrote) on both sides with
this tool's evaluator. The headline says how many were actually compared and how many could not be ("nothing could be compared" means no
agreement is claimed). It is not proof of equivalence; NAT, routing, VPN and local services are not part of it. An independent parser (Batfish, CP12)
agreed with it on the clean example.

## How RuleTruss reads the result

What each statement rests on is marked: **[export]** seen in a real export (Network 10.6.106), **[docs]** from Ubiquiti's API reference or
third-party guides (Ubiquiti's help-center pages could not be fetched), **[assumed]** not verified.

* **Zone pairs and order.** A policy belongs to one source zone and one destination zone. Within a pair the policies run in `index` order and
  the first match wins. **[export]** user-written policies have indexes from 10000, policies UniFi creates for you (predefined and derived)
  from 30000, and the final predefined policy of every pair has the index 2147483647. **[docs]** your policies are evaluated before the
  predefined ones. **[assumed]** that `index` is exactly the evaluation order in every case (the API also lets a user policy be placed before
  or after the system ones; the index is how this tool follows that).
* **Every zone pair ends in a default.** **[export]** each pair lists a final policy: *Allow All Traffic* (for example Internal to External,
  anything from the Gateway or a VPN) or *Block All Traffic* (for example External to Internal). Those are the built-in defaults, and they are
  read like any other policy. A pair with no policy at all is reported as undecidable.
* **Connection states.** A policy can match New, Established, Related and Invalid traffic. A first packet is New; a reply is Established and
  is checked against the policies of the reverse zone pair. So *Allow Return Traffic* (Established and Related, in the pairs that need it) is
  what lets replies in. **[docs]** third-party guides say that a policy blocking **all** states from A to B also blocks the replies of
  connections that B started, unless an earlier policy lets them through. **[tested once]** on one gateway, a phone could not ping a camera on a
  network whose policy blocks all states toward the phone's network, while a device on the camera's own network could; the flows view still listed
  the phone's flows as Allow, because the first packet is allowed. So Compare checks the reply direction and says when it would be blocked.
  Swapping the source and destination of a return-traffic allow policy so that it matched the cameras' replies (above the block) then made the
  ping work, as the model predicted. Both checks used ping (ICMP) on one gateway and one firmware version (Network 10.6.106). Policies that never match a New connection (the Invalid blockers, the return-traffic allowers) are shown but
  do not decide a new connection, are not translated as permit or block rules to another firewall, and never hide other policies in the
  rule analysis.
* **Predefined policies.** The names you see (*Allow All Traffic*, *Block All Traffic*, *Block Invalid Traffic*, *Allow Return Traffic*,
  *Isolated Networks*, *Allow mDNS*, the DHCPv6 and router-discovery ones) are read from the export and marked "predefined by UniFi" with
  their origin. They are not reported as broad or as conflicting with your policies, which is their normal job; one summary line lists the
  zone pairs that end in *Allow All Traffic*. **[export]** the API leaves the ICMPv6 message type out of the predefined *Neighbor
  Solicitation / Advertisement / Router Advertisement* policies, so they look identical; RuleTruss treats their type as unknown (undecidable
  for ICMPv6) instead of reading them as "all ICMPv6", and does not call them redundant.
* **Zones of addresses.** An address inside one of your networks is in that network's zone; the gateway's own addresses are the Gateway
  zone; any other public address is External; an unknown private address has no zone and is undecidable. Two hosts on the **same network**
  never pass the gateway, so Compare marks that traffic as not crossing it.
* **Filters.** Source and destination filters are read for IP addresses, ranges and subnets, traffic matching lists, networks, ports,
  protocols and "match opposite". Filters for domains, applications, regions, VPN members, MAC addresses and IPv6 interface identifiers cannot
  be decided from an export, so a policy that uses one is undecidable for traffic it might match. So are schedules and IPsec matching.
* **Not in the export [assumed to exist].** Port forwards and the rules they create, IPS/IDS and traffic-inspection actions, DNS and content
  filtering, VPN-internal rules, and anything the gateway adds that the policy API does not list. The result describes the policy table, not
  every packet path.
