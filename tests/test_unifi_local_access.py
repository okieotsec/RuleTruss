"""UniFi to Cisco ASA: policies to the gateway itself, from and to VPN clients, and MAC address filters.

The fixture (tests/unifi_zones.py) is invented. Each test edits a copy of it so that exactly one situation is under test. What the tool
cannot check is said in the tests too: the management-access lines and the VPN filter are not covered by the validation (it samples
through-traffic), and the VPN part has not been tried on a device.
"""
import ipaddress
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import unifi_zones

from ruletruss.service import ApiError, Service
from ruletruss.store import Store

MAP = {"Default": "Gi0/0", "IP_CAMERAS": "Gi0/1", "WIRELESS_DEVICES": "Gi0/2", "SOC_SERVICES": "Gi0/3", "OT_LAB_DEVICES": "Gi0/4",
       "ISOLATION": "Gi0/5", "SANDBOX": "Gi0/6", "zone-External": "Gi0/7"}
SSH = {"type": "PORT", "portFilter": {"type": "PORTS", "matchOpposite": False, "items": [{"type": "PORT_NUMBER", "value": 22}]}}
TCP = {"ipVersion": "IPV4_AND_IPV6", "protocolFilter": {"type": "NAMED_PROTOCOL", "matchOpposite": False, "protocol": {"name": "TCP"}}}
count = [5000]


def ports(*numbers):
    return {"type": "PORT", "portFilter": {"type": "PORTS", "matchOpposite": False,
                                           "items": [{"type": "PORT_NUMBER", "value": n} for n in numbers]}}


def ip(*values):
    return {"type": "IP_ADDRESS", "ipAddressFilter": {"type": "IP_ADDRESSES", "matchOpposite": False,
                                                      "items": [{"type": "SUBNET" if "/" in x else "IP_ADDRESS", "value": x} for x in values]}}


def mac(*macs):
    return {"type": "MAC_ADDRESS", "macAddressFilter": {"macAddresses": list(macs)}}


def add(data, src, dst, name, action="ALLOW", index=10000, origin="USER_DEFINED", src_filter=None, dst_filter=None, states=None, scope=None):
    count[0] += 1
    policy = {"id": unifi_zones.U(count[0]), "name": name, "description": "", "enabled": True, "index": index, "loggingEnabled": False,
              "action": {"type": action, **({"allowReturnTraffic": False} if action == "ALLOW" else {})},
              "source": {"zoneId": unifi_zones.zid[src], **({"trafficFilter": src_filter} if src_filter else {})},
              "destination": {"zoneId": unifi_zones.zid[dst], **({"trafficFilter": dst_filter} if dst_filter else {})},
              "ipProtocolScope": scope or {"ipVersion": "IPV4_AND_IPV6"}, "metadata": {"origin": origin}}
    if states:
        policy["connectionStateFilter"] = states
    data["policies"].append(policy)
    return policy


def drop(data, src, dst, name):
    ids = (unifi_zones.zid[src], unifi_zones.zid[dst])
    data["policies"] = [p for p in data["policies"] if not (
        (p["source"]["zoneId"], p["destination"]["zoneId"]) == ids and p["name"] == name)]


def make(edit=None, problems=False):
    data = unifi_zones.build(problems)
    if edit:
        edit(data)
    return json.dumps(data)


def project(text):
    service = Service(Store(tempfile.mkdtemp()))
    pid = service.store.create_project("zones")["id"]
    upload = service.store.new_upload_path(pid)
    Path(upload).write_text(text, encoding="utf-8")
    entry = service.import_upload(pid, upload, "unifi-export.json")
    return service, pid, entry["id"]


def translate(text, target="cisco-asa", zone_map=None, **body):
    """`text` is an export, or the (service, project id, source id) of one already imported."""
    service, pid, sid = text if isinstance(text, tuple) else project(text)
    return service.translation_json(pid, {"workflow": "preserve", "policy": sid, "target": target,
                                          "zone_map": MAP if zone_map is None else zone_map, **body})


def lines(result):
    return result["text"].splitlines()


def entry(result, name, pair=None):
    found = [e for e in result["report"] if e["source_rule"] == name and (pair is None or e["pair"] == pair)]
    assert len(found) == 1, (name, pair, [(e["source_rule"], e["pair"]) for e in result["report"]])
    return found[0]


def covered(result, command, interface):
    """The networks a command ('ssh', 'http') permits on an interface, from the generated text."""
    nets = []
    for ln in lines(result):
        parts = ln.split()
        if len(parts) == 4 and parts[0] == command and parts[3] == interface:
            nets.append(ipaddress.ip_network(f"{parts[1]}/{parts[2]}"))
    return nets


def has(nets, address):
    return any(ipaddress.ip_address(address) in n for n in nets)


class GatewayTests(unittest.TestCase):
    def test_allow_all_to_the_gateway_opens_ssh_http_and_ping_from_that_network_only(self):
        result = translate(make())
        text = result["text"]
        for line in ("ssh 10.0.100.0 255.255.255.0 Gi0/3", "http 10.0.100.0 255.255.255.0 Gi0/3",
                     "icmp permit 10.0.100.0 255.255.255.0 Gi0/3"):
            self.assertIn("\n" + line + "\n", text)
        self.assertEqual(covered(result, "ssh", "Gi0/3"), [ipaddress.ip_network("10.0.100.0/24")])      # not another network's addresses
        got = entry(result, "Allow All Traffic", "SOC Services to Gateway")
        self.assertEqual(got["disposition"], "translated")
        self.assertIn("ssh, http and icmp", got["reason"])                      # what the ASA offers; the rest is said, not implied

    def test_a_block_before_the_allow_all_removes_access_and_ping_is_denied_by_name(self):
        def edit(data):
            add(data, "IP Cameras", "Gateway", "Cameras may not manage the firewall", "BLOCK")
        result = translate(make(edit))
        self.assertEqual(covered(result, "ssh", "Gi0/1"), [])
        self.assertEqual(covered(result, "http", "Gi0/1"), [])
        self.assertIn("\nicmp deny 10.0.10.0 255.255.255.0 Gi0/1\n", result["text"])           # the ASA answers ping unless told not to
        self.assertNotIn("icmp permit 10.0.10.0", result["text"])
        self.assertEqual(entry(result, "Cameras may not manage the firewall")["disposition"], "translated")
        shadowed = entry(result, "Allow All Traffic", "IP Cameras to Gateway")
        self.assertEqual(shadowed["disposition"], "not-applicable")
        self.assertIn("Cameras may not manage the firewall", shadowed["reason"])

    def test_when_the_pair_default_blocks_only_what_is_allowed_is_opened(self):
        def edit(data):
            drop(data, "Isolation", "Gateway", "Allow All Traffic")
            add(data, "Isolation", "Gateway", "Block All Traffic", "BLOCK", unifi_zones.LAST, "SYSTEM_DEFINED")
            add(data, "Isolation", "Gateway", "SSH for the isolation network", "ALLOW", dst_filter=ports(22), scope=TCP)
        result = translate(make(edit))
        self.assertEqual(covered(result, "ssh", "Gi0/5"), [ipaddress.ip_network("10.0.250.0/24")])
        self.assertEqual(covered(result, "http", "Gi0/5"), [])
        self.assertIn("\nicmp deny 10.0.250.0 255.255.255.0 Gi0/5\n", result["text"])
        self.assertEqual(entry(result, "SSH for the isolation network")["disposition"], "translated")

    def test_a_service_the_asa_does_not_offer_stays_unresolved_for_you_and_says_what_it_does_offer(self):
        def edit(data):
            drop(data, "Isolation", "Gateway", "Allow All Traffic")
            add(data, "Isolation", "Gateway", "Block All Traffic", "BLOCK", unifi_zones.LAST, "SYSTEM_DEFINED")
            add(data, "Isolation", "Gateway", "Web on 8443", "ALLOW", dst_filter=ports(8443), scope=TCP)
        result = translate(make(edit))
        got = entry(result, "Web on 8443")
        self.assertEqual(got["disposition"], "unresolved")
        self.assertIn("8443", got["reason"])
        self.assertIn("ssh (22)", got["reason"])
        self.assertEqual(covered(result, "http", "Gi0/5"), [])
        self.assertTrue(any(i["code"] == "local-services" for i in result["issues"]))
        self.assertEqual(entry(translate(make(edit), confirm=["gateway"]), "Web on 8443")["disposition"], "implemented")

    def test_a_host_blocked_before_an_allow_is_cut_out_of_what_the_allow_opens(self):
        def edit(data):
            add(data, "SOC Services", "Gateway", "Not that host", "BLOCK", src_filter=ip("10.0.100.5"), dst_filter=ports(22), scope=TCP)
        result = translate(make(edit))
        nets = covered(result, "ssh", "Gi0/3")
        self.assertFalse(has(nets, "10.0.100.5"))
        self.assertTrue(has(nets, "10.0.100.4") and has(nets, "10.0.100.6") and has(nets, "10.0.100.200"))
        self.assertTrue(has(covered(result, "http", "Gi0/3"), "10.0.100.5"))          # the block was about ssh only
        self.assertEqual(entry(result, "Not that host")["disposition"], "translated")

    def test_thousands_of_earlier_blocks_are_refused_not_ground_through(self):
        def edit(data):
            for n in range(300):
                add(data, "SOC Services", "Gateway", f"Block host {n}", "BLOCK", 9000 + n, src_filter=ip(f"10.0.100.{n % 250}/32"), dst_filter=ports(22), scope=TCP)
        result = translate(make(edit))
        self.assertEqual(entry(result, "Allow All Traffic", "SOC Services to Gateway")["disposition"], "unsupported")
        self.assertEqual(covered(result, "ssh", "Gi0/3"), [])                  # nothing half-written for that interface
        self.assertIn("address entries", entry(result, "Allow All Traffic", "SOC Services to Gateway")["reason"])

    def test_a_policy_naming_the_gateways_own_address_is_translated_and_one_naming_another_address_is_not(self):
        def edit(data):
            drop(data, "Isolation", "Gateway", "Allow All Traffic")
            add(data, "Isolation", "Gateway", "Block All Traffic", "BLOCK", unifi_zones.LAST, "SYSTEM_DEFINED")
            own = {**ip("10.0.250.1"), "portFilter": ports(22)["portFilter"]}
            add(data, "Isolation", "Gateway", "SSH to the gateway address", "ALLOW", dst_filter=own, scope=TCP)
            other = {**ip("10.0.250.99"), "portFilter": ports(22)["portFilter"]}
            add(data, "Isolation", "Gateway", "SSH to some other address", "ALLOW", dst_filter=other, scope=TCP)
        result = translate(make(edit))
        self.assertEqual(entry(result, "SSH to the gateway address")["disposition"], "translated")
        self.assertIn("own interface", entry(result, "SSH to the gateway address")["reason"])
        self.assertEqual(covered(result, "ssh", "Gi0/5"), [ipaddress.ip_network("10.0.250.0/24")])
        got = entry(result, "SSH to some other address")
        self.assertEqual(got["disposition"], "unsupported")
        self.assertIn("not an address of the gateway", got["reason"])

    def test_a_dhcp_policy_that_names_the_gateways_address_is_a_local_service_not_an_unsupported_one(self):
        def edit(data):
            dhcp = {**ip("10.0.0.1"), "portFilter": ports(67)["portFilter"]}
            add(data, "Default LAN", "Gateway", "Allow DHCP", "ALLOW", 30001, "SYSTEM_DEFINED", dst_filter=dhcp,
                scope={"ipVersion": "IPV4", "protocolFilter": {"type": "NAMED_PROTOCOL", "matchOpposite": False, "protocol": {"name": "UDP"}}})
        result = translate(make(edit))
        self.assertEqual(entry(result, "Allow DHCP")["disposition"], "unresolved")

    def test_a_dhcp_reply_policy_with_a_source_port_is_a_local_service_too(self):
        def edit(data):
            add(data, "Default LAN", "Gateway", "DHCP from the server port", "ALLOW", 30001, "SYSTEM_DEFINED", src_filter=ports(547), dst_filter=ports(546),
                scope={"ipVersion": "IPV4", "protocolFilter": {"type": "NAMED_PROTOCOL", "matchOpposite": False, "protocol": {"name": "UDP"}}})
        result = translate(make(edit))
        self.assertEqual(entry(result, "DHCP from the server port")["disposition"], "unresolved")

    def test_a_tcp_policy_with_a_source_port_cannot_be_written_as_ssh_or_http(self):
        def edit(data):
            drop(data, "Isolation", "Gateway", "Allow All Traffic")
            add(data, "Isolation", "Gateway", "Block All Traffic", "BLOCK", unifi_zones.LAST, "SYSTEM_DEFINED")
            add(data, "Isolation", "Gateway", "SSH from one source port", "ALLOW", src_filter=ports(40000), dst_filter=ports(22), scope=TCP)
        result = translate(make(edit))
        got = entry(result, "SSH from one source port")
        self.assertEqual(got["disposition"], "unsupported")
        self.assertIn("source port", got["reason"])
        self.assertEqual(covered(result, "ssh", "Gi0/5"), [])

    def test_other_local_services_stay_unresolved_until_confirmed_but_the_access_lines_are_still_written(self):
        def edit(data):
            add(data, "Default LAN", "Gateway", "Allow DHCP", "ALLOW", 30001, "SYSTEM_DEFINED", dst_filter=ports(67),
                scope={"ipVersion": "IPV4", "protocolFilter": {"type": "NAMED_PROTOCOL", "matchOpposite": False, "protocol": {"name": "UDP"}}})
        text = make(edit)
        result = translate(text)
        self.assertEqual(entry(result, "Allow DHCP")["disposition"], "unresolved")
        self.assertIn("firewall itself", entry(result, "Allow DHCP")["reason"])
        self.assertTrue(any(i["code"] == "local-services" for i in result["issues"]))
        self.assertIn("\nssh 10.0.0.0 255.255.255.0 Gi0/0\n", result["text"])
        handled = translate(text, confirm=["gateway"])
        self.assertEqual(entry(handled, "Allow DHCP")["disposition"], "implemented")
        self.assertIn("\nssh 10.0.0.0 255.255.255.0 Gi0/0\n", handled["text"])             # confirming does not switch the access lines off

    def test_access_from_the_internet_uses_the_outside_interface(self):
        def edit(data):
            add(data, "External", "Gateway", "SSH from the office", "ALLOW", src_filter=ip("203.0.113.0/28"), dst_filter=ports(22), scope=TCP)
        result = translate(make(edit))
        self.assertEqual(covered(result, "ssh", "Gi0/7"), [ipaddress.ip_network("203.0.113.0/28")])
        self.assertEqual(entry(result, "SSH from the office")["disposition"], "translated")

    def test_the_access_lines_are_disclosed_and_the_validation_does_not_claim_to_cover_them(self):
        result = translate(make())
        codes = {i["code"]: i for i in result["issues"]}
        self.assertEqual(codes["management-access"]["severity"], "warning")
        self.assertIn("not covered by the validation", codes["management-access"]["message"])
        self.assertIn("http server enable", codes["management-access"]["message"])

    def test_ios_gets_no_invented_access_lines(self):
        result = translate(make(), target="cisco-ios")
        self.assertNotIn("\nssh ", result["text"])
        self.assertEqual(entry(result, "Allow All Traffic", "SOC Services to Gateway")["disposition"], "unresolved")

    def test_an_ipv4_policy_with_no_address_limit_is_not_called_stale(self):
        def edit(data):
            add(data, "Isolation", "External", "Any IPv4", "ALLOW", scope={"ipVersion": "IPV4"})
            add(data, "SOC Services", "OT Lab", "Any IPv4 inside", "ALLOW", scope={"ipVersion": "IPV4"})
        result = translate(make(edit))
        self.assertEqual(entry(result, "Any IPv4")["disposition"], "translated")
        self.assertEqual(entry(result, "Any IPv4 inside")["disposition"], "translated")


class VpnTests(unittest.TestCase):
    POOL = ["10.200.0.0/24"]

    @staticmethod
    def edit(data):
        add(data, "Vpn", "Default LAN", "VPN to LAN", "ALLOW")
        add(data, "Vpn", "SOC Services", "VPN to SOC web", "ALLOW", dst_filter=ports(443), scope=TCP)
        add(data, "Vpn", "SOC Services", "Block All Traffic", "BLOCK", unifi_zones.LAST, "SYSTEM_DEFINED")
        add(data, "Default LAN", "Vpn", "LAN to VPN", "ALLOW")

    def test_without_the_client_pool_the_vpn_policies_ask_for_it(self):
        result = translate(make(self.edit))
        got = entry(result, "VPN to LAN")
        self.assertEqual(got["disposition"], "unresolved")
        self.assertIn("address pool", got["reason"])
        self.assertNotIn("RT-VPN-FILTER", result["text"])

    def test_with_the_pool_client_started_traffic_becomes_a_vpn_filter_in_order(self):
        result = translate(make(self.edit), vpn_networks=self.POOL)
        acl = [ln.split(" extended ", 1)[1] for ln in lines(result) if ln.startswith("access-list RT-VPN-FILTER extended")]
        self.assertEqual(acl, ["permit ip 10.200.0.0 255.255.255.0 10.0.0.0 255.255.255.0",
                               "permit tcp 10.200.0.0 255.255.255.0 10.0.100.0 255.255.255.0 eq 443",
                               "deny ip 10.200.0.0 255.255.255.0 10.0.100.0 255.255.255.0"])
        self.assertIn("\ngroup-policy RT-VPN-POLICY internal\n", result["text"])
        self.assertIn("\ngroup-policy RT-VPN-POLICY attributes\n vpn-filter value RT-VPN-FILTER\n", result["text"])
        self.assertEqual(entry(result, "VPN to LAN")["disposition"], "translated")
        self.assertNotIn("RT-VPN", "".join(ln for ln in lines(result) if ln.startswith("access-group")))     # not bound to an interface

    def test_nothing_about_the_vpn_is_called_deployable_because_no_device_has_run_it(self):
        result = translate(make(self.edit), vpn_networks=self.POOL, zone_map=MAP)
        issue = next(i for i in result["issues"] if i["code"] == "vpn-filter-untested")
        self.assertEqual(issue["severity"], "blocker")
        self.assertFalse(result["deployable"])
        self.assertIn("not been tried on a device", issue["message"])

    def test_traffic_started_toward_vpn_clients_stays_unresolved_until_you_handle_it(self):
        result = translate(make(self.edit), vpn_networks=self.POOL)
        self.assertEqual(entry(result, "LAN to VPN")["disposition"], "unresolved")
        handled = translate(make(self.edit), vpn_networks=self.POOL, confirm=["vpn"])
        self.assertEqual(entry(handled, "LAN to VPN")["disposition"], "implemented")
        self.assertEqual(entry(handled, "VPN to LAN")["disposition"], "translated")          # confirming does not switch the filter off

    def test_a_pool_that_is_not_a_network_or_overlaps_a_zone_is_refused_not_guessed(self):
        text = make(self.edit)
        service = project(text)
        for bad in (["not-a-network"], ["0.0.0.0/0"], ["10.0.100.0/25"], ["2001:db8::/64"], "10.200.0.0/24", [f"10.{i}.0.0/24" for i in range(40)]):
            with self.assertRaises(ApiError, msg=bad):
                translate(service, vpn_networks=bad)

    def test_a_policy_limited_to_addresses_outside_the_pool_is_unresolved(self):
        def edit(data):
            add(data, "Vpn", "Default LAN", "Admin PC over VPN", "ALLOW", src_filter=ip("192.0.2.10"))
        result = translate(make(edit), vpn_networks=self.POOL)
        got = entry(result, "Admin PC over VPN")
        self.assertEqual(got["disposition"], "unresolved")
        self.assertIn("not inside the VPN client address pool", got["reason"])

    def test_the_other_targets_do_not_get_a_vpn_filter(self):
        result = translate(make(self.edit), target="cisco-ios", vpn_networks=self.POOL)
        self.assertNotIn("vpn-filter", result["text"])
        self.assertEqual(entry(result, "VPN to LAN")["disposition"], "unresolved")


class MacFilterTests(unittest.TestCase):
    A, B = "60:45:2e:77:05:2e", "72:e9:41:e8:b1:16"

    @staticmethod
    def edit(data):
        add(data, "Wireless Devices", "SOC Services", "Two phones to SOC", "ALLOW", src_filter=mac("60:45:2E:77:05:2E", "72:e9:41:e8:b1:16"))
        add(data, "IP Cameras", "External", "Block one camera", "BLOCK", src_filter=mac("bc:24:11:81:fa:29"))

    def test_without_addresses_the_mac_policies_are_unsupported_and_the_input_is_offered(self):
        result = translate(make(self.edit))
        got = entry(result, "Two phones to SOC")
        self.assertEqual(got["disposition"], "unsupported")
        self.assertIn("MAC address", got["reason"])
        wanted = {m["mac"]: m for m in result["inputs"]["mac_filters"]}
        self.assertEqual(set(wanted), {self.A, self.B, "bc:24:11:81:fa:29"})
        self.assertEqual(wanted[self.A]["policies"], ["Two phones to SOC"])
        self.assertEqual(wanted[self.A]["ip"], "")

    def test_mapped_macs_become_host_addresses_and_the_text_says_so(self):
        result = translate(make(self.edit), mac_map={self.A.upper(): "10.0.20.31", self.B: "10.0.20.32"})
        aces = [ln for ln in lines(result) if ln.startswith("access-list RT-WIRELESS_DEVICES-IN extended")]
        self.assertIn("access-list RT-WIRELESS_DEVICES-IN extended permit ip host 10.0.20.31 10.0.100.0 255.255.255.0", aces)
        self.assertIn("access-list RT-WIRELESS_DEVICES-IN extended permit ip host 10.0.20.32 10.0.100.0 255.255.255.0", aces)
        got = entry(result, "Two phones to SOC")
        self.assertEqual(got["disposition"], "translated")
        self.assertIn("60:45:2e:77:05:2e", got["reason"])
        self.assertIn("10.0.20.31", got["reason"])
        self.assertIn("address changes", got["reason"])
        remark = [ln for ln in lines(result) if ln.startswith("access-list RT-WIRELESS_DEVICES-IN remark") and "Two_phones_to_SOC" in ln]
        self.assertTrue(remark and all("MAC filter replaced" in ln for ln in remark))

    def test_a_block_by_mac_says_it_stops_working_if_the_device_gets_another_address(self):
        result = translate(make(self.edit), mac_map={"bc:24:11:81:fa:29": "10.0.10.77"})
        got = entry(result, "Block one camera")
        self.assertEqual(got["disposition"], "translated")
        self.assertIn("BROADENS", got["reason"])
        self.assertIn("RT-IP_CAMERAS-IN extended deny ip host 10.0.10.77 any\n", result["text"])
        issue = next(i for i in result["issues"] if i["code"] == "mac-substituted")
        self.assertEqual(issue["severity"], "warning")
        self.assertIn("1 deny", issue["message"])

    def test_one_missing_mac_leaves_the_whole_policy_untranslated(self):
        result = translate(make(self.edit), mac_map={self.A: "10.0.20.31"})
        got = entry(result, "Two phones to SOC")
        self.assertEqual(got["disposition"], "unsupported")
        self.assertIn(self.B, got["reason"])
        self.assertNotIn("10.0.20.31 10.0.100.0", result["text"])               # no partial rule that narrows or widens it

    def test_an_address_outside_the_source_zone_is_unresolved_not_moved(self):
        result = translate(make(self.edit), mac_map={self.A: "10.0.20.31", self.B: "10.0.0.9"})
        got = entry(result, "Two phones to SOC")
        self.assertEqual(got["disposition"], "unresolved")
        self.assertIn("10.0.0.9", got["reason"])

    def test_an_address_for_a_mac_no_policy_uses_is_reported_not_ignored_silently(self):
        result = translate(make(self.edit), mac_map={self.A: "10.0.20.31", self.B: "10.0.20.32", "02:00:00:00:00:99": "10.0.20.99"})
        issue = next(i for i in result["issues"] if i["code"] == "mac-map-unused")
        self.assertIn("02:00:00:00:00:99", issue["message"])
        self.assertEqual(issue["severity"], "warning")

    def test_bad_input_is_refused(self):
        service = project(make(self.edit))
        for bad in ({"nonsense": "10.0.0.1"}, {self.A: "not-an-address"}, {self.A: "10.0.0.0/24"}, {self.A: "2001:db8::1"},
                    {self.A: ".".join("0000")}, {self.A: "10.0.20.1\nno shutdown"}, ["x"], {f"aa:bb:cc:dd:ee:{i:02x}": "10.0.20.9" for i in range(250)} | {
                        f"aa:bb:cc:dd:{j:02x}:00": "10.0.20.9" for j in range(250)}):
            with self.assertRaises(ApiError, msg=str(bad)[:60]):
                translate(service, mac_map=bad)

    def test_the_address_text_that_reaches_the_configuration_is_only_what_ipaddress_wrote(self):
        result = translate(make(self.edit), mac_map={"60-45-2E-77-05-2E": " 10.0.20.031 ".strip().replace("031", "31"), self.B: "10.0.20.32"})
        self.assertNotIn("\r", result["text"])
        self.assertIn("host 10.0.20.31 ", result["text"])

    def test_a_captured_arp_or_dhcp_binding_is_offered_as_a_suggestion_with_its_basis_and_never_applied(self):
        facts = {"bindings": [{"mac": self.A, "ip": "10.0.20.31", "basis": "arp", "packets": 9, "evidence": []},
                              {"mac": self.B, "ip": "10.0.20.32", "basis": "frame", "packets": 9, "evidence": []},
                              {"mac": "bc:24:11:81:fa:29", "ip": "10.0.10.77", "basis": "dhcp", "packets": 1, "evidence": []},
                              {"mac": "bc:24:11:81:fa:29", "ip": "10.0.10.78", "basis": "dhcp", "packets": 1, "evidence": []}],
                 "l2_senders": [], "observations": [], "limits_hit": []}
        with mock.patch.object(Service, "device_facts", return_value=facts):
            result = translate(make(self.edit))
        wanted = {m["mac"]: m for m in result["inputs"]["mac_filters"]}
        self.assertEqual((wanted[self.A]["suggestion"], wanted[self.A]["suggestion_basis"]), ("10.0.20.31", "arp"))
        self.assertEqual(wanted[self.B]["suggestion"], "")                  # a frame only shows which MAC carried the packet
        self.assertEqual(wanted["bc:24:11:81:fa:29"]["suggestion"], "")     # two addresses: not a single answer
        self.assertEqual(entry(result, "Two phones to SOC")["disposition"], "unsupported")      # a suggestion is not an answer

    def test_mac_filters_are_translated_for_ios_too(self):
        result = translate(make(self.edit), target="cisco-ios", mac_map={self.A: "10.0.20.31", self.B: "10.0.20.32"})
        self.assertEqual(entry(result, "Two phones to SOC")["disposition"], "translated")


if __name__ == "__main__":
    unittest.main()
