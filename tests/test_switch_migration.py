"""Moving from layer 3 switch ACLs to a firewall (east/west): what an L3 switch config means and what the translation must say.

An IOS switch routes between its VLAN interfaces and filters only where an ACL is bound: a routed interface with no inbound ACL lets everything
through, an outbound ACL on a VLAN interface filters what leaves toward that VLAN, and VLAN access maps and port ACLs filter at layer 2. A stateful
firewall denies whatever no rule permits, so each of those has to be said, not assumed. The configuration (tests/fixtures/ios_l3_switch.cfg) is invented.
"""
import tempfile
import unittest
from pathlib import Path

from ruletruss.adapters import cisco
from ruletruss.service import ApiError, Service
from ruletruss.store import Store

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "ios_l3_switch.cfg"
MAP = {"Vlan10": "Gi0/1", "Vlan20": "Gi0/2", "Vlan30": "Gi0/3"}


def project(text=None):
    service = Service(Store(tempfile.mkdtemp()))
    pid = service.store.create_project("switch")["id"]
    upload = service.store.new_upload_path(pid)
    Path(upload).write_text(text or FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
    entry = service.import_upload(pid, upload, "dist-sw.cfg")
    return service, pid, entry["id"]


def translate(target="cisco-asa", handle=None, zone_map=None, **body):
    service, pid, sid = handle or project()
    return service.translation_json(pid, {"workflow": "preserve", "policy": sid, "target": target,
                                          "zone_map": MAP if zone_map is None else zone_map, **body})


def entry(result, name):
    found = [e for e in result["report"] if e["source_rule"] == name]
    assert len(found) == 1, (name, [e["source_rule"] for e in result["report"]])
    return found[0]


def codes(result, severity=None):
    return {i["code"] for i in result["issues"] if severity is None or i["severity"] == severity}


class SwitchModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = cisco.parse(FIXTURE.read_text(encoding="utf-8"), "s1", "ios")

    def test_vlan_interfaces_are_routed_and_a_switch_port_is_not(self):
        interfaces = self.policy.interfaces
        self.assertTrue(interfaces["Vlan10"]["routed"] and interfaces["Vlan30"]["routed"])
        self.assertFalse(interfaces["GigabitEthernet1/0/5"]["routed"])

    def test_filters_that_work_at_layer_2_are_reported_not_ignored(self):
        by_code = {i.code: i for i in self.policy.issues}
        self.assertIn("vlan-access-map", by_code)
        self.assertIn("NO-TELNET", by_code["vlan-access-map"].message)
        self.assertIn("port-acl", by_code)
        self.assertIn("GigabitEthernet1/0/5", by_code["port-acl"].message)

    def test_a_switch_that_does_not_route_says_its_acls_filter_nothing_between_vlans(self):
        text = FIXTURE.read_text(encoding="utf-8").replace("ip routing\n", "")
        policy = cisco.parse(text, "s1", "ios")
        self.assertIn("ip-routing-missing", {i.code for i in policy.issues})
        self.assertNotIn("ip-routing-missing", {i.code for i in self.policy.issues})


class OpenInterfaceTests(unittest.TestCase):
    """A routed interface with no inbound ACL permits everything it carries. The firewall will not, so the translation has to say so."""

    def test_every_routed_interface_with_no_inbound_acl_is_listed_and_blocks_deployment(self):
        result = translate()
        open_ones = {e["source_rule"] for e in result["report"] if e["source_rule"].startswith("(no inbound ACL on")}
        self.assertEqual(open_ones, {"(no inbound ACL on Vlan20)", "(no inbound ACL on Vlan30)"})     # Vlan40 is shut down
        got = entry(result, "(no inbound ACL on Vlan20)")
        self.assertEqual(got["disposition"], "unresolved")
        self.assertIn("permitted everything", got["reason"])
        self.assertIn("switch-open-interface", codes(result, "blocker"))
        self.assertFalse(result["deployable"])

    def test_naming_an_interface_to_keep_open_writes_a_labelled_permit_for_ipv4_only(self):
        result = translate(keep_open=["Vlan20"])
        self.assertEqual(entry(result, "(no inbound ACL on Vlan20)")["disposition"], "translated")
        self.assertIn("access-list RT-Vlan20-IN extended permit ip any4 any4\n", result["text"])
        self.assertIn("kept open", result["text"])
        self.assertEqual(entry(result, "(no inbound ACL on Vlan30)")["disposition"], "unresolved")       # only what was named
        self.assertGreaterEqual(result["summary"]["rules_known_broader"], 1)

    def test_an_unknown_or_shut_down_interface_cannot_be_kept_open(self):
        handle = project()
        for bad in (["Vlan99"], ["Vlan40"], "Vlan20", [["Vlan20"]], ["Vlan20\nno shutdown"]):
            with self.assertRaises(ApiError, msg=str(bad)):
                translate(handle=handle, keep_open=bad)

    def test_the_input_offers_the_open_interfaces_and_the_ones_already_kept(self):
        result = translate(keep_open=["Vlan20"])
        rows = {r["interface"]: r for r in result["inputs"]["open_interfaces"]}
        self.assertEqual(set(rows), {"Vlan20", "Vlan30"})
        self.assertTrue(rows["Vlan20"]["kept"] and not rows["Vlan30"]["kept"])

    def test_the_other_families_of_the_report_are_not_polluted_for_a_firewall_source(self):
        # an ASA source with no ACL on an interface is decided by security levels, not by this rule
        text = ("ASA Version 9.16\ninterface Gi0/0\n nameif inside\n security-level 100\n ip address 10.0.0.1 255.255.255.0\n"
                "interface Gi0/1\n nameif outside\n security-level 0\n ip address 192.0.2.1 255.255.255.0\n"
                "access-list X extended permit ip any any\naccess-group X in interface outside\n")
        result = translate(handle=project(text), zone_map={})
        self.assertFalse(any(e["source_rule"].startswith("(no inbound ACL") for e in result["report"]))


class OutboundAclTests(unittest.TestCase):
    def test_an_outbound_acl_stays_an_outbound_acl_on_the_asa(self):
        result = translate()
        text = result["text"]
        self.assertIn("access-list RT-Vlan30-OUT extended permit tcp 10.10.10.0 255.255.255.0 10.10.30.0 255.255.255.0 eq 443\n", text)
        self.assertIn("access-group RT-Vlan30-OUT out interface Gi0/3\n", text)
        self.assertNotIn("RT-GLOBAL", text)                                    # it is not widened into a global rule
        self.assertNotIn("dst-zone-dropped", codes(result))
        self.assertEqual(entry(result, "SERVERS-OUT:1")["disposition"], "translated")

    def test_the_inbound_acl_keeps_its_own_binding_and_skips_the_reply_entry(self):
        result = translate()
        self.assertIn("access-group RT-Vlan10-IN in interface Gi0/1\n", result["text"])
        self.assertEqual(entry(result, "USERS-IN:3")["disposition"], "implemented")        # the established entry: the firewall tracks replies

    def test_ios_gets_an_outbound_binding_too(self):
        result = translate(target="cisco-ios")
        self.assertIn("ip access-group RT-Vlan30-OUT out", result["text"])

    def test_fortios_names_the_destination_interface(self):
        result = translate(target="fortios")
        self.assertIn('set dstintf "Gi0/3"', result["text"])

    def test_the_validation_finds_no_unexplained_case_the_asa_allows_that_the_switch_denied(self):
        result = translate(keep_open=["Vlan20", "Vlan30"])
        summary = result["validation"]["summary"]
        self.assertGreater(summary["compared"], 0)
        self.assertEqual(summary["unexplained_broader"], 0, result["validation"].get("mismatches"))
        for mismatch in result["validation"].get("mismatches", []):         # what differs is a stateless switch dropping a reply the firewall lets through
            self.assertTrue(mismatch["explained_by_source_return_path"] or mismatch["explained_by_known_broader_rule"], mismatch)


if __name__ == "__main__":
    unittest.main()
