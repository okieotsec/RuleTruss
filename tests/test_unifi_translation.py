"""UniFi (zone-pair) to Cisco ASA: policy meaning is preserved, nothing is silently widened, and every source policy is accounted for.

The fixture (tests/unifi_zones.py) is invented but shaped like a gateway with one zone per VLAN. Decisions of the SOURCE policy are tested
separately from the generated ACLs: a policy decision is not end-to-end reachability (NAT, routing, VPN and local services need more
context than an export carries).
"""
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import unifi_zones

from ruletruss.adapters import registry
from ruletruss.evaluate import ALLOW, DENY, INDETERMINATE, Probe, evaluate, evaluate_connection
from ruletruss.service import ApiError, Service
from ruletruss.store import Store

MAP = {"Default": "Gi0/0", "IP_CAMERAS": "Gi0/1", "WIRELESS_DEVICES": "Gi0/2", "SOC_SERVICES": "Gi0/3", "OT_LAB_DEVICES": "Gi0/4",
       "ISOLATION": "Gi0/5", "SANDBOX": "Gi0/6", "zone-External": "Gi0/7"}


def project(text):
    service = Service(Store(tempfile.mkdtemp()))
    pid = service.store.create_project("zones")["id"]
    upload = service.store.new_upload_path(pid)
    Path(upload).write_text(text, encoding="utf-8")
    entry = service.import_upload(pid, upload, "unifi-export.json")
    return service, pid, entry["id"]


def translate(service, pid, sid, target="cisco-asa", **body):
    return service.translation_json(pid, {"workflow": "preserve", "policy": sid, "target": target, "zone_map": body.pop("zone_map", {}), **body})


class SourceDecisionTests(unittest.TestCase):
    """The review's regression table: what the SOURCE policy decides."""

    @classmethod
    def setUpClass(cls):
        cls.policy = registry.parse_config(unifi_zones.text(), "s1")

    def probe(self, src, dst, src_zone, dst_zone, **kw):
        return Probe(src, dst, "tcp", 40000, 443, src_zone=src_zone, dst_zone=dst_zone, **kw)

    def test_ot_lab_to_soc_services_is_allowed(self):
        self.assertEqual(evaluate(self.policy, self.probe("10.0.101.5", "10.0.100.5", "OT Lab", "SOC Services")).outcome, ALLOW)

    def test_soc_services_to_ot_lab_new_connection_is_denied(self):
        decision = evaluate(self.policy, self.probe("10.0.100.5", "10.0.101.5", "SOC Services", "OT Lab"))
        self.assertEqual((decision.outcome, decision.original_id), (DENY, "Block All Traffic"))

    def test_the_reply_to_an_allowed_session_is_allowed(self):
        forward, reply = evaluate_connection(self.policy, self.probe("10.0.101.5", "10.0.100.5", "OT Lab", "SOC Services"))
        self.assertEqual((forward.outcome, reply.outcome), (ALLOW, ALLOW))

    def test_a_wireless_device_outside_the_two_mac_allowlist_is_denied_and_an_unknown_one_is_undecidable(self):
        outside = self.probe("10.0.20.50", "10.0.100.5", "Wireless Devices", "SOC Services", src_mac="aa:aa:aa:aa:aa:aa")
        self.assertEqual(evaluate(self.policy, outside).outcome, DENY)
        listed = self.probe("10.0.20.51", "10.0.100.5", "Wireless Devices", "SOC Services", src_mac="60:45:2E:77:05:2E")
        self.assertEqual(evaluate(self.policy, listed).outcome, ALLOW)
        self.assertEqual(evaluate(self.policy, self.probe("10.0.20.52", "10.0.100.5", "Wireless Devices", "SOC Services")).outcome, INDETERMINATE)

    def test_isolation_to_external_new_connection_is_allowed(self):
        self.assertEqual(evaluate(self.policy, self.probe("10.0.250.5", "198.51.100.7", "Isolation", "External")).outcome, ALLOW)


class TranslationCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.service, cls.pid, cls.sid = project(unifi_zones.text())
        cls.result = translate(cls.service, cls.pid, cls.sid)
        cls.lines = cls.result["text"].splitlines()
        cls.aces = [ln for ln in cls.lines if ln.startswith("access-list") and " extended " in ln]

    def acl(self, name):
        return [ln.split(" extended ", 1)[1] for ln in self.aces if ln.split()[1] == name]


class ZoneScopeTests(TranslationCase):
    def test_no_entry_is_a_universal_permit_or_deny(self):
        for ace in self.aces:
            self.assertNotRegex(ace, r"extended (permit|deny) ip any any$", ace)
            self.assertNotRegex(ace, r"extended (permit|deny) ip any4 any4$", ace)

    def test_a_zone_to_zone_policy_keeps_both_ends(self):
        self.assertIn("permit ip 10.0.100.0 255.255.255.0 10.0.0.0 255.255.255.0", self.acl("RT-SOC_SERVICES-IN"))       # SOC -> Default LAN
        self.assertIn("permit ip 10.0.101.0 255.255.255.0 10.0.100.0 255.255.255.0", self.acl("RT-OT_LAB_DEVICES-IN"))   # OT Lab -> SOC

    def test_every_pair_default_is_scoped_to_its_own_destination(self):
        for name in ("RT-SOC_SERVICES-IN", "RT-OT_LAB_DEVICES-IN", "RT-WIRELESS_DEVICES-IN", "RT-Default-IN"):
            for ace in self.acl(name):
                self.assertRegex(ace, r"^(permit|deny) ip 10\.0\.\d+\.0 255\.255\.255\.0 (10\.0\.\d+\.0 255\.255\.255\.0|any)$", ace)

    def test_nothing_is_written_for_traffic_inside_one_network(self):
        for name in ("RT-SOC_SERVICES-IN",):
            self.assertNotIn("deny ip 10.0.100.0 255.255.255.0 10.0.100.0 255.255.255.0", self.acl(name))

    def test_unknown_scope_is_never_widened(self):
        for e in self.result["report"]:
            if e["disposition"] in ("unsupported", "unresolved"):
                self.assertFalse(e["interfaces"], e["source_rule"])        # nothing was written for it


class OrderingTests(TranslationCase):
    def test_a_pair_default_never_sits_above_another_pairs_permits(self):
        """Permits for destination B must not be shadowed by the default of pair A: each default names only its own destination."""
        acl = self.acl("RT-SOC_SERVICES-IN")
        first_deny = next(i for i, ace in enumerate(acl) if ace.startswith("deny"))
        permit_default_lan = acl.index("permit ip 10.0.100.0 255.255.255.0 10.0.0.0 255.255.255.0")
        self.assertLess(permit_default_lan, acl.index("deny ip 10.0.100.0 255.255.255.0 10.0.0.0 255.255.255.0"))
        self.assertTrue(first_deny >= 0)

    def test_external_is_last_in_every_acl(self):
        for name in {ace.split()[1] for ace in self.aces}:
            entries = self.acl(name)
            anys = [i for i, e in enumerate(entries) if e.endswith(" any")]
            if anys:
                self.assertEqual(anys, list(range(len(entries) - len(anys), len(entries))), name)

    def test_the_generated_acls_decide_the_review_cases_like_the_source(self):
        text = self.service.translation(self.pid, {"workflow": "preserve", "policy": self.sid, "target": "cisco-asa",
                                                   "zone_map": MAP})[0].text
        target = registry.parse_config(text, "t", "cisco-asa")

        def decide(src, dst, iface):
            return evaluate(target, Probe(src, dst, "tcp", 40000, 443, src_zone=iface)).outcome
        self.assertEqual(decide("10.0.101.5", "10.0.100.5", "Gi0/4"), ALLOW)      # OT Lab -> SOC Services
        self.assertEqual(decide("10.0.100.5", "10.0.101.5", "Gi0/3"), DENY)       # SOC Services -> OT Lab, new
        self.assertEqual(decide("10.0.250.5", "198.51.100.7", "Gi0/5"), ALLOW)    # Isolation -> External
        self.assertEqual(decide("10.0.100.5", "10.0.0.5", "Gi0/3"), ALLOW)        # SOC Services -> Default LAN
        self.assertEqual(decide("10.0.0.5", "10.0.100.5", "Gi0/0"), DENY)         # nothing allows Default LAN -> SOC Services


class MappingTests(TranslationCase):
    def test_every_network_is_its_own_interface_placeholder_and_external_is_the_wan_side(self):
        self.assertEqual(set(self.result["placeholders"]), {f"<TARGET-IF:{k}>" for k in MAP})
        self.assertFalse(any("Default_LAN" in p for p in self.result["placeholders"]))      # a zone is not an interface

    def test_gateway_and_vpn_stay_unresolved_until_you_say_you_handle_them(self):
        by = {}
        for e in self.result["report"]:
            by.setdefault(e["disposition"], []).append(e)
        reasons = " | ".join(e["reason"] for e in by["unresolved"])
        self.assertIn("firewall itself", reasons)
        self.assertIn("VPN", reasons)
        handled = translate(self.service, self.pid, self.sid, confirm=["gateway", "vpn"])
        self.assertLess(handled["dispositions"].get("unresolved", 0), self.result["dispositions"]["unresolved"])
        self.assertFalse(any("firewall itself" in e["reason"] and e["disposition"] == "unresolved" for e in handled["report"]))

    def test_the_external_zone_with_missing_networks_is_reported_not_guessed(self):
        view = self.service.policy_view(self.pid, self.sid)
        codes = {i["code"] for i in view["issues"]}
        self.assertTrue({"zone-network-missing", "zone-address-mismatch", "zone-has-no-networks"} <= codes)

    def test_two_networks_cannot_share_one_target_interface_and_stray_entries_are_reported(self):
        shared = translate(self.service, self.pid, self.sid, zone_map={"SOC_SERVICES": "Gi0/9", "OT_LAB_DEVICES": "Gi0/9", "NoSuchNetwork": "Gi0/1"})
        codes = {i["code"] for i in shared["issues"]}
        self.assertTrue({"interface-mapping-duplicate", "interface-mapping-unused"} <= codes)
        self.assertFalse(shared["deployable"])

    def test_preview_until_everything_is_mapped_and_resolved(self):
        self.assertFalse(self.result["deployable"])
        self.assertIn("DIAGNOSTIC PREVIEW - NOT DEPLOYABLE", self.result["text"])
        self.assertTrue(self.result["blockers"])


class DispositionTests(TranslationCase):
    def test_every_source_policy_has_exactly_one_disposition_and_an_id(self):
        policies = self.service.policy(self.service.project(self.pid), self.sid)[1].rules
        self.assertEqual(len(self.result["report"]), len(policies))
        self.assertEqual(sum(self.result["dispositions"].values()), len(policies))
        self.assertTrue(all(e["disposition"] in ("translated", "implemented", "unsupported", "unresolved", "not-applicable") for e in self.result["report"]))
        self.assertEqual(len({e["policy_id"] for e in self.result["report"]}), len(policies))

    def test_the_text_lists_every_policy_so_nothing_is_silent(self):
        appendix = [ln for ln in self.lines if re.match(r"^! (translated|implemented|unsupported|unresolved|not-applicable)\s", ln)]
        self.assertEqual(len(appendix), len(self.result["report"]))
        for e in self.result["report"][:5]:
            self.assertTrue(any(e["policy_id"][:8] in ln for ln in appendix))

    def test_state_policies_are_implemented_by_the_target_and_say_how(self):
        state_only = [e for e in self.result["report"] if e["source_rule"] in ("Allow Return Traffic", "Block Invalid Traffic")]
        self.assertTrue(state_only)
        for e in state_only:
            self.assertEqual(e["disposition"], "implemented")
            self.assertIn("ASA", e["reason"])
        self.assertTrue(any(i["code"] == "states-by-target" for i in self.result["issues"]))

    def test_the_unsupported_ones_say_what_happens_to_their_traffic(self):
        mac_allow = next(e for e in self.result["report"] if "two devices" in e["source_rule"])
        self.assertEqual(mac_allow["disposition"], "unsupported")
        self.assertIn("MAC address filter", mac_allow["reason"])
        self.assertIn("falls through", mac_allow["reason"])
        icmp = next(e for e in self.result["report"] if e["source_rule"] == "Allow Neighbor Solicitations")
        self.assertEqual(icmp["disposition"], "unsupported")
        self.assertTrue(any(i["code"] == "predefined-not-translated" for i in self.result["issues"]))

    def test_an_untranslated_block_is_reported_as_broadening(self):
        blocked = [e for e in self.result["report"] if e["disposition"] in ("unsupported", "unresolved") and e["source_rule"].startswith("BLOCK tablet")]
        self.assertTrue(blocked)
        self.assertIn("BROADENS", blocked[0]["reason"])
        self.assertGreaterEqual(self.result["summary"]["blocked_deny_rules"], 1)

    def test_stale_assignments_are_unresolved_and_not_moved(self):
        stale = next(e for e in self.result["report"] if e["source_rule"].startswith("Block Traffic from 10.0.20.197"))
        self.assertEqual(stale["disposition"], "unresolved")
        self.assertIn("no networks", stale["reason"])
        self.assertFalse(any("10.0.20.197" in ace for ace in self.aces))

    def test_the_validation_calls_the_untranslated_block_the_cause_of_the_difference(self):
        summary = self.result["validation"]["summary"]
        self.assertEqual(summary["unexplained_broader"], 0)
        self.assertGreaterEqual(summary["explained_by_blocked_rule"], 1)
        self.assertEqual(summary["target_narrower"], 0)
        self.assertTrue(any("not proof" in x.lower() or "does not show" in x for x in self.result["validation"]["limits"]))


class CleanGatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.service, cls.pid, cls.sid = project(unifi_zones.text(with_problems=False))

    def test_a_fully_mapped_clean_gateway_is_deployable_and_agrees_on_the_sampled_connections(self):
        result = translate(self.service, self.pid, self.sid, zone_map=MAP, confirm=["gateway", "vpn"])
        self.assertTrue(result["deployable"], result["blockers"])
        self.assertNotIn("DIAGNOSTIC PREVIEW", result["text"])
        self.assertEqual(result["validation"]["summary"]["result"], "no difference found on the sampled connections")
        self.assertEqual(result["validation"]["summary"]["target_broader"], 0)
        self.assertEqual(result["validation"]["summary"]["target_narrower"], 0)

    def test_without_the_mapping_the_same_gateway_is_still_a_preview(self):
        result = translate(self.service, self.pid, self.sid, confirm=["gateway", "vpn"])
        self.assertFalse(result["deployable"])
        self.assertTrue(any("placeholder" in b for b in result["blockers"]))


class ExportGateTests(TranslationCase):
    def test_a_preview_is_not_exported_without_acknowledgement_and_is_labelled(self):
        body = {"kind": "firewall-text", "workflow": "preserve", "policy": self.sid, "target": "cisco-asa", "zone_map": {}}
        with self.assertRaises(ApiError) as raised:
            self.service.export(self.pid, body)
        self.assertEqual(raised.exception.status, 409)
        _, name, data = self.service.export(self.pid, {**body, "acknowledge_preview": True})
        self.assertIn("PREVIEW-NOT-DEPLOYABLE", name)
        self.assertIn(b"DIAGNOSTIC PREVIEW", data)
        _, report_name, report = self.service.export(self.pid, {**body, "kind": "firewall-markdown", "acknowledge_preview": True})
        self.assertIn("DIAGNOSTIC PREVIEW", report.decode())
        self.assertIn("Per-policy disposition", report.decode())


class OtherTargetsTests(TranslationCase):
    def test_ios_says_plainly_that_return_paths_are_not_generated_for_zone_pairs(self):
        ios = translate(self.service, self.pid, self.sid, target="cisco-ios")
        self.assertFalse(ios["deployable"])
        self.assertTrue(any(i["code"] == "stateless-returns" for i in ios["issues"]))
        self.assertEqual(sum(ios["dispositions"].values()), len(ios["report"]))

    def test_fortios_still_accounts_for_every_policy(self):
        forti = translate(self.service, self.pid, self.sid, target="fortios")
        self.assertEqual(sum(forti["dispositions"].values()), len(forti["report"]))
        self.assertTrue(all(e["disposition"] for e in forti["report"]))


class HostileNameTests(unittest.TestCase):
    def test_line_breaks_in_zone_and_policy_names_cannot_add_lines_to_the_generated_configuration(self):
        evil = "SOC Services\npermit ip any any\r\n! injected"
        data = json.loads(unifi_zones.text())

        def rename(node):
            for key, value in (node.items() if isinstance(node, dict) else enumerate(node) if isinstance(node, list) else ()):
                if isinstance(value, str) and value in ("SOC Services", "OT Lab", "Block All Traffic"):
                    node[key] = evil
                else:
                    rename(value)

        rename(data)
        service, pid, sid = project(json.dumps(data))
        for target in ("cisco-asa", "cisco-ios", "fortios"):
            text = translate(service, pid, sid, target=target)["text"]
            for line in text.splitlines():
                self.assertNotEqual(line.strip(), "! injected", target)
                self.assertFalse(line.startswith("permit ip any any"), target)


if __name__ == "__main__":
    unittest.main()
