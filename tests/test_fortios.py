import json
import unittest
from pathlib import Path

from pbridge.adapters import fortios
from pbridge.evaluate import ALLOW, DENY, INDETERMINATE, Probe, evaluate, evaluate_connection
from pbridge.model import to_plain

FIX = Path(__file__).parent / "fixtures"


def tcp(src, dst, dport, src_zone, dst_zone):
    return Probe(src, dst, "tcp", 40000, dport, src_zone=src_zone, dst_zone=dst_zone)


class FortiosTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = fortios.parse((FIX / "fortios_plant.conf").read_text(), "f1")

    def rule(self, original_id):
        return next(r for r in self.p.rules if r.original_id == original_id)

    def test_metadata(self):
        self.assertEqual(self.p.hostname, "plant-fgt-1")
        self.assertIn("7.2.5", self.p.version)
        self.assertEqual(self.p.interfaces["port3"]["nets"], ["10.30.0.0/16"])

    def test_nested_groups_services_and_ranges(self):
        self.assertEqual(sorted(self.rule("1").src.nets), ["10.20.1.15/32", "10.20.1.16/32"])
        self.assertIn("tcp dport 502", self.rule("1").svc.text())
        self.assertIn("udp dport 2222", self.rule("1").svc.text())
        self.assertEqual(self.rule("3").dst.nets, ["10.30.5.10/31", "10.30.5.12/32"])

    def test_first_match_and_evidence(self):
        decision = evaluate(self.p, tcp("10.20.1.15", "10.30.2.40", 502, "port2", "port3"))
        self.assertEqual((decision.outcome, decision.original_id), (ALLOW, "1"))
        self.assertIn("edit 1", decision.evidence[0].text)

    def test_implicit_deny(self):
        decision = evaluate(self.p, tcp("10.20.1.15", "10.30.2.40", 9999, "port2", "port3"))
        self.assertEqual((decision.outcome, decision.original_id), (DENY, "9"))     # policy 9 has no action: deny
        decision = evaluate(self.p, tcp("10.20.1.15", "10.20.2.40", 80, "port2", "port2"))
        self.assertEqual(decision.outcome, DENY)
        self.assertIn("implicit", decision.basis)

    def test_policy_without_action_is_deny(self):
        self.assertEqual(self.rule("9").action, "deny")
        self.assertTrue(self.rule("9").notes)

    def test_disabled_policy_is_ignored(self):
        self.assertFalse(self.rule("3").enabled)

    def test_zone_expansion_and_identity_condition(self):
        self.assertIn("port2", self.rule("5").src_zones)
        self.assertEqual(self.rule("5").users, ["Engineers"])
        decision = evaluate(self.p, tcp("10.20.9.9", "10.30.5.11", 22, "port2", "port3"))
        self.assertEqual(decision.outcome, INDETERMINATE)

    def test_schedule_makes_a_match_undecidable(self):
        decision = evaluate(self.p, tcp("10.20.9.9", "10.30.99.9", 80, "port2", "port3"))
        self.assertEqual(decision.outcome, INDETERMINATE)
        self.assertTrue(any("business-hours" in u for u in decision.uncertain))

    def test_fqdn_and_geography_objects_are_unresolved(self):
        self.assertTrue(self.rule("4").dst.unresolved)
        self.assertTrue(self.rule("8").src.unresolved)

    def test_vip_matches_the_external_address_and_records_nat(self):
        self.assertEqual(self.rule("7").dst.nets, ["203.0.113.50/32"])
        dnat = next(n for n in self.p.nat_rules if n.kind == "destination")
        self.assertEqual(dnat.translated_dst.nets, ["10.30.5.10/32"])
        self.assertEqual(self.p.address_context, "original-packet")

    def test_policy_nat_is_recorded(self):
        self.assertTrue(any(n.kind == "source" and "policy 4" in " ".join(n.notes) for n in self.p.nat_rules))

    def test_ipv6_policy(self):
        decision = evaluate(self.p, Probe("2001:db8:20::1", "2001:db8:30::5", "tcp", 1, 502, src_zone="port2", dst_zone="port3"))
        self.assertEqual((decision.outcome, decision.original_id), (ALLOW, "20"))

    def test_stateful(self):
        _, reply = evaluate_connection(self.p, tcp("10.20.1.15", "10.30.2.40", 502, "port2", "port3"))
        self.assertIsNone(reply)

    def test_secrets_are_not_stored(self):
        dump = json.dumps(to_plain(self.p))
        self.assertNotIn("thisshouldnotappear", dump)

    def test_rejects_other_formats(self):
        with self.assertRaises(ValueError):
            fortios.parse("hello", "x")

    def test_unbalanced_and_hostile_input_does_not_crash(self):
        fortios.parse("config firewall policy\n edit 1\n set name 'unterminated\n", "x")
        fortios.parse("config firewall policy\n" + " edit 1\n set srcintf a\n next\n" * 2000 + "end\n", "x")
        fortios.parse("end\nend\nnext\nconfig firewall policy\n", "x")


if __name__ == "__main__":
    unittest.main()
