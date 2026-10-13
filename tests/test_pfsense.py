import json
import unittest
from pathlib import Path

from pbridge.adapters import pfsense
from pbridge.evaluate import ALLOW, DENY, Probe, evaluate
from pbridge.model import to_plain

FIX = Path(__file__).parent / "fixtures"


def tcp(src, dst, dport, zone):
    return Probe(src, dst, "tcp", 40000, dport, src_zone=zone)


class PfsenseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = pfsense.parse((FIX / "pfsense_plant.xml").read_text(), "q1")

    def rule(self, tracker):
        return next(r for r in self.p.rules if r.original_id == tracker)

    def test_interfaces_and_vendor(self):
        self.assertEqual(self.p.vendor, "pfsense")
        self.assertEqual(self.p.interfaces["lan"]["nets"], ["10.20.0.0/16"])
        self.assertTrue(self.p.interfaces["wan"]["dynamic"])

    def test_nested_aliases_and_port_aliases(self):
        self.assertEqual(sorted(self.rule("1000001").src.nets), ["10.20.1.15/32", "10.20.1.16/32", "10.20.8.0/24"])
        self.assertEqual(self.rule("1000001").svc.entries[0].dports, [(502, 502), (44818, 44819)])

    def test_floating_quick_rules_come_first(self):
        self.assertEqual(self.p.rules[0].original_id, "1000009")

    def test_first_match_on_ingress_interface(self):
        decision = evaluate(self.p, tcp("10.20.1.15", "10.30.2.40", 502, "lan"))
        self.assertEqual((decision.outcome, decision.original_id), (ALLOW, "1000001"))

    def test_shadowed_rule_never_decides(self):
        decision = evaluate(self.p, tcp("10.20.9.9", "10.30.2.40", 80, "lan"))
        self.assertEqual((decision.outcome, decision.original_id), (DENY, "1000003"))

    def test_default_block_when_nothing_matches(self):
        decision = evaluate(self.p, tcp("10.20.9.9", "10.99.2.40", 22, "opt1"))
        self.assertEqual(decision.outcome, DENY)

    def test_rules_on_another_interface_do_not_apply(self):
        decision = evaluate(self.p, tcp("10.30.2.9", "198.51.100.5", 53, "opt1"))
        self.assertNotEqual(decision.original_id, "1000005")

    def test_hostname_and_url_table_aliases_are_unresolved(self):
        self.assertTrue(self.rule("1000006").dst.unresolved)
        self.assertTrue(self.rule("1000009").src.unresolved)

    def test_stateless_rule_is_flagged(self):
        self.assertTrue(self.rule("1000007").unsupported)

    def test_disabled_rule(self):
        self.assertFalse(self.rule("1000008").enabled)

    def test_port_forward_is_nat_context(self):
        self.assertEqual(self.p.address_context, "post-nat")
        self.assertEqual(self.p.nat_rules[0].translated_dst.nets, ["10.30.5.10/32"])

    def test_secrets_are_not_stored(self):
        dump = json.dumps(to_plain(self.p))
        self.assertNotIn("shouldneverappear", dump)
        self.assertNotIn("abcdeverysecret", dump)

    def test_rejects_wrong_documents(self):
        with self.assertRaises(ValueError):
            pfsense.parse("<other/>", "x")

    def test_opnsense_root_is_recognised(self):
        text = (FIX / "pfsense_plant.xml").read_text().replace("<pfsense>", "<opnsense>").replace("</pfsense>", "</opnsense>")
        policy = pfsense.parse(text, "q2")
        self.assertEqual(policy.vendor, "opnsense")
        self.assertTrue(all(r.extra["quick"] for r in policy.rules))


if __name__ == "__main__":
    unittest.main()
