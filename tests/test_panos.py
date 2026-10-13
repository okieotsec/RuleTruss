import json
import unittest
from pathlib import Path

from pbridge import limits
from pbridge.adapters import panos
from pbridge.adapters.xmlsafe import parse_xml
from pbridge.evaluate import ALLOW, DENY, INDETERMINATE, Probe, evaluate, evaluate_connection
from pbridge.model import to_plain

FIX = Path(__file__).parent / "fixtures"


def tcp(src, dst, dport, src_zone, dst_zone):
    return Probe(src, dst, "tcp", 40000, dport, src_zone=src_zone, dst_zone=dst_zone)


class PanosTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = panos.parse((FIX / "panos_plant.xml").read_text(), "p1")

    def rule(self, name):
        return next(r for r in self.p.rules if r.original_id == name)

    def test_metadata_zones_and_interface_networks(self):
        self.assertEqual((self.p.hostname, self.p.version), ("plant-pa-1", "10.2.0"))
        self.assertEqual(self.p.interfaces["ot"]["nets"], ["10.30.0.0/16"])
        self.assertTrue(self.p.stateful)

    def test_nested_address_groups_and_service_groups(self):
        self.assertEqual(sorted(self.rule("eng-to-plc").src.nets), ["10.20.1.15/32", "10.20.1.16/32"])
        text = self.rule("eng-to-plc").svc.text()
        self.assertIn("tcp dport 502", text)
        self.assertIn("2222,44818", text)

    def test_ordered_first_match(self):
        decision = evaluate(self.p, tcp("10.20.1.15", "10.30.2.40", 502, "eng", "ot"))
        self.assertEqual((decision.outcome, decision.original_id), (ALLOW, "eng-to-plc"))
        self.assertTrue(decision.evidence[0].text)

    def test_application_default_and_application_conditions_are_undecidable(self):
        decision = evaluate(self.p, tcp("10.20.9.9", "10.30.2.40", 22, "eng", "ot"))
        self.assertEqual(decision.outcome, INDETERMINATE)
        self.assertTrue(any("application" in u for u in decision.uncertain))

    def test_cleanup_deny_applies_when_nothing_earlier_could_match(self):
        decision = evaluate(self.p, tcp("10.20.1.15", "10.99.0.1", 502, "eng", "ot"))
        self.assertEqual((decision.outcome, decision.original_id), (DENY, "cleanup-deny"))

    def test_disabled_rule_is_ignored(self):
        self.assertFalse(self.rule("disabled-rdp").enabled)

    def test_fqdn_and_dynamic_groups_are_unresolved(self):
        self.assertTrue(self.rule("ot-updates").dst.unresolved)
        self.assertTrue(self.rule("tagged-in").src.unresolved)

    def test_negated_destination(self):
        rule = self.rule("ot-not-plc")
        self.assertTrue(rule.dst.negate)
        self.assertFalse(rule.dst.contains("10.20.1.15"))
        self.assertTrue(rule.dst.contains("10.20.7.7"))

    def test_intrazone_rule_type_needs_known_zones(self):
        same = Probe("10.30.9.1", "10.30.9.2", "tcp", 1, 80, src_zone="ot", dst_zone="ot")
        self.assertEqual(evaluate(self.p, same).original_id, "cleanup-deny")   # cleanup-deny is earlier and matches everything

    def test_default_rules_when_no_rule_matches(self):
        text = (FIX / "panos_plant.xml").read_text()
        start, end = text.index("<rules>"), text.index("</rules>") + len("</rules>")
        empty = panos.parse(text[:start] + "<rules/>" + text[end:], "p2")
        self.assertEqual(evaluate(empty, tcp("10.30.1.1", "10.30.1.2", 80, "ot", "ot")).outcome, ALLOW)
        self.assertEqual(evaluate(empty, tcp("10.30.1.1", "10.20.1.2", 80, "ot", "eng")).outcome, DENY)
        self.assertEqual(evaluate(empty, tcp("10.30.1.1", "10.20.1.2", 80, None, None)).outcome, INDETERMINATE)

    def test_stateful_replies_are_not_separately_evaluated(self):
        forward, reply = evaluate_connection(self.p, tcp("10.20.1.15", "10.30.2.40", 502, "eng", "ot"))
        self.assertEqual(forward.outcome, ALLOW)
        self.assertIsNone(reply)

    def test_nat_rules_are_recorded_with_pre_nat_context(self):
        self.assertEqual(self.p.address_context, "pre-nat")
        kinds = {n.kind for n in self.p.nat_rules}
        self.assertEqual(kinds, {"destination", "source"})
        dnat = next(n for n in self.p.nat_rules if n.kind == "destination")
        self.assertIn("10.30.5.12/32", dnat.translated_dst.nets)

    def test_secrets_are_not_in_the_model(self):
        self.assertNotIn("should-never-appear", json.dumps(to_plain(self.p)))


class XmlSafetyTests(unittest.TestCase):
    def test_doctype_and_entities_are_refused(self):
        for payload in ('<!DOCTYPE x [<!ENTITY a "aaaa">]><config>&a;</config>',
                        '<?xml version="1.0"?><!DOCTYPE config SYSTEM "file:///etc/passwd"><config/>'):
            with self.assertRaises(ValueError):
                parse_xml(payload)

    def test_deep_nesting_is_refused(self):
        with self.assertRaises(limits.LimitExceeded):
            parse_xml("<a>" * 200 + "</a>" * 200)

    def test_malformed_xml_gives_a_readable_error(self):
        with self.assertRaises(ValueError):
            parse_xml("<config><devices></config>")

    def test_wrong_document_is_rejected(self):
        with self.assertRaises(ValueError):
            panos.parse("<html/>", "x")
        with self.assertRaises(ValueError):
            panos.parse("<config/>", "x")


if __name__ == "__main__":
    unittest.main()
