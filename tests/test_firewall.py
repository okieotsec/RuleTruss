import os
import tempfile
import unittest
from pathlib import Path

from ruletruss import analysis
from ruletruss.adapters import panos
from ruletruss.adapters.registry import parse_config
from ruletruss.capture.flows import analyze_capture
from ruletruss.migrate import firewall as fw
from ruletruss.migrate import validate as val
from ruletruss.model import Subnet
from ruletruss.synthetic import plant_capture

FIX = Path(__file__).parent / "fixtures"
SIMPLE = """interface Gi0/0
 nameif corp
 security-level 90
 ip address 10.10.0.1 255.255.0.0
interface Gi0/1
 nameif ot
 security-level 50
 ip address 10.30.0.1 255.255.0.0
access-list C extended deny tcp host 10.10.1.99 10.30.2.0 255.255.255.0 eq 502
access-list C extended permit tcp 10.10.1.0 255.255.255.0 10.30.2.0 255.255.255.0 eq 502
access-list C extended permit tcp 10.10.1.0 255.255.255.0 host 10.30.2.40 range 44818 44819
access-list C extended permit udp 10.10.1.0 255.255.255.0 host 10.30.2.40 eq 161
access-list C extended permit icmp 10.10.1.0 255.255.255.0 10.30.2.0 255.255.255.0 echo
access-list C extended permit tcp any6 any6 eq 22
access-group C in interface corp
"""
ZONES = {"corp": "corp", "ot": "ot"}
CTX = analysis.build_context(subnets=[Subnet("10.10.0.0/16", "corp", "corp"), Subnet("10.30.0.0/16", "ot", "ot")])


def load(name):
    return (FIX / name).read_text()


def translate(text, target, **kw):
    src = parse_config(text, "src")
    t = fw.translate_policy(src, target, kw.pop("zone_map", ZONES), ctx=CTX, **kw)
    fw.render(t, target)
    return src, t


class OrderAndBlockingTests(unittest.TestCase):
    def test_order_is_preserved_and_deny_stays_before_the_allow(self):
        for target in ("cisco-asa", "cisco-ios", "fortios"):
            with self.subTest(target=target):
                _, t = translate(SIMPLE, target)
                names = [r.source_ids_text for r in t.rules if r.kind == "translated"]
                self.assertEqual(names[:2], ["C:1", "C:2"])
                self.assertEqual(t.rules[0].action, "deny")

    def test_blocked_rules_are_commented_never_widened(self):
        _, t = translate(load("asa_plant.cfg"), "cisco-asa", zone_map={})
        text = t.text
        self.assertIn("! NOT TRANSLATED CORP-IN:3", text)
        self.assertIn("! NOT TRANSLATED CORP-IN:4", text)
        for line in text.splitlines():
            if line.startswith("access-list") and "CORP-IN:3" in line:
                self.fail("a blocked rule produced an ACE")
        blocked = [r for r in t.rules if r.kind == "blocked"]
        self.assertTrue(blocked)
        self.assertTrue(all("NOT TRANSLATED" in r.comment for r in blocked))

    def test_every_blocked_rule_is_reported_with_its_reason(self):
        _, t = translate(load("panos_plant.xml"), "cisco-asa", zone_map={})
        reasons = {e["source_rule"]: e["reason"] for e in t.report if e["status"] == "blocked"}
        self.assertIn("application condition", reasons["eng-to-plc-apps"])
        self.assertIn("not IP addresses", reasons["ot-updates"])
        self.assertIn("negated", reasons["ot-not-plc"])
        self.assertIn("intrazone", reasons["intra-ot-only"])

    def test_negation_is_carried_where_the_destination_can_express_it(self):
        _, t = translate(load("panos_plant.xml"), "fortios", zone_map={})
        blocked = {e["source_rule"] for e in t.report if e["status"] == "blocked"}
        self.assertNotIn("ot-not-plc", blocked)
        self.assertIn("dstaddr-negate enable", t.text)

    def test_blocked_deny_rule_is_called_out_as_broadening(self):
        text = SIMPLE.replace("access-list C extended deny tcp host 10.10.1.99",
                              "access-list C extended deny tcp host 10.10.1.99 time-range NIGHT")
        text = text.replace("10.30.2.0 255.255.255.0 eq 502\naccess-list C extended permit tcp 10.10.1.0 255.255.255.0 10.30.2.0",
                            "10.30.2.0 255.255.255.0 eq 502\naccess-list C extended permit tcp 10.10.1.0 255.255.255.0 10.30.2.0")
        _, t = translate(text, "cisco-ios")
        self.assertEqual(t.summary["blocked_deny_rules"], 1)
        self.assertIn("BROADEN", t.summary["verdict"])

    def test_untrusted_rule_names_cannot_inject_configuration_lines(self):
        xml = load("panos_plant.xml").replace('name="eng-to-plc"', 'name="evil&#10;permit ip any any"')
        src = panos.parse(xml, "x")
        t = fw.translate_policy(src, "cisco-asa", {})
        text = fw.render(t, "cisco-asa")
        self.assertNotIn("\npermit ip any any", text)
        for line in text.splitlines():
            self.assertFalse(line.startswith("permit"), line)

    def test_unmapped_zones_become_visible_placeholders(self):
        _, t = translate(SIMPLE, "cisco-asa", zone_map={})
        self.assertIn("<TARGET-IF:corp>", t.text)
        self.assertEqual(t.placeholders, ["<TARGET-IF:corp>"])
        self.assertIn("placeholders must be replaced", t.summary["verdict"])

    def test_nat_with_a_different_address_context_blocks_the_rule(self):
        _, t = translate(load("fortios_plant.conf"), "cisco-asa", zone_map={})
        reasons = {e["source_rule"]: e["reason"] for e in t.report if e["status"] == "blocked"}
        self.assertIn("NAT", reasons["7"])


class StatefulnessTests(unittest.TestCase):
    def test_stateful_to_stateless_adds_marked_return_rules(self):
        _, t = translate(SIMPLE, "cisco-ios")
        returns = [r for r in t.rules if r.kind == "return-path"]
        self.assertTrue(returns)
        self.assertTrue(all(r.broader and r.src_zone == "ot" for r in returns))
        self.assertIn("permit tcp 10.30.2.0 0.0.0.255 eq 502 10.10.1.0 0.0.0.255 established", t.text)
        self.assertIn("not a stateful check", " ".join(i.message for i in t.issues))
        self.assertIn("ANY datagram from the server port", " ".join(i.message for i in t.issues))
        self.assertGreater(t.summary["rules_known_broader"], 0)

    def test_stateless_to_stateful_drops_reply_only_entries(self):
        _, t = translate(load("ios_ot_switch.cfg"), "cisco-asa", zone_map={})
        reasons = {e["source_rule"]: e["reason"] for e in t.report if e["status"] == "skipped"}
        self.assertIn("reply traffic only", reasons["OT-TO-CTRL:3"])
        self.assertIn("reply traffic only", reasons["FROM-CTRL:2"])

    def test_tcp_return_rule_does_not_permit_a_new_connection_but_udp_one_does(self):
        src, t = translate(SIMPLE, "cisco-ios")
        report = val.validate_preserve(src, t, CTX)
        reverse = [m for m in report["mismatches"] if m["case"].startswith("new connection from the other side")]
        self.assertTrue(reverse, "the unsolicited UDP datagram from the server port should be permitted by the stateless return rule")
        self.assertTrue(all(m["kind"] == "target_broader" and m["explained_by_known_broader_rule"] for m in reverse))
        self.assertTrue(all("udp" in m["connection"] for m in reverse))
        self.assertEqual(report["summary"]["unexplained_broader"], 0)


class RoundTripTests(unittest.TestCase):
    def test_every_destination_matches_the_source_on_sampled_connections(self):
        for target in ("cisco-asa", "cisco-ios", "fortios"):
            with self.subTest(target=target):
                src, t = translate(SIMPLE, target)
                report = val.validate_preserve(src, t, CTX)
                s = report["summary"]
                self.assertGreater(s["same_allow"], 3)
                self.assertGreater(s["same_deny"], 3)
                self.assertEqual(s["unexplained_broader"], 0, report["mismatches"])
                self.assertEqual(s["target_narrower"], 0, report["mismatches"])
                self.assertIn("does not show the two policies are equivalent", " ".join(report["limits"]))

    def test_validation_detects_a_deliberately_broken_translation(self):
        src, t = translate(SIMPLE, "cisco-asa")
        t.rules[0].action = "allow"          # the leading deny becomes an allow
        report = val.validate_preserve(src, t, CTX)
        self.assertGreater(report["summary"]["target_broader"], 0)
        self.assertEqual(report["summary"]["result"], "destination allows connections the source denied")
        self.assertGreater(report["summary"]["unexplained_broader"], 0)

    def test_validation_detects_a_dropped_allow(self):
        src, t = translate(SIMPLE, "fortios")
        t.rules = [r for r in t.rules if r.source_ids_text != "C:2"]
        report = val.validate_preserve(src, t, CTX)
        self.assertGreater(report["summary"]["target_narrower"], 0)

    def test_blocked_rule_effects_are_attributed(self):
        src, t = translate(load("fortios_plant.conf"), "cisco-asa", zone_map={})
        report = val.validate_preserve(src, t)
        self.assertGreaterEqual(report["summary"]["explained_by_blocked_rule"], 1)

    def test_ipv6_and_icmp_survive_the_round_trip(self):
        _, t = translate(SIMPLE, "cisco-asa")
        self.assertIn("any6", t.text)
        self.assertIn("icmp 10.10.1.0 255.255.255.0 10.30.2.0 255.255.255.0 8", t.text)


class NarrowRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.pcap")
            plant_capture().write(path)
            _, cls.flows = analyze_capture(path, "c", "s", "p.pcap")
        cls.ctx = analysis.build_context(subnets=[Subnet("10.20.0.0/16", "eng", "eng"), Subnet("10.30.0.0/16", "ot", "ot"),
                                                  Subnet("10.10.0.0/16", "corp", "corp")])
        cls.comms = analysis.aggregate(cls.flows)

    def build(self, target):
        t = fw.rules_from_observation(self.comms, self.ctx, lambda ip: self.ctx.zone_of(ip),
                                      stateless=not fw.TARGETS[target]["stateful"])
        t.zone_map = {"eng": "eng", "ot": "ot", "corp": "corp"}
        t.target = target
        fw.render(t, target)
        return t

    def test_observed_rules_are_exact_and_marked_observed(self):
        t = self.build("cisco-asa")
        self.assertIn("access-list RT-eng-IN extended permit tcp host 10.20.1.15 host 10.30.2.40 eq 502", t.text)
        self.assertTrue(all(r.kind == "observed" for r in t.rules))
        self.assertIn("not proof of business need", " ".join(i.message for i in t.issues))

    def test_low_confidence_direction_is_held_back(self):
        t = self.build("fortios")
        held = [e for e in t.report if e["status"] == "skipped"]
        self.assertTrue(any("low confidence" in e["reason"] for e in held))
        self.assertNotIn("10.20.1.60", t.text)

    def test_observed_policy_allows_what_was_seen_and_nothing_else(self):
        for target in ("cisco-asa", "fortios", "cisco-ios"):
            with self.subTest(target=target):
                t = self.build(target)
                report = val.validate_observed(t, self.comms, self.ctx)
                s = report["summary"]
                self.assertGreater(s["observed_allowed"], 5)
                self.assertEqual((s["observed_blocked"], s["reverse_allowed"], s["other_port_allowed"]), (0, 0, 0), report["problems"])


if __name__ == "__main__":
    unittest.main()


class SecurityLevelDefaultTests(unittest.TestCase):
    def test_source_default_that_is_not_translated_is_reported_and_attributed(self):
        text = SIMPLE.replace("nameif corp\n security-level 90", "nameif corp\n security-level 50").replace(
            "nameif ot\n security-level 50", "nameif ot\n security-level 90")
        src, t = translate(text, "fortios")
        self.assertIn("default-security-level", {i.code for i in t.issues})
        report = val.validate_preserve(src, t, CTX)
        self.assertGreater(report["summary"]["explained_by_source_default"], 0)


class ReturnPathPlacementTests(unittest.TestCase):
    def test_return_rules_come_before_a_catch_all_deny_in_their_acl(self):
        from ruletruss.samples import SUBNETS
        ctx = analysis.build_context(subnets=[Subnet(**s) for s in SUBNETS])
        config = (Path(__file__).parent.parent / "ruletruss" / "samples" / "demo_asa.cfg").read_text()
        src = parse_config(config.replace(" nat (plc,hist) static 10.30.5.201\n", ""), "demo")      # a static NAT would (rightly) block the rules
        t = fw.translate_policy(src, "cisco-ios", {z["zone"]: z["zone"] for z in SUBNETS}, ctx=ctx)
        text = fw.render(t, "cisco-ios", identity=True)
        hist = text.split("ip access-list extended RT-hist-IN")[1].split("ip access-list extended")[0]
        lines = [x.strip() for x in hist.splitlines() if x.strip() and not x.strip().startswith(("remark", "!"))]
        first_deny = next(i for i, x in enumerate(lines) if x.startswith("deny"))
        returns = [i for i, x in enumerate(lines) if "eq 4840" in x or "eq 123" in x]
        self.assertTrue(returns)
        self.assertTrue(all(i < first_deny for i in returns), lines)
        report = val.validate_preserve(src, t, ctx)
        self.assertEqual(report["summary"]["target_narrower"], 0, report["mismatches"])


class SeparateAclsOnOneInterfaceTests(unittest.TestCase):
    def test_an_ipv6_deny_all_does_not_cut_the_ipv4_acl_short_in_the_destination(self):
        text = ("ip access-list extended V4\n permit tcp any any eq 80\n permit tcp any any eq 22\n deny ip any any\n"
                "ipv6 access-list V6\n deny ipv6 any any\n"
                "interface Vlan1\n ip address 10.0.0.1 255.255.255.0\n ip access-group V4 in\n ipv6 traffic-filter V6 in\n")
        src = parse_config(text, "ios")
        t = fw.translate_policy(src, "cisco-asa", {"Vlan1": "inside"})
        fw.render(t, "cisco-asa")
        lines = [line for line in t.text.splitlines() if line.startswith("access-list") and " extended " in line]
        self.assertEqual([line.split(" extended ")[1] for line in lines],
                         ["permit tcp any any eq 80", "permit tcp any any eq 22", "deny ip any any", "deny ip any6 any6"])
