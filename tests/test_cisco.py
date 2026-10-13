import json
import unittest
from pathlib import Path

from ruletruss.adapters import cisco
from ruletruss.evaluate import ALLOW, DENY, INDETERMINATE, Probe, evaluate, evaluate_connection
from ruletruss.model import to_plain

FIX = Path(__file__).parent / "fixtures"


def load(name, source="s1"):
    return cisco.parse((FIX / name).read_text(), source)


def tcp(src, dst, dport, src_zone=None, dst_zone=None, sport=40000):
    return Probe(src, dst, "tcp", sport, dport, src_zone=src_zone, dst_zone=dst_zone)


class AsaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = load("asa_plant.cfg")

    def rule(self, original_id):
        return next(r for r in self.p.rules if r.original_id == original_id)

    def test_metadata_and_detection(self):
        self.assertEqual(self.p.hostname, "plant-fw-1")
        self.assertEqual(self.p.version, "9.16(4)")
        self.assertEqual(cisco.detect((FIX / "asa_plant.cfg").read_text()), "asa")
        self.assertEqual(cisco.detect((FIX / "ios_ot_switch.cfg").read_text()), "ios")
        self.assertTrue(self.p.stateful)

    def test_nested_groups_and_objects_resolve(self):
        self.assertEqual(sorted(self.rule("OT-IN:1").src.nets), ["10.20.1.15/32", "10.20.1.16/32"])
        self.assertEqual(self.rule("OT-IN:1").svc.entries[0].dports, [(502, 502), (44818, 44819)])
        self.assertIn("10.30.2.0/24", self.rule("CORP-IN:5").src.nets)      # OT-ALL contains ENGINEERING and PLC-NET
        self.assertIn("10.20.1.15/32", self.rule("CORP-IN:5").src.nets)

    def test_mixed_service_group(self):
        text = self.rule("CORP-IN:5").svc.text()
        self.assertIn("tcp dport 102", text)
        self.assertIn("udp dport 161", text)
        self.assertIn("icmp type 8", text)

    def test_group_cycle_is_reported_not_followed(self):
        text = ("object-group network A\n group-object B\nobject-group network B\n group-object A\n"
                "access-list X extended permit ip object-group A any\naccess-group X in interface inside\n"
                "interface Gi0/0\n nameif inside\n security-level 100\n")
        policy = cisco.parse(text, "s2", "asa")
        self.assertIn("group-cycle", [i.code for i in policy.issues])

    def test_fqdn_object_is_unresolved_and_makes_rule_undecidable(self):
        self.assertTrue(self.rule("CORP-IN:3").dst.unresolved)
        decision = evaluate(self.p, tcp("10.10.4.4", "198.51.100.9", 443, "corp", "outside"))
        self.assertEqual(decision.outcome, INDETERMINATE)

    def test_engineering_workstation_permitted_to_controllers(self):
        decision = evaluate(self.p, tcp("10.20.1.15", "10.30.2.40", 502, "ot", "ot"))
        self.assertEqual((decision.outcome, decision.original_id), (ALLOW, "OT-IN:1"))
        self.assertTrue(decision.evidence)

    def test_later_rule_after_deny_any_is_shadowed(self):
        # OT-IN:4 permits tcp/80 but sits after "deny ip any any".
        decision = evaluate(self.p, tcp("10.20.9.9", "10.30.2.40", 80, "ot", "ot"))
        self.assertEqual((decision.outcome, decision.original_id), (DENY, "OT-IN:3"))

    def test_implicit_deny_at_end_of_acl_and_global_acl_fallthrough(self):
        decision = evaluate(self.p, tcp("10.10.4.4", "10.30.5.10", 25, "corp", "ot"))
        self.assertEqual(decision.outcome, DENY)
        self.assertIn("implicit deny", decision.basis)
        global_hit = evaluate(self.p, Probe("10.10.4.4", "10.30.5.10", "udp", 5000, 123, src_zone="corp", dst_zone="ot"))
        self.assertEqual((global_hit.outcome, global_hit.original_id), (ALLOW, "GLOBAL-ACL:1"))

    def test_inactive_rule_is_ignored(self):
        self.assertFalse(self.rule("CORP-IN:6").enabled)
        decision = evaluate(self.p, tcp("10.10.4.4", "10.30.5.10", 3389, "corp", "ot"))
        self.assertEqual(decision.outcome, DENY)

    def test_time_range_makes_a_match_undecidable(self):
        decision = evaluate(self.p, tcp("10.10.4.4", "10.30.8.8", 8080, "corp", "ot"))
        self.assertEqual(decision.outcome, INDETERMINATE)
        self.assertTrue(any("BUSINESS-HOURS" in u for u in decision.uncertain))

    def test_identity_condition_is_kept_not_dropped(self):
        rule = self.rule("GLOBAL-ACL:2")
        self.assertTrue(rule.unsupported)
        decision = evaluate(self.p, tcp("10.50.0.77", "10.30.9.9", 22, "dmz", "ot"))
        self.assertEqual(decision.outcome, INDETERMINATE)

    def test_unbound_acl_is_not_evaluated(self):
        self.assertEqual(self.rule("UNUSED:1").extra["stage"], "unbound")
        decision = evaluate(self.p, tcp("10.50.0.77", "10.30.9.9", 9999, "dmz", "ot"))
        self.assertNotEqual(decision.original_id, "UNUSED:1")

    def test_unknown_ingress_interface_is_indeterminate(self):
        decision = evaluate(self.p, tcp("10.20.1.15", "10.30.2.40", 502))
        self.assertEqual(decision.outcome, INDETERMINATE)

    def test_asa_is_stateful_so_replies_are_not_separately_evaluated(self):
        forward, reply = evaluate_connection(self.p, tcp("10.20.1.15", "10.30.2.40", 502, "ot", "ot"))
        self.assertEqual(forward.outcome, ALLOW)
        self.assertIsNone(reply)

    def test_security_levels_decide_when_no_acl_is_applied(self):
        text = ("interface Gi0/0\n nameif inside\n security-level 100\ninterface Gi0/1\n nameif dmz\n security-level 50\n"
                "interface Gi0/2\n nameif outside\n security-level 0\n")
        policy = cisco.parse(text + "access-list X extended permit ip any any\n", "s3", "asa")
        self.assertEqual(evaluate(policy, tcp("10.0.0.1", "8.8.8.8", 80, "inside", "outside")).outcome, ALLOW)
        self.assertEqual(evaluate(policy, tcp("8.8.8.8", "10.0.0.1", 80, "outside", "inside")).outcome, DENY)
        self.assertEqual(evaluate(policy, tcp("10.1.1.1", "10.2.2.2", 80, "dmz", "outside")).outcome, ALLOW)
        self.assertEqual(evaluate(policy, tcp("10.1.1.1", "10.2.2.2", 80, "dmz", "inside")).outcome, DENY)
        self.assertEqual(evaluate(policy, tcp("10.1.1.1", "10.2.2.2", 80)).outcome, INDETERMINATE)

    def test_nat_is_recorded_not_applied(self):
        kinds = [n.kind for n in self.p.nat_rules]
        self.assertIn("static", kinds)
        self.assertEqual(self.p.address_context, "internal-real")
        self.assertTrue(all(n.evidence for n in self.p.nat_rules))

    def test_ipv6_any6(self):
        decision = evaluate(self.p, Probe("2001:db8::1", "2001:db8::2", "tcp", 1, 22, src_zone="outside", dst_zone="ot"))
        self.assertEqual(decision.outcome, ALLOW)


class IosTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = load("ios_ot_switch.cfg", "s9")

    def test_acls_are_stateless_and_bound_per_interface(self):
        self.assertFalse(self.p.stateful)
        self.assertEqual(self.p.interfaces["Vlan20"]["acl_in"], "OT-TO-CTRL")
        self.assertEqual(self.p.interfaces["Vlan40"]["acl_out"], "ODD")
        self.assertEqual(self.p.interfaces["Vlan40"]["acl_in6"], "V6-OT")

    def test_wildcard_masks(self):
        rule = next(r for r in self.p.rules if r.original_id == "OT-TO-CTRL:1")
        self.assertEqual((rule.src.nets, rule.dst.nets), (["10.20.1.0/24"], ["10.30.2.0/24"]))

    def test_non_contiguous_wildcard_is_flagged_and_undecidable(self):
        rule = next(r for r in self.p.rules if r.original_id == "ODD:1")
        self.assertTrue(rule.unsupported)
        self.assertIn("ace-parse", [i.code for i in self.p.issues])

    def test_unsupported_options_are_recorded(self):
        by_id = {r.original_id: r for r in self.p.rules}
        self.assertIn("DSCP match", by_id["ODD:2"].unsupported)
        self.assertTrue(any("reflexive" in u for u in by_id["ODD:3"].unsupported))

    def test_tcp_reply_is_allowed_by_established_entry(self):
        probe = tcp("10.20.1.15", "10.30.2.40", 502, "Vlan20", "Vlan30")
        forward, reply = evaluate_connection(self.p, probe)
        self.assertEqual(forward.outcome, ALLOW)
        self.assertEqual(reply.outcome, ALLOW)
        self.assertEqual(reply.original_id, "FROM-CTRL:1")

    def test_established_entry_does_not_permit_connection_initiation(self):
        # OT-TO-CTRL:3 says "permit tcp 10.30.2.0/24 -> 10.20.1.0/24 established". A new connection (SYN) from the
        # controller subnet must not match it.
        decision = evaluate(self.p, tcp("10.30.2.40", "10.20.1.15", 5000, "Vlan20", "Vlan30"))
        self.assertEqual((decision.outcome, decision.original_id), (DENY, "OT-TO-CTRL:6"))

    def test_stateless_return_path_missing_is_reported(self):
        # EtherNet/IP is permitted forward but FROM-CTRL only permits replies from source port 502.
        forward, reply = evaluate_connection(self.p, tcp("10.20.1.15", "10.30.2.40", 44818, "Vlan20", "Vlan30"))
        self.assertEqual(forward.outcome, ALLOW)
        self.assertEqual(reply.outcome, DENY)

    def test_udp_reply_needs_its_own_entry(self):
        probe = Probe("10.20.1.15", "10.30.2.40", "udp", 50000, 161, src_zone="Vlan20", dst_zone="Vlan30")
        forward, reply = evaluate_connection(self.p, probe)
        self.assertEqual((forward.outcome, reply.outcome), (ALLOW, ALLOW))
        other = Probe("10.20.1.15", "10.30.2.40", "udp", 50000, 162, src_zone="Vlan20", dst_zone="Vlan30")
        self.assertEqual(evaluate(self.p, other).outcome, DENY)

    def test_icmp_echo_reply_is_denied_without_an_entry(self):
        probe = Probe("10.20.1.15", "10.30.2.9", "icmp", icmp_type=8, icmp_code=0, src_zone="Vlan20", dst_zone="Vlan30")
        forward, reply = evaluate_connection(self.p, probe)
        self.assertEqual(forward.outcome, ALLOW)
        self.assertEqual(reply.outcome, DENY)

    def test_outbound_acl_is_a_second_check(self):
        # ODD is bound out on Vlan40; ODD:1 is undecidable, so traffic leaving Vlan40 cannot be decided as allowed.
        decision = evaluate(self.p, tcp("10.20.1.15", "10.40.1.5", 22, "Vlan20", "Vlan40"))
        self.assertIn(decision.outcome, (INDETERMINATE, DENY))

    def test_ipv6_acl_uses_the_ipv6_binding(self):
        probe = Probe("2001:db8:20::5", "2001:db8:30::9", "tcp", 1, 502, src_zone="Vlan40", dst_zone="Vlan30")
        self.assertEqual(evaluate(self.p, probe).outcome, ALLOW)
        probe = Probe("2001:db8:20::5", "2001:db8:30::9", "tcp", 1, 80, src_zone="Vlan40", dst_zone="Vlan30")
        self.assertEqual(evaluate(self.p, probe).outcome, DENY)

    def test_no_secret_reaches_the_stored_model(self):
        dump = json.dumps(to_plain(self.p))
        for secret in ("thisshouldneverappear", "leakleakleak", "PUBLICSECRET"):
            self.assertNotIn(secret, dump)


class RejectionTests(unittest.TestCase):
    def test_not_a_cisco_config(self):
        with self.assertRaises(ValueError):
            cisco.parse("hello world\n", "x")

    def test_garbage_lines_do_not_crash(self):
        text = ("access-list A extended permit tcp any\naccess-list A extended permit ??? any any\n"
                "ip access-list extended B\n permit\n")
        policy = cisco.parse(text, "x", "asa")
        self.assertGreaterEqual(len(policy.rules), 1)
        self.assertTrue(all(r.unsupported for r in policy.rules))


if __name__ == "__main__":
    unittest.main()


class Ipv6AclTests(unittest.TestCase):
    TEXT = ("ip access-list extended V4\n permit tcp any any eq 80\n permit tcp any any eq 22\n deny ip any any\n"
            "ipv6 access-list V6\n permit tcp any any eq 443\n deny ipv6 any any\n"
            "interface Vlan1\n ip address 10.0.0.1 255.255.255.0\n ip access-group V4 in\n ipv6 traffic-filter V6 in\n")

    def test_any_in_an_ipv6_acl_means_any_ipv6_address_only(self):
        policy = cisco.parse(self.TEXT, "x", "ios")
        v6 = [r for r in policy.rules if r.extra["acl"] == "V6"]
        self.assertTrue(all(r.src.nets == ["::/0"] and not r.src.any for r in v6))
        v4 = [r for r in policy.rules if r.extra["acl"] == "V4"]
        self.assertTrue(v4[0].src.any)

