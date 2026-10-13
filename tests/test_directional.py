import os
import tempfile
import unittest
from pathlib import Path

from pbridge import analysis
from pbridge.adapters import cisco, fortios
from pbridge.capture.flows import analyze_capture
from pbridge.migrate import directional as bs
from pbridge.migrate import groups as grp
from pbridge.model import Subnet
from pbridge.synthetic import plant_capture

FIX = Path(__file__).parent / "fixtures"


def make_groups(*specs):
    return grp.validate_groups([{"name": n, "members": m, "gateway_isolated": g} for n, m, g in specs])


CONFIG = """interface Gi0/0
 nameif eng
 security-level 50
object-group network ENG
 network-object host 10.20.1.15
 network-object host 10.20.1.16
object-group network PLC
 network-object 10.30.2.0 255.255.255.0
object-group network HIST
 network-object host 10.30.5.10
access-list A extended deny tcp host 10.20.1.16 object-group PLC eq 502
access-list A extended permit tcp object-group ENG object-group PLC eq 502
access-list A extended permit ip object-group ENG object-group HIST
access-list A extended permit tcp any object-group PLC eq 22
access-list A extended permit tcp object-group ENG object-group PLC eq 80 time-range HOURS
access-list A extended permit tcp object-group HIST eq 502 object-group ENG
access-group A in interface eng
"""


class DirectionTests(unittest.TestCase):
    def setUp(self):
        self.policy = cisco.parse(CONFIG, "x", "asa")
        self.groups = make_groups(("ENG", ["10.20.1.15", "10.20.1.16"], False), ("PLC", ["10.30.2.0/24"], False),
                                  ("HIST", ["10.30.5.10"], False))
        self.plan = bs.plan_preserve(self.policy, self.groups)

    def pol(self, f, t):
        return next(p for p in self.plan.policies if p.from_groups == [f] and p.to_groups == [t])

    def test_policy_goes_from_the_initiating_group_to_the_responding_group_only(self):
        self.assertTrue(self.pol("ENG", "PLC"))
        self.assertFalse([p for p in self.plan.policies if p.from_groups == ["PLC"] and p.status != "blocked"])
        self.assertIn("may not initiate", self.pol("ENG", "PLC").direction_note)

    def test_reply_entry_does_not_become_a_reverse_policy(self):
        self.assertFalse([p for p in self.plan.policies if p.from_groups == ["HIST"] and p.to_groups == ["ENG"]])
        self.assertIn("reply-rule", {i.code for i in self.plan.review_items})

    def test_services_are_informational_and_the_loss_is_reported(self):
        p = self.pol("ENG", "PLC")
        self.assertTrue(p.loses_restrictions)
        self.assertIn("services-not-enforced", {w.code for w in p.warnings})
        self.assertIn("tcp dport 502", " ".join(p.services_informational))
        warning = next(w for w in p.warnings if w.code == "services-not-enforced")
        self.assertIn("not carried over", warning.message)

    def test_unrestricted_service_is_not_reported_as_lost(self):
        p = self.pol("ENG", "HIST")
        self.assertFalse(p.loses_restrictions)

    def test_earlier_deny_that_is_lost_is_reported_as_broadening(self):
        p = self.pol("ENG", "PLC")
        self.assertTrue(p.broadens)
        codes = {w.code for w in p.warnings}
        self.assertIn("earlier-deny-lost", codes)
        self.assertIn("deny-not-translated", {g.code for g in self.plan.gaps})

    def test_any_source_and_conditions_block_instead_of_widening(self):
        blocked = [p for p in self.plan.policies if p.status == "blocked"]
        text = " ".join(w.message for p in blocked for w in p.warnings)
        self.assertIn("source is 'any'", text)
        self.assertIn("schedule HOURS", text)
        self.assertEqual({g.code for g in self.plan.gaps} & {"rule-not-translated"}, {"rule-not-translated"})

    def test_summary_says_broadened(self):
        s = self.plan.summary
        self.assertGreaterEqual(s["policies_that_broaden_access"], 1)
        self.assertGreaterEqual(s["policies_that_lose_restrictions"], 1)
        self.assertIn("broadens access or drops restrictions", s["verdict"])

    def test_every_translated_policy_points_to_source_rules_and_evidence(self):
        p = self.pol("ENG", "PLC")
        self.assertTrue(p.source_rule_ids and p.evidence)
        self.assertEqual(p.origin, "preserved")


class AggregationTests(unittest.TestCase):
    def test_group_aggregation_that_grants_unintended_access_is_detected(self):
        policy = cisco.parse("interface Gi0/0\n nameif a\n security-level 1\n"
                             "access-list A extended permit tcp host 10.1.1.1 host 10.2.2.2 eq 80\n"
                             "access-group A in interface a\n", "x", "asa")
        groups = make_groups(("SRC", ["10.1.1.1", "10.1.1.9"], False), ("DST", ["10.2.2.2"], False))
        plan = bs.plan_preserve(policy, groups)
        self.assertEqual([p.status for p in plan.policies], ["blocked"])   # SRC is not wholly inside the source: no exact group
        groups = make_groups(("S1", ["10.1.1.1"], False), ("S2", ["10.1.1.9"], False), ("DST", ["10.2.2.2"], False),
                             ("WIDE", ["10.1.1.1", "10.1.1.9"], False))
        plan = bs.plan_preserve(policy, groups)
        live = [p for p in plan.policies if p.status != "blocked"]
        self.assertEqual([(p.from_groups, p.to_groups) for p in live], [(["S1"], ["DST"])])

    def test_overlapping_membership_that_makes_pairs_bidirectional_is_flagged(self):
        policy = cisco.parse("interface Gi0/0\n nameif a\n security-level 1\n"
                             "access-list A extended permit ip 10.0.0.0 255.255.0.0 10.0.0.0 255.255.0.0\n"
                             "access-group A in interface a\n", "x", "asa")
        groups = make_groups(("NET", ["10.0.0.1", "10.0.0.2", "10.0.0.3"], False))
        plan = bs.plan_preserve(policy, groups)
        codes = {w.code for p in plan.policies for w in p.warnings}
        self.assertIn("implied-reverse-initiation", codes)

    def test_one_policy_over_a_wider_rule_is_not_reported_as_broadening_when_every_pair_was_permitted(self):
        policy = cisco.parse("interface Gi0/0\n nameif a\n security-level 1\n"
                             "access-list A extended permit tcp 10.1.1.0 255.255.255.0 10.2.2.0 255.255.255.0 eq 80\n"
                             "access-group A in interface a\n", "y", "asa")
        plan = bs.plan_preserve(policy, make_groups(("S", ["10.1.1.1", "10.1.1.2"], False), ("D", ["10.2.2.1"], False)))
        live = [p for p in plan.policies if p.status != "blocked"]
        self.assertEqual(len(live), 1)
        self.assertNotIn("aggregation-grants-extra", {w.code for w in live[0].warnings})
        self.assertIn("address-not-in-any-group", {w.code for w in live[0].warnings})


class NarrowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.pcap")
            plant_capture().write(path)
            cls.info, cls.flows = analyze_capture(path, "c", "s", "p.pcap", "mirror of the distribution switch")
        cls.ctx = analysis.build_context(subnets=[Subnet("10.20.0.0/16", "Engineering"), Subnet("10.30.0.0/16", "Controllers"),
                                                  Subnet("10.10.0.0/16", "Corporate")])
        cls.comms = analysis.aggregate(cls.flows)
        cls.groups = make_groups(("Engineering", ["10.20.0.0/16"], False), ("Controllers", ["10.30.0.0/16"], False),
                                 ("Corporate", ["10.10.0.0/16"], False))
        cls.by_id = {f.flow_id: f for f in cls.flows}
        cls.plan = bs.plan_narrow(cls.comms, cls.by_id, cls.groups, cls.ctx, bs.observation_summary([cls.info], cls.comms))

    def test_reverse_initiation_is_a_separate_policy(self):
        pairs = {(tuple(p.from_groups), tuple(p.to_groups)) for p in self.plan.policies}
        self.assertIn((("Controllers",), ("Controllers",)), pairs)
        self.assertIn((("Engineering",), ("Controllers",)), pairs)

    def test_controller_to_engineering_is_proposed_separately_for_syslog_only_if_direction_is_trusted(self):
        # Syslog is one-way UDP: direction is low confidence, so it is held back, not proposed.
        held = [i for i in self.plan.review_items if i.code == "direction-uncertain"]
        self.assertTrue(held)
        self.assertTrue(any("10.30.2.40" in i.message and "514" in i.message for i in held))
        pairs = {(tuple(p.from_groups), tuple(p.to_groups)) for p in self.plan.policies}
        self.assertNotIn((("Controllers",), ("Engineering",)), pairs)

    def test_including_low_confidence_adds_the_policy_with_a_warning(self):
        plan = bs.plan_narrow(self.comms, self.by_id, self.groups, self.ctx, {}, include_low_confidence=True)
        pairs = {(tuple(p.from_groups), tuple(p.to_groups)) for p in plan.policies}
        self.assertIn((("Controllers",), ("Engineering",)), pairs)

    def test_observation_period_and_review_requirement_are_present(self):
        self.assertEqual(self.plan.review_items[0].code, "observation-limits")
        self.assertIn("scheduled or seasonal jobs", self.plan.review_items[0].message)
        self.assertGreater(self.plan.observation["duration_seconds"], 100)
        self.assertEqual(self.plan.observation["captures"][0]["observation_point"], "mirror of the distribution switch")
        self.assertIn("require review", self.plan.summary["verdict"])
        self.assertTrue(all(p.origin == "proposed" for p in self.plan.policies))

    def test_proposals_note_that_group_membership_can_grant_more_than_was_observed(self):
        p = next(p for p in self.plan.policies if p.from_groups == ["Engineering"] and p.to_groups == ["Controllers"])
        self.assertTrue(p.broadens)
        self.assertEqual(p.status, "needs_review")
        self.assertIn("aggregation-grants-extra", {w.code for w in p.warnings})

    def test_observed_services_are_informational_and_carry_confirmation(self):
        p = next(p for p in self.plan.policies if p.from_groups == ["Engineering"] and p.to_groups == ["Controllers"])
        self.assertTrue(any("Modbus/TCP" in s and "confirmed" in s for s in p.services_informational))

    def test_not_in_a_group_is_reported_not_guessed(self):
        groups = make_groups(("Engineering", ["10.20.0.0/16"], False))
        plan = bs.plan_narrow(self.comms, self.by_id, groups, self.ctx, {})
        self.assertIn("not-in-a-group", {i.code for i in plan.review_items})


class EgressTests(unittest.TestCase):
    def test_gateway_isolated_endpoints_reaching_outside_every_group_get_an_egress_policy(self):
        from pbridge.model import Flow
        flows = [Flow(flow_id="f1", source_id="s", ip_version=4, proto="tcp", initiator="10.30.2.40", responder="198.51.100.7",
                      initiator_port=40000, responder_port=443, direction_confidence="high", direction_basis=["SYN"], pkts_fwd=3,
                      pkts_rev=2, hostnames=["updates.vendor.example"]),
                 Flow(flow_id="f2", source_id="s", ip_version=4, proto="tcp", initiator="10.30.2.40", responder="10.30.5.10",
                      initiator_port=40001, responder_port=4840, direction_confidence="high", direction_basis=["SYN"], pkts_fwd=3,
                      pkts_rev=2)]
        ctx = analysis.build_context(subnets=[Subnet("10.30.0.0/16", "Controllers")])
        groups = make_groups(("PLCs", ["10.30.2.40"], True), ("Historians", ["10.30.5.10"], False))
        plan = bs.plan_narrow(analysis.aggregate(flows), {f.flow_id: f for f in flows}, groups, ctx, {})
        self.assertEqual(len(plan.egress_policies), 1)
        e = plan.egress_policies[0]
        self.assertEqual((e.endpoint_groups, e.allowed_prefixes), (["PLCs"], ["198.51.100.7/32"]))
        self.assertEqual(e.allowed_dns_names, ["updates.vendor.example"])
        self.assertFalse(e.allow_all_dns)
        self.assertEqual(e.status, "needs_review")
        self.assertEqual([(p.from_groups, p.to_groups) for p in plan.policies], [(["PLCs"], ["Historians"])])

    def test_preserved_egress_from_a_firewall_rule_with_an_fqdn(self):
        policy = fortios.parse((FIX / "fortios_plant.conf").read_text(), "f")
        groups = make_groups(("PLC-NET", ["10.30.2.0/24"], True), ("ENG", ["10.20.1.15", "10.20.1.16"], False),
                             ("HIST", ["10.30.5.10/31", "10.30.5.12"], False))
        plan = bs.plan_preserve(policy, groups)
        self.assertEqual(len(plan.egress_policies), 1)
        e = plan.egress_policies[0]
        self.assertEqual(e.allowed_dns_names, ["updates.vendor.example"])
        self.assertEqual(e.endpoint_groups, ["PLC-NET"])
        self.assertTrue(any("wildcard" in w.message for w in e.warnings))


class FactsTests(unittest.TestCase):
    def test_the_model_is_defined_by_this_app_and_states_what_it_does_not_carry(self):
        text = " ".join(bs.MODEL_FACTS["not_modelled"])
        for word in ("Ports and protocols", "Deny actions", "Application"):
            self.assertIn(word, text)
        self.assertIn("not the policy format of any product", bs.MODEL_FACTS["note"])
        self.assertNotIn("http", str(bs.MODEL_FACTS))


class GroupTests(unittest.TestCase):
    def test_validation(self):
        for bad in ([{"name": "", "members": []}], [{"name": "a", "members": ["not-an-ip"]}],
                    [{"name": "a", "members": []}, {"name": "A", "members": []}], "x", [1]):
            with self.assertRaises(ValueError):
                grp.validate_groups(bad)

    def test_endpoint_can_be_in_several_groups(self):
        groups = make_groups(("A", ["10.0.0.0/24"], False), ("B", ["10.0.0.5"], False))
        self.assertEqual([g.name for g in grp.groups_for_ip("10.0.0.5", groups)], ["A", "B"])

    def test_cover_prefers_groups_wholly_inside_and_reports_the_rest(self):
        groups = make_groups(("INSIDE", ["10.0.0.0/25"], False), ("TOO_BIG", ["10.0.0.0/16"], False))
        from pbridge.model import AddrSet
        result = grp.cover_addrset(AddrSet(nets=["10.0.0.0/24"]), groups)
        self.assertEqual([g.name for g in result["exact"]], ["INSIDE"])
        self.assertEqual(result["uncovered"], ["10.0.0.128/25"])
        self.assertEqual([g.name for g, _ in result["overlapping"]], ["TOO_BIG"])


if __name__ == "__main__":
    unittest.main()
