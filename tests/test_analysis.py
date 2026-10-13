import os
import tempfile
import unittest
from pathlib import Path

from pbridge import analysis
from pbridge.adapters import cisco, fortios
from pbridge.capture.flows import analyze_capture
from pbridge.model import AppGuess, Flow, Subnet
from pbridge.synthetic import plant_capture

FIX = Path(__file__).parent / "fixtures"


def flow(i, src, dst, dport, conf="high", proto="tcp", apps=None, rev=1):
    return Flow(flow_id=f"f{i}", source_id="s", ip_version=4, proto=proto, initiator=src, responder=dst, initiator_port=40000 + i,
                responder_port=dport, direction_confidence=conf, direction_basis=["test basis"], pkts_fwd=3, pkts_rev=rev,
                apps=apps or [])


class ExplainTests(unittest.TestCase):
    ctx = analysis.build_context({"10.20.1.15": "Engineering workstation", "10.30.2.40": "controller"})

    def explain(self, **kw):
        return analysis.explain_communication(analysis.aggregate([flow(1, "10.20.1.15", "10.30.2.40", 502, **kw)])[0], self.ctx)

    def test_the_example_from_the_brief(self):
        confirmed = AppGuess("Modbus/TCP", "confirmed", "decoded Modbus/TCP header in packet 4")
        text = self.explain(apps=[confirmed])
        self.assertIn('10.20.1.15 (labelled "Engineering workstation") initiated 1 TCP connection to 10.30.2.40 '
                      '(labelled "controller") on destination port 502.', text)
        self.assertIn("Modbus/TCP was identified from packet decoding", text)

    def test_port_only_is_a_possibility_not_a_finding(self):
        text = self.explain(apps=[AppGuess("Modbus/TCP", "possible", "only the port number suggests this")])
        self.assertIn("Modbus/TCP is possible", text)
        self.assertNotIn("was identified", text)

    def test_wording_follows_direction_confidence(self):
        self.assertIn("most likely initiated", self.explain(conf="medium"))
        self.assertIn("low confidence", self.explain(conf="low"))
        self.assertIn("could not be determined", self.explain(conf="unknown"))

    def test_no_reply_is_stated(self):
        self.assertIn("No reply was captured", self.explain(rev=0))

    def test_labels_are_attributed_to_the_user(self):
        self.assertIn("labelled", self.explain())


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.ctx = analysis.build_context({"10.20.1.15": "EWS"}, [Subnet("10.20.0.0/16", "Engineering", "eng"),
                                                                  Subnet("10.30.0.0/16", "Controllers", "ot")])
        self.flows = [flow(1, "10.20.1.15", "10.30.2.40", 502), flow(2, "10.30.2.40", "10.20.1.15", 4840),
                      flow(3, "10.99.0.1", "10.30.2.40", 80, conf="low")]
        self.comms = analysis.aggregate(self.flows)

    def test_inventory_has_counts_and_no_role_inference(self):
        inv = analysis.inventory(self.flows, self.ctx)
        plc = next(d for d in inv["devices"] if d["ip"] == "10.30.2.40")
        self.assertEqual((plc["received_flows"], plc["initiated_flows"], plc["subnet"]), (2, 1, "10.30.0.0/16"))
        self.assertNotIn("role", plc)
        self.assertIn("not inferred", plc["note"])
        self.assertEqual(next(d for d in inv["devices"] if d["ip"] == "10.99.0.1")["subnet"], "")
        self.assertIn("(not in a defined subnet)", [s["subnet"] for s in inv["subnets"]])

    def test_matrix_keeps_direction(self):
        cells = {(c["from"], c["to"]): c for c in analysis.matrix(self.comms, self.ctx)}
        self.assertIn(("10.20.0.0/16", "10.30.0.0/16"), cells)
        self.assertIn(("10.30.0.0/16", "10.20.0.0/16"), cells)
        self.assertEqual(cells[("(undefined)", "10.30.0.0/16")]["low_confidence"], 1)

    def test_aggregate_uses_the_weakest_direction_confidence(self):
        comms = analysis.aggregate([flow(1, "10.0.0.1", "10.0.0.2", 80), flow(2, "10.0.0.1", "10.0.0.2", 80, conf="low")])
        self.assertEqual((len(comms), comms[0].flows, comms[0].direction_confidence), (1, 2, "low"))


class CompareTests(unittest.TestCase):
    def test_observed_versus_configured_on_the_plant_example(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.pcap")
            plant_capture().write(path)
            _, flows = analyze_capture(path, "c", "s", "p.pcap")
        ctx = analysis.build_context(subnets=[Subnet("10.20.0.0/16", "Engineering", "ot"), Subnet("10.30.0.0/16", "Controllers", "ot"),
                                              Subnet("10.10.0.0/16", "Corporate", "corp")])
        policy = cisco.parse((FIX / "asa_plant.cfg").read_text(), "a")
        comms = analysis.aggregate(flows)
        rows, hits = analysis.compare_observed(policy, comms, ctx)
        by = {(c.initiator, c.responder, c.responder_port): r for c, r in zip(comms, rows, strict=True)}
        self.assertEqual(by[("10.20.1.15", "10.30.2.40", 502)]["outcome"], "allow")
        self.assertEqual(by[("10.20.1.15", "10.30.2.40", 502)]["rule"], "OT-IN:1")
        self.assertEqual(by[("10.20.1.15", "10.30.2.99", 8888)]["outcome"], "deny")
        self.assertIn("does not pass through this device", by[("10.20.1.15", "10.30.2.99", 8888)]["reading"])
        self.assertEqual(by[("2001:db8:20::15", "2001:db8:30::40", 502)]["outcome"], "indeterminate")   # no zone for IPv6
        unobserved = analysis.unobserved_rules(policy, hits)
        self.assertTrue(unobserved)
        self.assertIn("does not show it is unused", unobserved[0]["note"])

    def test_stateless_return_failure_is_surfaced(self):
        policy = cisco.parse((FIX / "ios_ot_switch.cfg").read_text(), "i")
        ctx = analysis.build_context(subnets=[Subnet("10.20.1.0/24", "eng", "Vlan20"), Subnet("10.30.2.0/24", "plc", "Vlan30")])
        comms = analysis.aggregate([flow(1, "10.20.1.15", "10.30.2.40", 44818), flow(2, "10.20.1.15", "10.30.2.40", 502)])
        rows, _ = analysis.compare_observed(policy, comms, ctx)
        by = {c.responder_port: r for c, r in zip(comms, rows, strict=True)}
        self.assertEqual(by[502]["return_path"]["outcome"], "allow")
        self.assertEqual(by[44818]["return_path"]["outcome"], "deny")
        self.assertIn("reply direction is not permitted", by[44818]["reading"])


class RuleAnalysisTests(unittest.TestCase):
    CONFIG = """interface Gi0/0
 nameif inside
 security-level 100
object network NET
 subnet 10.1.0.0 255.255.0.0
access-list A extended permit tcp 10.1.0.0 255.255.0.0 any eq 80
access-list A extended permit tcp 10.1.2.0 255.255.255.0 any eq 80
access-list A extended deny tcp 10.1.2.0 255.255.255.0 any eq 80
access-list A extended deny tcp any any range 70 90
access-list A extended permit ip any any
access-list A extended permit tcp object NET any eq 443 time-range HOURS
access-list A extended permit tcp 10.1.3.0 255.255.255.0 any eq 443
access-group A in interface inside
"""

    def kinds(self):
        policy = cisco.parse(self.CONFIG, "x", "asa")
        return policy, analysis.analyze_rules(policy)

    def test_redundant_and_shadowed_rules(self):
        _, findings = self.kinds()
        by = {(f["kind"], f["rule"]) for f in findings}
        self.assertIn(("redundant", "A:2"), by)         # same action, fully covered by A:1
        self.assertIn(("shadowed", "A:3"), by)          # opposite action, fully covered by A:1: a conflict whose later rule never applies

    def test_partial_overlap_is_a_conflict_not_shadowing(self):
        _, findings = self.kinds()
        by = {(f["kind"], f["rule"]) for f in findings}
        self.assertIn(("conflict", "A:4"), by)
        self.assertNotIn(("shadowed", "A:4"), by)

    def test_broad_and_unevaluated_rules(self):
        _, findings = self.kinds()
        by = {(f["kind"], f["rule"]) for f in findings}
        self.assertIn(("broad", "A:5"), by)
        self.assertIn(("unevaluated", "A:6"), by)

    def test_rule_with_an_undecidable_condition_never_shadows_a_later_one(self):
        _, findings = self.kinds()
        self.assertNotIn(("shadowed", "A:7"), {(f["kind"], f["rule"]) for f in findings})

    def test_rules_in_different_acls_are_not_compared(self):
        policy = cisco.parse("interface Gi0/0\n nameif a\n security-level 1\ninterface Gi0/1\n nameif b\n security-level 2\n"
                             "access-list X extended permit ip any any\naccess-list Y extended deny ip any any\n"
                             "access-group X in interface a\naccess-group Y in interface b\n", "y", "asa")
        self.assertFalse([f for f in analysis.analyze_rules(policy) if f["kind"] in ("shadowed", "conflict", "redundant")])

    def test_fortios_shadowing(self):
        policy = fortios.parse((FIX / "fortios_plant.conf").read_text(), "f")
        findings = analysis.analyze_rules(policy)
        self.assertTrue([f for f in findings if f["kind"] == "disabled"])


if __name__ == "__main__":
    unittest.main()
