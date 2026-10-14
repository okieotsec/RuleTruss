"""The graph's drill-down: what a node or an edge stands for, with a small sample of the traffic behind it."""
import tempfile
import unittest
from unittest import mock

from ruletruss.samples import create_riverbend
from ruletruss.service import ApiError, Service
from ruletruss.store import Store

SCADA, PLC, CELL1 = "10.20.0.10", "10.30.1.11", "10.30.1.0/24"


class GraphCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.svc = Service(Store(cls.dir.name))
        cls.pid = create_riverbend(cls.svc)["id"]

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def detail(self, **params):
        return self.svc.graph_detail(self.pid, params)


class GraphDataTests(GraphCase):
    def test_subnet_nodes_carry_weight_and_device_counts(self):
        g = self.svc.graph(self.pid, {"level": "subnet"})
        node = next(n for n in g["nodes"] if n["id"] == CELL1)
        self.assertGreater(node["weight"], 0)
        self.assertEqual(node["devices"], 3)
        self.assertEqual(node["address"], CELL1)

    def test_focus_shows_one_subnets_devices_and_their_peers(self):
        g = self.svc.graph(self.pid, {"level": "device", "focus": CELL1})
        ids = {n["id"] for n in g["nodes"]}
        self.assertTrue({"10.30.1.11", "10.30.1.12", "10.30.1.13"} <= ids)
        self.assertIn(SCADA, ids)                                       # a peer outside the subnet that talks to it
        self.assertNotIn("10.30.3.31", ids)                             # a device that has nothing to do with it
        self.assertEqual(g["focus"], CELL1)
        self.assertFalse(g["truncated"])

    def test_a_bad_focus_is_a_clean_error(self):
        with self.assertRaises(ApiError) as raised:
            self.svc.graph(self.pid, {"level": "device", "focus": "<script>"})
        self.assertEqual(raised.exception.status, 400)

    def test_device_nodes_know_their_weight(self):
        g = self.svc.graph(self.pid, {"level": "device"})
        self.assertTrue(all(n["weight"] > 0 and n["address"] == n["id"] for n in g["nodes"]))


class DeviceDetailTests(GraphCase):
    def test_a_device_says_who_it_talks_to_and_what_it_uses_and_offers(self):
        d = self.detail(kind="device", id=PLC)
        self.assertEqual((d["address"], d["label"], d["subnet"]), (PLC, "Intake pump PLC 1", CELL1))
        self.assertGreater(d["answered_flows"], 0)
        self.assertIn("tcp/502", [x["name"] for x in d["offers"]])
        scada = self.detail(kind="device", id=SCADA)
        self.assertGreater(scada["started_flows"], 0)
        self.assertIn(PLC, [x["name"] for x in scada["talks_to"]])
        self.assertIn("tcp/502", [x["name"] for x in scada["uses"]])
        self.assertEqual(scada["labels"][PLC], "Intake pump PLC 1")

    def test_samples_are_small_and_carry_evidence(self):
        d = self.detail(kind="device", id=SCADA)
        self.assertTrue(0 < len(d["sample_communications"]) <= 6)
        self.assertTrue(0 < len(d["sample_flows"]) <= 5)
        for c in d["sample_communications"]:
            self.assertTrue(c["text"] and c["direction_confidence"] and c["evidence"])
        for f in d["sample_flows"]:
            self.assertTrue(f["proto"] and f["evidence"] and f["packets"] > 0)
        self.assertEqual([f["last_ts"] for f in d["sample_flows"]], sorted((f["last_ts"] for f in d["sample_flows"]), reverse=True))
        for lists in ("talks_to", "reached_by", "offers", "uses"):
            self.assertLessEqual(len(d[lists]), 6)

    def test_what_is_known_about_the_network_card_and_identity_comes_along(self):
        d = self.detail(kind="device", id="10.30.1.11")
        self.assertTrue(d["mac"])
        self.assertIn("Pump controller", d["identity"])

    def test_unknown_and_malformed_ids(self):
        with self.assertRaises(ApiError) as raised:
            self.detail(kind="device", id="203.0.113.250")
        self.assertEqual(raised.exception.status, 404)
        for bad in ("", "not-an-ip", "10.0.0.1/24", "<img>"):
            with self.assertRaises(ApiError) as raised:
                self.detail(kind="device", id=bad)
            self.assertEqual(raised.exception.status, 400, bad)
        with self.assertRaises(ApiError):
            self.detail(kind="nonsense", id=PLC)


class SubnetAndEdgeTests(GraphCase):
    def test_a_subnet_lists_its_busiest_devices_and_peers(self):
        d = self.detail(kind="subnet", id=CELL1)
        self.assertEqual((d["id"], d["label"], d["devices"]), (CELL1, "Cell 1: intake", 3))
        self.assertTrue(d["busiest_devices"] and d["busiest_devices"][0]["flows"] >= d["busiest_devices"][-1]["flows"])
        self.assertIn("10.20.0.0/24", [x["name"] for x in d["reached_by"]])
        self.assertIn("tcp/502", [x["name"] for x in d["offers"]])
        self.assertEqual(d["filter_key"], "Cell 1: intake")
        self.assertTrue(0 < len(d["sample_communications"]) <= 6)

    def test_a_device_edge_and_a_subnet_edge(self):
        e = self.detail(kind="edge", level="device", **{"from": SCADA, "to": PLC})
        self.assertEqual((e["from"], e["to"]), (SCADA, PLC))
        self.assertGreater(e["flows"], 0)
        self.assertIn("tcp/502", [x["name"] for x in e["services"]])
        s = self.detail(kind="edge", level="subnet", **{"from": "10.20.0.0/24", "to": CELL1})
        self.assertGreaterEqual(s["flows"], e["flows"])
        with self.assertRaises(ApiError) as raised:
            self.detail(kind="edge", level="device", **{"from": PLC, "to": SCADA})        # nothing was seen in that direction
        self.assertEqual(raised.exception.status, 404)

    def test_unknown_subnets_are_a_clean_error(self):
        with self.assertRaises(ApiError) as raised:
            self.detail(kind="subnet", id="172.31.0.0/16")
        self.assertEqual(raised.exception.status, 404)
        with self.assertRaises(ApiError) as raised:
            self.detail(kind="subnet", id="garbage")
        self.assertEqual(raised.exception.status, 400)


class CacheTests(GraphCase):
    def test_the_observed_data_is_computed_once_until_the_project_changes(self):
        project = self.svc.project(self.pid)
        self.svc._comm_cache = None
        with mock.patch.object(Service, "_comm_rows", autospec=True, side_effect=Service._comm_rows) as compute:
            self.svc.comm_rows(project)
            self.svc.comm_rows(project)
            self.svc.graph_detail(self.pid, {"kind": "device", "id": PLC})
            self.assertEqual(compute.call_count, 1)
            self.svc.store.update_context(self.pid, labels={PLC: "A new name"})
            self.assertEqual(self.detail(kind="device", id=PLC)["label"], "A new name")
            self.assertEqual(compute.call_count, 2)
        self.svc.store.update_context(self.pid, labels={PLC: "Intake pump PLC 1"})

    def test_a_hostile_label_comes_back_as_plain_text(self):
        self.svc.store.update_context(self.pid, labels={PLC: "<img src=x onerror=alert(1)>"})
        try:
            self.assertEqual(self.detail(kind="device", id=PLC)["label"], "<img src=x onerror=alert(1)>")
        finally:
            self.svc.store.update_context(self.pid, labels={PLC: "Intake pump PLC 1"})


if __name__ == "__main__":
    unittest.main()
