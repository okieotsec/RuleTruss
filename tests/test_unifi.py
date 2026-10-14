"""The UniFi adapter and the read-only export helper. The fixture is written from Ubiquiti's published schema, not exported from a gateway."""
import copy
import importlib.util
import json
import os
import ssl
import stat
import subprocess  # nosec B404 - runs openssl with a fixed argument list to make a throw-away test certificate
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from ruletruss import isolate, limits
from ruletruss.adapters import registry, unifi
from ruletruss.evaluate import ALLOW, DENY, INDETERMINATE, Probe, evaluate

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "unifi-export.json"
TEXT = FIXTURE.read_text(encoding="utf-8")


def load_tool():
    spec = importlib.util.spec_from_file_location("unifi_export", ROOT / "tools" / "unifi_export.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = registry.parse_config(TEXT, "s1")
        cls.rules = {r.original_id: r for r in cls.policy.rules}

    def decide(self, src, dst, src_zone, dst_zone, proto="tcp", dport=None, **kw):
        return evaluate(self.policy, Probe(src, dst, proto, 40000, dport, src_zone=src_zone, dst_zone=dst_zone, **kw))

    def test_the_file_is_recognised_by_content_and_summarised(self):
        self.assertEqual(registry.detect_format(TEXT), "unifi")
        p = self.policy
        self.assertEqual((p.vendor, p.version, p.hostname, len(p.rules)), ("unifi", "10.3.58", "Default", 25))
        self.assertEqual(p.interfaces["IoT"]["nets"], ["192.168.20.0/24"])
        self.assertEqual(sorted(p.interfaces["Internal"]["nets"]), ["10.10.10.0/24", "192.168.1.0/24"])     # the VLAN-only network has none
        self.assertIn("192.168.1.1/32", p.interfaces["Gateway"]["nets"])
        self.assertTrue(any(i.code == "network-no-subnet" for i in p.issues))
        self.assertTrue(any(i.code == "acl-rules-not-evaluated" for i in p.issues))
        self.assertTrue(any(i.code == "unifi-schema" for i in p.issues))

    def test_policies_are_ordered_per_zone_pair_by_index(self):
        pair = [r.original_id for r in self.policy.rules if r.scope == "Internal to External"]
        self.assertEqual(pair, ["Old rule (off)", "Reject telnet", "Streaming app", "Not the lab range", "Strange protocol", "Allow All Traffic"])
        self.assertEqual([r.position for r in self.policy.rules], list(range(1, 26)))

    def test_actions_zones_and_enabled(self):
        self.assertEqual((self.rules["Reject telnet"].action, self.rules["Reject telnet"].original_action), ("deny", "reject"))
        self.assertFalse(self.rules["Old rule (off)"].enabled)
        self.assertEqual((self.rules["IoT to NAS web"].src_zones, self.rules["IoT to NAS web"].dst_zones), (["IoT"], ["Internal"]))

    def test_addresses_ports_and_lists(self):
        r = self.rules["IoT to NAS web"]
        self.assertEqual(r.dst.nets, ["10.10.10.5/32"])
        self.assertEqual(r.svc.text(), "tcp dport 80,443,8080-8090")                      # from the traffic matching list
        self.assertEqual(self.rules["Admins to IoT"].src.nets, ["192.168.1.10/32", "192.168.1.20/30"])   # the range became a subnet
        self.assertEqual(self.rules["Web to DMZ"].dst.nets, ["172.16.50.0/24"])           # from the network filter
        self.assertEqual(self.rules["IoT DNS only"].svc.text(), "tcp dport 53; udp dport 53")

    def test_match_opposite_negates_addresses_and_complements_ports(self):
        r = self.rules["Not the lab range"]
        self.assertTrue(r.dst.negate)
        self.assertEqual(r.svc.text(), "tcp dport 1-24,26-65535")

    def test_conditions_that_cannot_be_evaluated_are_kept_and_named(self):
        self.assertTrue(any("schedule" in c for c in self.rules["DMZ out of hours"].condition_unknowns()))
        self.assertTrue(any("application" in c for c in self.rules["Streaming app"].condition_unknowns()))
        self.assertTrue(any("MAC address" in c for c in self.rules["Admin MAC to gateway"].condition_unknowns()))
        self.assertIn("fqdn:cloud.camera-vendor.example", self.rules["IoT vendor cloud"].dst.unresolved)
        self.assertEqual(self.rules["IoT vendor cloud"].dst.fqdn_names(), ["cloud.camera-vendor.example"])
        self.assertTrue(self.rules["Region allow"].src.unresolved)
        self.assertTrue(self.rules["VPN to servers"].src.unresolved)
        self.assertTrue(any("not recognised" in c for c in self.rules["Strange protocol"].condition_unknowns()))
        self.assertTrue(self.rules["Strange protocol"].svc.unresolved)

    def test_ipv6_scope_and_icmp_type(self):
        r = self.rules["Ping the gateway"]
        self.assertEqual((r.src.nets, r.svc.text()), (["::/0"], "icmp6 type 128"))

    def test_connection_state_policies_never_match_a_new_connection(self):
        r = self.rules["Allow Return Traffic"]
        self.assertIs(r.extra["new_connections"], False)
        d = self.decide("203.0.113.9", "192.168.1.50", "External", "Internal", dport=22)
        self.assertEqual((d.outcome, d.original_id), (DENY, "Block All Traffic"))

    def test_decisions(self):
        self.assertEqual(self.decide("192.168.20.5", "10.10.10.5", "IoT", "Internal", dport=443).original_id, "IoT to NAS web")
        d = self.decide("192.168.20.5", "10.10.10.6", "IoT", "Internal", dport=443)
        self.assertEqual((d.outcome, d.original_id), (DENY, "Block IoT to LAN"))
        self.assertEqual(self.decide("192.168.20.5", "8.8.8.8", "IoT", "External", proto="udp", dport=53).original_id, "IoT DNS only")
        d = self.decide("192.168.20.5", "8.8.8.8", "IoT", "External", dport=443)
        self.assertEqual(d.outcome, INDETERMINATE)             # the vendor-cloud policy (a domain) might match first, and would allow
        self.assertEqual(self.decide("192.168.1.50", "172.16.50.10", "Internal", "DMZ", dport=443).outcome, ALLOW)

    def test_a_zone_pair_nothing_matches_is_undecidable_not_denied(self):
        d = self.decide("192.168.1.50", "172.16.50.10", "Internal", "DMZ", dport=22)
        self.assertEqual(d.outcome, INDETERMINATE)
        self.assertIn("lists no final", d.basis)

    def test_an_undecidable_earlier_policy_limits_what_is_claimed(self):
        d = self.decide("192.168.1.50", "198.51.100.7", "Internal", "External", dport=443)
        self.assertEqual(d.outcome, INDETERMINATE)             # an application policy (block) before an allow: cannot say which wins
        self.assertTrue(d.uncertain)

    def test_unknown_zones_are_undecidable(self):
        self.assertEqual(self.decide("192.168.1.50", "8.8.8.8", None, None, dport=443).outcome, INDETERMINATE)


class SemanticsTests(unittest.TestCase):
    """Behaviour checked against the structure of a real export (Network 10.6.106): ordering, connection states, predefined policies."""

    @classmethod
    def setUpClass(cls):
        cls.policy = registry.parse_config(TEXT, "s1")
        cls.by_name = {r.original_id: r for r in cls.policy.rules}

    def variant(self, **changes):
        doc = json.loads(TEXT)
        for pol in doc["policies"]:
            if pol["name"] == "Block Servers to LAN":
                pol.update(changes)
        return unifi.parse(json.dumps(doc), "s1")

    def connection(self, policy, src, dst, src_zone, dst_zone, dport=443):
        from ruletruss.evaluate import evaluate_connection
        return evaluate_connection(policy, Probe(src, dst, "tcp", 40000, dport, src_zone=src_zone, dst_zone=dst_zone))

    def test_zone_pair_ends_in_the_predefined_default_at_the_last_index(self):
        defaults = [r for r in self.policy.rules if r.extra["default_policy"]]
        self.assertTrue(defaults and all(r.extra["index"] == 2147483647 for r in defaults))
        for pair in {tuple(r.extra["zone_pair"]) for r in defaults}:
            ordered = [r for r in self.policy.rules if tuple(r.extra["zone_pair"]) == pair]
            self.assertTrue(ordered[-1].extra["default_policy"], pair)

    def test_a_policy_for_all_states_that_blocks_the_reverse_direction_also_blocks_the_replies(self):
        forward, reply = self.connection(self.policy, "192.168.1.50", "10.10.10.9", "Internal", "Internal")
        self.assertEqual(forward.outcome, ALLOW)
        self.assertEqual((reply.outcome, reply.original_id), (DENY, "Block Servers to LAN"))

    def test_the_same_policy_limited_to_new_connections_lets_the_replies_through(self):
        forward, reply = self.connection(self.variant(connectionStateFilter=["NEW"]), "192.168.1.50", "10.10.10.9", "Internal", "Internal")
        self.assertEqual((forward.outcome, reply.outcome), (ALLOW, ALLOW))

    def test_replies_coming_back_into_a_blocked_zone_are_allowed_by_the_return_traffic_policy(self):
        forward, reply = self.connection(self.policy, "192.168.1.50", "198.51.100.7", "Internal", "External", dport=8443)
        self.assertNotEqual(forward.outcome, DENY)
        self.assertEqual((reply.outcome, reply.original_id), (ALLOW, "Allow Return Traffic"))      # External to Internal, state ESTABLISHED

    def test_a_new_connection_into_the_same_zone_pair_is_blocked_by_the_default(self):
        probe = Probe("203.0.113.9", "192.168.1.50", "tcp", 40000, 22, src_zone="External", dst_zone="Internal")
        d = evaluate(self.policy, probe)
        self.assertEqual((d.outcome, d.original_id), (DENY, "Block All Traffic"))      # the 'Allow Return Traffic' policy needs a state NEW lacks
        self.assertEqual(evaluate(self.policy, probe.reply()).original_id, "Allow All Traffic")      # the reply travels Internal to External

    def test_a_predefined_icmpv6_policy_without_a_message_type_is_not_read_as_all_icmpv6(self):
        for name in ("Allow Neighbor Solicitations", "Allow Router Advertisements"):
            rule = self.by_name[name]
            self.assertTrue(rule.svc.unresolved, name)
            self.assertTrue(any("not in the export" in c for c in rule.condition_unknowns()), name)
        probe = Probe("2001:db8::5", "2001:db8::1", "icmp6", None, None, 128, 0, src_zone="External", dst_zone="Gateway")
        self.assertEqual(evaluate(self.policy, probe).outcome, INDETERMINATE)

    def test_addresses_outside_every_known_network_are_external_but_unknown_private_ones_are_not(self):
        from ruletruss.analysis import build_context, zone_for
        ctx = build_context()
        self.assertEqual(zone_for("8.8.8.8", ctx, self.policy), "External")
        self.assertEqual(zone_for("192.168.20.9", ctx, self.policy), "IoT")
        self.assertEqual(zone_for("192.168.1.1", ctx, self.policy), "Gateway")          # the gateway's own address
        self.assertIsNone(zone_for("10.99.0.5", ctx, self.policy))


class AnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from ruletruss import analysis
        cls.policy = registry.parse_config(TEXT, "s1")
        cls.findings = analysis.analyze_rules(cls.policy)
        cls.by_id = {r.rule_id: r for r in cls.policy.rules}

    def kinds(self, kind):
        return [f for f in self.findings if f["kind"] == kind]

    def test_predefined_policies_are_not_reported_as_broad_or_in_conflict(self):
        for finding in self.kinds("broad"):
            self.assertEqual(self.by_id[finding["rule_id"]].extra["origin"], "USER_DEFINED")
        for finding in self.kinds("conflict"):
            self.assertFalse(self.by_id[finding["rule_id"]].extra["default_policy"], finding["message"])

    def test_policies_that_only_cover_existing_connections_hide_nothing(self):
        flagged = {f["rule_id"] for f in self.findings if f["kind"] in ("shadowed", "redundant")}
        for rule in self.policy.rules:
            if rule.extra.get("new_connections") is False:
                self.assertNotIn(rule.rule_id, flagged)
                self.assertTrue(all(f.get("by_rule_id") != rule.rule_id for f in self.findings))

    def test_different_icmp_messages_are_not_redundant_with_each_other(self):
        from ruletruss import analysis
        doc = json.loads(TEXT)
        for pol in doc["policies"]:
            if pol["name"] == "Ping the gateway":
                twin = copy.deepcopy(pol)
                twin["id"], twin["name"], twin["index"] = "00000000-0000-4000-8000-000000009999", "Echo reply too", 3
                twin["ipProtocolScope"]["protocolFilter"]["protocol"]["typenameFilter"] = "ECHO_REPLY"
                doc["policies"].append(twin)
        findings = analysis.analyze_rules(unifi.parse(json.dumps(doc), "s1"))
        self.assertFalse([f for f in findings if f["kind"] in ("redundant", "shadowed") and f["rule"] == "Echo reply too"])

    def test_the_built_in_posture_is_summarised_once(self):
        default = self.kinds("default")
        self.assertEqual(len(default), 1)
        self.assertIn("Internal to External", default[0]["message"])

    def test_a_policy_for_new_connections_only_does_not_shadow_a_later_one_for_all_states(self):
        from ruletruss import analysis
        doc = json.loads(TEXT)
        base = next(p for p in doc["policies"] if p["name"] == "Block Servers to LAN")
        base["connectionStateFilter"] = ["NEW"]
        later = copy.deepcopy(base)
        later["id"], later["name"], later["index"], later["action"] = "00000000-0000-4000-8000-000000008888", "Later all states", 6, {"type": "ALLOW"}
        del later["connectionStateFilter"]
        doc["policies"].append(later)
        findings = analysis.analyze_rules(unifi.parse(json.dumps(doc), "s1"))
        self.assertFalse([f for f in findings if f["kind"] in ("shadowed", "redundant") and f["rule"] == "Later all states"])
        base["connectionStateFilter"] = None
        del base["connectionStateFilter"]
        findings = analysis.analyze_rules(unifi.parse(json.dumps(doc), "s1"))
        self.assertTrue([f for f in findings if f["kind"] == "shadowed" and f["rule"] == "Later all states"])


class ZoneMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from ruletruss import analysis
        cls.analysis = analysis
        cls.policy = registry.parse_config(TEXT, "s1")
        cls.matrix = analysis.zone_matrix(cls.policy)
        cls.cell = {(c["src"], c["dst"]): c for c in cls.matrix["cells"]}

    def test_every_pair_of_zones_has_one_cell_and_zones_use_the_familiar_order(self):
        zones = self.matrix["zones"]
        self.assertEqual(zones[:6], ["Internal", "External", "Gateway", "Vpn", "Hotspot", "DMZ"])
        self.assertEqual(zones[6:], ["IoT"])                                   # a zone you made comes after the built-in ones
        self.assertEqual(len(self.matrix["cells"]), len(zones) ** 2)

    def test_a_pair_ending_in_allow_with_blocks_before_it(self):
        c = self.cell[("Internal", "External")]
        self.assertEqual((c["label"], c["tone"], c["default"]["action"]), ("Allow, 2 blocked", "mixed", "allow"))
        self.assertEqual((c["custom_block"], c["custom_allow"], c["custom_disabled"]), (2, 2, 1))        # the disabled policy is not counted as a block
        self.assertGreaterEqual(c["undecidable"], 2)                                                      # application and unknown-protocol policies

    def test_a_blocked_pair_whose_replies_are_allowed(self):
        c = self.cell[("External", "Internal")]
        self.assertEqual((c["label"], c["tone"], c["replies_allowed"]), ("Block (replies allowed)", "block", True))
        self.assertEqual(c["predefined_block"], 0)          # 'Block Invalid Traffic' matches only invalid packets, not new connections

    def test_all_state_blocks_and_predefined_policies_are_counted_in_the_label(self):
        self.assertEqual(self.cell[("Internal", "Internal")]["label"], "Allow, 1 blocked")        # 'Block Servers to LAN'

    def test_pairs_with_nothing_or_no_final_default_say_so(self):
        self.assertEqual(self.cell[("Gateway", "Internal")]["label"], "No policy listed")
        self.assertEqual(self.cell[("Internal", "DMZ")]["label"], "No default listed")

    def test_other_platforms_have_no_matrix(self):
        from ruletruss.adapters import cisco
        self.assertIsNone(self.analysis.zone_matrix(cisco.parse((ROOT / "tests" / "fixtures" / "asa_plant.cfg").read_text(), "s", "asa")))

    def test_the_service_returns_the_matrix_and_the_row_fields_the_page_needs(self):
        from ruletruss.samples import create_demo
        from ruletruss.service import Service
        from ruletruss.store import Store
        with tempfile.TemporaryDirectory() as d:
            service = Service(Store(d))
            project = create_demo(service)
            upload = service.store.new_upload_path(project["id"])
            Path(upload).write_text(TEXT, encoding="utf-8")
            entry = service.import_upload(project["id"], upload, "unifi-export.json")
            view = service.policy_view(project["id"], entry["id"])
            self.assertEqual(len(view["zone_matrix"]["cells"]), len(view["zone_matrix"]["zones"]) ** 2)
            row = next(r for r in view["rules"] if r["id"] == "Allow Return Traffic")
            self.assertEqual((row["replies_only"], row["origin"]), (True, "DERIVED"))
            self.assertTrue(any(r["final_default"] for r in view["rules"]))
            asa = next(s for s in service.project(project["id"])["sources"] if s["kind"] == "policy" and s["vendor"] != "unifi")
            self.assertIsNone(service.policy_view(project["id"], asa["id"])["zone_matrix"])


class ExampleTests(unittest.TestCase):
    """The 'Load the UniFi example' project: what it teaches is checked, so the training guide cannot describe something it does not show."""

    @classmethod
    def setUpClass(cls):
        from ruletruss.samples import create_unifi
        from ruletruss.service import Service
        from ruletruss.store import Store
        cls.dir = tempfile.TemporaryDirectory()
        cls.service = Service(Store(cls.dir.name))
        cls.project = create_unifi(cls.service)
        cls.policy = next(s for s in cls.project["sources"] if s["kind"] == "policy")
        cls.compare = cls.service.compare(cls.project["id"], cls.policy["id"])
        cls.rows = {(r["observed"]["initiator"], r["observed"]["responder"], r["observed"]["port"]): r for r in cls.compare["rows"]}

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def row(self, src, dst, port):
        return self.rows[(src, dst, port)]

    def test_what_is_loaded(self):
        self.assertEqual(sorted(s["kind"] for s in self.project["sources"]), ["capture", "policy"])
        self.assertEqual(self.policy["rules"], 85)
        self.assertEqual(len(self.rows), 11)
        self.assertTrue(all(r["crosses_device"] for r in self.rows.values()))

    def test_allowed_traffic_with_replies_that_pass(self):
        for key, rule in ((("192.168.1.10", "192.168.20.31", 80), "Admins to IoT"), (("192.168.20.31", "10.10.10.5", 443), "IoT to NAS web")):
            self.assertEqual((self.row(*key)["outcome"], self.row(*key)["rule"], self.row(*key)["return_path"]["outcome"]), ("allow", rule, "allow"), key)

    def test_a_block_for_all_states_drops_the_replies_of_an_allowed_connection(self):
        row = self.row("192.168.1.50", "10.10.10.5", 443)
        self.assertEqual((row["outcome"], row["return_path"]["outcome"], row["return_path"]["rule"]), ("allow", "deny", "Block Servers to LAN"))
        self.assertIn("reply path blocked", row["reading_short"])
        self.assertIn("would not work", row["reading"])

    def test_traffic_the_gateway_blocks(self):
        self.assertEqual(self.row("192.168.20.31", "10.10.10.9", 445)["rule"], "Block IoT to LAN")
        self.assertEqual(self.row("192.168.20.32", "198.51.100.7", 8883)["rule"], "IoT block the rest")
        self.assertEqual(self.row("203.0.113.9", "192.168.1.50", 22)["rule"], "Block All Traffic")
        self.assertEqual(self.row("192.168.1.50", "172.16.50.10", 22)["outcome"], "deny")
        self.assertEqual(self.row("192.168.1.50", "172.16.50.10", 22)["rule"], "Block All Traffic")

    def test_conditions_it_cannot_decide_are_named(self):
        browsing = self.row("192.168.1.50", "198.51.100.7", 443)
        self.assertEqual(browsing["outcome"], "indeterminate")
        self.assertIn("application", browsing["reading_short"])
        self.assertEqual(self.row("192.168.20.32", "198.51.100.7", 443)["outcome"], "indeterminate")      # a domain policy first

    def test_the_schedule_policy_makes_one_reply_uncertain(self):
        self.assertEqual(self.row("192.168.1.50", "172.16.50.10", 443)["return_path"]["outcome"], "indeterminate")

    def test_the_matrix_and_findings_are_readable(self):
        view = self.service.policy_view(self.project["id"], self.policy["id"])
        cells = {(c["src"], c["dst"]): c for c in view["zone_matrix"]["cells"]}
        self.assertEqual(cells[("IoT", "Internal")]["label"], "Block, 1 allowed")
        self.assertEqual(cells[("Internal", "DMZ")]["label"], "Block, 1 allowed")
        self.assertEqual(cells[("DMZ", "Internal")]["label"], "Block (replies allowed)")
        kinds = {f["kind"] for f in view["findings"]}
        self.assertTrue({"unevaluated", "disabled", "default"} <= kinds)

    def test_the_route_creates_it(self):
        import threading

        from ruletruss import server
        with tempfile.TemporaryDirectory() as data:
            srv = server.build_server("127.0.0.1", 0, data, token="t" * 24)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                import http.client
                conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=60)
                body = json.dumps({"name": "unifi"}).encode()
                conn.request("POST", "/api/sample", body=body, headers={"Host": f"127.0.0.1:{srv.server_address[1]}", "Authorization": "Bearer " + "t" * 24,
                                                                       "Content-Length": str(len(body))})
                response = conn.getresponse()
                project = json.loads(response.read().decode())
                conn.close()
            finally:
                srv.shutdown()
                srv.server_close()
        self.assertEqual(response.status, 201)
        self.assertIn("UniFi", project["name"])


class RobustnessTests(unittest.TestCase):
    def doc(self):
        return json.loads(TEXT)

    def parse(self, doc):
        return unifi.parse(json.dumps(doc), "s1")

    def test_not_json_or_not_ours(self):
        for bad in ("", "{", "[]", '{"a": 1}', "null"):
            with self.assertRaises(ValueError):
                unifi.parse(bad, "s1")

    def test_deeply_nested_json_is_a_clean_error(self):
        with self.assertRaises(ValueError):
            unifi.parse('{"ruletruss_unifi_export": 1, "x": ' + "[" * 100_000 + "]" * 100_000 + "}", "s1")

    def test_wrong_types_everywhere_do_not_raise(self):
        base = self.doc()
        for key in ("zones", "policies", "networks", "traffic_matching_lists", "acl_rules", "site"):
            for junk in (None, 5, "text", [1, "a", None, [], {}], {"x": 1}, True):
                doc = copy.deepcopy(base)
                doc[key] = junk
                self.parse(doc)
        doc = self.doc()
        for policy in doc["policies"]:
            for field in ("source", "destination", "action", "ipProtocolScope", "metadata", "schedule", "connectionStateFilter", "index", "enabled"):
                policy[field] = ["junk", 3, None]
        self.parse(doc)

    def test_hostile_names_and_values_are_plain_bounded_text(self):
        doc = self.doc()
        doc["policies"][0]["name"] = "<img src=x onerror=alert(1)>\x1b[31m" + "A" * 5000
        doc["policies"][0]["description"] = "line\nbreak\x00"
        doc["zones"][0]["name"] = "Zone" + chr(0x202E) + "X"
        policy = self.parse(doc)
        names = {r.original_id for r in policy.rules}
        weird = next(n for n in names if n.startswith("<img"))
        self.assertTrue(weird.isprintable() and len(weird) <= 120)
        self.assertNotIn("\x1b", weird)

    def test_huge_lists_are_refused_not_cut_short(self):
        doc = self.doc()
        doc["policies"] = [doc["policies"][0]] * (unifi.MAX_ITEMS + 5)
        with self.assertRaises(limits.LimitExceeded):
            self.parse(doc)

    def test_a_policy_for_an_unknown_zone_gets_a_placeholder_name(self):
        doc = self.doc()
        doc["policies"][0]["source"]["zoneId"] = "ffffffff-0000-4000-8000-000000000000"
        policy = self.parse(doc)
        self.assertTrue(any(r.src_zones == ["zone-ffffffff"] for r in policy.rules))

    def test_empty_filters_are_undecidable_never_match_nothing_or_everything(self):
        doc = self.doc()
        pols = {p["name"]: p for p in doc["policies"]}
        pols["Web to DMZ"]["destination"]["trafficFilter"]["networkFilter"]["networkIds"] = []           # a deleted network
        pols["IoT DNS only"]["destination"]["trafficFilter"]["portFilter"]["items"] = []                   # no ports left
        pols["Admins to IoT"]["source"]["trafficFilter"] = {"type": "IP_ADDRESS", "ipAddressFilter": {"type": "IP_ADDRESSES", "matchOpposite": False,
                                                                                                      "items": []}}
        policy = self.parse(doc)
        rules = {r.original_id: r for r in policy.rules}
        self.assertTrue(rules["Web to DMZ"].dst.unresolved)
        self.assertTrue(rules["IoT DNS only"].svc.unresolved)            # not "any port"
        self.assertTrue(rules["Admins to IoT"].src.unresolved)
        self.assertTrue(any(i.code == "empty-filter" for i in policy.issues))
        for name in ("Web to DMZ", "IoT DNS only", "Admins to IoT"):
            self.assertTrue(rules[name].condition_unknowns() or rules[name].src.unresolved or rules[name].dst.unresolved, name)
        probe = Probe("192.168.1.50", "172.16.50.10", "tcp", 40000, 443, src_zone="Internal", dst_zone="DMZ")
        self.assertEqual(evaluate(policy, probe).outcome, INDETERMINATE)

    def test_unknown_filter_types_are_reported_and_undecidable(self):
        doc = self.doc()
        doc["policies"][0]["destination"]["trafficFilter"] = {"type": "FUTURE_THING", "futureFilter": {}}
        rule = self.parse(doc).rules
        hit = next(r for r in rule if r.rule_id.endswith(str(next(i for i, x in enumerate(rule, 1) if x.extra["uuid"] == doc["policies"][0]["id"]))))
        self.assertTrue(hit.dst.unresolved)
        self.assertTrue(any("FUTURE_THING" in c for c in hit.condition_unknowns()))


class PipelineTests(unittest.TestCase):
    def test_the_worker_reads_it_as_a_policy_not_as_a_zeek_log(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "unifi-export.json")
            Path(path).write_text(TEXT, encoding="utf-8")
            result = isolate.parse_file(path, "s1", "unifi-export.json")
        self.assertEqual((result["kind"], result["format"], result["policy"]["vendor"]), ("policy", "unifi", "unifi"))

    def test_a_policy_that_only_covers_existing_connections_is_never_translated_as_allow_all(self):
        from ruletruss.samples import create_demo
        from ruletruss.service import Service
        from ruletruss.store import Store
        with tempfile.TemporaryDirectory() as d:
            service = Service(Store(d))
            project = create_demo(service)
            upload = service.store.new_upload_path(project["id"])
            Path(upload).write_text(TEXT, encoding="utf-8")
            entry = service.import_upload(project["id"], upload, "unifi-export.json")
            for target in ("cisco-asa", "cisco-ios", "fortios"):
                result = service.translation_json(project["id"], {"workflow": "preserve", "policy": entry["id"], "target": target, "zone_map": {}})
                for name in ("Allow Return Traffic", "Block Invalid Traffic"):
                    row = next(r for r in result["report"] if r["source_rule"] == name)
                    self.assertEqual(row["disposition"], "implemented", (target, name))       # never an entry that allows or blocks everything
                self.assertTrue(any(i["code"] == "default-zone-pairs" for i in result["issues"]), target)
                self.assertFalse(result["deployable"], target)
            plan = service.plan_json(project["id"], {"workflow": "preserve", "policy": entry["id"]})
            self.assertTrue(any("Allow Return Traffic" in str(x) for x in plan["review_items"]))

    def test_import_compare_and_view_work_end_to_end(self):
        from ruletruss.samples import create_demo
        from ruletruss.service import Service
        from ruletruss.store import Store
        with tempfile.TemporaryDirectory() as d:
            service = Service(Store(d))
            project = create_demo(service)
            upload = service.store.new_upload_path(project["id"])
            Path(upload).write_text(TEXT, encoding="utf-8")
            entry = service.import_upload(project["id"], upload, "unifi-export.json")
            self.assertEqual((entry["kind"], entry["vendor"], entry["rules"]), ("policy", "unifi", 25))
            view = service.policy_view(project["id"], entry["id"])
            self.assertTrue(view["rules"])
            compare = service.compare(project["id"], entry["id"])
            self.assertTrue(compare["rows"])
            self.assertTrue(all("crosses_device" in r for r in compare["rows"]))


class FakeApi:
    """The Integration API as the exporter sees it, built from the fixture, with paging."""

    def __init__(self, page_limit=5):
        doc = json.loads(TEXT)
        self.site = {"id": "00000000-0000-4000-8000-000000000900", "name": "Default", "internalReference": "default"}
        self.doc, self.calls, self.page_limit = doc, [], page_limit
        self.networks = {n["id"]: n for n in doc["networks"]}

    def page(self, items, params):
        offset, limit = int(params["offset"]), min(int(params["limit"]), self.page_limit)
        return {"offset": offset, "limit": limit, "count": len(items[offset:offset + limit]), "totalCount": len(items),
                "data": items[offset:offset + limit]}

    def get(self, path, params=None):
        self.calls.append((path, dict(params or {})))
        prefix = f"/sites/{self.site['id']}"
        if path == "/info":
            return {"applicationVersion": "10.3.58"}
        if path == "/sites":
            return self.page([self.site], params)
        if path == f"{prefix}/firewall/zones":
            return self.page(self.doc["zones"], params)
        if path == f"{prefix}/firewall/policies":
            return self.page(self.doc["policies"], params)
        if path == f"{prefix}/networks":
            return self.page([{"id": n["id"], "name": n["name"]} for n in self.doc["networks"]], params)
        if path.startswith(f"{prefix}/networks/"):
            return self.networks[path.rsplit("/", 1)[1]]
        if path == f"{prefix}/traffic-matching-lists":
            return self.page(self.doc["traffic_matching_lists"], params)
        if path == f"{prefix}/acl-rules":
            return self.page(self.doc["acl_rules"], params)
        raise AssertionError(f"unexpected request {path}")


class ExporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def test_paging_collects_everything_and_the_result_round_trips_through_the_adapter(self):
        api = FakeApi(page_limit=5)
        bundle = self.tool.export(api.get)
        self.assertEqual(len(bundle["policies"]), 25)
        self.assertGreater(sum(1 for path, _ in api.calls if path.endswith("/firewall/policies")), 3)      # several pages
        self.assertEqual(bundle["application_version"], "10.3.58")
        parsed = unifi.parse(json.dumps(bundle), "s1")
        original = unifi.parse(TEXT, "s1")
        self.assertEqual([(r.original_id, r.action, r.scope) for r in parsed.rules], [(r.original_id, r.action, r.scope) for r in original.rules])
        self.assertEqual(parsed.interfaces, original.interfaces)

    def test_a_gateway_that_never_stops_paging_or_sends_oversized_pages_is_cut_off(self):
        def endless(path, params=None):
            return {"data": [{"id": "x"}] * 200, "totalCount": 10_000_000}

        def oversized(path, params=None):
            return {"data": [{"id": "x"}] * 201, "totalCount": 201}

        for source in (endless, oversized):
            with self.assertRaises(self.tool.ExportError):
                self.tool.pages(source, "/sites")

    def test_the_whole_run_has_a_request_and_a_time_budget(self):
        gateway = self.tool.Gateway("192.0.2.1", "key")
        gateway.requests = self.tool.MAX_REQUESTS
        with self.assertRaises(self.tool.ExportError):
            gateway.get("/info")
        gateway = self.tool.Gateway("192.0.2.1", "key")
        gateway.started -= self.tool.MAX_SECONDS + 1
        with self.assertRaises(self.tool.ExportError):
            gateway.get("/info")

    def test_every_request_is_a_get_of_a_known_read_path(self):
        api = FakeApi()
        self.tool.export(api.get)
        for path, _ in api.calls:
            self.assertRegex(path, r"^/(info|sites(/[0-9a-f-]+/(firewall/zones|firewall/policies|networks(/[0-9a-f-]+)?|traffic-matching-lists|acl-rules))?)$")

    def test_site_choice(self):
        sites = [{"id": "a", "name": "Home", "internalReference": "default"}, {"id": "b", "name": "Shop", "internalReference": "x"}]
        self.assertEqual(self.tool.pick_site(sites, "Shop")["id"], "b")
        self.assertEqual(self.tool.pick_site(sites, None)["id"], "a")
        with self.assertRaises(self.tool.ExportError):
            self.tool.pick_site(sites, "Nope")
        with self.assertRaises(self.tool.ExportError):
            self.tool.pick_site([{"id": "a", "name": "A", "internalReference": "q"}, {"id": "b", "name": "B", "internalReference": "r"}], None)

    def test_a_missing_acl_endpoint_does_not_stop_the_export(self):
        api = FakeApi()
        original = api.get

        def get(path, params=None):
            if path.endswith("/acl-rules"):
                raise self.tool.ExportError("not found")
            return original(path, params)
        self.assertEqual(self.tool.export(get)["acl_rules"], [])

    def test_fingerprint_validation(self):
        self.assertEqual(self.tool.clean_fingerprint("AA:" * 31 + "AA"), "aa" * 32)
        for bad in ("", "zz" * 32, "aa" * 31, "aa" * 33):
            with self.assertRaises(self.tool.ExportError):
                self.tool.clean_fingerprint(bad)

    def test_the_output_file_is_private_and_holds_no_key(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.json")
            self.tool.write_private(path, self.tool.export(FakeApi().get))
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertNotIn("X-API-KEY", Path(path).read_text())

    def test_the_key_comes_from_the_environment_or_a_file_not_the_command_line(self):
        with tempfile.TemporaryDirectory() as d:
            key_file = os.path.join(d, "key")
            Path(key_file).write_text("file-key\n")
            self.assertEqual(self.tool.read_key(key_file), "file-key")
        os.environ["UNIFI_API_KEY"] = "env-key"
        self.addCleanup(os.environ.pop, "UNIFI_API_KEY", None)
        self.assertEqual(self.tool.read_key(None), "env-key")
        self.assertNotIn("--api-key ", Path(ROOT / "tools" / "unifi_export.py").read_text())

    def test_at_a_terminal_the_key_is_asked_for_hidden_and_otherwise_missing_is_an_error(self):
        from unittest import mock
        os.environ.pop("UNIFI_API_KEY", None)
        with mock.patch.object(self.tool.sys.stdin, "isatty", return_value=True), \
                mock.patch.object(self.tool.getpass, "getpass", return_value="  typed-key \n") as ask:
            self.assertEqual(self.tool.read_key(None), "typed-key")
        ask.assert_called_once()
        with mock.patch.object(self.tool.sys.stdin, "isatty", return_value=False), mock.patch.object(self.tool.getpass, "getpass") as never:
            self.assertEqual(self.tool.read_key(None), "")
        never.assert_not_called()


@unittest.skipUnless(subprocess.run(["which", "openssl"], capture_output=True, check=False).returncode == 0, "needs openssl")  # noqa: S607
class TlsPinningTests(unittest.TestCase):
    """A real local HTTPS server with a throw-away self-signed certificate."""

    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()
        cls.dir = tempfile.TemporaryDirectory()
        cert, key = os.path.join(cls.dir.name, "c.pem"), os.path.join(cls.dir.name, "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "1",  # noqa: S603, S607
                        "-subj", "/CN=localhost"], capture_output=True, check=True)
        cls.seen = []
        outer = cls

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.seen.append((self.command, self.path, self.headers.get("X-API-KEY")))
                status = 404 if "missing" in self.path else 200
                body = json.dumps({"applicationVersion": "10.3.58"}).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                return
        class QuietHTTPServer(HTTPServer):
            def handle_error(self, request, client_address):      # a client that refuses the certificate hangs up mid-handshake: expected
                return
        cls.server = QuietHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.fingerprint = cls.tool.show_fingerprint("127.0.0.1", cls.port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.dir.cleanup()

    def test_a_self_signed_certificate_is_refused_by_default(self):
        with self.assertRaises(self.tool.ExportError) as raised:
            self.tool.Gateway("127.0.0.1", "KEY", self.port).get("/info")
        self.assertIn("--show-fingerprint", str(raised.exception))
        self.assertEqual(self.seen, [])

    def test_the_pinned_certificate_is_accepted_and_the_key_is_sent_only_then(self):
        self.assertEqual(self.tool.Gateway("127.0.0.1", "KEY", self.port, fingerprint=self.fingerprint).get("/info")["applicationVersion"], "10.3.58")
        self.assertEqual(self.seen[-1], ("GET", "/proxy/network/integration/v1/info", "KEY"))

    def test_a_different_fingerprint_stops_before_anything_is_sent(self):
        before = len(self.seen)
        with self.assertRaises(self.tool.ExportError) as raised:
            self.tool.Gateway("127.0.0.1", "KEY", self.port, fingerprint="ab" * 32).get("/info")
        self.assertIn("not the one you gave", str(raised.exception))
        self.assertEqual(len(self.seen), before)

    def test_old_versions_get_a_clear_message(self):
        with self.assertRaises(self.tool.ExportError) as raised:
            self.tool.Gateway("127.0.0.1", "KEY", self.port, fingerprint=self.fingerprint).get("/missing")
        self.assertIn("10.1 or later", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
