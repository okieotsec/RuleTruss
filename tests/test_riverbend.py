"""Every teaching point in samples/riverbend/GUIDE.md is checked here, so the guide cannot describe something the data does not show."""
import tempfile
import unittest

from ruletruss.adapters.registry import parse_config
from ruletruss.migrate import firewall as fw
from ruletruss.migrate import validate as val
from ruletruss.riverbend_configs import configs
from ruletruss.samples import create_riverbend, riverbend_files, vendor_names
from ruletruss.service import Service
from ruletruss.store import Store


class RiverbendCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.svc = Service(Store(cls.dir.name))
        vendor_names.install(cls.svc.vendor_path)         # the fictional table: no real vendor is named by the example
        cls.project = create_riverbend(cls.svc)
        cls.pid = cls.project["id"]
        cls.rows = cls.svc.communications(cls.pid, {"limit": "500"})["rows"]
        cls.policy_ids = {s["filename"]: s["id"] for s in cls.project["sources"] if s["kind"] == "policy"}

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def comm(self, src, dst, port=None, proto=None):
        found = [r for r in self.rows if r["initiator"] == src and r["responder"] == dst and (port is None or r["port"] == port)
                 and (proto is None or r["proto"] == proto)]
        self.assertEqual(len(found), 1, f"{src}->{dst}:{port} matched {len(found)}")
        return found[0]

    def compare(self, name):
        return {(r["observed"]["initiator"], r["observed"]["responder"], r["observed"]["port"], r["observed"]["proto"]): r
                for r in self.svc.compare(self.pid, self.policy_ids[name])["rows"]}

    def plan(self, **body):
        return self.svc.plan_json(self.pid, body)


class DeviceTeachingTests(RiverbendCase):
    """D01-D07 in the guide."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.ov = cls.svc.overview(cls.pid)
        cls.devs = {d["ip"]: d for d in cls.ov["inventory"]["devices"]}
        cls.extras = cls.ov["device_extras"]

    def test_d01_arp_confirms_some_hosts_and_others_are_only_probable(self):
        for ip in ("10.20.0.10", "10.20.0.50", "10.20.0.60"):
            self.assertEqual(self.devs[ip]["mac_confidence"], "confirmed", ip)
        for ip in ("10.20.0.70", "10.20.0.2"):
            self.assertEqual(self.devs[ip]["mac_confidence"], "probable", ip)

    def test_d02_the_firewall_mac_is_shared_by_the_plcs_and_not_attributed(self):
        from ruletruss import riverbend
        router = {m["mac"]: m for m in self.extras["shared_macs"]}[riverbend.OPS_MACS["10.20.0.1"]]
        self.assertGreaterEqual(len(router["ips"]), 10)
        self.assertEqual(router["confirmed_ips"], ["10.20.0.1"])
        self.assertIn("10.30.1.13", router["ips"])
        self.assertEqual(self.devs["10.30.1.13"]["mac"], "")         # no capture sees this PLC on its own segment
        self.assertTrue(any(m["nic_vendor"] == "Example Security Appliances Inc." for m in self.extras["shared_macs"]))   # the DMZ tap's firewall

    def test_d03_card_maker_is_the_registry_name(self):
        self.assertEqual(self.devs["10.30.2.21"]["nic_vendor"], "Example Automation AG")
        self.assertEqual(self.devs["10.30.2.30"]["nic_vendor"], "Example Industrial Controls")
        self.assertEqual(self.devs["10.20.0.10"]["nic_vendor"], "Example Virtualization Inc.")
        self.assertEqual(self.devs["10.30.2.21"]["mac_confidence"], "confirmed")
        for ip in ("10.30.2.22", "10.30.2.23", "10.30.2.24"):
            self.assertEqual(self.devs[ip]["mac_confidence"], "probable", ip)

    def test_d04_self_reported_identity(self):
        self.assertEqual(self.devs["10.30.1.11"]["identity_short"], "Pump controller (Example Controls; EC-100; revision V3.1)")
        dosing = {i["kind"]: i for i in self.devs["10.30.2.30"]["identity"]}
        self.assertTrue(dosing["enip-identity"]["value"].startswith("Dosing controller (CIP vendor ID 9999"))
        self.assertEqual(sum(1 for d in self.devs.values() if any(i["kind"] == "snmp-sysdescr" for i in d["identity"])), 3)
        self.assertTrue(any(i["kind"] == "http-server" for i in self.devs["10.30.1.12"]["identity"]))
        self.assertEqual(self.devs["10.30.2.2"]["identity_short"], "Managed industrial switch, 8 ports")
        for d in self.devs.values():
            for i in d["identity"]:
                self.assertIn(i["type"], ("self-reported", "weak-hint"))

    def test_d05_a_randomised_mac_has_no_maker_and_dhcp_ties_it_to_an_address(self):
        row = self.devs["10.30.2.77"]
        self.assertEqual((row["mac_kind"], row["nic_vendor"], row["mac_confidence"], row["mac_basis"]), ("local", "", "confirmed", "dhcp"))
        self.assertEqual(row["identity_short"], "CONTRACTOR-LT")

    def test_d06_a_switch_seen_only_at_layer_2(self):
        self.assertEqual([m["identity_short"] for m in self.extras["l2_only"]], ["cell1-sw1"])

    def test_d07_ttl_hints_are_apart_and_can_mislead(self):
        self.assertTrue(self.devs["10.20.0.10"]["hint"].startswith("initial TTL probably 128"))
        self.assertTrue(self.devs["10.30.1.11"]["hint"].startswith("initial TTL probably 64"))
        self.assertTrue(self.devs["10.30.3.40"]["hint"].startswith("initial TTL probably 255"))
        self.assertTrue(self.devs["10.30.2.23"]["hint"].startswith("initial TTL probably 128"))      # a PLC that says 128
        self.assertNotIn("TTL", self.devs["10.30.2.23"]["identity_short"])

    def test_the_example_uses_no_mac_twice_by_accident(self):
        from ruletruss import riverbend
        every = {**riverbend.OPS_MACS, **riverbend.DMZ_MACS, **riverbend.CELL_MACS}
        self.assertEqual(len(set(every.values())), len(every))


class DatasetShapeTests(RiverbendCase):
    def test_the_example_has_the_advertised_files(self):
        kinds = sorted((s["filename"], s["kind"]) for s in self.project["sources"])
        self.assertEqual([k for _, k in kinds].count("capture"), 3)
        self.assertEqual([k for _, k in kinds].count("flows"), 1)
        self.assertEqual([k for _, k in kinds].count("policy"), 5)
        self.assertEqual(set(riverbend_files()), {s["filename"] for s in self.project["sources"]})

    def test_all_five_formats_are_recognised(self):
        from ruletruss.adapters.registry import detect_format
        self.assertEqual(sorted(detect_format(t) for t in configs().values()), ["cisco-asa", "cisco-ios", "fortios", "panos", "pfsense"])

    def test_nothing_in_the_example_is_a_real_address_or_secret(self):
        import ipaddress
        text = "".join(t for t in configs().values())
        for token in text.replace("/", " ").replace('"', " ").split():
            try:
                ip = ipaddress.ip_address(token)
            except ValueError:
                continue
            documentation = ("192.0.2.", "198.51.100.", "203.0.113.")
            self.assertTrue(ip.is_private or str(ip).startswith(documentation) or ip.is_multicast or ip.is_unspecified, token)
        for secret in ("notarealcommunitystring", "notarealhashvalue", "notarealpassword"):
            parsed = str(self.svc.policy_view(self.pid, self.policy_ids["perimeter-asa.cfg"]))
            self.assertNotIn(secret, parsed)

    def test_the_capture_scale_is_what_the_guide_says(self):
        o = self.svc.overview(self.pid)
        self.assertEqual((o["flows"], o["communications"]), (198, 82))
        self.assertEqual(len(o["inventory"]["devices"]), 47)      # 43 with flows, plus 4 seen only by ARP or LLDP


class CaptureLessonTests(RiverbendCase):
    def test_T01_confirmed_modbus_and_a_port_502_that_is_not_modbus(self):
        confirmed = self.comm("10.20.0.10", "10.30.1.12", 502)
        self.assertEqual((confirmed["apps"][0]["name"], confirmed["apps"][0]["confidence"]), ("Modbus/TCP", "confirmed"))
        odd = self.comm("10.20.0.51", "10.30.1.13", 502)
        self.assertEqual((odd["apps"][0]["name"], odd["apps"][0]["confidence"]), ("Modbus/TCP", "possible"))
        self.assertIn("did not decode", odd["apps"][0]["basis"])

    def test_T02_a_protocol_the_tool_does_not_decode_is_only_possible(self):
        row = self.comm("10.20.0.20", "10.40.0.20", 1433)
        self.assertEqual((row["apps"][0]["name"], row["apps"][0]["confidence"]), ("Microsoft SQL Server", "possible"))

    def test_T03_unknown_protocol_gets_no_guess(self):
        self.assertEqual(self.comm("10.20.0.51", "10.30.2.24", 4000)["apps"], [])

    def test_T04_s7comm_and_dnp3_and_iec104_levels(self):
        self.assertEqual(self.comm("10.20.0.10", "10.30.2.22", 102)["apps"][0]["name"], "S7comm")
        self.assertEqual(self.comm("10.20.0.10", "10.30.3.31", 20000)["apps"][0]["confidence"], "confirmed")
        self.assertEqual(self.comm("10.20.0.11", "10.30.3.40", 2404)["apps"][0]["confidence"], "probable")

    def test_T05_an_rtu_that_initiates_to_the_scada_server_is_a_separate_direction(self):
        rtu = self.comm("10.30.3.32", "10.20.0.10", 20000)
        self.assertEqual(rtu["direction_confidence"], "high")
        self.assertIn("SYN", rtu["direction_basis"][0])
        plan = self.plan(workflow="narrow")
        pairs = {(tuple(p["from_groups"]), tuple(p["to_groups"])) for p in plan["policies"]}
        self.assertIn((("Distribution RTUs",), ("SCADA servers",)), pairs)
        self.assertIn((("SCADA servers",), ("Distribution RTUs",)), pairs)

    def test_T06_a_capture_that_started_late_cannot_prove_who_connected(self):
        merged = self.comm("10.20.0.10", "10.30.2.21", 102)
        self.assertEqual(merged["direction_confidence"], "medium")
        self.assertTrue(any("not proven" in n for n in merged["notes"]))

    def test_T07_one_direction_only_is_stated(self):
        row = self.comm("10.20.0.10", "10.30.3.33", 20000)
        self.assertIn("asymmetric visibility", " ".join(row["notes"]))

    def test_T08_one_way_udp_is_low_confidence_and_held_back_from_policy(self):
        syslog = self.comm("10.30.2.21", "10.20.0.2", 514)
        self.assertEqual(syslog["direction_confidence"], "low")
        plan = self.plan(workflow="narrow")
        self.assertTrue(any(i["code"] == "direction-uncertain" and "514" in i["message"] for i in plan["review_items"]))

    def test_T09_replies_to_a_broadcast_look_like_initiations_and_say_so(self):
        reply = self.comm("10.30.2.21", "10.20.0.50", 44818)
        self.assertEqual(reply["direction_confidence"], "low")

    def test_T10_broadcast_and_multicast_noise_is_not_turned_into_policy(self):
        plan = self.plan(workflow="narrow")
        messages = " ".join(i["message"] for i in plan["review_items"] if i["code"] == "broadcast-or-multicast")
        for address in ("255.255.255.255", "224.0.0.251", "239.255.255.250", "10.30.2.255"):
            self.assertIn(address, messages)

    def test_T11_connection_attempts_nobody_answered(self):
        for src, dst, port in (("10.20.0.61", "10.30.3.31", 23), ("10.10.4.20", "10.40.0.10", 3389), ("10.10.7.7", "10.40.0.40", 445)):
            row = self.comm(src, dst, port)
            self.assertIn("no SYN-ACK", " ".join(row["notes"]) + " " + row["explanation"])

    def test_T12_plc_to_vendor_cloud_becomes_an_egress_policy_with_a_dns_name(self):
        plan = self.plan(workflow="narrow")
        self.assertEqual(len(plan["egress_policies"]), 1)
        egress = plan["egress_policies"][0]
        self.assertEqual((egress["endpoint_groups"], egress["allowed_prefixes"], egress["allowed_dns_names"]),
                         (["Treatment PLCs"], ["203.0.113.10/32"], ["telemetry.vendor.example"]))
        self.assertFalse(egress["allow_all_dns"])

    def test_T13_captures_from_different_points_are_merged_with_the_weakest_confidence(self):
        row = self.comm("10.20.0.10", "10.30.1.11", 502)
        self.assertEqual(row["flows"], 2)
        self.assertEqual(row["direction_confidence"], "medium")

    def test_T14_zeek_summaries_carry_lower_confidence_and_are_labelled(self):
        row = self.comm("10.10.1.10", "9.9.9.9", 53)
        self.assertEqual(row["direction_confidence"], "low")
        self.assertIn("Zeek", " ".join(row["direction_basis"]))


class ConfigurationLessonTests(RiverbendCase):
    def test_C01_a_broad_temporary_rule_hides_specific_ones_and_shadows_a_later_deny(self):
        view = self.svc.policy_view(self.pid, self.policy_ids["perimeter-asa.cfg"])
        shadowed = [f for f in view["findings"] if f["kind"] == "shadowed"]
        self.assertTrue(any(f["rule"] == "CORP-IN:5" and f["by_rule"] == "CORP-IN:4" for f in shadowed))
        rows = self.compare("perimeter-asa.cfg")
        for key in (("10.10.4.20", "10.40.0.10", 3389, "tcp"), ("10.10.7.7", "10.40.0.40", 445, "tcp")):
            self.assertEqual((rows[key]["outcome"], rows[key]["rule"]), ("allow", "CORP-IN:4"))

    def test_C02_identity_fqdn_and_schedule_make_decisions_undecidable_and_a_stale_rule_is_unobserved(self):
        rows = self.compare("perimeter-asa.cfg")
        self.assertEqual(rows[("198.51.100.50", "10.40.0.10", 3389, "tcp")]["outcome"], "indeterminate")
        self.assertEqual(rows[("10.40.0.30", "192.0.2.80", 443, "tcp")]["outcome"], "indeterminate")
        unobserved = [u["rule"] for u in self.svc.compare(self.pid, self.policy_ids["perimeter-asa.cfg"])["unobserved_rules"]]
        self.assertIn("OUTSIDE-IN:3", unobserved)

    def test_C03_static_nat_blocks_rules_when_translating_to_a_product_with_a_different_address_context(self):
        t = self.svc.translation_json(self.pid, {"workflow": "preserve", "policy": self.policy_ids["perimeter-asa.cfg"], "target": "fortios",
                                                 "zone_map": {}})
        blocked = {e["source_rule"]: e["reason"] for e in t["report"] if e["status"] == "blocked"}
        self.assertIn("NAT", blocked["OUTSIDE-IN:2"])
        self.assertIn("identity", blocked["OUTSIDE-IN:1"])
        self.assertIn("schedule", blocked["DMZ-IN:4"])
        self.assertIn("not IP addresses", blocked["DMZ-IN:3"])

    def test_C04_panos_app_id_dynamic_groups_negation_and_destination_nat(self):
        policy = parse_config(configs()["it-ot-boundary-panos.xml"], "p")
        by_name = {r.original_id: r for r in policy.rules}
        self.assertTrue(by_name["jump-to-engineering"].applications)
        self.assertTrue(by_name["contractor-laptops"].src.unresolved)
        self.assertTrue(by_name["ops-sql-anywhere-but-xfer"].dst.negate)
        self.assertEqual(by_name["ops-internal-log"].extra["rule_type"], "intrazone")
        self.assertFalse(by_name["legacy-opc-gateway"].enabled)
        self.assertEqual(policy.nat_rules[0].kind, "destination")
        rows = self.compare("it-ot-boundary-panos.xml")
        self.assertEqual(rows[("10.40.0.10", "10.20.0.50", 3389, "tcp")]["outcome"], "indeterminate")
        self.assertEqual(rows[("10.20.0.20", "10.40.0.20", 1433, "tcp")]["rule"], "historian-replication")

    def test_C05_fortios_broad_rule_allows_the_odd_engineering_workstation_traffic(self):
        rows = self.compare("ops-field-fortios.conf")
        for key in (("10.20.0.51", "10.30.1.13", 502, "tcp"), ("10.20.0.51", "10.30.2.24", 4000, "tcp"), ("10.20.0.51", "10.30.1.12", 80, "tcp")):
            self.assertEqual((rows[key]["outcome"], rows[key]["rule"]), ("allow", "5"))
        view = self.svc.policy_view(self.pid, self.policy_ids["ops-field-fortios.conf"])
        self.assertTrue(any(f["kind"] == "redundant" and f["rule"] == "6" for f in view["findings"]))
        self.assertIn("vip-priority", {i["code"] for i in view["issues"]})
        policy = parse_config(configs()["ops-field-fortios.conf"], "f")
        self.assertEqual(next(r for r in policy.rules if r.original_id == "15").action, "deny")      # no action set: FortiOS denies

    def test_C06_ios_stateless_acls_an_unreadable_entry_and_reflexive_option(self):
        policy = parse_config(configs()["cell3-router-ios.cfg"], "i")
        self.assertFalse(policy.stateful)
        entries = {r.original_id: r for r in policy.rules}
        self.assertTrue(entries["CELL3-IN:2"].svc.entries[0].established)
        self.assertTrue(any("unreadable" in u for u in entries["OPS-TO-CELL3:8"].unsupported) or any("unreadable" in u for u in entries["OPS-TO-CELL3:7"].unsupported))
        self.assertTrue(any("reflexive" in u for r in policy.rules for u in r.unsupported))
        rows = self.compare("cell3-router-ios.cfg")
        self.assertEqual(rows[("10.30.3.32", "10.20.0.10", 20000, "tcp")]["rule"], "CELL3-IN:1")
        self.assertEqual(rows[("10.20.0.11", "10.30.3.40", 2404, "tcp")]["outcome"], "indeterminate")

    def test_C07_pfsense_unresolved_aliases_floating_rule_and_stateless_rule(self):
        policy = parse_config(configs()["vendor-access-pfsense.xml"], "q")
        self.assertTrue(policy.rules[0].extra["floating"])
        self.assertTrue(any(r.src.unresolved for r in policy.rules))
        self.assertTrue(any("does not keep state" in " ".join(r.unsupported) for r in policy.rules))
        self.assertEqual(policy.address_context, "internal-real")
        rows = self.compare("vendor-access-pfsense.xml")
        self.assertEqual(rows[("198.51.100.50", "10.40.0.10", 3389, "tcp")]["outcome"], "indeterminate")

    def test_C08_traffic_that_does_not_cross_a_device_is_separated(self):
        for name in self.policy_ids:
            c = self.svc.compare(self.pid, self.policy_ids[name])
            self.assertGreater(len(c["rows"]), c["crossing"], name)
            self.assertGreater(c["crossing"], 0, name)


class MigrationLessonTests(RiverbendCase):
    def test_M01_preserve_to_group_policies_reports_blocked_rules_lost_services_and_deny_rules(self):
        plan = self.plan(workflow="preserve", policy=self.policy_ids["perimeter-asa.cfg"])
        s = plan["summary"]
        self.assertGreater(s["blocked_rules"], 0)
        self.assertGreater(s["deny_rules_not_translated"], 0)
        self.assertIn("broadens access or drops restrictions", s["verdict"])

    def test_M02_narrow_proposals_flag_group_aggregation(self):
        plan = self.plan(workflow="narrow")
        broad = [p for p in plan["policies"] if p["from_groups"] == ["Corporate IT"] or p["to_groups"] == ["Corporate IT"]]
        self.assertTrue(broad)
        self.assertTrue(all(p["broadens"] for p in broad))
        self.assertGreater(plan["summary"]["policies_that_broaden_access"], len(plan["policies"]) // 2)

    def test_M03_ios_destination_gets_return_rules_and_an_ipv6_default_deny(self):
        t = self.svc.translation_json(self.pid, {"workflow": "preserve", "policy": self.policy_ids["ops-field-fortios.conf"], "target": "cisco-ios",
                                                 "zone_map": {"ops": "Vlan20", "cell1": "Vlan11", "cell2": "Vlan12", "field": "Vlan11"}})
        self.assertGreater(t["summary"]["return_rules_added"], 0)
        self.assertIn("deny ipv6 any any", t["text"])
        self.assertIn("not a stateful check", " ".join(i["message"] for i in t["issues"]))

    def test_M04_translating_fortios_to_asa_blocks_what_asa_cannot_express_and_validates(self):
        t = self.svc.translation_json(self.pid, {"workflow": "preserve", "policy": self.policy_ids["ops-field-fortios.conf"], "target": "cisco-asa",
                                                 "zone_map": {}})
        reasons = {e["source_rule"]: e["reason"] for e in t["report"] if e["status"] == "blocked"}
        self.assertTrue(reasons)
        self.assertEqual(t["validation"]["summary"]["unexplained_broader"], 0)

    def test_M05_every_configuration_translates_to_every_destination_without_unexplained_broadening(self):
        ctx = self.svc.context(self.svc.project(self.pid))
        for name, text in configs().items():
            source = parse_config(text, "src")
            for target in fw.TARGETS:
                t = fw.translate_policy(source, target, {}, ctx=ctx)
                fw.render(t, target)
                summary = val.validate_preserve(source, t, ctx)["summary"]
                self.assertEqual(summary["unexplained_broader"], 0, f"{name} -> {target}")


if __name__ == "__main__":
    unittest.main()
