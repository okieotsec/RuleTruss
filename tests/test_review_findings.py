"""Regression tests for the defects an independent reviewer (CP15) found in the parsers. Each case is the reviewer's trigger, reduced to
the smallest input, with the behaviour that must hold. They were run against the code as reviewed and failed there."""
import contextlib
import copy
import http.server
import json
import os
import re
import struct
import sys
import tempfile
import threading
import unittest
from pathlib import Path

import dpkt

from ruletruss import limits, service
from ruletruss.adapters import unifi
from ruletruss.adapters.registry import parse_config
from ruletruss.capture import zeek
from ruletruss.capture.flows import analyze_capture_full
from ruletruss.evaluate import INDETERMINATE, Probe, evaluate
from ruletruss.migrate.firewall import render, translate_policy
from ruletruss.model import PolicySet, Rule, to_plain
from ruletruss.store import Store

sys.path.insert(0, str(Path(__file__).resolve().parent))
import unifi_zones


def parse(text, fmt):
    return parse_config(text, "s", fmt)


def codes(policy):
    return {i.code for i in policy.issues}


class LineAndCountLimitTests(unittest.TestCase):
    def test_a_line_over_the_limit_is_refused_not_cut_short(self):
        # cutting at 20,000 characters removed a trailing "inactive" and left an enabled permit-any rule
        line = "access-list A extended permit ip any any" + " " * limits.MAX_LINE_CHARS + "inactive"
        with self.assertRaises(limits.LimitExceeded):
            parse("hostname r\n" + line + "\n", "cisco-asa")

    def test_unifi_refuses_a_policy_list_over_the_limit_instead_of_dropping_the_rest(self):
        saved = unifi.MAX_ITEMS
        unifi.MAX_ITEMS = 5
        try:
            doc = {"ruletruss_unifi_export": 1, "zones": [], "networks": [], "traffic_matching_lists": [],
                   "policies": [{"id": f"{i:08d}-0000-4000-8000-000000000000", "name": f"p{i}", "action": {"type": "ALLOW"}} for i in range(6)]}
            with self.assertRaises(limits.LimitExceeded):
                parse(json.dumps(doc), "unifi")
        finally:
            unifi.MAX_ITEMS = saved

    def test_panos_pfsense_and_fortios_enforce_the_rule_limit(self):
        saved = limits.MAX_RULES
        limits.MAX_RULES = 20
        try:
            panos = ('<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase><security><rules>'
                     + "".join(f'<entry name="r{i}"><from><member>any</member></from><to><member>any</member></to><source><member>any</member></source>'
                               '<destination><member>any</member></destination><application><member>any</member></application>'
                               '<service><member>any</member></service><action>allow</action></entry>' for i in range(21))
                     + "</rules></security></rulebase></entry></vsys></entry></devices></config>")
            pfsense = ("<pfsense><interfaces><lan><if>em0</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan></interfaces><filter>"
                       + "".join(f"<rule><type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol><protocol>any</protocol>"
                                 f"<source><any/></source><destination><any/></destination><tracker>{i}</tracker></rule>" for i in range(21))
                       + "</filter></pfsense>")
            forti = ("config firewall policy\n" + "".join(f" edit {i}\n  set srcintf lan\n  set dstintf wan\n  set srcaddr all\n  set dstaddr all\n"
                                                         "  set action accept\n  set service ALL\n next\n" for i in range(1, 22)) + "end\n")
            for text, fmt in ((panos, "panos"), (pfsense, "pfsense"), (forti, "fortios")):
                with self.subTest(fmt), self.assertRaises(limits.LimitExceeded):
                    parse(text, fmt)
        finally:
            limits.MAX_RULES = saved


class GroupExpansionTests(unittest.TestCase):
    """A group that lists its predecessor twice, sixteen levels deep, is 65,536 entries from about a kilobyte of text."""

    def test_cisco_service_groups_stop_at_the_expansion_limit(self):
        lines = ["hostname r", "object-group service G0", " service-object tcp destination eq 80"]
        for i in range(1, 17):
            lines += [f"object-group service G{i}", f" group-object G{i - 1}", f" group-object G{i - 1}"]
        lines.append("access-list A extended permit object-group G16 any any")
        policy = parse("\n".join(lines) + "\n", "cisco-asa")
        self.assertIn("group-too-large", codes(policy))
        self.assertTrue(all(len(r.svc.entries) <= limits.MAX_EXPANSION for r in policy.rules))
        self.assertTrue(any(r.svc.unresolved for r in policy.rules), "a truncated group must leave the rule undecidable")

    def test_fortios_service_groups_stop_at_the_expansion_limit(self):
        text = ("config firewall service custom\n edit S0\n  set tcp-portrange 80\n next\nend\nconfig firewall service group\n"
                + "".join(f" edit G{i}\n  set member {'S0' if i == 1 else f'G{i - 1}'} {'S0' if i == 1 else f'G{i - 1}'}\n next\n" for i in range(1, 17))
                + "end\nconfig firewall policy\n edit 1\n  set srcintf lan\n  set dstintf wan\n  set srcaddr all\n  set dstaddr all\n"
                  "  set action accept\n  set service G16\n next\nend\n")
        policy = parse(text, "fortios")
        self.assertIn("group-too-large", codes(policy))
        self.assertTrue(all(len(r.svc.entries) <= limits.MAX_EXPANSION for r in policy.rules))

    def test_panos_service_groups_stop_at_the_expansion_limit(self):
        groups = "".join(f'<entry name="G{i}"><members><member>{"S0" if i == 1 else f"G{i - 1}"}</member>'
                         f'<member>{"S0" if i == 1 else f"G{i - 1}"}</member></members></entry>' for i in range(1, 17))
        text = ('<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">'
                '<service><entry name="S0"><protocol><tcp><port>80</port></tcp></protocol></entry></service>'
                f"<service-group>{groups}</service-group>"
                '<rulebase><security><rules><entry name="r"><from><member>any</member></from><to><member>any</member></to>'
                '<source><member>any</member></source><destination><member>any</member></destination>'
                '<application><member>any</member></application><service><member>G16</member></service><action>allow</action></entry>'
                "</rules></security></rulebase></entry></vsys></entry></devices></config>")
        policy = parse(text, "panos")
        self.assertIn("group-too-large", codes(policy))
        self.assertTrue(all(len(r.svc.entries) <= limits.MAX_EXPANSION for r in policy.rules))

    def test_pfsense_aliases_stop_at_the_expansion_limit(self):
        aliases = '<alias><name>A0</name><type>host</type><address>10.0.0.1</address></alias>' + "".join(
            f"<alias><name>A{i}</name><type>network</type><address>A{i - 1} A{i - 1}</address></alias>" for i in range(1, 17))
        text = ("<pfsense><interfaces><lan><if>em0</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan></interfaces>"
                f"<aliases>{aliases}</aliases><filter><rule><type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol>"
                "<protocol>any</protocol><source><address>A16</address></source><destination><any/></destination><tracker>1</tracker></rule>"
                "</filter></pfsense>")
        self.assertIn("group-too-large", codes(parse(text, "pfsense")))


class PfsenseIcmpTests(unittest.TestCase):
    TEMPLATE = ("<pfsense><interfaces><lan><if>em0</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan></interfaces><filter>"
                "<rule><type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol><protocol>icmp</protocol>{type}"
                "<source><any/></source><destination><any/></destination><tracker>1</tracker></rule></filter></pfsense>")

    def test_an_icmp_rule_with_no_type_or_with_any_is_every_icmp_message_not_an_import_failure(self):
        for extra in ("", "<icmptype>any</icmptype>"):
            with self.subTest(extra=extra):
                rule = parse(self.TEMPLATE.format(type=extra), "pfsense").rules[0]
                self.assertEqual([e.proto for e in rule.svc.entries], ["icmp"])
                self.assertFalse(rule.unsupported)

    def test_a_named_type_is_kept_and_an_unknown_one_makes_the_rule_undecidable(self):
        rule = parse(self.TEMPLATE.format(type="<icmptype>echoreq</icmptype>"), "pfsense").rules[0]
        self.assertEqual([e.icmp_type for e in rule.svc.entries], [8])
        self.assertTrue(parse(self.TEMPLATE.format(type="<icmptype>NOT_A_TYPE</icmptype>"), "pfsense").rules[0].unsupported)


class MalformedValueTests(unittest.TestCase):
    def survives(self, text, fmt):
        """Parsing may succeed or refuse with a user-safe message, but must not raise anything else."""
        with contextlib.suppress(ValueError):
            return parse(text, fmt)

    def test_a_range_that_mixes_ipv4_and_ipv6_is_not_a_crash(self):
        cisco = "hostname r\nobject network N\n range 10.0.0.1 2001:db8::1\naccess-list A extended permit ip object N any\n"
        forti = ("config firewall address\n edit N\n  set type iprange\n  set start-ip 10.0.0.1\n  set end-ip 2001:db8::1\n next\nend\n"
                 "config firewall policy\n edit 1\n  set srcintf lan\n  set dstintf wan\n  set srcaddr N\n  set dstaddr all\n"
                 "  set action accept\n  set service ALL\n next\nend\n")
        panos = ('<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">'
                 '<address><entry name="N"><ip-range>10.0.0.1-2001:db8::1</ip-range></entry></address>'
                 '<rulebase><security><rules><entry name="r"><from><member>any</member></from><to><member>any</member></to>'
                 '<source><member>N</member></source><destination><member>any</member></destination>'
                 '<application><member>any</member></application><service><member>any</member></service><action>allow</action></entry>'
                 "</rules></security></rulebase></entry></vsys></entry></devices></config>")
        for text, fmt in ((cisco, "cisco-asa"), (forti, "fortios"), (panos, "panos")):
            with self.subTest(fmt):
                policy = self.survives(text, fmt)
                if policy is not None:
                    self.assertTrue(any(r.src.unresolved for r in policy.rules), "the bad range must leave the rule undecidable")

    def test_pfsense_ipv6_interface_host_keeps_its_full_prefix(self):
        text = ("<pfsense><interfaces><lan><if>em0</if><ipaddr>2001:db8::1</ipaddr><subnet>64</subnet></lan></interfaces>"
                "<filter><rule><type>pass</type><interface>lan</interface><ipprotocol>inet6</ipprotocol><protocol>any</protocol>"
                "<source><network>lanip</network></source><destination><any/></destination><tracker>1</tracker></rule></filter></pfsense>")
        policy = parse(text, "pfsense")
        self.assertEqual(policy.interfaces["lan"]["host_ips"], ["2001:db8::1/128"])

    def test_an_unknown_pfsense_icmp_type_is_not_read_as_all_icmp(self):
        text = ("<pfsense><interfaces><lan><if>em0</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></lan></interfaces><filter>"
                "<rule><type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol><protocol>icmp</protocol>"
                "<icmptype>NOT_A_TYPE</icmptype><source><any/></source><destination><any/></destination><tracker>1</tracker></rule>"
                "</filter></pfsense>")
        rule = parse(text, "pfsense").rules[0]
        self.assertTrue(rule.svc.unresolved or rule.unsupported, "an ICMP type nobody could read must not become 'every ICMP type'")


class CaptureValueTests(unittest.TestCase):
    def write_pcap(self, nanoseconds):
        packet = bytes(dpkt.ip.IP(src=b"\x0a\x00\x00\x01", dst=b"\x0a\x00\x00\x02", p=17, data=bytes(dpkt.udp.UDP(sport=1000, dport=53, data=b"x"))))
        magic = b"\x4d\x3c\xb2\xa1" if nanoseconds else b"\xd4\xc3\xb2\xa1"
        header = magic + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 101)
        record = struct.pack("<IIII", 1700000000, 123456789 if nanoseconds else 123456, len(packet), len(packet))
        handle, path = tempfile.mkstemp(suffix=".pcap")
        with os.fdopen(handle, "wb") as out:
            out.write(header + record + packet)
        self.addCleanup(os.unlink, path)
        return path

    def test_a_nanosecond_pcap_can_be_analysed_and_serialised(self):
        for nanoseconds in (False, True):
            with self.subTest(nanoseconds=nanoseconds):
                info, flows, devices = analyze_capture_full(self.write_pcap(nanoseconds), "c", "c", "x.pcap")
                self.assertEqual(len(flows), 1)
                json.dumps({"info": to_plain(info), "flows": to_plain(flows), "devices": to_plain(devices)}, allow_nan=False)

    def test_zeek_rows_with_impossible_ports_or_durations_are_errors_not_flows(self):
        head = ("#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes"
                "\tconn_state\thistory\torig_pkts\tresp_pkts\n")
        rows = ("1700000000.0\tC1\t10.0.0.1\t1000\t10.0.0.2\t-1\ttcp\t-\t1.0\t1\t1\tSF\tShADadFf\t1\t1\n"
                "1700000000.0\tC2\t10.0.0.1\t1000\t10.0.0.2\t65536\ttcp\t-\t1.0\t1\t1\tSF\tShADadFf\t1\t1\n"
                "1700000000.0\tC3\t10.0.0.1\t1000\t10.0.0.2\t1.9\ttcp\t-\t1.0\t1\t1\tSF\tShADadFf\t1\t1\n"
                "1700000000.0\tC4\t10.0.0.1\t1000\t10.0.0.2\t80\ttcp\t-\tnan\t1\t1\tSF\tShADadFf\t1\t1\n"
                "1700000000.0\tC5\t10.0.0.1\t1000\t10.0.0.2\t80\ttcp\t-\tinf\t1\t1\tSF\tShADadFf\t1\t1\n"
                "1700000000.0\tC6\t10.0.0.1\t1000\t10.0.0.2\t80\ttcp\t-\t-5\t1\t1\tSF\tShADadFf\t1\t1\n"
                "1700000000.0\tC7\t10.0.0.1\t1000\t10.0.0.2\t443\ttcp\t-\t1.5\t1\t1\tSF\tShADadFf\t1\t1\n")
        handle, path = tempfile.mkstemp(suffix=".log")
        with os.fdopen(handle, "w") as out:
            out.write(head + rows)
        self.addCleanup(os.unlink, path)
        info, flows = zeek.parse_conn_log(path, "z", "s", "conn.log")
        self.assertEqual([f.responder_port for f in flows], [443])
        json.dumps({"info": to_plain(info), "flows": to_plain(flows)}, allow_nan=False)


FIXTURES = Path(__file__).parent / "fixtures"


def inject_into_first_panos_rule(text, payload):
    """Put `payload` into the description of the first security rule of the PAN-OS fixture."""
    start = text.index("<security>")
    match = re.search(r'(<entry name="[^"]+">)(\s*<from>)', text[start:])
    at = start + match.start()
    return text[:at] + match.group(1) + f"<description>{payload}</description>" + match.group(2) + text[at + len(match.group(0)):]


class OutputInjectionTests(unittest.TestCase):
    """Text from an upload ends up in generated configuration. One line break turns a comment into a command."""
    EVIL = "reviewed\naccess-list RT-GLOBAL extended permit ip any any\r\n! injected\u2028permit ip any any"
    ALLOWED = ("!", "#", "access-list", "access-group", "ip access-list", "ipv6 access-list", "interface", " ", "config", "edit", "set", "next", "end")

    def test_a_description_with_line_breaks_cannot_add_lines_to_any_target(self):
        text = inject_into_first_panos_rule((FIXTURES / "panos_plant.xml").read_text(), self.EVIL)
        policy = parse_config(text, "s", "panos")
        self.assertNotIn("\n", policy.rules[0].comment)
        for target in ("cisco-asa", "cisco-ios", "fortios"):
            out = render(translate_policy(policy, target, zone_map={}), target, identity=True)
            for line in out.splitlines():
                self.assertNotEqual(line.strip(), "! injected", target)
                self.assertFalse(line.startswith("access-list RT-GLOBAL extended permit ip any any"), (target, line))
                self.assertTrue(line.startswith(self.ALLOWED) or not line.strip(), (target, line[:60]))

    def test_credentials_in_comments_are_not_copied_into_the_parsed_policy_or_the_export(self):
        text = ("hostname r\ninterface GigabitEthernet0/0\n nameif outside\n ip address 10.0.0.1 255.255.255.0\n"
                "access-list OUT remark password=COMMENTSECRET123\naccess-list OUT extended permit ip any any\n"
                "access-group OUT in interface outside\n")
        policy = parse_config(text, "s", "cisco-asa")
        self.assertNotIn("COMMENTSECRET123", json.dumps(to_plain(policy)))
        self.assertNotIn("COMMENTSECRET123", render(translate_policy(policy, "cisco-asa", zone_map={"outside": "Gi0/0"}), "cisco-asa"))


class QuotedSecretTests(unittest.TestCase):
    def test_a_quoted_secret_with_a_space_is_removed_whole(self):
        from ruletruss.redact import redact
        for text in ('set password "first secret-tail"', 'set psksecret ENC "alpha beta gamma"', 'password: "two words"', "token='x y z'"):
            with self.subTest(text):
                out = redact(text)
                for leak in ("secret-tail", "beta", "gamma", "two words", "words", "x y z", "y z"):
                    self.assertNotIn(leak, out)


class OversizedRuleTests(unittest.TestCase):
    def test_a_rule_needing_more_lines_than_are_written_blocks_deployment_and_is_never_partly_written(self):
        lines = ["ASA Version 9.16(1)", "hostname t", "interface GigabitEthernet0/0", " nameif inside", " security-level 100",
                 " ip address 10.0.0.1 255.255.255.0", "object-group network SRC"]
        lines += [f" network-object host 10.1.0.{i}" for i in range(1, 51)] + ["object-group network DST"]
        lines += [f" network-object host 10.2.0.{i}" for i in range(1, 51)]
        lines += ["access-list IN extended permit tcp object-group SRC object-group DST eq 443", "access-group IN in interface inside"]
        translation = translate_policy(parse_config("\n".join(lines) + "\n", "s", "cisco-asa"), "cisco-asa", zone_map={"inside": "Gi0/0"})
        text = render(translation, "cisco-asa")
        self.assertFalse(translation.deployable)
        self.assertEqual(sum(1 for line in text.splitlines() if " extended permit" in line), 0, "a partly written rule permits less than the source")
        self.assertFalse(any("TRUNCATED" in line for line in text.splitlines()))
        self.assertEqual(translation.report[0]["disposition"], "unsupported")


class EvaluatorTests(unittest.TestCase):
    def test_an_earlier_maybe_matching_rule_of_the_other_action_keeps_the_answer_open_even_when_a_later_rule_agrees(self):
        rules = [Rule("p#1", "a", 1, "allow", unsupported=["condition one"]), Rule("p#2", "b", 2, "deny", unsupported=["condition two"]),
                 Rule("p#3", "c", 3, "allow")]
        decision = evaluate(PolicySet("p", "s", "cisco-asa", rules=rules), Probe("10.0.0.1", "10.0.0.2", "tcp", 1000, 80))
        self.assertEqual(decision.outcome, INDETERMINATE)

    def test_a_known_source_mac_does_not_settle_a_destination_mac_condition(self):
        doc = json.loads(unifi_zones.text(False))
        rule = copy.deepcopy(next(p for p in doc["policies"] if p["name"] == "ALLOW OT Lab -> SOC"))
        rule.update(id="ffffffff-0000-4000-8000-000000000001", name="block by two MACs", index=9999, action={"type": "BLOCK"})
        rule["source"]["trafficFilter"] = {"type": "MAC_ADDRESS", "macAddressFilter": {"macAddresses": ["aa:aa:aa:aa:aa:aa"]}}
        rule["destination"]["trafficFilter"] = {"type": "MAC_ADDRESS", "macAddressFilter": {"macAddresses": ["bb:bb:bb:bb:bb:bb"]}}
        doc["policies"].append(rule)
        policy = parse(json.dumps(doc), "unifi")
        probe = Probe("10.0.101.5", "10.0.100.5", "tcp", 40000, 443, src_zone="OT Lab", dst_zone="SOC Services", src_mac="aa:aa:aa:aa:aa:aa")
        self.assertEqual(evaluate(policy, probe).outcome, INDETERMINATE, "the destination MAC is unknown, so the block might apply")


class AiRedirectTests(unittest.TestCase):
    def test_the_ai_request_does_not_follow_a_redirect_to_an_address_that_was_never_checked(self):
        hits = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                hits.append(("POST", self.path))
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if self.path == "/chat":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{self.server.server_address[1]}/elsewhere")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"{}")

            def do_GET(self):
                hits.append(("GET", self.path))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *args):
                return

        srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        svc = service.Service(Store(tempfile.mkdtemp()), ai_endpoint=f"http://127.0.0.1:{srv.server_address[1]}/chat")
        pid = svc.store.create_project("x")["id"]
        with self.assertRaises(service.ApiError):
            svc.ai_ask(pid, "summary")
        self.assertEqual(hits, [("POST", "/chat")], "the redirect target must never be requested")


class IcmpCodeTests(unittest.TestCase):
    ROWS = ("#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes"
            "\tconn_state\thistory\torig_pkts\tresp_pkts\n"
            "1700000000.0\tC1\t10.0.0.1\t3\t10.0.0.2\t3\ticmp\t-\t0.1\t1\t0\tOTH\t-\t1\t0\n"
            "1700000001.0\tC2\t10.0.0.1\t3\t10.0.0.2\t1\ticmp\t-\t0.1\t1\t0\tOTH\t-\t1\t0\n")

    def test_observed_icmp_codes_are_kept_apart_and_reach_the_decision(self):
        from ruletruss.analysis import aggregate, build_context, probe_for
        handle, path = tempfile.mkstemp(suffix=".log")
        with os.fdopen(handle, "w") as out:
            out.write(self.ROWS)
        self.addCleanup(os.unlink, path)
        _, flows = zeek.parse_conn_log(path, "z", "s", "conn.log")
        comms = aggregate(flows)
        self.assertEqual(sorted(c.icmp_code for c in comms), [1, 3], "two codes of one type are two communications")
        policy = PolicySet("p", "s", "cisco-asa")
        self.assertEqual(sorted(probe_for(c, build_context(), policy).icmp_code for c in comms), [1, 3])


if __name__ == "__main__":
    unittest.main()
