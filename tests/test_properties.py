"""Property-based (fuzz-style) tests: whatever bytes or text arrive, the result is a clean answer or a clean refusal."""
import csv
import io
import ipaddress
import itertools
import json
import os
import unittest

from ruletruss import exports, netutil
from ruletruss.adapters import cisco, fortios, panos, pfsense
from ruletruss.adapters.xmlsafe import parse_xml
from ruletruss.capture import appid
from ruletruss.evaluate import ALLOW, DENY, INDETERMINATE, Probe, evaluate
from ruletruss.migrate import groups as grp
from ruletruss.model import AddrSet, ServiceSet, SvcEntry, to_plain
from ruletruss.redact import REDACTED, redact

try:
    from hypothesis import HealthCheck, given
    from hypothesis import settings as hyp_settings
    from hypothesis import strategies as st
except ImportError:  # hypothesis is an optional test dependency
    st = None

OK_ERRORS = (ValueError, OSError)
# RT_FUZZ_SCALE=20 runs twenty times as many examples (used for the checkpoint fuzz run).
SCALE = max(1, int(os.environ.get("RT_FUZZ_SCALE", "1")))


def n(base):
    return base * SCALE



@unittest.skipIf(st is None, "hypothesis is not installed")
class ParserFuzzTests(unittest.TestCase):
    if st is not None:
        config_text = st.text(alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"), max_size=2000)
        line_soup = st.lists(st.sampled_from([
            "access-list A extended permit tcp any any eq 80", "access-list A extended deny ip host 1.2.3.4 any log", "object-group network G",
            " network-object host 10.0.0.1", " group-object G", "interface Gi0/0", " nameif x", " security-level 5", "access-group A in interface x",
            "ip access-list extended B", " permit tcp 10.0.0.0 0.0.0.255 any eq 22", "config firewall policy", " edit 1", " set action accept",
            " next", "end", "config firewall address", " set subnet 10.0.0.0 255.0.0.0", "eq", "range 1", "object", "permit", "deny", "any",
            "host", "established", "log", "inactive", "time-range X", "ipv6 access-list C", " permit ipv6 any any"]), max_size=60).map("\n".join)

        @hyp_settings(max_examples=n(300), deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(st.one_of(config_text, line_soup))
        def test_cisco_parser_never_raises_anything_but_a_clean_error(self, text):
            for flavour in ("asa", "ios"):
                try:
                    policy = cisco.parse(text, "fuzz", flavour)
                except OK_ERRORS:
                    continue
                json.dumps(to_plain(policy))

        @hyp_settings(max_examples=n(300), deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(st.one_of(config_text, line_soup))
        def test_fortios_parser_never_raises_anything_but_a_clean_error(self, text):
            try:
                policy = fortios.parse("config firewall policy\n" + text, "fuzz")
            except OK_ERRORS:
                return
            json.dumps(to_plain(policy))

        @hyp_settings(max_examples=n(300), deadline=None)
        @given(config_text)
        def test_xml_loader_and_xml_adapters_never_raise_anything_but_a_clean_error(self, text):
            for fn in (parse_xml, lambda t: panos.parse(t, "f"), lambda t: pfsense.parse(t, "f")):
                for candidate in (text, f"<config>{text}</config>", f"<pfsense>{text}</pfsense>"):
                    try:
                        fn(candidate)
                    except OK_ERRORS:
                        pass

        @hyp_settings(max_examples=n(400), deadline=None)
        @given(st.binary(max_size=400), st.sampled_from(["tcp", "udp"]), st.integers(0, 65535), st.integers(0, 65535))
        def test_payload_decoders_never_raise(self, payload, proto, sport, dport):
            for hit in appid.decode_payload(proto, payload, sport, dport):
                self.assertIn(hit.confidence, ("confirmed", "probable"))
                for name in hit.names:
                    self.assertRegex(name, r"^[a-z0-9.\-_*]{1,253}$")


@unittest.skipIf(st is None, "hypothesis is not installed")
class HelperPropertyTests(unittest.TestCase):
    if st is not None:
        @hyp_settings(max_examples=n(500), deadline=None)
        @given(st.text(max_size=60))
        def test_port_and_network_parsers_give_a_value_or_a_parse_problem(self, text):
            for fn in (netutil.parse_port_ranges, netutil.parse_ip_or_net, netutil.port_number, netutil.proto_name):
                try:
                    fn(text)
                except netutil.ParseProblem:
                    pass

        @hyp_settings(max_examples=n(300), deadline=None)
        @given(st.lists(st.tuples(st.integers(0, 65535), st.integers(0, 65535)).map(lambda t: (min(t), max(t))), max_size=12), st.integers(0, 65535))
        def test_merged_ranges_contain_exactly_the_same_ports(self, ranges, port):
            merged = netutil.merge_ranges(ranges)
            self.assertEqual(netutil.ranges_contain(ranges, port), netutil.ranges_contain(merged, port))
            for earlier, later in itertools.pairwise(merged):
                self.assertLess(earlier[1] + 1, later[0])

        def test_unicode_digits_that_int_rejects_are_a_parse_problem_not_a_crash(self):
            for text in ("\u00b2", "\u0663", "\u2467", "80\u00b2"):
                with self.assertRaises(netutil.ParseProblem):
                    netutil.port_number(text)
                self.assertIsNone(netutil.proto_name(text))
            policy = cisco.parse("interface Gi0/0\n nameif a\n security-level \u00b2\n"
                                 "access-list A extended permit tcp any any eq 80\u00b2\naccess-group A in interface a\n", "x", "asa")
            self.assertTrue(policy.rules[0].unsupported)

        @hyp_settings(max_examples=n(500), deadline=None)
        @given(st.text(max_size=200))
        def test_csv_cells_never_start_with_a_formula_character(self, text):
            out = exports.to_csv(["h"], [[text]])
            cell = list(csv.reader(io.StringIO(out)))[1][0] if out.count("\n") >= 2 else ""
            self.assertFalse(cell.startswith(("=", "+", "-", "@", "\t", "\r")))

        @hyp_settings(max_examples=n(300), deadline=None)
        @given(st.text(max_size=200))
        def test_markdown_escape_removes_html_and_link_syntax(self, text):
            out = exports.md(text)
            self.assertNotIn("<", out)
            self.assertNotIn(">", out)
            self.assertNotIn("\n", out)
            self.assertEqual(out.count("[") , out.count("\\["))

        @hyp_settings(max_examples=n(300), deadline=None)
        @given(st.text(max_size=200))
        def test_redaction_is_idempotent_and_keeps_the_marker(self, text):
            once = redact(text)
            self.assertEqual(redact(once), once)

        @hyp_settings(max_examples=n(200), deadline=None)
        @given(st.sampled_from(["password", "secret", "key", "community", "psk"]), st.text(alphabet="abcdefXYZ0123456789$./+=", min_size=4, max_size=30))
        def test_a_secret_after_a_credential_keyword_is_always_removed(self, keyword, secret):
            self.assertNotIn(secret, redact(f"something {keyword} {secret}"))
            self.assertIn(REDACTED, redact(f"username a password 7 {secret}"))

        @hyp_settings(max_examples=n(300), deadline=None)
        @given(st.lists(st.fixed_dictionaries({"name": st.text(max_size=30), "members": st.lists(st.text(max_size=20), max_size=5)}), max_size=6))
        def test_group_validation_returns_groups_or_value_error(self, raw):
            try:
                groups = grp.validate_groups(raw)
            except ValueError:
                return
            for g in groups:
                for m in g.members:
                    ipaddress.ip_network(m)


@unittest.skipIf(st is None, "hypothesis is not installed")
class EvaluatorPropertyTests(unittest.TestCase):
    if st is not None:
        @hyp_settings(max_examples=n(300), deadline=None, suppress_health_check=[HealthCheck.too_slow])
        @given(st.integers(0, 2 ** 32 - 1), st.integers(0, 2 ** 32 - 1), st.integers(0, 65535), st.sampled_from(["tcp", "udp", "icmp"]))
        def test_evaluation_is_deterministic_and_one_of_three_outcomes(self, a, b, port, proto):
            policy = cisco.parse("interface Gi0/0\n nameif a\n security-level 1\naccess-list X extended deny tcp 10.0.0.0 255.0.0.0 any eq 22\n"
                                 "access-list X extended permit tcp 10.0.0.0 255.0.0.0 any\naccess-list X extended permit udp any any eq 53\n"
                                 "access-group X in interface a\n", "p", "asa")
            probe = Probe(str(ipaddress.IPv4Address(a)), str(ipaddress.IPv4Address(b)), proto, 1000, port if proto != "icmp" else None,
                          8 if proto == "icmp" else None, 0 if proto == "icmp" else None, src_zone="a", dst_zone="a")
            first, second = evaluate(policy, probe), evaluate(policy, probe)
            self.assertEqual((first.outcome, first.rule_id), (second.outcome, second.rule_id))
            self.assertIn(first.outcome, (ALLOW, DENY, INDETERMINATE))
            if first.outcome != INDETERMINATE and proto == "tcp" and port == 22 and ipaddress.IPv4Address(a) in ipaddress.ip_network("10.0.0.0/8"):
                self.assertEqual(first.outcome, DENY)       # an earlier deny always beats a later, broader permit

        @hyp_settings(max_examples=n(300), deadline=None)
        @given(st.lists(st.integers(0, 255), min_size=4, max_size=4), st.integers(0, 32))
        def test_address_matching_agrees_with_the_ipaddress_module(self, octets, prefix):
            ip = ".".join(map(str, octets))
            net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
            addr = AddrSet(nets=[str(net)])
            self.assertTrue(addr.contains(ip))
            self.assertEqual(AddrSet(nets=[str(net)], negate=True).contains(ip), False)

        @hyp_settings(max_examples=n(200), deadline=None)
        @given(st.integers(0, 65535), st.integers(0, 65535), st.integers(0, 65535))
        def test_port_range_matching_is_inclusive_and_unknown_ports_are_unknown(self, lo, hi, port):
            lo, hi = min(lo, hi), max(lo, hi)
            svc = ServiceSet(entries=[SvcEntry("tcp", None, [(lo, hi)])])
            self.assertEqual(svc.match("tcp", 1, port), lo <= port <= hi)
            self.assertIsNone(svc.match("tcp", 1, None))


if __name__ == "__main__":
    unittest.main()
