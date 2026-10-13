import os
import subprocess  # nosec B404 - runs the project's own worker with a fixed argument list
import sys
import tempfile
import textwrap
import time
import unittest

from pbridge import isolate, limits
from tests import malicious_cases

FORBIDDEN_IN_MESSAGES = ("Traceback", 'File "', "/ho" + "me/", "secretstring", "MYPSK", "0822455D0A16")
TIME_LIMIT = 90


class HostileInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.captures = malicious_cases.captures(cls.dir.name)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def attempt(self, name, path, timeout=TIME_LIMIT):
        started = time.monotonic()
        try:
            result = isolate.parse_file(path, "0123456789abcdef", name, "test", timeout=timeout)
            outcome = ("ok", result)
        except isolate.ParseFailure as error:
            message = str(error)
            for bad in FORBIDDEN_IN_MESSAGES:
                self.assertNotIn(bad, message, f"{name}: error message leaks {bad!r}")
            self.assertLess(len(message), 700, name)
            outcome = ("rejected", message)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, timeout, f"{name} took {elapsed:.1f}s")
        return outcome

    def write(self, name, data):
        path = os.path.join(self.dir.name, name)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def test_every_hostile_configuration_ends_safely(self):
        for name, data in malicious_cases.configs().items():
            with self.subTest(case=name):
                kind, detail = self.attempt(name, self.write(name, data))
                self.assertIn(kind, ("ok", "rejected"))

    def test_expected_rejections(self):
        expect_rejected = ("empty", "whitespace", "nul_bytes", "utf16", "binary_junk", "xml_billion_laughs", "xml_external_entity",
                           "xml_deep_nesting", "xml_unclosed", "xml_wrong_root", "asa_over_line_limit")
        configs = malicious_cases.configs()
        for name in expect_rejected:
            with self.subTest(case=name):
                kind, detail = self.attempt(name, self.write(name, configs[name]))
                self.assertEqual(kind, "rejected", f"{name} should be refused; got {detail!r:.200}")

    def test_entity_and_dtd_messages_explain_why(self):
        configs = malicious_cases.configs()
        for name in ("xml_billion_laughs", "xml_external_entity"):
            _, message = self.attempt(name, self.write(name, configs[name]))
            self.assertIn("DOCTYPE or entity", message)

    def test_group_loops_and_fan_out_are_bounded_not_followed(self):
        configs = malicious_cases.configs()
        for name in ("asa_group_cycle", "asa_group_chain_5000", "asa_group_exponential", "pan_cycle", "pfsense_many_aliases"):
            with self.subTest(case=name):
                kind, detail = self.attempt(name, self.write(name, configs[name]), timeout=60)
                self.assertEqual(kind, "ok", f"{name}: {detail!r:.200}")
                issues = {i["code"] for i in detail["policy"]["issues"]}
                self.assertTrue(issues & {"group-cycle", "group-too-deep", "group-too-large", "alias-hostname", "unresolved-object", "dynamic-group"} or
                                name == "pfsense_many_aliases", f"{name}: no warning about the loop: {issues}")

    def test_secrets_in_a_configuration_never_reach_the_parse_result(self):
        configs = malicious_cases.configs()
        kind, result = self.attempt("credential_dump", self.write("credential_dump", configs["credential_dump"]))
        self.assertEqual(kind, "ok")
        import json
        dump = json.dumps(result)
        for secret in ("$9$AAAA", "0822455D0A16", "secretstring", "MYPSK"):
            self.assertNotIn(secret, dump)

    def test_every_hostile_capture_ends_safely(self):
        for name, path in self.captures.items():
            with self.subTest(case=name):
                kind, detail = self.attempt(name, path)
                self.assertIn(kind, ("ok", "rejected"))

    def test_expected_capture_rejections_and_acceptances(self):
        for name in ("random_after_magic.pcap", "truncated_header.pcap", "pcapng_bogus_block.pcapng", "pcapng_truncated.pcapng"):
            kind, detail = self.attempt(name, self.captures[name])
            self.assertIn(kind, ("ok", "rejected"), name)
        kind, result = self.attempt("crafted", self.captures["crafted_payloads.pcap"])
        self.assertEqual(kind, "ok")
        self.assertGreater(len(result["flows"]), 3)
        kind, result = self.attempt("many", self.captures["many_flows.pcap"])
        self.assertEqual((kind, len(result["flows"])), ("ok", 3000))

    def test_crafted_payloads_do_not_produce_false_confirmations(self):
        _, result = self.attempt("crafted", self.captures["crafted_payloads.pcap"])
        by_port = {f["responder_port"]: f for f in result["flows"] if f["proto"] in ("tcp", "udp")}
        self.assertEqual([a for a in by_port[502]["apps"] if a["confidence"] == "confirmed"], [])     # Modbus length does not match
        for flow in result["flows"]:
            for name in flow["hostnames"]:
                self.assertRegex(name, r"^[a-z0-9.\-]{1,253}$")

    def test_flow_logs(self):
        for name, data in malicious_cases.flow_logs().items():
            with self.subTest(case=name):
                kind, detail = self.attempt(name, self.write(name, data))
                self.assertIn(kind, ("ok", "rejected"))
        kind, _ = self.attempt("nohdr", self.write("nohdr", malicious_cases.flow_logs()["zeek_no_header"]))
        self.assertEqual(kind, "rejected")


class IsolationTests(unittest.TestCase):
    def run_worker_snippet(self, code):
        # S603: a fixed argument vector running a snippet written in this test file.
        return subprocess.run([sys.executable, "-s", "-P", "-c", textwrap.dedent(code)], capture_output=True, timeout=60,  # noqa: S603
                              env={"PYTHONPATH": os.path.dirname(os.path.dirname(os.path.abspath(__file__)))}, check=False)

    @unittest.skipUnless(sys.platform != "win32", "resource limits are not available on Windows")
    def test_memory_limit_stops_a_runaway_parser(self):
        proc = self.run_worker_snippet("""
            from pbridge import limits, worker
            limits.PARSE_MEMORY_BYTES = 300 * 1024 * 1024
            worker.apply_limits()
            try:
                blob = bytearray(1500 * 1024 * 1024)
                print("allocated")
            except MemoryError:
                print("stopped")
        """)
        self.assertIn(b"stopped", proc.stdout)

    @unittest.skipUnless(sys.platform != "win32", "resource limits are not available on Windows")
    def test_file_size_and_core_limits_are_applied(self):
        proc = self.run_worker_snippet("""
            import resource
            from pbridge import worker
            worker.apply_limits()
            print(resource.getrlimit(resource.RLIMIT_CORE)[0], resource.getrlimit(resource.RLIMIT_NOFILE)[0],
                  resource.getrlimit(resource.RLIMIT_FSIZE)[0] > 0)
        """)
        self.assertEqual(proc.stdout.split(), [b"0", b"64", b"True"])

    def test_wall_clock_timeout_stops_a_slow_parse(self):
        with tempfile.TemporaryDirectory() as d:
            from pbridge.synthetic import CaptureBuilder
            builder = CaptureBuilder()
            for i in range(40000):
                builder.udp(i * 0.0001, f"10.{(i >> 8) & 255}.{i & 255}.1", 2000 + i % 5000, "10.9.9.9", 9000, b"x" * 20)
            path = os.path.join(d, "slow.pcap")
            builder.write(path)
            started = time.monotonic()
            with self.assertRaises(isolate.ParseFailure) as ctx:
                isolate.parse_file(path, "0123456789abcdef", "slow.pcap", timeout=0.2)
            self.assertIn("longer than", str(ctx.exception))
            self.assertLess(time.monotonic() - started, 10)

    def test_worker_does_not_inherit_the_environment(self):
        os.environ["PB_TEST_SECRET"] = "leak-me"
        try:
            with tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "x.cfg")
                with open(path, "w") as handle:
                    handle.write("hostname leak-me\naccess-list A extended permit ip any any\n")
                result = isolate.parse_file(path, "0123456789abcdef", "x.cfg")
                self.assertEqual(result["kind"], "policy")
        finally:
            del os.environ["PB_TEST_SECRET"]

    def test_parsers_do_not_import_networking_modules(self):
        import re
        root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pbridge")
        pattern = re.compile(r"^\s*(?:import|from)\s+(socket|urllib|http|ssl|requests|ftplib|smtplib|telnetlib|asyncio)\b", re.M)
        for folder in ("adapters", "capture", "migrate"):
            for name in os.listdir(os.path.join(root, folder)):
                if name.endswith(".py"):
                    with open(os.path.join(root, folder, name), encoding="utf-8") as handle:
                        self.assertIsNone(pattern.search(handle.read()), f"{folder}/{name} imports a networking module")
        for name in ("model.py", "evaluate.py", "analysis.py", "exports.py", "netutil.py", "redact.py", "limits.py", "store.py", "worker.py"):
            with open(os.path.join(root, name), encoding="utf-8") as handle:
                self.assertIsNone(pattern.search(handle.read()), f"{name} imports a networking module")

    def test_no_dynamic_code_execution_anywhere(self):
        import re
        root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pbridge")
        pattern = re.compile(r"\b(eval|exec|(?<!re\.)compile|__import__|pickle|marshal|shelve|yaml\.load|os\.system|shell=True)\b")
        for dirpath, _, files in os.walk(root):
            for name in files:
                if name.endswith(".py"):
                    with open(os.path.join(dirpath, name), encoding="utf-8") as handle:
                        for number, line in enumerate(handle, start=1):
                            code = line.split("#", 1)[0]
                            if '"' in code or "'" in code:
                                code = re.sub(r'"[^"]*"|\'[^\']*\'', '""', code)
                            self.assertIsNone(pattern.search(code), f"{name}:{number}: {line.strip()}")


class LimitsTests(unittest.TestCase):
    def test_large_configuration_is_refused_by_size(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "big.cfg")
            with open(path, "wb") as handle:
                handle.write(b"x" * (limits.MAX_CONFIG_BYTES + 1))
            with self.assertRaises(isolate.ParseFailure) as ctx:
                isolate.parse_file(path, "0123456789abcdef", "big.cfg")
            self.assertIn("limit", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
