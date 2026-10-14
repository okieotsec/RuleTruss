"""The optional vendor-name download: nothing is shipped, nothing is fetched unless asked, and what is fetched is treated as untrusted."""
import csv
import gzip
import http.client
import json
import os
import re
import socket
import stat
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from ruletruss import isolate, oui, oui_build, server
from ruletruss.samples import create_riverbend, vendor_names
from ruletruss.service import ApiError, Service
from ruletruss.store import Store

ROOT = Path(__file__).resolve().parent.parent
HEADER = ["Registry", "Assignment", "Organization Name", "Organization Address"]


def write_listings(folder, count=30_500, extra=()):
    """Three CSV files in the IEEE format with invented organisations."""
    with open(os.path.join(folder, "oui.csv"), "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(HEADER)
        for i in range(count):
            writer.writerow(["MA-L", f"{0x100000 + i:06X}", f"Test Organisation {i}", "Nowhere"])
        for row in extra:
            writer.writerow(row)
    for name, kind, width in (("oui28.csv", "MA-M", 7), ("oui36.csv", "MA-S", 9)):
        with open(os.path.join(folder, name), "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(HEADER)
            writer.writerow([kind, f"{0xABC:0{width}X}", f"Test {kind} Holder", "Nowhere"])


class BuilderTests(unittest.TestCase):
    def build(self, extra=(), count=30_500):
        with tempfile.TemporaryDirectory() as folder:
            write_listings(folder, count, extra)
            return oui_build.build(folder)

    def test_prefixes_and_names_are_kept_and_nothing_else(self):
        rows = self.build()
        self.assertEqual(rows["100000"], ("MA-L", "Test Organisation 0"))
        self.assertEqual(rows["0000ABC"][0], "MA-M")
        self.assertEqual(rows["000000ABC"][0], "MA-S")
        self.assertNotIn("Nowhere", json.dumps(rows))           # the address column is dropped

    def test_hostile_rows_are_dropped_or_cleaned(self):
        rows = self.build([["MA-L", "ZZZZZZ", "bad hex", ""], ["MA-L", "12345", "short", ""], ["XX-L", "ABCDEF", "bad kind", ""],
                           ["MA-L", "ABCDE0", "=cmd|'/C calc'!A0\x1b[31m" + chr(0x202E) + "x" * 500, ""], ["MA-L", "ABCDE1", "   ", ""],
                           ["MA-L", "ABCDE2", "<img src=x onerror=alert(1)>", ""]])
        self.assertNotIn("ZZZZZZ", rows)
        self.assertNotIn("12345", rows)
        self.assertNotIn("ABCDEF", rows)
        name = rows["ABCDE0"][1]
        self.assertTrue(name.isascii() and name.isprintable() and len(name) <= 80, name)
        self.assertEqual(rows["ABCDE1"][1], "Private (registrant not published)")
        self.assertEqual(rows["ABCDE2"][1], "<img src=x onerror=alert(1)>")      # kept as text; every place that shows it escapes it

    def test_files_that_are_not_ieee_listings_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            for name in oui_build.SOURCES:
                Path(folder, name).write_text("<html>captive portal</html>\n", encoding="utf-8")
            with self.assertRaises(oui_build.BuildError) as raised:
                oui_build.build(folder)
        self.assertIn("do not look like", str(raised.exception))
        with tempfile.TemporaryDirectory() as folder, self.assertRaises(oui_build.BuildError):
            oui_build.build(folder)                              # files missing
        with tempfile.TemporaryDirectory() as folder:
            for name in oui_build.SOURCES:
                Path(folder, name).write_bytes(b"\xff\xfe\x00binary")
            with self.assertRaises(oui_build.BuildError):
                oui_build.build(folder)

    def test_the_written_file_is_private_and_reads_back(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sub", "oui.tsv.gz")
            oui_build.write({"001122": ("MA-L", "Example")}, path)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            registry = oui.Registry(path)
            self.assertEqual(registry.lookup("00:11:22:33:44:55")["vendor"], "Example")
            self.assertEqual(os.listdir(os.path.dirname(path)), ["oui.tsv.gz"])          # no temp file left behind


class DownloadRuleTests(unittest.TestCase):
    def test_only_https_on_the_ieee_host_is_allowed(self):
        for url in oui_build.SOURCES.values():
            self.assertTrue(oui_build.allowed_host(url))
        for url in ("http://standards-oui.ieee.org/oui/oui.csv", "https://ieee.org.evil.example/x", "https://evilieee.org/x",
                    "https://user@standards-oui.ieee.org/x", "https://standards-oui.ieee.org:8443/x", "file:///etc/passwd",
                    "https://example.com/oui.csv", "ftp://standards-oui.ieee.org/x"):
            self.assertFalse(oui_build.allowed_host(url), url)

    def test_a_redirect_off_the_ieee_host_is_refused(self):
        handler = oui_build._OnlyIeee()
        request = mock.Mock(full_url="https://standards-oui.ieee.org/oui/oui.csv", headers={}, origin_req_host="x", unverifiable=False,
                            data=None, get_method=lambda: "GET")
        with self.assertRaises(urllib.error.URLError):
            handler.redirect_request(request, None, 302, "Found", {}, "https://evil.example/oui.csv")
        with self.assertRaises(urllib.error.URLError):
            handler.redirect_request(request, None, 302, "Found", {}, "http://standards-oui.ieee.org/oui/oui.csv")

    def test_the_source_list_itself_is_all_ieee(self):
        self.assertTrue(all(oui_build.allowed_host(u) for u in oui_build.SOURCES.values()))


class RegistryFileTests(unittest.TestCase):
    def test_missing_corrupt_and_oversized_files_mean_no_names_not_a_crash(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "n.tsv.gz")
            registry = oui.Registry(path)
            self.assertFalse(registry.available())
            Path(path).write_bytes(b"not gzip at all")
            self.assertFalse(oui.Registry(path).available())
            with gzip.open(path, "wt") as handle:
                handle.write("#retrieved 2026-01-01\nno-tabs-here\n")
            self.assertFalse(oui.Registry(path).available())
            oui_build.write({f"{i:06X}": ("MA-L", "x") for i in range(50)}, path)
            with mock.patch.object(oui, "MAX_TABLE_LINES", 10):
                self.assertFalse(oui.Registry(path).available())
            self.assertTrue(oui.Registry(path).available())

    def test_a_replaced_file_is_picked_up_without_a_restart(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "n.tsv.gz")
            oui_build.write({"001122": ("MA-L", "First")}, path)
            registry = oui.Registry(path)
            self.assertEqual(registry.lookup("00:11:22:00:00:01")["vendor"], "First")
            oui_build.write({"001122": ("MA-L", "Second Owner")}, path)
            self.assertEqual(registry.lookup("00:11:22:00:00:01")["vendor"], "Second Owner")


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.service = Service(Store(self.dir.name))

    def test_nothing_is_loaded_at_first_and_the_file_lives_in_the_data_folder(self):
        self.assertFalse(self.service.vendor_names()["available"])
        self.assertTrue(self.service.vendor_path.startswith(os.path.abspath(self.dir.name)))

    def fake_download(self, path, **_):
        vendor_names.install(path)
        return 12

    def test_update_then_remove(self):
        with mock.patch.object(isolate, "build_vendor_names", side_effect=self.fake_download) as build:
            info = self.service.update_vendor_names()
        build.assert_called_once()
        self.assertTrue(info["available"])
        self.assertEqual(self.service.registry.lookup("00:00:0c:00:00:01")["vendor"], "Example Networks Corp.")
        self.assertFalse(self.service.remove_vendor_names()["available"])
        self.assertFalse(os.path.exists(self.service.vendor_path))

    def test_repeated_requests_are_held_back_so_the_ieee_is_not_hammered(self):
        with mock.patch.object(isolate, "build_vendor_names", side_effect=self.fake_download) as build:
            self.service.update_vendor_names()
            with self.assertRaises(ApiError) as raised:
                self.service.update_vendor_names()
        self.assertEqual(raised.exception.status, 429)
        self.assertEqual(build.call_count, 1)

    def test_a_failed_download_is_reported_cleanly_and_leaves_no_file(self):
        failure = isolate.ParseFailure("could not download oui.csv from the IEEE")
        with mock.patch.object(isolate, "build_vendor_names", side_effect=failure), self.assertRaises(ApiError) as raised:
            self.service.update_vendor_names()
        self.assertEqual(raised.exception.status, 502)
        self.assertIn("could not download", str(raised.exception))
        self.assertFalse(self.service.vendor_names()["available"])

    def test_the_real_worker_process_builds_from_local_files_without_the_network(self):
        with tempfile.TemporaryDirectory() as folder:
            write_listings(folder)
            with mock.patch.object(socket, "getaddrinfo", side_effect=AssertionError("network used")):
                count = isolate.build_vendor_names(self.service.vendor_path, source_dir=folder)
        self.assertGreater(count, 30_000)
        self.assertTrue(self.service.registry.available())
        self.assertEqual(stat.S_IMODE(os.stat(self.service.vendor_path).st_mode), 0o600)

    def test_the_worker_reports_bad_files_without_a_traceback(self):
        with tempfile.TemporaryDirectory() as folder:
            for name in oui_build.SOURCES:
                Path(folder, name).write_text("nothing useful\n", encoding="utf-8")
            with self.assertRaises(isolate.ParseFailure) as raised:
                isolate.build_vendor_names(self.service.vendor_path, source_dir=folder)
        self.assertNotIn("Traceback", str(raised.exception))
        self.assertFalse(os.path.exists(self.service.vendor_path))


class NoNetworkUnlessAskedTests(unittest.TestCase):
    def test_a_full_analysis_opens_no_network_connection(self):
        def refuse(*_a, **_k):
            raise AssertionError("the application tried to use the network")
        with tempfile.TemporaryDirectory() as d, mock.patch.object(socket.socket, "connect", refuse), \
                mock.patch.object(socket, "getaddrinfo", refuse), mock.patch.object(socket, "create_connection", refuse):
            service = Service(Store(d))
            project = create_riverbend(service)
            overview = service.overview(project["id"])
            service.export(project["id"], {"kind": "devices-csv"})
            service.export(project["id"], {"kind": "devices-markdown"})
        self.assertFalse(overview["device_extras"]["snapshot"]["available"])
        self.assertTrue(any(d["mac"] for d in overview["inventory"]["devices"]))        # MACs work without any names
        self.assertFalse(any(d["nic_vendor"] for d in overview["inventory"]["devices"]))

    def test_only_the_download_module_and_the_ai_path_import_network_code(self):
        pattern = re.compile(r"^\s*(import|from)\s+(urllib\.request|http\.client|socket|requests|httpx|ssl|ftplib|smtplib|telnetlib)\b", re.M)
        allowed = {"oui_build.py", "service.py", "server.py"}      # service.py: the optional AI call; server.py: the loopback listener
        found = {p.name for p in (ROOT / "ruletruss").rglob("*.py") if pattern.search(p.read_text(encoding="utf-8"))}
        self.assertLessEqual(found, allowed, found - allowed)
        self.assertIn("urllib.request", (ROOT / "ruletruss" / "oui_build.py").read_text(encoding="utf-8"))

    def test_no_ieee_data_is_shipped_in_the_repository(self):
        shipped = [p for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts and ".venv" not in p.parts
                   and ((p.name.startswith("oui") and p.suffix in (".gz", ".csv", ".txt", ".tsv")) or p.name == "manuf")]
        self.assertEqual(shipped, [])


class ServerRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.srv = server.build_server("127.0.0.1", 0, cls.dir.name, token="test-token-1234567890")
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.dir.cleanup()

    def call(self, method, path, token=True, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        hdrs = {"Host": f"127.0.0.1:{self.port}", "Content-Length": "0"}
        if token:
            hdrs["Authorization"] = "Bearer test-token-1234567890"
        hdrs.update(headers or {})
        try:
            conn.request(method, path, headers=hdrs)
            response = conn.getresponse()
            body = response.read()
            return response.status, json.loads(body.decode()) if body else {}
        finally:
            conn.close()

    def test_the_download_needs_the_token_and_a_local_origin(self):
        for method in ("GET", "POST", "DELETE"):
            self.assertEqual(self.call(method, "/api/vendor-names", token=False)[0], 401, method)
        self.assertEqual(self.call("POST", "/api/vendor-names", headers={"Origin": "http://evil.example"})[0], 403)

    def test_status_reports_vendor_names_and_the_network_statement(self):
        status, body = self.call("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertFalse(body["vendor_names"]["available"])
        self.assertIn("only when you press its button", body["network"])

    def test_download_and_remove_through_the_api(self):
        def fake(path, **_):
            vendor_names.install(path)
            return 12
        with mock.patch.object(isolate, "build_vendor_names", side_effect=fake):
            status, body = self.call("POST", "/api/vendor-names")
        self.assertEqual((status, body["available"]), (200, True))
        self.assertEqual(self.call("POST", "/api/vendor-names")[0], 429)
        status, body = self.call("DELETE", "/api/vendor-names")
        self.assertEqual((status, body["available"]), (200, False))


if __name__ == "__main__":
    unittest.main()
