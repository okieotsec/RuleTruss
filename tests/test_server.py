import http.client
import json
import os
import tempfile
import threading
import unittest

from ruletruss import limits, server
from ruletruss.synthetic import CaptureBuilder, modbus_request, modbus_response, plant_capture


class ServerCase(unittest.TestCase):
    ai_endpoint = None

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.srv = server.build_server("127.0.0.1", 0, cls.dir.name, ai_endpoint=cls.ai_endpoint, token="test-token-1234567890")
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.thread.join(5)
        cls.dir.cleanup()

    def request(self, method, path, body=None, headers=None, raw=False, token=True, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        hdrs = {"Host": host or f"127.0.0.1:{self.port}"}
        if token:
            hdrs["Authorization"] = "Bearer test-token-1234567890"
        hdrs.update(headers or {})
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            hdrs.setdefault("Content-Length", str(len(data)))
        try:
            conn.request(method, path, body=data, headers=hdrs)
            resp = conn.getresponse()
            payload = resp.read()
            if raw:
                return resp.status, resp, payload
            return resp.status, json.loads(payload.decode()) if payload else {}
        finally:
            conn.close()

    def upload(self, pid, data, name="x.bin", point=""):
        from urllib.parse import quote
        return self.request("POST", f"/api/projects/{pid}/sources?name={quote(name)}&observation_point={quote(point)}", data,
                            {"Content-Type": "application/octet-stream"})

    def new_project(self, name="t"):
        status, project = self.request("POST", "/api/projects", {"name": name})
        self.assertEqual(status, 201)
        return project["id"]

    def pcap_bytes(self, fmt="pcap"):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p")
            plant_capture().write(path, fmt)
            with open(path, "rb") as handle:
                return handle.read()


class AccessControlTests(ServerCase):
    def test_every_api_call_needs_the_token(self):
        for method, path in (("GET", "/api/status"), ("GET", "/api/projects"), ("POST", "/api/projects"), ("DELETE", "/api/data")):
            status, body = self.request(method, path, {} if method == "POST" else None, token=False)
            self.assertEqual(status, 401, (method, path))
            self.assertIn("token", body["error"])

    def test_wrong_token_is_refused(self):
        status, _ = self.request("GET", "/api/status", headers={"Authorization": "Bearer nope"})
        self.assertEqual(status, 401)

    def test_foreign_host_header_is_refused_dns_rebinding(self):
        status, _ = self.request("GET", "/api/status", host="evil.example:80")
        self.assertEqual(status, 403)
        status, _, _ = self.request("GET", "/", host="attacker.test", raw=True)
        self.assertEqual(status, 403)

    def test_foreign_origin_is_refused_csrf(self):
        status, _ = self.request("POST", "/api/projects", {"name": "x"}, {"Origin": "http://evil.example"})
        self.assertEqual(status, 403)
        status, _ = self.request("POST", "/api/projects", {"name": "x"}, {"Origin": f"http://127.0.0.1:{self.port}"})
        self.assertEqual(status, 201)

    def test_cors_preflight_is_refused_and_no_cors_headers_are_sent(self):
        status, resp, _ = self.request("OPTIONS", "/api/projects", headers={"Origin": "http://evil.example"}, raw=True)
        self.assertEqual(status, 405)
        self.assertIsNone(resp.getheader("Access-Control-Allow-Origin"))

    def test_static_page_has_strict_security_headers_and_no_inline_script(self):
        status, resp, body = self.request("GET", "/", raw=True, token=False)
        self.assertEqual(status, 200)
        csp = resp.getheader("Content-Security-Policy")
        self.assertIn("default-src 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.getheader("Cache-Control"), "no-store")
        self.assertNotIn(b"<script>", body)
        self.assertNotIn(b" onclick=", body)

    def test_binding_to_a_non_loopback_address_is_refused_without_the_explicit_flag(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(SystemExit):
            server.build_server("0.0.0.0", 0, d)  # noqa: S104 - proving that this is refused

    def test_unknown_paths_and_traversal_are_not_served(self):
        for path in ("/../../etc/passwd", "/ruletruss/server.py", "/%2e%2e/%2e%2e/etc/passwd", "/static/../x"):
            status, _, _ = self.request("GET", path, raw=True, token=False)
            self.assertEqual(status, 404, path)

    def test_the_data_folder_is_private(self):
        mode = os.stat(self.dir.name).st_mode & 0o777
        self.assertEqual(mode, 0o700)


class InputHandlingTests(ServerCase):
    def test_ids_must_be_the_expected_shape(self):
        for pid in ("../etc", "..%2f..%2fetc", "A" * 16, "g" * 16, "0" * 15):
            status, _ = self.request("GET", f"/api/projects/{pid}")
            self.assertEqual(status, 404, pid)

    def test_oversized_json_and_missing_length_are_refused(self):
        status, _ = self.request("POST", "/api/projects", headers={"Content-Length": str(server.MAX_JSON_BODY + 1)})
        self.assertEqual(status, 413)
        status, body = self.request("POST", "/api/projects", b"not json")
        self.assertEqual(status, 400)
        status, body = self.request("POST", "/api/projects", b"[1,2,3]")
        self.assertEqual(status, 400)
        status, body = self.request("POST", "/api/projects", b"{" * 100000)
        self.assertEqual(status, 400)

    def test_upload_over_the_limit_is_refused_before_it_is_read(self):
        pid = self.new_project()
        status, body = self.request("POST", f"/api/projects/{pid}/sources?name=x", headers={
            "Content-Length": str(limits.MAX_CAPTURE_BYTES + 1)})
        self.assertEqual(status, 413)

    def test_chunked_and_empty_uploads_are_refused(self):
        pid = self.new_project()
        status, _ = self.request("POST", f"/api/projects/{pid}/sources?name=x", b"",
                                 {"Transfer-Encoding": "chunked", "Content-Length": "0"})
        self.assertEqual(status, 411)
        status, _ = self.upload(pid, b"")
        self.assertEqual(status, 400)

    def test_garbage_and_wrong_types_are_rejected_with_a_readable_message(self):
        pid = self.new_project()
        for name, data in (("a.pcap", os.urandom(300)), ("b.cfg", b"hello world\n" * 20), ("c.xml", b"<html></html>"),
                           ("d.zip", b"PK\x03\x04" + b"\x00" * 50)):
            status, body = self.upload(pid, data, name)
            self.assertEqual(status, 422, name)
            self.assertNotIn("Traceback", body["error"])
            self.assertNotIn("/ho" + "me/", body["error"])
        status, project = self.request("GET", f"/api/projects/{pid}")
        self.assertEqual(project["sources"], [])
        incoming = os.path.join(self.srv.app.store.project_dir(pid), "incoming")
        self.assertEqual(os.listdir(incoming) if os.path.isdir(incoming) else [], [], "rejected uploads must not stay on disk")

    def test_xml_entity_attack_is_refused(self):
        pid = self.new_project()
        bomb = b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;">]><pfsense>&b;</pfsense>'
        status, body = self.upload(pid, bomb, "config.xml")
        self.assertEqual(status, 422)
        self.assertIn("DOCTYPE or entity", body["error"])

    def test_context_validation(self):
        pid = self.new_project()
        for body in ({"subnets": [{"cidr": "nope"}]}, {"labels": {"x": "y"}}, {"groups": [{"name": "", "members": []}]},
                     {"groups": [{"name": "a", "members": ["300.1.1.1"]}]}, {"subnets": "x"}):
            status, _ = self.request("PUT", f"/api/projects/{pid}/context", body)
            self.assertEqual(status, 400, body)
        status, ctx = self.request("PUT", f"/api/projects/{pid}/context", {"labels": {"10.0.0.1": "<img src=x onerror=alert(1)>"}})
        self.assertEqual(status, 200)
        self.assertEqual(ctx["labels"]["10.0.0.1"], "<img src=x onerror=alert(1)>")   # stored as text; the page uses textContent


class WorkflowTests(ServerCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        status, project = cls.request_class("POST", "/api/sample", {})
        cls.pid = project["id"]
        _, overview = cls.request_class("GET", f"/api/projects/{cls.pid}/overview")
        cls.sid = next(s["id"] for s in overview["sources"] if s["kind"] == "policy")

    @classmethod
    def request_class(cls, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=60)
        data = json.dumps(body).encode() if body is not None else None
        hdrs = {"Authorization": "Bearer test-token-1234567890", "Host": f"127.0.0.1:{cls.port}"}
        if data is not None:
            hdrs["Content-Length"] = str(len(data))
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        out = json.loads(resp.read().decode())
        conn.close()
        return resp.status, out

    def test_overview_inventory_and_matrix(self):
        status, o = self.request("GET", f"/api/projects/{self.pid}/overview")
        self.assertEqual(status, 200)
        self.assertEqual((o["flows"], o["communications"]), (21, 16))
        self.assertEqual(o["kind"], "OBSERVED")
        self.assertTrue(any("not evidence of absence" in n for n in o["coverage"]))
        self.assertTrue(o["matrix"])
        self.assertNotIn("role", o["inventory"]["devices"][0])

    def test_communications_filters_and_explanations(self):
        status, d = self.request("GET", f"/api/projects/{self.pid}/communications?port=502&min_confidence=high")
        self.assertEqual(status, 200)
        self.assertTrue(all(r["port"] == 502 and r["direction_confidence"] == "high" for r in d["rows"]))
        status, d = self.request("GET", f"/api/projects/{self.pid}/communications?q=Engineering")
        self.assertTrue(d["rows"])
        self.assertIn('labelled "Engineering workstation"', d["rows"][0]["explanation"])
        status, d = self.request("GET", f"/api/projects/{self.pid}/communications?limit=abc")
        self.assertEqual(status, 400)

    def test_graph(self):
        for level in ("subnet", "device"):
            status, g = self.request("GET", f"/api/projects/{self.pid}/graph?level={level}")
            self.assertEqual(status, 200)
            self.assertTrue(g["nodes"] and g["edges"])

    def test_policy_view_and_compare_keep_the_three_kinds_apart(self):
        _, v = self.request("GET", f"/api/projects/{self.pid}/policies/{self.sid}")
        self.assertEqual(v["kind"], "CONFIGURED")
        self.assertTrue(v["rules"] and v["rules"][0]["evidence"])
        self.assertIn("redundant", {f["kind"] for f in v["findings"]})
        self.assertNotIn("notarealhash", json.dumps(v))
        self.assertNotIn("notarealcommunity", json.dumps(v))
        _, c = self.request("GET", f"/api/projects/{self.pid}/policies/{self.sid}/compare")
        self.assertIn("OBSERVED", c["kind"])
        self.assertTrue(c["unobserved_rules"])

    def test_plans_for_both_workflows(self):
        _, plan = self.request("POST", f"/api/projects/{self.pid}/plan", {"workflow": "preserve", "policy": self.sid})
        self.assertEqual(plan["kind"], "PROPOSED")
        self.assertIn("directional", json.dumps(plan["facts"]).lower())
        _, narrow = self.request("POST", f"/api/projects/{self.pid}/plan", {"workflow": "narrow"})
        self.assertEqual(narrow["workflow"], "narrow")
        self.assertTrue(narrow["egress_policies"])
        status, bad = self.request("POST", f"/api/projects/{self.pid}/plan", {"workflow": "other"})
        self.assertEqual(status, 400)

    def test_narrow_export_requires_the_acknowledgement(self):
        status, body = self.request("POST", f"/api/projects/{self.pid}/export", {"kind": "plan-markdown", "workflow": "narrow"})
        self.assertEqual(status, 409)
        status, resp, payload = self.request("POST", f"/api/projects/{self.pid}/export", {
            "kind": "plan-markdown", "workflow": "narrow", "acknowledge_observation_limits": True}, raw=True)
        self.assertEqual(status, 200)
        text = payload.decode()
        self.assertIn("Observation period", text)
        self.assertIn("PROPOSED", text)
        self.assertIn("attachment", resp.getheader("Content-Disposition"))

    def test_translation_for_each_target_returns_validation_with_limits(self):
        for target in ("cisco-asa", "cisco-ios", "fortios"):
            status, t = self.request("POST", f"/api/projects/{self.pid}/translate", {
                "workflow": "preserve", "policy": self.sid, "target": target, "zone_map": {}})
            self.assertEqual(status, 200, target)
            self.assertIn("does not show the two policies are equivalent", " ".join(t["validation"]["limits"]))
            self.assertTrue(t["text"])
        status, _ = self.request("POST", f"/api/projects/{self.pid}/translate", {"workflow": "preserve", "target": "nope"})
        self.assertEqual(status, 400)

    def test_csv_exports_neutralise_formulas(self):
        pid = self.new_project("formulas")
        evil = '=HYPERLINK("http://example.invalid","x")'
        self.request("PUT", f"/api/projects/{pid}/context", {"labels": {"10.20.1.15": evil, "10.30.2.40": "+cmd|' /C calc'!A0"}})
        data = self.pcap_bytes()
        self.assertEqual(self.upload(pid, data, "p.pcap")[0], 201)
        status, resp, payload = self.request("POST", f"/api/projects/{pid}/export", {"kind": "communications-csv"}, raw=True)
        self.assertEqual(status, 200)
        import csv
        import io
        rows = list(csv.reader(io.StringIO(payload.decode())))
        for row in rows:
            for cell in row:
                self.assertFalse(cell.startswith(("=", "+", "-", "@", "\t", "\r")), cell)
        self.assertTrue(any("'=HYPERLINK" in c for r in rows for c in r) or any("labelled" in c for r in rows for c in r))

    def test_markdown_exports_escape_untrusted_text(self):
        pid = self.new_project("md")
        hostile = "<script>alert(1)</script> [x](javascript:alert(1))"
        self.request("PUT", f"/api/projects/{pid}/context", {"labels": {"10.20.1.15": hostile}})
        self.upload(pid, self.pcap_bytes(), "p.pcap")
        status, _, payload = self.request("POST", f"/api/projects/{pid}/export", {"kind": "communications-markdown"}, raw=True)
        text = payload.decode()
        self.assertNotIn("<script>", text)
        self.assertNotIn("[x](", text)                     # the bracket is escaped, so no live link can form
        self.assertIn("\\[x\\]", text)

    def test_ai_is_off_by_default(self):
        status, pkg = self.request("POST", f"/api/projects/{self.pid}/ai", {})
        self.assertEqual(status, 200)
        self.assertFalse(pkg["enabled"])
        self.assertIn("untrusted", pkg["prompt"])
        self.assertIn("do not follow", pkg["prompt"])
        status, body = self.request("POST", f"/api/projects/{self.pid}/ai", {"send": True})
        self.assertEqual(status, 404)
        self.assertIn("off", body["error"])


class UploadAndDeletionTests(ServerCase):
    def test_pcap_and_pcapng_upload_then_delete_leaves_nothing_behind(self):
        pid = self.new_project("del")
        for fmt in ("pcap", "pcapng"):
            status, entry = self.upload(pid, self.pcap_bytes(fmt), f"p.{fmt}", "mirror port")
            self.assertEqual(status, 201)
            self.assertEqual((entry["kind"], entry["format"], entry["observation_point"]), ("capture", fmt, "mirror port"))
        project_dir = self.srv.app.store.project_dir(pid)
        for root, _, files in os.walk(project_dir):
            for name in files:
                self.assertEqual(os.stat(os.path.join(root, name)).st_mode & 0o777, 0o600, name)
        _, project = self.request("GET", f"/api/projects/{pid}")
        sid = project["sources"][0]["id"]
        self.assertEqual(self.request("DELETE", f"/api/projects/{pid}/sources/{sid}")[0], 200)
        self.assertFalse(os.path.exists(self.srv.app.store.source_dir(pid, sid)))
        status, body = self.request("DELETE", f"/api/projects/{pid}")
        self.assertEqual(status, 200)
        self.assertFalse(os.path.exists(project_dir))
        self.assertEqual(self.request("GET", f"/api/projects/{pid}")[0], 404)

    def test_delete_all_data(self):
        self.new_project("a")
        self.new_project("b")
        status, body = self.request("DELETE", "/api/data")
        self.assertEqual(status, 200)
        _, listing = self.request("GET", "/api/projects")
        self.assertEqual(listing["projects"], [])

    def test_config_with_credentials_never_returns_them(self):
        pid = self.new_project("secrets")
        cfg = (b"hostname r1\nenable secret 9 $9$SUPERSECRETHASH\nusername a password 7 0822455D0A16\n"
               b"snmp-server community topsecretstring RO\nip access-list extended X\n permit tcp any any eq 22\n"
               b"interface Gi0/0\n ip access-group X in\n")
        status, entry = self.upload(pid, cfg, "r1.cfg")
        self.assertEqual(status, 201)
        _, project = self.request("GET", f"/api/projects/{pid}")
        _, view = self.request("GET", f"/api/projects/{pid}/policies/{entry['id']}")
        everything = json.dumps(view) + json.dumps(project)
        for secret in ("SUPERSECRETHASH", "0822455D0A16", "topsecretstring"):
            self.assertNotIn(secret, everything)
        for root, _, files in os.walk(self.srv.app.store.source_dir(pid, entry["id"])):
            for name in files:
                if name == "parsed.json":
                    with open(os.path.join(root, name), "rb") as handle:
                        stored = handle.read().decode()
                    for secret in ("SUPERSECRETHASH", "topsecretstring"):
                        self.assertNotIn(secret, stored, "credentials must not be stored in the parse result")

    def test_concurrent_uploads_do_not_interfere(self):
        pid = self.new_project("conc")
        results = []

        def worker():
            builder = CaptureBuilder()
            builder.session(0, "10.0.0.1", 40000, "10.0.0.2", 502, modbus_request(1), modbus_response(1))
            with tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "x.pcap")
                builder.write(path)
                with open(path, "rb") as handle:
                    results.append(self.upload(pid, handle.read(), "c.pcap")[0])
        threads = [threading.Thread(target=worker) for _ in range(4)]
        [t.start() for t in threads]
        [t.join(60) for t in threads]
        self.assertEqual(results, [201] * 4)
        _, project = self.request("GET", f"/api/projects/{pid}")
        self.assertEqual(len(project["sources"]), 4)


class RetentionTests(unittest.TestCase):
    def test_purge_older_than_removes_old_projects_only(self):
        from ruletruss.store import Store
        with tempfile.TemporaryDirectory() as d:
            store = Store(d)
            old, new = store.create_project("old"), store.create_project("new")
            old["created"] -= 40 * 86400
            store.save_project(old)
            self.assertEqual(store.purge_older_than(0), [])
            self.assertEqual(store.purge_older_than(30), [old["id"]])
            self.assertEqual([p["id"] for p in store.list_projects()], [new["id"]])


if __name__ == "__main__":
    unittest.main()


class AiAssistanceTests(unittest.TestCase):
    """The optional AI path: off by default, endpoint restrictions, grounded prompt, untrusted data labelled."""

    def make(self, endpoint, allow_remote=False):
        from ruletruss.service import Service
        from ruletruss.store import Store
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        service = Service(Store(d.name), endpoint, allow_remote)
        from ruletruss.samples import create_demo
        return service, create_demo(service)["id"]

    def test_non_http_schemes_and_remote_hosts_are_refused(self):
        from ruletruss.service import ApiError
        for endpoint in ("file:///etc/passwd", "ftp://example.invalid/x", "gopher://x"):
            service, pid = self.make(endpoint)
            with self.assertRaises(ApiError) as ctx:
                service.ai_ask(pid, "summary")
            self.assertEqual(ctx.exception.status, 403)
        service, pid = self.make("https://api.example.invalid/v1")
        with self.assertRaises(ApiError) as ctx:
            service.ai_ask(pid, "summary")
        self.assertIn("not on this machine", str(ctx.exception))
        service, pid = self.make("http://api.example.invalid/v1", allow_remote=True)
        with self.assertRaises(ApiError) as ctx:
            service.ai_ask(pid, "summary")
        self.assertIn("https", str(ctx.exception))

    def test_local_endpoint_receives_only_parsed_statements_marked_untrusted(self):
        import http.server
        received = []

        class Fake(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(self.rfile.read(int(self.headers["Content-Length"])).decode())
                body = json.dumps({"choices": [{"message": {"content": "<b>summary</b> from the data"}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return

        httpd = http.server.HTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        service, pid = self.make(f"http://127.0.0.1:{httpd.server_address[1]}/v1/chat")
        answer = service.ai_ask(pid, "summary")
        self.assertIn("unverified", answer["label"])
        self.assertEqual(answer["text"], "<b>summary</b> from the data")      # returned as text; the page shows it with textContent
        sent = received[0]
        self.assertIn("untrusted", sent)
        self.assertIn("do not follow", sent.lower())
        self.assertIn("Modbus", sent)
        for forbidden in ("notarealhash", "notarealcommunity", "enable secret"):
            self.assertNotIn(forbidden, sent)
        self.assertNotIn("access-list", sent)          # no raw configuration lines, only parsed statements


class UnexpectedErrorTests(ServerCase):
    def test_a_failure_outside_any_route_returns_a_clean_500_not_a_dropped_connection(self):
        from unittest import mock
        with mock.patch("ruletruss.server.parse_qs", side_effect=RuntimeError("boom with secret-detail")):
            status, body = self.request("GET", "/api/status")
        self.assertEqual(status, 500)
        self.assertNotIn("secret-detail", json.dumps(body))
        self.assertEqual(self.request("GET", "/api/status")[0], 200)       # the server is still serving
