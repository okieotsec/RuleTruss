"""Adjustable size limits, background imports with progress and cancel, and the disk-space check."""
import http.client
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from unittest import mock

from ruletruss import isolate, jobs, limits, server, worker
from ruletruss.capture import reader
from ruletruss.capture.flows import analyze_capture_full
from ruletruss.synthetic import plant_capture

TOKEN = "test-token-1234567890"


class LimitsCase(unittest.TestCase):
    def setUp(self):
        saved = limits.snapshot()
        self.addCleanup(limits.apply, saved)


class AdjustableLimitTests(LimitsCase):
    def test_flags_become_limits_in_the_right_units(self):
        limits.configure(max_capture_mb=4096, max_packets=50_000_000, parse_minutes=90, max_flows=300_000, parse_memory_gb=8)
        self.assertEqual(limits.MAX_CAPTURE_BYTES, 4096 * 1024 ** 2)
        self.assertEqual((limits.MAX_PACKETS, limits.PARSE_SECONDS, limits.MAX_FLOWS), (50_000_000, 5400, 300_000))
        self.assertEqual(limits.PARSE_MEMORY_BYTES, 8 * 1024 ** 3)

    def test_unset_flags_leave_the_defaults_alone(self):
        before = limits.snapshot()
        limits.configure()
        self.assertEqual(limits.snapshot(), before)

    def test_nonsense_and_over_ceiling_values_are_refused_and_change_nothing(self):
        before = limits.snapshot()
        for bad in ({"MAX_PACKETS": 0}, {"MAX_PACKETS": -5}, {"MAX_PACKETS": True}, {"MAX_PACKETS": "7"}, {"MAX_PACKETS": 1.5},
                    {"MAX_PACKETS": limits.CEILINGS["MAX_PACKETS"] + 1}, {"PARSE_SECONDS": 10 ** 9}, {"NOT_A_LIMIT": 5},
                    {"MAX_FLOWS": limits.CEILINGS["MAX_FLOWS"] + 1}):
            with self.assertRaises(ValueError, msg=bad):
                limits.apply(bad)
        self.assertEqual(limits.snapshot(), before)

    def test_the_command_line_rejects_bad_limits_before_starting(self):
        for argv in (["--max-packets", "0"], ["--max-capture-mb", "99999999999"], ["--parse-minutes", "-1"]):
            with self.assertRaises(SystemExit) as raised:
                server.main(argv)
            self.assertIn("Invalid size limit", str(raised.exception))

    def test_the_command_line_sets_the_limits_the_server_then_uses(self):
        with mock.patch.object(server, "build_server", side_effect=SystemExit("stop here")), self.assertRaises(SystemExit):
            server.main(["--max-capture-mb", "4096", "--parse-minutes", "120"])
        self.assertEqual((limits.MAX_CAPTURE_BYTES, limits.PARSE_SECONDS), (4096 * 1024 ** 2, 7200))

    def test_the_analysis_process_gets_the_same_limits(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.pcap")
            plant_capture().write(path)
            limits.apply({"MAX_PACKETS": 20})
            result = isolate.parse_file(path, "s1", "p.pcap")
        self.assertEqual(result["info"]["packets_read"], 20)
        self.assertTrue(any("stopped after 20 packets" in n for n in result["info"]["coverage_notes"]))

    def test_a_file_over_the_size_limit_says_how_to_raise_it(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.pcap")
            plant_capture().write(path)
            limits.apply({"MAX_CAPTURE_BYTES": 100})
            with self.assertRaises(limits.LimitExceeded) as raised:
                analyze_capture_full(path, "c", "s", "p.pcap")
        self.assertIn("--max-capture-mb", str(raised.exception))


class ProgressTests(LimitsCase):
    def test_progress_is_reported_with_position_and_size(self):
        calls = []
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.pcap")
            plant_capture().write(path)
            with mock.patch.object(reader, "PROGRESS_EVERY", 10):
                analyze_capture_full(path, "c", "s", "p.pcap", progress=lambda *a: calls.append(a))
            size = os.path.getsize(path)
        self.assertGreaterEqual(len(calls), 2)
        self.assertEqual([c[0] for c in calls], sorted(c[0] for c in calls))
        self.assertTrue(all(0 < c[1] <= c[2] == size for c in calls))

    def test_the_worker_writes_progress_atomically_and_the_parent_reads_only_numbers(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "progress.json")
            worker.progress_writer(path)(1000, 500, 2000)
            self.assertEqual(isolate.read_progress(path), {"packets": 1000, "bytes": 500, "total": 2000})
            self.assertEqual(os.listdir(d), ["progress.json"])
            for bad in (b"", b"not json", b'{"packets": "x"}', b'{"packets": 1}', b"\xff\xfe", b"[1,2,3]"):
                with open(path, "wb") as handle:
                    handle.write(bad)
                self.assertIsNone(isolate.read_progress(path), bad)
        self.assertIsNone(isolate.read_progress(os.path.join(d, "missing.json")))
        self.assertIsNone(isolate.read_progress(None))


class CancelTests(unittest.TestCase):
    def test_cancelling_stops_the_analysis_process(self):
        seen = {}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.pcap")
            plant_capture().write(path)
            with self.assertRaises(isolate.Cancelled):
                isolate.parse_file(path, "s1", "p.pcap", on_start=lambda proc, progress: seen.update(proc=proc), cancelled=lambda: True)
        self.assertIsNotNone(seen["proc"].poll())              # the worker is no longer running
        self.assertFalse(os.path.exists(os.path.join(d, "result.json")))

    def test_the_time_limit_message_names_the_flag(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.pcap")
            plant_capture().write(path)
            with mock.patch.object(isolate.time, "monotonic", side_effect=[0, 10 ** 6, 10 ** 6, 10 ** 6]), \
                    self.assertRaises(isolate.ParseFailure) as raised:
                isolate.parse_file(path, "s1", "p.pcap", timeout=5)
        self.assertIn("--parse-minutes", str(raised.exception))


class JobTests(unittest.TestCase):
    def wait(self, job, state="running", seconds=10):
        end = time.time() + seconds
        while job.state == state and time.time() < end:
            time.sleep(0.02)

    def test_a_job_runs_and_reports_its_result(self):
        registry = jobs.Jobs()
        job = registry.start("p1", "a.pcap", lambda j: {"kind": "capture"})
        self.wait(job)
        view = registry.get(job.id).view()
        self.assertEqual((view["state"], view["entry"]), ("done", {"kind": "capture"}))

    def test_errors_are_shown_safely_and_unexpected_ones_are_hidden(self):
        registry = jobs.Jobs()

        def known(_):
            raise isolate.ParseFailure("not a capture file")

        def unexpected(_):
            raise RuntimeError("secret internal detail at a private path")
        a, b = registry.start("p", "a", known), registry.start("p", "b", unexpected)
        self.wait(a)
        self.wait(b)
        self.assertEqual((a.view()["state"], a.view()["message"]), ("error", "not a capture file"))
        self.assertEqual((b.view()["state"], b.view()["message"]), ("error", "the file could not be processed"))

    def test_only_a_few_run_at_once_and_cancel_works(self):
        registry = jobs.Jobs()
        release = threading.Event()

        def slow(job):
            while not job.is_cancelled() and not release.is_set():
                time.sleep(0.02)
            if job.is_cancelled():
                raise isolate.Cancelled("stopped")
            return {"kind": "capture"}
        running = [registry.start("p", f"f{i}", slow) for i in range(jobs.MAX_RUNNING)]
        self.assertFalse(registry.has_room())
        with self.assertRaises(RuntimeError):
            registry.start("p", "one too many", slow)
        registry.cancel(running[0].id)
        self.wait(running[0])
        self.assertEqual(running[0].state, "cancelled")
        self.assertTrue(registry.has_room())
        release.set()
        self.wait(running[1])
        self.assertEqual(running[1].state, "done")

    def test_finished_jobs_do_not_pile_up(self):
        registry = jobs.Jobs()
        for i in range(jobs.KEEP_FINISHED + 10):
            self.wait(registry.start("p", f"f{i}", lambda j: {}))
        self.assertLessEqual(len(registry._jobs), jobs.KEEP_FINISHED + 1)

    def test_an_unknown_job_is_none(self):
        self.assertIsNone(jobs.Jobs().get("0" * 16))


class ServerCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.srv = server.build_server("127.0.0.1", 0, cls.dir.name, token=TOKEN)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.dir.cleanup()

    def call(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        headers = {"Host": f"127.0.0.1:{self.port}", "Authorization": f"Bearer {TOKEN}", "Content-Length": str(len(body or b""))}
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            payload = response.read()
            return response.status, json.loads(payload.decode()) if payload else {}
        finally:
            conn.close()

    def project(self):
        return self.call("POST", "/api/projects", json.dumps({"name": "big"}).encode())[1]["id"]

    def pcap(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.pcap")
            plant_capture().write(path)
            with open(path, "rb") as handle:
                return handle.read()


class BackgroundImportTests(ServerCase):
    def test_a_background_import_returns_a_job_that_finishes_with_the_new_source(self):
        pid = self.project()
        status, body = self.call("POST", f"/api/projects/{pid}/sources?name=big.pcap&async=1", self.pcap())
        self.assertEqual(status, 202)
        end = time.time() + 60
        view = {}
        while time.time() < end:
            _, view = self.call("GET", f"/api/jobs/{body['job']}")
            if view["state"] != "running":
                break
            time.sleep(0.2)
        self.assertEqual(view["state"], "done", view)
        self.assertEqual(view["entry"]["kind"], "capture")
        status, overview = self.call("GET", f"/api/projects/{pid}/overview")
        self.assertEqual((status, overview["flows"] > 0), (200, True))

    def test_a_failed_background_import_reports_the_reason_and_removes_the_upload(self):
        pid = self.project()
        _, body = self.call("POST", f"/api/projects/{pid}/sources?name=x.pcap&async=1", b"\x00" * 64 + b"not a capture or a config")
        end = time.time() + 30
        view = {}
        while time.time() < end:
            _, view = self.call("GET", f"/api/jobs/{body['job']}")
            if view["state"] != "running":
                break
            time.sleep(0.2)
        self.assertEqual(view["state"], "error")
        self.assertTrue(view["message"])
        self.assertNotIn("Traceback", json.dumps(view))
        uploads = os.path.join(self.srv.app.store.project_dir(pid), "uploads")
        self.assertEqual(os.listdir(uploads) if os.path.isdir(uploads) else [], [])

    def test_cancel_through_the_api(self):
        pid = self.project()

        def slow(project_id, path, filename, point, fmt, job=None):
            while not job.is_cancelled():
                time.sleep(0.02)
            raise isolate.Cancelled("stopped")
        with mock.patch.object(self.srv.app.service, "import_upload", side_effect=slow):
            _, body = self.call("POST", f"/api/projects/{pid}/sources?name=x.pcap&async=1", self.pcap())
            self.assertEqual(self.call("GET", f"/api/jobs/{body['job']}")[1]["state"], "running")
            self.call("DELETE", f"/api/jobs/{body['job']}")
            end = time.time() + 10
            while time.time() < end and self.call("GET", f"/api/jobs/{body['job']}")[1]["state"] == "running":
                time.sleep(0.05)
        self.assertEqual(self.call("GET", f"/api/jobs/{body['job']}")[1]["state"], "cancelled")

    def test_too_many_imports_at_once_get_a_clean_refusal_before_the_upload(self):
        pid = self.project()
        with mock.patch.object(self.srv.app.jobs, "has_room", return_value=False):
            status, body = self.call("POST", f"/api/projects/{pid}/sources?name=x.pcap&async=1", self.pcap())
        self.assertEqual(status, 429)
        self.assertIn("already running", body["error"])

    def test_unknown_jobs_and_bad_ids(self):
        self.assertEqual(self.call("GET", "/api/jobs/" + "0" * 16)[0], 404)
        self.assertEqual(self.call("DELETE", "/api/jobs/" + "0" * 16)[0], 404)
        self.assertEqual(self.call("GET", "/api/jobs/not-an-id")[0], 404)

    def test_a_full_disk_is_refused_before_anything_is_written(self):
        pid = self.project()
        fake = shutil._ntuple_diskusage(10 ** 12, 10 ** 12 - 1000, 1000)
        with mock.patch.object(server.shutil, "disk_usage", return_value=fake):
            status, body = self.call("POST", f"/api/projects/{pid}/sources?name=x.pcap", self.pcap())
        self.assertEqual(status, 507)
        self.assertIn("free disk space", body["error"])

    def test_the_status_page_shows_the_current_limits(self):
        status, body = self.call("GET", "/api/status")
        self.assertEqual(body["limits"]["max_capture_bytes"], limits.MAX_CAPTURE_BYTES)


if __name__ == "__main__":
    unittest.main()
