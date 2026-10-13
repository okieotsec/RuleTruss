import json
import os
import secrets
import shutil
import subprocess  # nosec B404 - runs node on this repository's own script with a fixed argument list
import tempfile
import threading
import unittest
from pathlib import Path

from ruletruss import server
from ruletruss.samples import create_demo

ROOT = Path(__file__).resolve().parent.parent
BROWSER = shutil.which("chromium") or shutil.which("chromium-browser")
NODE = shutil.which("node")


@unittest.skipUnless(BROWSER and NODE, "needs node and chromium; the check runs headless and never opens a window")
class HeadlessInterfaceTests(unittest.TestCase):
    def test_the_interface_works_end_to_end_in_a_real_browser(self):
        token = secrets.token_urlsafe(24)
        with tempfile.TemporaryDirectory() as data:
            srv = server.build_server("127.0.0.1", 0, data, token=token)
            thread = threading.Thread(target=srv.serve_forever, daemon=True)
            thread.start()
            try:
                create_demo(srv.app.service)
                env = {k: v for k, v in os.environ.items() if k not in ("DISPLAY", "WAYLAND_DISPLAY")}
                env["CHROMIUM"] = BROWSER
                url = f"http://127.0.0.1:{srv.server_address[1]}/#token={token}"
                proc = subprocess.run([NODE, str(ROOT / "tools" / "ui_check.mjs"), url], env=env, capture_output=True, text=True,  # noqa: S603
                                      timeout=300, check=False)
            finally:
                srv.shutdown()
                srv.server_close()
                thread.join(5)
        report = json.loads(proc.stdout) if proc.stdout.strip() else {"ok": False, "failures": [proc.stderr[-500:]]}
        self.assertTrue(report["ok"], json.dumps(report.get("failures"), indent=1) + "\n" + proc.stderr[-300:])
        self.assertGreaterEqual(len(report["checks"]), 20)


if __name__ == "__main__":
    unittest.main()
