"""Take screenshots of the interface with headless Chromium (no window is opened) for the documentation.

    .venv/bin/python tools/make_screenshots.py

Starts a throw-away server on a free local port with the synthetic Riverbend example, then photographs a few tabs. The DISPLAY and
WAYLAND_DISPLAY variables are removed so that nothing can appear on a real desktop. Needs `chromium` (or chromium-browser) on the PATH.
"""
import os
import secrets
import shutil
import subprocess  # nosec B404 - runs headless Chromium with a fixed argument list
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from ruletruss import server  # noqa: E402
from ruletruss.samples import create_riverbend, create_unifi  # noqa: E402

TABS = [("inventory", 1100), ("comms", 900), ("graph", 800), ("compare", 1000), ("migrate", 1400)]


def main():
    browser = shutil.which("chromium") or shutil.which("chromium-browser")
    if not browser:
        raise SystemExit("chromium not found; skipping screenshots")
    out = ROOT / "docs" / "images"
    out.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in os.environ.items() if k not in ("DISPLAY", "WAYLAND_DISPLAY")}
    with tempfile.TemporaryDirectory() as data, tempfile.TemporaryDirectory() as profile:
        token = secrets.token_urlsafe(24)
        srv = server.build_server("127.0.0.1", 0, data, token=token)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        create_riverbend(srv.app.service)
        port = srv.server_address[1]
        for tab, height in TABS:
            command = [browser, "--headless=new", "--disable-gpu", "--no-sandbox", f"--user-data-dir={profile}", "--hide-scrollbars",
                       f"--window-size=1300,{height}", "--virtual-time-budget=9000", f"--screenshot={out / (tab + '.png')}",
                       f"http://127.0.0.1:{port}/#token={token}&tab={tab}"]
            subprocess.run(command, env=env, capture_output=True, timeout=120, check=False)  # noqa: S603  # nosec B603
        srv.shutdown()
    with tempfile.TemporaryDirectory() as data, tempfile.TemporaryDirectory() as profile:      # the UniFi example, on its own, so it is the project shown
        token = secrets.token_urlsafe(24)
        srv = server.build_server("127.0.0.1", 0, data, token=token)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        create_unifi(srv.app.service)
        command = [browser, "--headless=new", "--disable-gpu", "--no-sandbox", f"--user-data-dir={profile}", "--hide-scrollbars", "--window-size=1300,1150",
                   "--virtual-time-budget=9000", f"--screenshot={out / 'zone-matrix.png'}",
                   f"http://127.0.0.1:{srv.server_address[1]}/#token={token}&tab=config"]
        subprocess.run(command, env=env, capture_output=True, timeout=120, check=False)  # noqa: S603  # nosec B603
        srv.shutdown()
    print("wrote docs/images/")


if __name__ == "__main__":
    main()
