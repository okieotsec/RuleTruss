"""Run the parsing worker with a timeout, a clean environment and a private working folder."""
import json
import os
import subprocess  # nosec B404 - runs this project's own worker module with a fixed argument vector, never a shell
import sys
import tempfile
import time

from . import limits

MAX_RESULT_BYTES = limits.MAX_RESULT_BYTES
VENDOR_NAMES_SECONDS = 240


class ParseFailure(ValueError):
    """The file could not be parsed. The message is safe to show."""


class Cancelled(ParseFailure):
    """The user stopped the analysis."""


def parse_file(path, source_id, filename, observation_point="", fmt=None, timeout=None, on_start=None, cancelled=None):
    """Parse one file in the worker process. `timeout` defaults to the current PARSE_SECONDS limit.

    `on_start(process, progress_path)` is called once the worker is running, so a caller can show progress or stop it;
    `cancelled()` is polled while waiting and ends the worker when it returns True.
    """
    timeout = timeout or limits.PARSE_SECONDS
    with tempfile.TemporaryDirectory(prefix="rt-work-") as work:
        out = os.path.join(work, "result.json")
        progress_path = os.path.join(work, "progress.json")
        options = {"source_id": source_id, "filename": filename, "observation_point": observation_point, "format": fmt,
                   "limits": limits.snapshot(), "progress_path": progress_path}
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"}
        # -I would ignore PYTHONPATH, so use -s (no user site) and -P (no cwd/script dir on sys.path) and name the package folder.
        package_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env["PYTHONPATH"] = package_parent
        command = [sys.executable, "-s", "-P", "-m", "ruletruss.worker", os.path.abspath(path), out, json.dumps(options)]
        # S603: fixed argument vector; the only untrusted values are a path we created and JSON the worker parses.
        proc = subprocess.Popen(command, cwd=work, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # noqa: S603  # nosec B603
        if on_start:
            on_start(proc, progress_path)
        deadline = time.monotonic() + timeout
        try:
            while True:
                if cancelled and cancelled():
                    raise Cancelled("the analysis was stopped")
                if time.monotonic() > deadline:
                    raise ParseFailure(f"processing took longer than {timeout} seconds and was stopped "
                                       "(raise it with --parse-minutes when starting RuleTruss)")
                try:
                    proc.wait(timeout=0.5)
                    break
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        if not os.path.exists(out):
            code = proc.returncode
            raise ParseFailure("the file could not be processed (the parser was stopped by its resource limits)"
                               if code and code < 0 else "the file could not be processed")
        if os.path.getsize(out) > MAX_RESULT_BYTES:
            raise ParseFailure("the result of analysing this file is larger than allowed")
        with open(out, "rb") as handle:
            payload = json.loads(handle.read().decode("ascii"))
    if not payload.get("ok"):
        raise ParseFailure(payload.get("error", "the file could not be processed"))
    return payload["result"]


def read_progress(progress_path):
    """The worker's latest progress record, or None. The file is small, written atomically, and never trusted beyond its numbers."""
    try:
        with open(progress_path, "rb") as handle:
            data = json.loads(handle.read(512).decode("ascii"))
        return {k: int(data[k]) for k in ("packets", "bytes", "total")}
    except (OSError, ValueError, KeyError, TypeError):
        return None


def build_vendor_names(out_path, timeout=VENDOR_NAMES_SECONDS, source_dir=None):
    """Download the IEEE vendor listings and write the vendor-name table, in a separate resource-limited process.

    This is the application's only outbound network use and it runs only when the user asks. With `source_dir` the three listings are
    read from that folder instead and nothing is downloaded. Returns the number of entries.
    """
    with tempfile.TemporaryDirectory(prefix="rt-oui-work-") as work:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1",
               "PYTHONPATH": os.path.dirname(os.path.dirname(os.path.abspath(__file__)))}
        command = [sys.executable, "-s", "-P", "-m", "ruletruss.oui_build", "--out", os.path.abspath(out_path)]
        if source_dir:
            command += ["--from", os.path.abspath(source_dir)]
        try:
            proc = subprocess.run(command, cwd=work, env=env, capture_output=True, timeout=timeout, check=False)  # noqa: S603  # nosec B603
        except subprocess.TimeoutExpired as error:
            raise ParseFailure(f"the download took longer than {timeout} seconds and was stopped") from error
    try:
        result = json.loads(proc.stdout[:4096].decode("ascii", "replace").strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise ParseFailure("the vendor names could not be downloaded") from None
    if not result.get("ok"):
        raise ParseFailure(str(result.get("error", "the vendor names could not be downloaded"))[:300])
    return int(result["entries"])
