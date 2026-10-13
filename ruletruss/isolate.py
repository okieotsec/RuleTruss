"""Run the parsing worker with a timeout, a clean environment and a private working folder."""
import json
import os
import subprocess  # nosec B404 - runs this project's own worker module with a fixed argument vector, never a shell
import sys
import tempfile

from . import limits

MAX_RESULT_BYTES = 256 * 1024 * 1024


class ParseFailure(ValueError):
    """The file could not be parsed. The message is safe to show."""


def parse_file(path, source_id, filename, observation_point="", fmt=None, timeout=limits.PARSE_SECONDS):
    options = {"source_id": source_id, "filename": filename, "observation_point": observation_point, "format": fmt}
    with tempfile.TemporaryDirectory(prefix="rt-work-") as work:
        out = os.path.join(work, "result.json")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"}
        # -I would ignore PYTHONPATH, so use -s (no user site) and -P (no cwd/script dir on sys.path) and name the package folder.
        package_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env["PYTHONPATH"] = package_parent
        command = [sys.executable, "-s", "-P", "-m", "ruletruss.worker", os.path.abspath(path), out, json.dumps(options)]
        try:
            # S603: fixed argument vector; the only untrusted values are a path we created and JSON the worker parses.
            proc = subprocess.run(command, cwd=work, env=env, capture_output=True, timeout=timeout, check=False)  # noqa: S603  # nosec B603
        except subprocess.TimeoutExpired as error:
            raise ParseFailure(f"processing took longer than {timeout} seconds and was stopped") from error
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
