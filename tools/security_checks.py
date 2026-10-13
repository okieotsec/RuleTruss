"""Run the security toolchain from SECURITY_TEST_PLAN.md and save every tool's raw output.

Usage:  .venv/bin/python tools/security_checks.py reports/cpN-name

Each tool's output is written under that folder (bandit.json, semgrep.json, ruff.json, gitleaks.json, pip-audit.json,
osv.json, versions.txt). The summary printed at the end says how many findings each tool reported; a tool that could not
run is listed as NOT RUN with the reason, never skipped silently. The exit status is 1 when any tool reports a finding.
"""
import json
import os
import shutil
import subprocess  # nosec B404 - runs fixed command lines for the security tools; no shell, no untrusted input
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = Path(sys.executable).parent


def tool(name):
    local = BIN / name
    return str(local) if local.exists() else shutil.which(name)


def run(command, output=None, cwd=ROOT, timeout=900):
    # S603: command lines are built from fixed strings and this repository's own paths.
    proc = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603  # nosec B603
    if output is not None:
        Path(output).write_text(proc.stdout)
    return proc


def count_json(path, key=None):
    try:
        data = json.loads(Path(path).read_text() or "null")
    except ValueError:
        return None
    if key is None:
        return len(data) if isinstance(data, list) else None
    return len(data.get(key, [])) if isinstance(data, dict) else None


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    out = ROOT / sys.argv[1]
    out.mkdir(parents=True, exist_ok=True)
    results, versions = [], []
    app_files = [str(p.relative_to(ROOT)) for p in sorted((ROOT / "pbridge").rglob("*.py"))] + \
                [str(p.relative_to(ROOT)) for p in sorted((ROOT / "tools").glob("*.py"))]

    def record(name, findings, note=""):
        results.append((name, findings, note))

    def version(name, args=("--version",)):
        exe = tool(name)
        if exe:
            versions.append(f"{name}: " + (run([exe, *args]).stdout.strip().splitlines() or ["?"])[0])

    # ruff (the S rules mirror bandit)
    exe = tool("ruff")
    if exe:
        run([exe, "check", ".", "--output-format", "json"], out / "ruff.json")
        record("ruff", count_json(out / "ruff.json"))
        version("ruff")
    else:
        record("ruff", None, "not installed")
    # bandit on application code (tests are excluded, as in the plan)
    exe = tool("bandit")
    if exe:
        run([exe, "-q", "-f", "json", "-o", str(out / "bandit.json"), *app_files])
        record("bandit", count_json(out / "bandit.json", "results"))
        version("bandit")
    else:
        record("bandit", None, "not installed")
    # semgrep downloads its rule packs; no project code is sent anywhere (metrics off)
    exe = tool("semgrep")
    if exe:
        proc = run([exe, "scan", "--config", "p/python", "--config", "p/security-audit", "--metrics", "off", "--json", "-o",
                    str(out / "semgrep.json"), "--quiet", "pbridge", "tools"], timeout=1800)
        n = count_json(out / "semgrep.json", "results") if (out / "semgrep.json").exists() else None
        record("semgrep", n, "" if n is not None else (proc.stderr.strip().splitlines() or ["did not run"])[-1][:200])
        version("semgrep")
    else:
        record("semgrep", None, "not installed")
    # gitleaks over the full git history and working tree
    exe = tool("gitleaks")
    if exe:
        proc = run([exe, "detect", "--source", ".", "--report-format", "json", "--report-path", str(out / "gitleaks.json"), "--no-banner"])
        text = (out / "gitleaks.json").read_text() if (out / "gitleaks.json").exists() else "[]"
        record("gitleaks", len(json.loads(text or "[]")), "" if proc.returncode in (0, 1) else proc.stderr[-200:])
        version("gitleaks", ("version",))
    else:
        record("gitleaks", None, "not installed")
    # dependencies
    exe = tool("pip-audit")
    if exe:
        proc = run([exe, "-r", "requirements.txt", "--require-hashes", "-f", "json", "-o", str(out / "pip-audit.json")], timeout=600)
        data = json.loads((out / "pip-audit.json").read_text() or "{}") if (out / "pip-audit.json").exists() else {}
        vulns = sum(len(d.get("vulns", [])) for d in data.get("dependencies", []))
        record("pip-audit", vulns if data else None, "" if data else proc.stderr[-200:])
        version("pip-audit")
    else:
        record("pip-audit", None, "not installed")
    exe = tool("osv-scanner")
    if exe:
        proc = run([exe, "--lockfile=requirements.txt", "--format", "json"], out / "osv.json", timeout=600)
        try:
            data = json.loads((out / "osv.json").read_text() or "{}")
            record("osv-scanner", sum(len(p.get("vulnerabilities", [])) for r in data.get("results", []) for p in r.get("packages", [])))
        except ValueError:
            record("osv-scanner", None, proc.stderr[-200:])
        version("osv-scanner", ("--version",))
    else:
        record("osv-scanner", None, "not installed")
    (out / "versions.txt").write_text("\n".join(versions) + "\n")
    width = max(len(n) for n, _, _ in results)
    failed = False
    print(f"\nSecurity checks written to {out.relative_to(ROOT)}")
    for name, findings, note in results:
        status = "NOT RUN" if findings is None else ("0 findings" if findings == 0 else f"{findings} FINDING(S)")
        failed = failed or (findings or 0) > 0
        print(f"  {name:<{width}}  {status}{('  (' + note + ')') if note else ''}")
    return 1 if failed else 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    sys.exit(main())
