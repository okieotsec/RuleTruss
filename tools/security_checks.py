"""Run the security toolchain from SECURITY_TEST_PLAN.md and save every tool's raw output.

Usage:  .venv/bin/python tools/security_checks.py reports/cpN-name [--accept-suppressions]

Each tool's output is written under that folder (bandit.json, semgrep.json, ruff.json, gitleaks.json, pip-audit.json,
osv.json, versions.txt, summary.txt). The summary printed at the end says how many findings each tool reported; a tool that
could not run is listed as NOT RUN with the reason, never skipped silently. The exit status is 1 when any check fails.

Beyond the scanners this runner does two things the test plan asks for:

* Suppression inventory (SSDF PW.7): every in-source suppression comment (the semgrep, bandit and ruff markers) is listed in
  suppressions.json and compared with security/suppressions.baseline.json. A suppression that is not in the baseline is a
  failure until someone has read it and accepted it with --accept-suppressions.
* SARIF and the MITRE SAF CLI (optional): ruff, semgrep, gitleaks, osv-scanner and (when bandit[sarif] is installed) bandit
  also write SARIF. If the `saf` command is found (PATH, or the SAF_CLI environment variable) each SARIF file is converted
  to the Heimdall Data Format (HDF) under hdf/ and checked with `saf validate threshold`; without it the step is reported as
  NOT RUN. SARIF results that are suppressed in the source are removed first, because the inventory above already accounts
  for them. Nothing here is required to build or run the application.
"""
import json
import os
import re
import shlex
import shutil
import subprocess  # nosec B404 - runs fixed command lines for the security tools; no shell, no untrusted input
import sys
import tempfile
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = Path(sys.executable).parent

# ---- Settings that differ between the sibling projects (everything below this block is the same in both) ----
SOURCE_DIRS = ["ruletruss", "tools"]       # bandit and semgrep scan these (tests are excluded, as in the plan)
REQUIREMENTS = "requirements.txt"          # None when the project has no third-party dependency
HASHED_REQUIREMENTS = True                 # pip-audit --require-hashes
SKIP_DIRS = {".git", ".venv", "__pycache__", ".hypothesis", ".ruff_cache", "node_modules", "dist"}
BASELINE = ROOT / "security" / "suppressions.baseline.json"
# ---------------------------------------------------------------------------------------------------------

# Built from pieces so this file does not hold a suppression of its own by accident.
MARKERS = ("nosem" + "grep", "nos" + "ec", "no" + "qa")
MARKER_RE = re.compile(r"\s*(" + "|".join(MARKERS) + r")\b(.*)")
CODE_RE = re.compile(r"\b[A-Z]{1,4}\d{2,4}\b|\b[\w-]+(?:\.[\w-]+)+\b")


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


def python_files():
    for folder, dirs, files in os.walk(ROOT):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            if name.endswith(".py"):
                yield Path(folder) / name


def find_suppressions():
    """Every suppression comment in every Python file, found with the tokenizer so text inside strings is never counted."""
    found = []
    for path in python_files():
        try:
            with open(path, "rb") as handle:
                tokens = list(tokenize.tokenize(handle.readline))
        except (tokenize.TokenError, SyntaxError, UnicodeDecodeError):
            found.append({"file": str(path.relative_to(ROOT)), "line": 0, "marker": "unreadable", "codes": [], "text": ""})
            continue
        for token in tokens:
            if token.type != tokenize.COMMENT:
                continue
            for part in token.string.split("#"):  # one comment can hold two markers, such as a ruff one and a bandit one
                match = MARKER_RE.match(part)
                if not match:
                    continue
                reason_cut = match.group(2).split(" - ")[0]
                if match.group(1) == MARKERS[0]:  # semgrep rule names are short words after a colon, so they have no code shape
                    codes = sorted(set(re.findall(r"[\w.-]+", reason_cut.split(":", 1)[1]))) if ":" in reason_cut else []
                else:
                    codes = sorted(set(CODE_RE.findall(reason_cut)))
                found.append({"file": str(path.relative_to(ROOT)), "line": token.start[0], "marker": match.group(1),
                              "codes": codes, "text": token.string.strip()[:200]})
    return found


def suppression_keys(entries):
    counts = {}
    for item in entries:
        key = f"{item['file']}|{item['marker']}|{','.join(item['codes'])}"
        counts[key] = counts.get(key, 0) + 1
    return counts


def check_suppressions(out, accept):
    entries = find_suppressions()
    (out / "suppressions.json").write_text(json.dumps(entries, indent=1) + "\n")
    current = suppression_keys(entries)
    if accept:
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(json.dumps({"version": 1, "entries": dict(sorted(current.items()))}, indent=1) + "\n")
        return 0, f"{len(entries)} suppression(s) accepted into {BASELINE.relative_to(ROOT)}"
    try:
        baseline = json.loads(BASELINE.read_text())["entries"]
    except (OSError, ValueError, KeyError):
        return None, f"no baseline at {BASELINE.relative_to(ROOT)}; review suppressions.json, then run with --accept-suppressions"
    new = [f"{key} (now {count}, accepted {baseline.get(key, 0)})" for key, count in sorted(current.items()) if count > baseline.get(key, 0)]
    if new:
        (out / "suppressions-unreviewed.txt").write_text("\n".join(new) + "\n")
        return len(new), "see suppressions-unreviewed.txt"
    return 0, f"{len(entries)} suppression(s), all in the accepted baseline"


def trim_sarif(source):
    """Return a SARIF document keeping only the rules that have results, without their long help text.

    The scanners embed their whole rule catalogue in every SARIF file. That is hundreds of kilobytes of third-party text, and
    its links and examples have no place in this repository's archive. Result indexes are renumbered to match.
    """
    data = json.loads(Path(source).read_text() or "{}")
    for run_ in data.get("runs", []):
        results = run_.get("results", [])
        driver = run_.get("tool", {}).get("driver", {})
        rules = driver.get("rules", [])
        used = sorted({r["ruleId"] for r in results if "ruleId" in r})
        position = {rule.get("id"): i for i, rule in enumerate(rules)}
        driver["rules"] = [{k: v for k, v in rules[position[i]].items() if k != "help"} for i in used if i in position]
        renumbered = {rule["id"]: n for n, rule in enumerate(driver["rules"])}
        for result in results:
            if result.get("ruleId") in renumbered:
                result["ruleIndex"] = renumbered[result["ruleId"]]
            else:
                result.pop("ruleIndex", None)
    return data


def without_suppressed(data):
    """Copy of a SARIF document without the results the source marks as suppressed, and how many were removed."""
    clone = json.loads(json.dumps(data))
    removed = 0
    for run_ in clone.get("runs", []):
        kept = [r for r in run_.get("results", []) if not r.get("suppressions")]
        removed += len(run_.get("results", [])) - len(kept)
        run_["results"] = kept
    return clone, removed


def write_sarif(data, target):
    """Write SARIF with this checkout's absolute path replaced, so an archived report never names where it was produced."""
    Path(target).write_text(json.dumps(data, indent=1).replace(str(ROOT), ".") + "\n")


def saf_command():
    configured = os.environ.get("SAF_CLI")
    if configured:
        return shlex.split(configured)
    found = shutil.which("saf")
    return [found] if found else None


def archive_sarif(out, work, names):
    """Archive each tool's trimmed SARIF; return {name: removed count} and write the suppression-free copies to `work`."""
    removed = {}
    for name in names:
        source = work / f"{name}.sarif"
        if not source.exists() or not source.stat().st_size:
            continue
        data = trim_sarif(source)
        write_sarif(data, out / f"{name}.sarif")
        active, removed[name] = without_suppressed(data)
        write_sarif(active, work / f"{name}.active.sarif")
    return removed


def saf_step(out, work, removed):
    """Convert each suppression-free SARIF file to HDF and check it with `saf validate threshold`. Returns (failures, note)."""
    command = saf_command()
    if not command:
        return None, "saf not found (npm install @mitre/saf, then put it on PATH or set SAF_CLI); optional"
    failures, notes, converted = 0, [], []
    for name, count in removed.items():
        hdf = f"{name}.hdf.json"
        # Relative names and a scratch working folder: saf prints and logs the paths it is given.
        proc = run([*command, "convert", "sarif2hdf", "-i", f"{name}.active.sarif", "-o", hdf], cwd=work, timeout=300)
        if proc.returncode != 0 or not (work / hdf).exists():
            failures += 1
            notes.append(f"{name}: convert failed")
            continue
        converted.append(hdf)
        check = run([*command, "validate", "threshold", "-i", hdf, "-I", "{failed.total.max: 0}"], cwd=work, timeout=300)
        if check.returncode != 0 or "Threshold not met" in (check.stdout + check.stderr):
            failures += 1
            notes.append(f"{name}: threshold not met")
        if count:
            notes.append(f"{name}: {count} suppressed result(s) left out (listed in suppressions.json)")
    if converted:
        summary = run([*command, "view", "summary", *[a for h in converted for a in ("-i", h)]], cwd=work, timeout=300)
        (out / "saf-summary.txt").write_text(summary.stdout)
        (out / "hdf").mkdir(exist_ok=True)
        for hdf in converted:
            (out / "hdf" / hdf).write_text((work / hdf).read_text().replace(str(ROOT), "."))
    return failures, "; ".join(notes)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    accept = "--accept-suppressions" in sys.argv[1:]
    if len(args) != 1:
        raise SystemExit(__doc__)
    out = ROOT / args[0]
    out.mkdir(parents=True, exist_ok=True)
    results, versions, sarif_names = [], [], []
    work = Path(tempfile.mkdtemp())  # raw SARIF and saf's working files live here and are not archived
    app_files = [str(p.relative_to(ROOT)) for d in SOURCE_DIRS for p in sorted((ROOT / d).rglob("*.py"))]

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
        run([exe, "check", ".", "--output-format", "sarif"], work / "ruff.sarif")
        sarif_names.append("ruff")
        version("ruff")
    else:
        record("ruff", None, "not installed")
    # bandit on application code (tests are excluded, as in the plan)
    exe = tool("bandit")
    if exe:
        run([exe, "-q", "-f", "json", "-o", str(out / "bandit.json"), *app_files])
        record("bandit", count_json(out / "bandit.json", "results"))
        run([exe, "-q", "-f", "sarif", "-o", str(work / "bandit.sarif"), *app_files])  # needs bandit[sarif]; skipped if absent
        sarif_names.append("bandit")
        version("bandit")
    else:
        record("bandit", None, "not installed")
    # semgrep downloads its rule packs; no project code is sent anywhere (metrics off). One pass writes JSON and SARIF.
    exe = tool("semgrep")
    if exe:
        proc = run([exe, "scan", "--config", "p/python", "--config", "p/security-audit", "--metrics", "off", "--json-output",
                    str(out / "semgrep.json"), "--sarif-output", str(work / "semgrep.sarif"), "--quiet", *SOURCE_DIRS], timeout=1800)
        n = count_json(out / "semgrep.json", "results") if (out / "semgrep.json").exists() else None
        record("semgrep", n, "" if n is not None else (proc.stderr.strip().splitlines() or ["did not run"])[-1][:200])
        sarif_names.append("semgrep")
        version("semgrep")
    else:
        record("semgrep", None, "not installed")
    # gitleaks over the full git history and working tree
    exe = tool("gitleaks")
    if exe:
        base = [exe, "detect", "--source", ".", "--no-banner"]
        proc = run([*base, "--report-format", "json", "--report-path", str(out / "gitleaks.json")])
        text = (out / "gitleaks.json").read_text() if (out / "gitleaks.json").exists() else "[]"
        record("gitleaks", len(json.loads(text or "[]")), "" if proc.returncode in (0, 1) else proc.stderr[-200:])
        run([*base, "--report-format", "sarif", "--report-path", str(work / "gitleaks.sarif")])
        sarif_names.append("gitleaks")
        version("gitleaks", ("version",))
    else:
        record("gitleaks", None, "not installed")
    # dependencies
    if REQUIREMENTS is None:
        record("pip-audit", 0, "n/a: no third-party dependency")
        record("osv-scanner", 0, "n/a: no third-party dependency")
    else:
        exe = tool("pip-audit")
        if exe:
            command = [exe, "-r", REQUIREMENTS, "-f", "json", "-o", str(out / "pip-audit.json")]
            proc = run([*command, "--require-hashes"] if HASHED_REQUIREMENTS else command, timeout=600)
            data = json.loads((out / "pip-audit.json").read_text() or "{}") if (out / "pip-audit.json").exists() else {}
            vulns = sum(len(d.get("vulns", [])) for d in data.get("dependencies", []))
            record("pip-audit", vulns if data else None, "" if data else proc.stderr[-200:])
            version("pip-audit")
        else:
            record("pip-audit", None, "not installed")
        exe = tool("osv-scanner")
        if exe:
            proc = run([exe, f"--lockfile={REQUIREMENTS}", "--format", "json"], out / "osv.json", timeout=600)
            try:
                data = json.loads((out / "osv.json").read_text() or "{}")
                record("osv-scanner", sum(len(p.get("vulnerabilities", [])) for r in data.get("results", []) for p in r.get("packages", [])))
            except ValueError:
                record("osv-scanner", None, proc.stderr[-200:])
            run([exe, f"--lockfile={REQUIREMENTS}", "--format", "sarif"], work / "osv.sarif", timeout=600)
            sarif_names.append("osv")
            version("osv-scanner", ("--version",))
        else:
            record("osv-scanner", None, "not installed")
    # suppression inventory (SSDF PW.7) and the optional MITRE SAF step
    findings, note = check_suppressions(out, accept)
    record("suppressions", findings, note)
    removed = archive_sarif(out, work, sarif_names)
    findings, note = saf_step(out, work, removed)
    record("saf (optional)", findings, note)
    command = saf_command()
    if command:
        with tempfile.TemporaryDirectory() as scratch:  # saf writes a log file into its working folder
            versions.append("saf: " + (run([*command, "--version"], cwd=scratch).stdout.strip().splitlines() or ["?"])[0])
    shutil.rmtree(work, ignore_errors=True)
    (out / "versions.txt").write_text("\n".join(versions) + "\n")
    width = max(len(n) for n, _, _ in results)
    failed = False
    lines = [f"Security checks written to {out.relative_to(ROOT)}"]
    for name, findings, note in results:
        status = "NOT RUN" if findings is None else ("0 findings" if findings == 0 else f"{findings} FINDING(S)")
        optional = name.endswith("(optional)")
        failed = failed or (findings or 0) > 0 or (findings is None and not optional and name == "suppressions")
        lines.append(f"  {name:<{width}}  {status}{('  (' + note + ')') if note else ''}")
    (out / "summary.txt").write_text("\n".join(lines) + "\n")
    print("\n" + "\n".join(lines))
    return 1 if failed else 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    sys.exit(main())
