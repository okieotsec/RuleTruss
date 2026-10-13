"""Regenerate sbom/sbom.cdx.json, the CycloneDX software bill of materials.

Policy Bridge has one runtime dependency (dpkt, for reading packet captures). To prove that, this tool builds a brand-new virtual
environment, installs ONLY requirements.txt into it with hash checking (`pip install --require-hashes`), and has cyclonedx-py
inspect that environment. Packages that are only used for development (linters, test and scanning tools) are therefore absent.

Usage (needs cyclonedx-bom, which provides cyclonedx-py, and network access to install the pinned packages):

    .venv/bin/python tools/make_sbom.py

It also checks that every package in the SBOM is pinned in requirements.txt and the other way round.
"""
import json
import re
import shutil
import subprocess  # nosec B404 - runs pip and cyclonedx-py on a throwaway environment this tool creates
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from pbridge.version import __version__  # noqa: E402

OUTPUT = ROOT / "sbom" / "sbom.cdx.json"
BOM_REF = f"pkg:generic/policy-bridge@{__version__}"


def find_cyclonedx():
    beside = Path(sys.executable).parent / "cyclonedx-py"
    found = str(beside) if beside.exists() else shutil.which("cyclonedx-py")
    if not found:
        raise SystemExit("cyclonedx-py not found: pip install cyclonedx-bom")
    return found


def pinned_requirements():
    names = {}
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s\\]+)", line)
        if m:
            names[m.group(1).lower().replace("_", "-")] = m.group(2)
    return names


def application_component():
    return {
        "type": "application", "bom-ref": BOM_REF, "name": "policy-bridge", "version": __version__,
        "description": "Local-first workbench that explains network communications and migrates security policies",
        "licenses": [{"license": {"id": "MIT"}}],
    }


def build():
    with tempfile.TemporaryDirectory() as folder:
        env = Path(folder) / "env"
        venv.create(env, with_pip=True)
        python = str(env / "bin" / "python")
        # Fixed commands on a folder this tool just created; requirements.txt carries the hashes.
        subprocess.run([python, "-m", "pip", "install", "-q", "--require-hashes", "-r", str(ROOT / "requirements.txt")],  # noqa: S603  # nosec B603
                       check=True)
        raw = Path(folder) / "raw.json"
        subprocess.run([find_cyclonedx(), "environment", python, "--of", "JSON", "--sv", "1.6", "--output-reproducible",  # noqa: S603  # nosec B603
                        "-o", str(raw)], check=True)
        bom = json.loads(raw.read_text(encoding="utf-8"))
    components = {c["name"].lower().replace("_", "-"): c["version"] for c in bom.get("components", [])
                  if c["name"].lower() not in ("pip", "setuptools", "wheel")}
    expected = pinned_requirements()
    if components != expected:
        raise SystemExit(f"SBOM and requirements.txt disagree: SBOM {components} vs requirements {expected}")
    bom["components"] = [c for c in bom["components"] if c["name"].lower() not in ("pip", "setuptools", "wheel")]
    bom["metadata"]["component"] = application_component()
    bom["dependencies"] = [{"ref": BOM_REF, "dependsOn": [c["bom-ref"] for c in bom["components"]]}]
    return bom


def main():
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)} for policy-bridge {__version__}")


if __name__ == "__main__":
    main()
