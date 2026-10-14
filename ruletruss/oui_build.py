"""Build the vendor-name table from the IEEE Registration Authority's public listings (MA-L, MA-M, MA-S).

    python -m ruletruss.oui_build --out PATH                 download the three listings from the IEEE and write PATH
    python -m ruletruss.oui_build --from DIR --out PATH      build from files you downloaded yourself (oui.csv, oui28.csv, oui36.csv)

This is the only code in RuleTruss that can reach the network, and it runs only when the user asks (the "Download vendor names"
button, or this command). It is started by the application in a separate resource-limited process. Only the prefix and the
organisation name are kept. The IEEE states no licence for redistributing its listings, so RuleTruss does not ship a copy: each user
downloads their own.
"""
import argparse
import csv
import gzip
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request  # nosec B410 - fixed https URLs on the IEEE host, restricted redirects; runs only when the user asks
from datetime import date

SOURCES = {"oui.csv": "https://standards-oui.ieee.org/oui/oui.csv", "oui28.csv": "https://standards-oui.ieee.org/oui28/mam.csv",
           "oui36.csv": "https://standards-oui.ieee.org/oui36/oui36.csv"}
LENGTH = {"MA-L": 6, "MA-M": 7, "MA-S": 9}
MAX_DOWNLOAD = 20_000_000
MIN_ENTRIES = 30_000
TIMEOUT = 60
USER_AGENT = "RuleTruss vendor-name update (local application; contact: none)"


class BuildError(ValueError):
    """The vendor names could not be built. The message is safe to show."""


def allowed_host(url):
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    on_ieee = host == "ieee.org" or host.endswith(".ieee.org")
    return parts.scheme == "https" and on_ieee and not parts.username and parts.port in (None, 443)


class _OnlyIeee(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed_host(newurl):
            raise urllib.error.URLError("the IEEE server redirected to an address that is not on ieee.org; stopped")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def clean(name):
    name = re.sub(r"[\x00-\x1f\x7f]", " ", name)
    name = re.sub(r"\s+", " ", name).strip()
    return name[:80].encode("ascii", "replace").decode("ascii") if name else "Private (registrant not published)"


def download(folder):
    opener = urllib.request.build_opener(_OnlyIeee)
    for filename, url in SOURCES.items():
        if not allowed_host(url):
            raise BuildError("refusing to download from an unexpected address")
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
        try:
            with opener.open(request, timeout=TIMEOUT) as response:  # nosec B310
                data = response.read(MAX_DOWNLOAD + 1)
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            raise BuildError(f"could not download {filename} from the IEEE: {getattr(error, 'reason', error)}") from error
        if len(data) > MAX_DOWNLOAD:
            raise BuildError(f"{filename} is larger than expected; stopped")
        with open(os.path.join(folder, filename), "wb") as handle:
            handle.write(data)


def build(folder, minimum=MIN_ENTRIES):
    rows = {}
    for filename in SOURCES:
        try:
            with open(os.path.join(folder, filename), encoding="utf-8-sig", newline="") as handle:
                for record in csv.DictReader(handle):
                    kind, prefix = (record.get("Registry") or "").strip(), (record.get("Assignment") or "").strip().upper()
                    if kind in LENGTH and len(prefix) == LENGTH[kind] and re.fullmatch(r"[0-9A-F]+", prefix):
                        rows[prefix] = (kind, clean(record.get("Organization Name") or ""))
        except (OSError, UnicodeDecodeError, csv.Error) as error:
            raise BuildError(f"{filename} could not be read as an IEEE listing ({type(error).__name__})") from error
    if len(rows) < minimum:
        raise BuildError(f"only {len(rows)} assignments were found; the files do not look like the IEEE listings")
    return rows


def write(rows, out):
    directory = os.path.dirname(os.path.abspath(out))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".vendor-names-")
    try:
        with os.fdopen(fd, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as handle:
            header = (f"#source IEEE Registration Authority public listings (MA-L, MA-M, MA-S): {', '.join(SOURCES.values())}\n"
                      f"#retrieved {date.today().isoformat()}\n#entries {len(rows)}\n")
            handle.write(header.encode("ascii"))
            for prefix in sorted(rows):
                kind, name = rows[prefix]
                handle.write(f"{prefix}\t{kind}\t{name}\n".encode("ascii"))
        os.chmod(tmp, 0o600)
        os.replace(tmp, out)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m ruletruss.oui_build")
    parser.add_argument("--out", required=True)
    parser.add_argument("--from", dest="source", help="folder holding oui.csv, oui28.csv and oui36.csv (no download)")
    args = parser.parse_args(argv)
    from .worker import apply_limits
    apply_limits()
    try:
        if args.source:
            rows = build(args.source)
        else:
            with tempfile.TemporaryDirectory(prefix="rt-oui-") as folder:
                download(folder)
                rows = build(folder)
        write(rows, args.out)
        result = {"ok": True, "entries": len(rows)}
    except BuildError as error:
        result = {"ok": False, "error": str(error)[:300]}
    except Exception:
        result = {"ok": False, "error": "the vendor names could not be built"}
    print(json.dumps(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
