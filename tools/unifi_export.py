"""Export a UniFi gateway's firewall zones and policies to a JSON file that RuleTruss can import.

    .venv/bin/python tools/unifi_export.py --host 192.168.1.1 --fingerprint <sha256-hex> --out unifi-export.json     (asks for the key)
    UNIFI_API_KEY=... .venv/bin/python tools/unifi_export.py --host 192.168.1.1 --out unifi-export.json
    .venv/bin/python tools/unifi_export.py --host 192.168.1.1 --api-key-file ~/unifi-key.txt --out unifi-export.json   (a file you make)

Only read-only GET requests are made, only to the host you name, using the local UniFi Network Integration API
(https://<host>/proxy/network/integration/v1/...). Create the API key in the UniFi Network application (see docs/EXPORT_UNIFI.md).
The key is typed at a hidden prompt, or read from the UNIFI_API_KEY environment variable or a file you make, never from the command line,
and is not written to the output.
The gateway's certificate is normally self-signed: run once with --show-fingerprint, check the value against what you expect,
then pass it with --fingerprint (the connection is refused if the certificate differs). --insecure skips the check entirely.

This is a separate command run by you. The RuleTruss server never contacts your gateway.
"""
import argparse
import getpass
import hashlib
import http.client
import json
import os
import ssl
import stat
import sys
from datetime import UTC, datetime

BASE = "/proxy/network/integration/v1"
PAGE = 200
MAX_BODY = 64 * 1024 * 1024
MAX_PAGES = 500
MARK = "ruletruss_unifi_export"


class ExportError(RuntimeError):
    """Something the user can act on."""


def make_context(fingerprint=None, insecure=False):
    context = ssl.create_default_context()
    if fingerprint or insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def clean_fingerprint(text):
    value = (text or "").replace(":", "").replace(" ", "").lower()
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ExportError("the fingerprint must be 64 hexadecimal characters (the SHA-256 of the certificate)")
    return value


class Gateway:
    """GET requests to one gateway, with an optional pinned certificate fingerprint."""

    def __init__(self, host, api_key, port=443, fingerprint=None, insecure=False, timeout=30):
        self.host, self.port, self.timeout = host, port, timeout
        self.api_key = api_key
        self.fingerprint = clean_fingerprint(fingerprint) if fingerprint else None
        self.context = make_context(self.fingerprint, insecure)

    def _connect(self):
        # nosemgrep: httpsconnection-detected - an explicit SSLContext is passed (verifying by default, or pinned by fingerprint)
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.context)
        try:
            conn.connect()
        except ssl.SSLCertVerificationError as error:
            raise ExportError("the gateway's certificate was not accepted (it is probably self-signed). Run with --show-fingerprint, "
                              "check the value, then pass it with --fingerprint.") from error
        except (OSError, ssl.SSLError) as error:
            raise ExportError(f"could not connect to {self.host}:{self.port}: {error}") from error
        if self.fingerprint:
            seen = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
            if seen != self.fingerprint:
                conn.close()
                raise ExportError(f"the gateway's certificate fingerprint is {seen}, not the one you gave; nothing was sent")
        return conn

    def get(self, path, params=None):
        query = "&".join(f"{k}={v}" for k, v in (params or {}).items())
        conn = self._connect()
        try:
            conn.request("GET", f"{BASE}{path}" + (f"?{query}" if query else ""),
                         headers={"X-API-KEY": self.api_key, "Accept": "application/json"})
            response = conn.getresponse()
            body = response.read(MAX_BODY + 1)
        finally:
            conn.close()
        if len(body) > MAX_BODY:
            raise ExportError(f"the answer to {path} is larger than {MAX_BODY // 2**20} MB; stopped")
        if response.status == 401 or response.status == 403:
            raise ExportError("the gateway refused the API key (check that it is current and belongs to the Network application)")
        if response.status == 404:
            raise ExportError(f"{path} was not found: this Network version may be too old for the firewall API (it needs 10.1 or later)")
        if response.status != 200:
            raise ExportError(f"{path} answered {response.status}")
        try:
            return json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as error:
            raise ExportError(f"the answer to {path} was not JSON") from error


def show_fingerprint(host, port=443, timeout=30):
    context = make_context(insecure=True)
    # nosemgrep: httpsconnection-detected - this call only reads the certificate, to show its fingerprint; nothing is sent
    conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    try:
        conn.connect()
        return hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
    except (OSError, ssl.SSLError) as error:
        raise ExportError(f"could not connect to {host}:{port}: {error}") from error
    finally:
        conn.close()


def pages(get, path):
    """Every item of a paged list endpoint."""
    items, offset = [], 0
    for _ in range(MAX_PAGES):
        page = get(path, {"offset": offset, "limit": PAGE})
        data = page.get("data") if isinstance(page, dict) else None
        if not isinstance(data, list):
            raise ExportError(f"{path} did not return a list")
        items += data
        offset += len(data)
        total = page.get("totalCount")
        if not data or (isinstance(total, int) and offset >= total):
            return items
    raise ExportError(f"{path} has more than {MAX_PAGES * PAGE:,} items; stopped")


def pick_site(sites, wanted):
    if wanted:
        for site in sites:
            if wanted in (site.get("id"), site.get("internalReference"), site.get("name")):
                return site
        raise ExportError(f"no site called {wanted!r}; the gateway has: " + ", ".join(str(s.get("name")) for s in sites))
    if len(sites) == 1:
        return sites[0]
    for site in sites:
        if site.get("internalReference") == "default":
            return site
    raise ExportError("the gateway has several sites; choose one with --site: " + ", ".join(str(s.get("name")) for s in sites))


def export(get, site_name=None):
    """Collect everything RuleTruss reads, through `get(path, params)`. Returns the JSON-ready bundle."""
    info = get("/info")
    site = pick_site(pages(get, "/sites"), site_name)
    prefix = f"/sites/{site['id']}"
    zones = pages(get, f"{prefix}/firewall/zones")
    policies = pages(get, f"{prefix}/firewall/policies")
    networks = [get(f"{prefix}/networks/{n['id']}") for n in pages(get, f"{prefix}/networks")]
    lists = pages(get, f"{prefix}/traffic-matching-lists")
    try:
        acl_rules = pages(get, f"{prefix}/acl-rules")
    except ExportError:
        acl_rules = []                      # switch ACLs are optional context; older versions do not have them
    return {MARK: 1, "exported_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "application_version": info.get("applicationVersion", "") if isinstance(info, dict) else "",
            "site": {k: site.get(k) for k in ("id", "name", "internalReference")}, "zones": zones, "policies": policies,
            "networks": networks, "traffic_matching_lists": lists, "acl_rules": acl_rules}


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=1, ensure_ascii=True)
        handle.write("\n")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def read_key(path):
    """The API key from a file, else the UNIFI_API_KEY variable, else (at a terminal) a hidden prompt. Never from the command line."""
    if path:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    key = os.environ.get("UNIFI_API_KEY", "").strip()
    if not key and sys.stdin.isatty():
        key = getpass.getpass("UniFi API key (not shown, not saved): ").strip()
    return key


def main(argv=None):
    parser = argparse.ArgumentParser(description="Export UniFi firewall zones and policies for RuleTruss (read-only).")
    parser.add_argument("--host", required=True, help="the gateway's address, for example 192.168.1.1")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--api-key-file", help="a file holding the API key (otherwise the UNIFI_API_KEY environment variable is used)")
    parser.add_argument("--site", help="site name or id (needed only if the gateway has several)")
    parser.add_argument("--fingerprint", help="SHA-256 of the gateway's certificate, from --show-fingerprint")
    parser.add_argument("--insecure", action="store_true", help="do not check the gateway's certificate at all")
    parser.add_argument("--show-fingerprint", action="store_true", help="print the certificate fingerprint and stop")
    parser.add_argument("--out", default="unifi-export.json")
    args = parser.parse_args(argv)
    try:
        if args.show_fingerprint:
            print(show_fingerprint(args.host, args.port))
            return 0
        key = read_key(args.api_key_file)
        if not key:
            raise ExportError("no API key: run this at a terminal to be asked for it, or set UNIFI_API_KEY, or use --api-key-file")
        if args.insecure and args.fingerprint:
            raise ExportError("use --fingerprint or --insecure, not both")
        gateway = Gateway(args.host, key, args.port, args.fingerprint, args.insecure)
        bundle = export(gateway.get, args.site)
        write_private(args.out, bundle)
    except (ExportError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    print(f"Wrote {args.out}: {len(bundle['zones'])} zones, {len(bundle['policies'])} policies, {len(bundle['networks'])} networks "
          f"(Network {bundle['application_version'] or 'version unknown'}). Import it into RuleTruss on the Import tab.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
