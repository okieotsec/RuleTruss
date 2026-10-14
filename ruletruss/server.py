"""The local web server: standard library only, loopback by default, token-protected, with bounded request sizes.

Protections, in order of what they stop:
  * Bound to 127.0.0.1 unless --allow-non-loopback is given.
  * Every /api/ call needs the per-run access token (printed in the start-up URL). That stops other local users and any web
    page in your browser from using the API, and a cross-site request cannot add the Authorization header.
  * The Host header must name this server (DNS rebinding) and a browser Origin, if sent, must be this server.
  * Request bodies are size-limited; uploads are streamed to disk, never held in memory; sockets time out.
  * Responses carry a strict Content-Security-Policy (no inline script, no remote resources) and no-store caching.
"""
import argparse
import errno
import hmac
import json
import os
import re
import secrets
import shutil
import sys
import threading
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import limits
from .adapters.registry import SOURCE_FORMATS
from .jobs import MAX_RUNNING as MAX_RUNNING_IMPORTS
from .jobs import Jobs
from .migrate import directional, firewall
from .model import to_plain
from .service import ApiError, Service
from .store import Store, StoreError
from .version import __version__

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
STATIC = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8"), "/graph.js": ("graph.js", "text/javascript; charset=utf-8"),
          **{f"/brand/{name}.svg": (f"brand/{name}.svg", "image/svg+xml") for name in (
              "okieotsec-shield", "okieotsec-shield-dark", "okieotsec-app-tile", "okieotsec-lockup", "okieotsec-lockup-dark")}}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
       "form-action 'none'; frame-ancestors 'none'")
MAX_JSON_BODY = 8 * 1024 * 1024
SOCKET_TIMEOUT = 60
DISK_HEADROOM = 1024 ** 3                  # free space that must remain after an upload is stored
ROUTES = []


def route(method, pattern):
    def wrap(fn):
        ROUTES.append((method, re.compile("^" + pattern + "$"), fn))
        return fn
    return wrap


class App:
    """Shared state for the handler: the service, the token, and the names this server answers to."""

    def __init__(self, data_store, token, host, port, ai_endpoint=None, ai_allow_remote=False):
        self.service = Service(data_store, ai_endpoint, ai_allow_remote)
        self.jobs = Jobs()
        self.store = data_store
        self.token = token
        self.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}", f"{host}:{port}"}
        self.allowed_origins = {f"http://{h}" for h in self.allowed_hosts}
        self.ai_enabled = bool(ai_endpoint)


class QuietServer(ThreadingHTTPServer):
    """A client that disconnects or sends a malformed request is routine, not an error worth a stack trace."""

    def handle_error(self, request, client_address):
        error = sys.exc_info()[1]
        if not isinstance(error, (BrokenPipeError, ConnectionResetError, TimeoutError)):
            traceback.print_exc(file=sys.stderr)


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = "RuleTruss"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            self.connection.settimeout(SOCKET_TIMEOUT)

        def log_message(self, fmt, *args):      # no access log of paths or queries
            return

        # ---------------------------------------------------------- helpers
        def send(self, status, body=b"", content_type="application/json", extra=None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def send_json(self, obj, status=200):
            self.send(status, json.dumps(to_plain(obj), ensure_ascii=True).encode("ascii"))

        def error(self, status, message):
            self.send_json({"error": message}, status)

        def send_error(self, code, message=None, explain=None):
            """The base class calls this itself for what it refuses before our code runs (an unsupported method, a malformed or over-long
            request line). It would answer with its own HTML page and none of the security headers, so answer like every other error."""
            self.close_connection = True
            try:
                reason = HTTPStatus(code).phrase.lower()
            except ValueError:
                reason = "request refused"
            self.send(code, json.dumps({"error": reason}).encode("ascii"), extra={"Connection": "close"})

        def check_host_and_origin(self):
            if self.headers.get("Host", "") not in app.allowed_hosts:
                self.error(403, "this server only answers to its own address")
                return False
            origin = self.headers.get("Origin")
            if origin is not None and origin not in app.allowed_origins:
                self.error(403, "cross-origin requests are refused")
                return False
            return True

        def check_token(self):
            header = self.headers.get("Authorization", "")
            given = header[7:] if header.startswith("Bearer ") else ""
            if not hmac.compare_digest(given.encode(), app.token.encode()):
                self.error(401, "missing or wrong access token; open the address printed when the server started")
                return False
            return True

        def read_json(self):
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                raise ApiError("a Content-Length header is required", 411) from None
            if length < 0 or length > MAX_JSON_BODY:
                raise ApiError("the request is too large", 413)
            raw = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw.decode("utf-8"))
            except (ValueError, RecursionError) as error:
                raise ApiError("the request body is not valid JSON") from error
            if not isinstance(body, dict):
                raise ApiError("the request body must be a JSON object")
            return body

        def stream_upload(self, project_id):
            if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
                raise ApiError("chunked uploads are not accepted; send a Content-Length", 411)
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                raise ApiError("a Content-Length header is required", 411) from None
            if length <= 0:
                raise ApiError("the file is empty")
            if length > limits.MAX_CAPTURE_BYTES:
                raise ApiError(f"the file is larger than the {limits.MAX_CAPTURE_BYTES // (1024 * 1024):,} MB limit "
                               "(start RuleTruss with --max-capture-mb to raise it)", 413)
            free = shutil.disk_usage(app.store.root).free
            if free < length + DISK_HEADROOM:
                raise ApiError(f"not enough free disk space for this file: it is {length // 1024 ** 2:,} MB and "
                               f"{free // 1024 ** 2:,} MB is free in {app.store.root}", 507)
            path = app.store.new_upload_path(project_id)
            remaining = length
            try:
                with open(path, "wb") as handle:
                    os.fchmod(handle.fileno(), 0o600)
                    while remaining > 0:
                        chunk = self.rfile.read(min(1 << 20, remaining))
                        if not chunk:
                            raise ApiError("the upload ended before the announced size")
                        handle.write(chunk)
                        remaining -= len(chunk)
            except BaseException:
                app.store.discard_upload(path)
                raise
            return path

        # ---------------------------------------------------------- dispatch
        def handle_any(self):
            """Any failure outside a route (static files, query parsing) still ends in a clean response or a closed connection."""
            try:
                self.dispatch()
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                self.close_connection = True
            except Exception:
                traceback.print_exc(file=sys.stderr)
                self.close_connection = True
                try:
                    self.error(500, "internal error; see the server console")
                except OSError:
                    pass

        def dispatch(self):
            if not self.check_host_and_origin():
                return
            parsed = urlparse(self.path)
            path = parsed.path
            if self.command in ("GET", "HEAD") and path in STATIC:
                name, ctype = STATIC[path]
                with open(os.path.join(WEB_DIR, name), "rb") as handle:
                    self.send(200, handle.read(), ctype)
                return
            if not path.startswith("/api/"):
                self.error(404, "not found")
                return
            if not self.check_token():
                return
            try:
                query = {k: v[0] for k, v in parse_qs(parsed.query, max_num_fields=40).items()}
            except ValueError:
                self.error(400, "the query string is not valid or has too many fields")
                return
            for method, pattern, fn in ROUTES:
                m = pattern.match(path)
                if m and method == self.command:
                    try:
                        fn(self, app, query, *m.groups())
                    except ApiError as error:
                        self.discard_unread_body()
                        self.error(error.status, str(error))
                    except StoreError as error:
                        self.discard_unread_body()
                        self.error(404 if "not found" in str(error) else 400, str(error))
                    except (TimeoutError, BrokenPipeError, ConnectionResetError):
                        self.close_connection = True
                    except Exception:
                        traceback.print_exc(file=sys.stderr)
                        self.discard_unread_body()
                        self.error(500, "internal error; see the server console")
                    return
            self.error(404, "not found")

        def discard_unread_body(self):
            """After an error the request body may be unread; close the connection instead of guessing where it ends."""
            self.close_connection = True

        do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = handle_any

        def do_OPTIONS(self):   # no CORS: a preflight is always refused
            self.error(405, "not allowed")

    return Handler


# ---------------------------------------------------------------------------------------------------- routes

@route("GET", "/api/status")
def status(h, app, q):
    h.send_json({"version": __version__, "formats": SOURCE_FORMATS, "targets": {k: v["label"] for k, v in firewall.TARGETS.items()},
                 "limits": {"max_capture_bytes": limits.MAX_CAPTURE_BYTES, "max_config_bytes": limits.MAX_CONFIG_BYTES,
                            "parse_seconds": limits.PARSE_SECONDS, "max_flows": limits.MAX_FLOWS, "max_packets": limits.MAX_PACKETS},
                 "model": directional.MODEL_FACTS, "usage": app.store.usage(), "ai_enabled": app.ai_enabled,
                 "vendor_names": app.service.vendor_names(),
                 "network": "This server makes no outbound connections of its own. The only exceptions: the vendor-name download, "
                            "and only when you press its button"
                            + (", and the AI endpoint you configured" if app.ai_enabled else "") + "."})


@route("GET", "/api/projects")
def list_projects(h, app, q):
    h.send_json({"projects": app.store.list_projects()})


@route("POST", "/api/projects")
def create_project(h, app, q):
    body = h.read_json()
    h.send_json(app.store.create_project(body.get("name", "")), 201)


@route("GET", r"/api/projects/([0-9a-f]{16})")
def get_project(h, app, q, pid):
    h.send_json(app.service.project(pid))


@route("DELETE", r"/api/projects/([0-9a-f]{16})")
def delete_project(h, app, q, pid):
    h.send_json({"deleted_files": app.store.delete_project(pid)})


@route("PUT", r"/api/projects/([0-9a-f]{16})/context")
def update_context(h, app, q, pid):
    body = h.read_json()
    project = app.store.update_context(pid, body.get("subnets"), body.get("labels"), body.get("groups"), body.get("name"),
                                       body.get("notes"))
    h.send_json({"subnets": project["subnets"], "labels": project["labels"], "groups": project["groups"]})


@route("POST", r"/api/projects/([0-9a-f]{16})/sources")
def upload(h, app, q, pid):
    app.service.project(pid)
    background = q.get("async") == "1"
    if background and not app.jobs.has_room():
        raise ApiError(f"{MAX_RUNNING_IMPORTS} imports are already running; wait for one to finish", 429)
    path = h.stream_upload(pid)
    filename = os.path.basename(q.get("name", "upload"))[:120] or "upload"
    observation_point, fmt = q.get("observation_point", ""), q.get("format") or None
    if not background:
        h.send_json(app.service.import_upload(pid, path, filename, observation_point, fmt), 201)
        return
    try:
        job = app.jobs.start(pid, filename, lambda j: app.service.import_upload(pid, path, filename, observation_point, fmt, job=j))
    except RuntimeError as error:
        app.store.discard_upload(path)
        raise ApiError(str(error), 429) from error
    h.send_json({"job": job.id}, 202)


@route("GET", r"/api/jobs/([0-9a-f]{16})")
def job_status(h, app, q, jid):
    job = app.jobs.get(jid)
    if job is None:
        raise ApiError("no such import", 404)
    h.send_json(job.view())


@route("DELETE", r"/api/jobs/([0-9a-f]{16})")
def job_cancel(h, app, q, jid):
    job = app.jobs.cancel(jid)
    if job is None:
        raise ApiError("no such import", 404)
    h.send_json(job.view())


@route("DELETE", r"/api/projects/([0-9a-f]{16})/sources/([0-9a-f]{16})")
def delete_source(h, app, q, pid, sid):
    app.store.delete_source(pid, sid)
    h.send_json({"deleted": sid})


@route("GET", r"/api/projects/([0-9a-f]{16})/overview")
def overview(h, app, q, pid):
    h.send_json(app.service.overview(pid))


@route("GET", r"/api/projects/([0-9a-f]{16})/communications")
def communications(h, app, q, pid):
    h.send_json(app.service.communications(pid, q))


@route("GET", r"/api/projects/([0-9a-f]{16})/graph")
def graph(h, app, q, pid):
    h.send_json(app.service.graph(pid, q))


@route("GET", r"/api/projects/([0-9a-f]{16})/graph/detail")
def graph_detail(h, app, q, pid):
    h.send_json(app.service.graph_detail(pid, q))


@route("GET", r"/api/projects/([0-9a-f]{16})/policies/([0-9a-f]{16})")
def policy_view(h, app, q, pid, sid):
    h.send_json(app.service.policy_view(pid, sid))


@route("GET", r"/api/projects/([0-9a-f]{16})/policies/([0-9a-f]{16})/compare")
def compare(h, app, q, pid, sid):
    h.send_json(app.service.compare(pid, sid))


@route("POST", r"/api/projects/([0-9a-f]{16})/plan")
def plan(h, app, q, pid):
    h.send_json(app.service.plan_json(pid, h.read_json()))


@route("POST", r"/api/projects/([0-9a-f]{16})/translate")
def translate(h, app, q, pid):
    h.send_json(app.service.translation_json(pid, h.read_json()))


@route("POST", r"/api/projects/([0-9a-f]{16})/export")
def export(h, app, q, pid):
    ctype, name, data = app.service.export(pid, h.read_json())
    h.send(200, data, ctype, {"Content-Disposition": f'attachment; filename="{re.sub(r"[^A-Za-z0-9._-]", "_", name)}"'})


@route("POST", r"/api/projects/([0-9a-f]{16})/suggest-groups")
def suggest_groups(h, app, q, pid):
    from .migrate.groups import suggest_groups as suggest
    project = app.service.project(pid)
    _, flows = app.service.captures(project)
    h.send_json(suggest(app.service.context(project), flows))


@route("POST", r"/api/projects/([0-9a-f]{16})/ai")
def ai(h, app, q, pid):
    body = h.read_json()
    if body.get("send"):
        h.send_json(app.service.ai_ask(pid, str(body.get("topic", "summary"))[:60]))
    else:
        h.send_json(app.service.ai_package(pid, str(body.get("topic", "summary"))[:60]))


@route("POST", "/api/sample")
def sample(h, app, q):
    from .samples import create_demo, create_riverbend, create_unifi
    body = h.read_json() if int(h.headers.get("Content-Length", "0") or 0) else {}
    maker = {"riverbend": create_riverbend, "unifi": create_unifi}.get(body.get("name"), create_demo)
    h.send_json(maker(app.service), 201)


@route("GET", "/api/vendor-names")
def vendor_names(h, app, q):
    h.send_json(app.service.vendor_names())


@route("POST", "/api/vendor-names")
def update_vendor_names(h, app, q):
    h.send_json(app.service.update_vendor_names())


@route("DELETE", "/api/vendor-names")
def remove_vendor_names(h, app, q):
    h.send_json(app.service.remove_vendor_names())


@route("DELETE", "/api/data")
def delete_data(h, app, q):
    h.send_json({"deleted_files": app.service.delete_all()})


# ---------------------------------------------------------------------------------------------------- entry point

def build_server(host, port, data_dir, ai_endpoint=None, ai_allow_remote=False, token=None, allow_non_loopback=False):
    loopback = host in ("127.0.0.1", "localhost", "::1")
    if not loopback and not allow_non_loopback:
        raise SystemExit("refusing to listen on a non-loopback address. This tool has no user accounts; add --allow-non-loopback only "
                         "if you understand that anyone who can reach the port and learns the token can use it.")
    data_store = Store(data_dir)
    token = token or secrets.token_urlsafe(32)
    server = QuietServer((host, port), BaseHTTPRequestHandler)
    server.daemon_threads = True
    app = App(data_store, token, host, server.server_address[1], ai_endpoint, ai_allow_remote)
    server.RequestHandlerClass = make_handler(app)
    server.app = app
    return server


def main(argv=None):
    parser = argparse.ArgumentParser(prog="ruletruss", description="Local-first network communication and policy migration workbench")
    parser.add_argument("--version", action="version", version=f"RuleTruss {__version__}")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--data-dir", default=None, help="where projects are stored (default: your user data folder)")
    parser.add_argument("--retention-days", type=int, default=0, help="delete projects older than this at start-up (0 keeps them)")
    parser.add_argument("--ai-endpoint", default=None, help="OPTIONAL: a chat endpoint to send parsed facts to (off by default)")
    parser.add_argument("--ai-allow-remote", action="store_true", help="allow the AI endpoint to be on another machine")
    parser.add_argument("--allow-non-loopback", action="store_true")
    group = parser.add_argument_group("size limits", "Defaults guard against hostile or broken files; raise them for captures you trust.")
    for flag, label, default in (("--max-capture-mb", "largest capture file in MB", limits.MAX_CAPTURE_BYTES // 1024 ** 2),
                                 ("--max-packets", "packets read from one capture", limits.MAX_PACKETS),
                                 ("--max-flows", "flows kept from one capture", limits.MAX_FLOWS),
                                 ("--parse-minutes", "minutes allowed to analyse one file", limits.PARSE_SECONDS // 60),
                                 ("--parse-memory-gb", "GB of memory one analysis may use", limits.PARSE_MEMORY_BYTES // 1024 ** 3)):
        group.add_argument(flag, type=int, default=None, help=f"{label} (default {default:,})")
    args = parser.parse_args(argv)
    try:
        limits.configure(args.max_capture_mb, args.max_packets, args.parse_minutes, args.max_flows, args.parse_memory_gb)
    except ValueError as error:
        raise SystemExit(f"Invalid size limit: {error}") from None
    try:
        server = build_server(args.host, args.port, args.data_dir, args.ai_endpoint, args.ai_allow_remote, None, args.allow_non_loopback)
    except OSError as error:
        if error.errno in (errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", -1)):
            raise SystemExit(f"Port {args.port} is already in use, probably by another copy of RuleTruss that is still running.\n"
                             f"  See what is using it:  ss -ltnp | grep :{args.port}\n"
                             f"  Or start on another port:  python -m ruletruss --port {args.port + 1}") from None
        raise SystemExit(f"Could not start the server: {error.strerror or error}") from None
    if args.retention_days > 0:
        removed = server.app.store.purge_older_than(args.retention_days)
        if removed:
            print(f"Removed {len(removed)} project(s) older than {args.retention_days} days.")
    port = server.server_address[1]
    print(f"RuleTruss {__version__}")
    print(f"Data folder: {server.app.store.root}")
    print(f"Limits per file: {limits.MAX_CAPTURE_BYTES // 1024 ** 2:,} MB, {limits.MAX_PACKETS:,} packets, {limits.MAX_FLOWS:,} flows, "
          f"{limits.PARSE_SECONDS // 60} minutes, {limits.PARSE_MEMORY_BYTES // 1024 ** 3} GB of memory")
    print("Open this address in your browser (the part after # is the access token and stays in your browser):")
    print(f"  http://{args.host}:{port}/#token={server.app.token}")
    print("Press Ctrl+C to stop. Nothing is sent anywhere" + (" except to your AI endpoint." if args.ai_endpoint else "."))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        thread.join()
    except KeyboardInterrupt:
        print("\nStopping.")
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
