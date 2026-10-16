"""Local storage: projects, uploaded files and parse results, kept in one data folder with user-only permissions.

Retention is explicit: nothing is deleted automatically unless a retention period is set, and every project, source file and the
whole data folder can be deleted from the interface. Deletion overwrites file contents before unlinking as a best effort; on
SSDs, copy-on-write or journaling file systems and in backups that cannot be guaranteed, and the documentation says so.
"""
import contextlib
import functools
import json
import os
import re
import secrets
import shutil
import tempfile
import threading
import time

from . import limits
from .model import Group, to_plain

ID_RE = re.compile(r"^[0-9a-f]{16}$")
MAX_JSON_BYTES = limits.MAX_RESULT_BYTES         # a stored analysis may be as large as the worker may return
MAX_PROJECTS = 500
MAX_SOURCES_PER_PROJECT = 100
# The version of what is stored for an analysed file. Raise it whenever a parser or the analysis starts storing something new or means
# something different: files analysed under an older number are re-read (configurations) or flagged (captures), never silently used.
PARSE_FORMAT = 6


class StoreError(ValueError):
    """A problem the user can read about (bad id, missing project, over a limit)."""


def default_data_dir():
    base = os.environ.get("RT_DATA_DIR")
    if base:
        return base
    xdg = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(xdg, "ruletruss")


def new_id():
    return secrets.token_hex(8)


def check_id(value):
    if not isinstance(value, str) or not ID_RE.match(value):
        raise StoreError("not a valid identifier")
    return value


def _atomic_write(path, data: bytes):
    folder = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def wipe_file(path):
    """Overwrite a file with zeros, then unlink it. Best effort only (see the module docstring)."""
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as handle:
            remaining = size
            block = b"\x00" * 65536
            while remaining > 0:
                handle.write(block[: min(len(block), remaining)])
                remaining -= len(block)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        pass
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)


def wipe_tree(path):
    if not os.path.isdir(path):
        return 0
    count = 0
    for root, _dirs, files in os.walk(path, topdown=False):
        for name in files:
            wipe_file(os.path.join(root, name))
            count += 1
        with contextlib.suppress(OSError):
            os.rmdir(root)
    shutil.rmtree(path, ignore_errors=True)
    return count


def _locked(method):
    """Serialise read-modify-write of project files: several uploads can arrive at once."""
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper


class Store:
    def __init__(self, root=None):
        self._lock = threading.RLock()
        self.root = os.path.abspath(root or default_data_dir())
        os.makedirs(self.root, mode=0o700, exist_ok=True)
        os.chmod(self.root, 0o700)  # nosemgrep: insecure-file-permissions - 0o700 is owner-only; directories need the execute bit
        self.projects_dir = os.path.join(self.root, "projects")
        os.makedirs(self.projects_dir, mode=0o700, exist_ok=True)
        self._cache = {}

    # ------------------------------------------------------------ paths
    def project_dir(self, project_id):
        return os.path.join(self.projects_dir, check_id(project_id))

    def source_dir(self, project_id, source_id):
        return os.path.join(self.project_dir(project_id), "sources", check_id(source_id))

    def new_upload_path(self, project_id):
        """A fresh path (inside the project's private folder) to stream an upload into."""
        self.get_project(project_id)
        folder = os.path.join(self.project_dir(project_id), "incoming")
        os.makedirs(folder, mode=0o700, exist_ok=True)
        return os.path.join(folder, new_id() + ".part")

    # ------------------------------------------------------------ json helpers
    def _read_json(self, path):
        if os.path.getsize(path) > MAX_JSON_BYTES:
            raise StoreError("a stored file is larger than allowed")
        with open(path, "rb") as handle:
            return json.loads(handle.read().decode("utf-8"))

    def _write_json(self, path, obj):
        _atomic_write(path, json.dumps(to_plain(obj), ensure_ascii=True, separators=(",", ":")).encode("ascii"))

    # ------------------------------------------------------------ projects
    def list_projects(self):
        out = []
        for name in sorted(os.listdir(self.projects_dir)):
            if ID_RE.match(name):
                try:
                    out.append(self.get_project(name, summary=True))
                except (OSError, ValueError):
                    continue
        return out

    @_locked
    def create_project(self, name):
        name = limits.clip(str(name).strip(), 100)
        if not name:
            raise StoreError("a project needs a name")
        if len([n for n in os.listdir(self.projects_dir) if ID_RE.match(n)]) >= MAX_PROJECTS:
            raise StoreError("too many projects; delete some first")
        pid = new_id()
        os.makedirs(os.path.join(self.project_dir(pid), "sources"), mode=0o700)
        project = {"id": pid, "name": name, "created": time.time(), "subnets": [], "labels": {}, "groups": [], "sources": [],
                   "notes": ""}
        self._write_json(os.path.join(self.project_dir(pid), "project.json"), project)
        return project

    def get_project(self, project_id, summary=False):
        path = os.path.join(self.project_dir(project_id), "project.json")
        if not os.path.isfile(path):
            raise StoreError("project not found")
        project = self._read_json(path)
        if summary:
            sources = project.get("sources", [])
            return {"id": project["id"], "name": project["name"], "created": project["created"], "sources": len(sources),
                    "traffic": sum(1 for s in sources if s.get("kind") in ("capture", "flows")),
                    "configs": sum(1 for s in sources if s.get("kind") == "policy"), "subnets": len(project.get("subnets", []))}
        return project

    def save_project(self, project):
        self._write_json(os.path.join(self.project_dir(project["id"]), "project.json"), project)

    @_locked
    def update_context(self, project_id, subnets=None, labels=None, groups=None, name=None, notes=None):
        from .migrate.groups import validate_groups
        project = self.get_project(project_id)
        if subnets is not None:
            project["subnets"] = _validate_subnets(subnets)
        if labels is not None:
            project["labels"] = _validate_labels(labels)
        if groups is not None:
            try:
                project["groups"] = [to_plain(g) for g in validate_groups(groups)]
            except ValueError as error:
                raise StoreError(str(error)) from error
        if name is not None:
            project["name"] = limits.clip(str(name).strip(), 100) or project["name"]
        if notes is not None:
            project["notes"] = limits.clip(str(notes), 2000)
        self.save_project(project)
        self._cache.clear()
        return project

    @_locked
    def delete_project(self, project_id):
        path = self.project_dir(project_id)
        if not os.path.isdir(path):
            raise StoreError("project not found")
        count = wipe_tree(path)
        self._cache.clear()
        return count

    @_locked
    def delete_everything(self):
        count = 0
        for name in os.listdir(self.projects_dir):
            if ID_RE.match(name):
                count += wipe_tree(os.path.join(self.projects_dir, name))
        self._cache.clear()
        return count

    @_locked
    def purge_older_than(self, days):
        """Delete projects created more than `days` days ago. days <= 0 does nothing."""
        if days <= 0:
            return []
        cutoff = time.time() - days * 86400
        removed = []
        for p in self.list_projects():
            if p["created"] < cutoff:
                self.delete_project(p["id"])
                removed.append(p["id"])
        return removed

    def usage(self):
        total, files = 0, 0
        for root, _d, names in os.walk(self.root):
            for n in names:
                with contextlib.suppress(OSError):
                    total += os.path.getsize(os.path.join(root, n))
                    files += 1
        return {"data_dir": self.root, "bytes": total, "files": files}

    # ------------------------------------------------------------ sources
    @_locked
    def add_source(self, project_id, kind, filename, upload_path, meta, parsed, source_id=None):
        """Move a validated upload into place and store its parse result. `kind` is capture, flows or policy."""
        project = self.get_project(project_id)
        if len(project["sources"]) >= MAX_SOURCES_PER_PROJECT:
            raise StoreError("too many files in this project; delete some first")
        sid = check_id(source_id) if source_id else new_id()
        folder = self.source_dir(project_id, sid)
        os.makedirs(folder, mode=0o700)
        os.replace(upload_path, os.path.join(folder, "original.bin"))
        os.chmod(os.path.join(folder, "original.bin"), 0o600)
        self._write_json(os.path.join(folder, "parsed.json"), parsed)
        entry = {"id": sid, "kind": kind, "filename": limits.clip(filename, 120), "added": time.time(), "parse_format": PARSE_FORMAT,
                 **meta}
        project["sources"].append(entry)
        self.save_project(project)
        self._cache.clear()
        return entry

    def original_path(self, project_id, source_id):
        return os.path.join(self.source_dir(project_id, source_id), "original.bin")

    @_locked
    def replace_parsed(self, project_id, source_id, parsed, meta):
        """Store a fresh parse of a file already in the project (the original is kept as it is), and update the file's summary."""
        project = self.get_project(project_id)
        entry = next((s for s in project["sources"] if s["id"] == source_id), None)
        if entry is None:
            raise StoreError("file not found in this project")
        self._write_json(os.path.join(self.source_dir(project_id, source_id), "parsed.json"), parsed)
        entry.update(meta, parse_format=PARSE_FORMAT)
        self.save_project(project)
        self._cache.clear()
        return entry

    @_locked
    def delete_source(self, project_id, source_id):
        project = self.get_project(project_id)
        if not any(s["id"] == source_id for s in project["sources"]):
            raise StoreError("file not found in this project")
        wipe_tree(self.source_dir(project_id, source_id))
        project["sources"] = [s for s in project["sources"] if s["id"] != source_id]
        self.save_project(project)
        self._cache.clear()

    def load_parsed(self, project_id, source_id):
        key = (project_id, source_id)
        if key not in self._cache:
            if len(self._cache) > 8:
                self._cache.clear()
            self._cache[key] = self._read_json(os.path.join(self.source_dir(project_id, source_id), "parsed.json"))
        return self._cache[key]

    def discard_upload(self, upload_path):
        wipe_file(upload_path)


def _validate_subnets(raw):
    import ipaddress
    if not isinstance(raw, list) or len(raw) > 5000:
        raise StoreError("subnets must be a list of at most 5000 entries")
    out = []
    for item in raw:
        if not isinstance(item, dict):
            raise StoreError("each subnet must be an object with cidr, label and optional zone")
        try:
            cidr = str(ipaddress.ip_network(str(item.get("cidr", "")).strip(), strict=False))
        except ValueError as error:
            raise StoreError(f"not a network: {str(item.get('cidr', ''))[:40]!r}") from error
        out.append({"cidr": cidr, "label": limits.clip(str(item.get("label", "")), 80), "zone": limits.clip(str(item.get("zone", "")), 60),
                    "external": bool(item.get("external", False))})
    return out


def _validate_labels(raw):
    import ipaddress
    if not isinstance(raw, dict) or len(raw) > 20000:
        raise StoreError("labels must be an object of at most 20000 entries")
    out = {}
    for ip, label in raw.items():
        try:
            key = str(ipaddress.ip_address(str(ip).strip()))
        except ValueError as error:
            raise StoreError(f"not an IP address: {str(ip)[:40]!r}") from error
        out[key] = limits.clip(str(label), 80)
    return out


def groups_from_project(project):
    return [Group(**g) for g in project.get("groups", [])]
