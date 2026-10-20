#!/usr/bin/env python3
"""Privacy check: keep the owner's private details out of a public repository.

It looks for three kinds of problem in files, commit messages and commit
metadata:

* anything on the owner's private deny-list (subnets, hostnames, names ...)
* absolute home-directory paths (Linux, macOS and Windows style) that carry a user name
* a git author or committer email that is not a GitHub noreply address

It prints only WHERE a problem is (file and line, or commit and file) and the
broad kind of problem. It never prints the text that matched or which
deny-list entry matched, because the output ends up in public CI logs.

Deny-list format, one entry per line (blank lines and lines starting with #
are ignored):

    203.0.113.0/24      a subnet or single address: any address inside matches
    some-hostname       a word or phrase, matched case-insensitively
    re:serial-[0-9]{6}  a regular expression

For subnets on a /8, /16 or /24 boundary, partial forms such as "203.0.113."
or "203.0.113.x" also match.

Exit status: 0 clean, 1 findings, 2 the check itself could not run.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import re
import shutil
import subprocess  # nosec B404 - runs git with an argument list, never a shell
import sys
from dataclasses import dataclass, field
from pathlib import Path

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_LINES_SHOWN = 12


def default_denylist_path() -> Path:
    config = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(config) / "okieotsec" / "privacy-denylist.txt"


class ConfigError(Exception):
    """The check could not run (bad deny-list, not a git repository ...)."""


# ---------------------------------------------------------------- deny-list

_IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\d)")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
_NETWORK_TOKEN = re.compile(r"[0-9A-Fa-f:.]+(?:/\d{1,3})?")


def _as_network(token: str):
    if not _NETWORK_TOKEN.fullmatch(token) or not ("." in token or ":" in token):
        return None
    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None


@dataclass
class DenyList:
    literals: list[str] = field(default_factory=list)
    regexes: list[re.Pattern] = field(default_factory=list)
    networks: list = field(default_factory=list)
    partials: list[re.Pattern] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.literals) + len(self.regexes) + len(self.networks)

    @classmethod
    def parse(cls, text: str) -> DenyList:
        deny = cls()
        for number, raw in enumerate(text.splitlines(), 1):
            entry = raw.strip()
            if not entry or entry.startswith("#"):
                continue
            if entry.lower().startswith("re:"):
                try:
                    deny.regexes.append(re.compile(entry[3:], re.IGNORECASE))
                except re.error:
                    raise ConfigError(f"deny-list line {number} is not a valid regular expression") from None
                continue
            network = _as_network(entry)
            if network is not None:
                deny.networks.append(network)
                if network.version == 4 and network.prefixlen in (8, 16, 24):
                    octets = str(network.network_address).split(".")[: network.prefixlen // 8]
                    deny.partials.append(re.compile(r"(?<![\d.])" + r"\.".join(octets) + r"\."))
                continue
            deny.literals.append(entry.lower())
        return deny

    def matches(self, text: str) -> bool:
        lowered = text.lower()
        if any(word in lowered for word in self.literals):
            return True
        if any(rx.search(text) for rx in self.regexes):
            return True
        if self.networks:
            if any(rx.search(text) for rx in self.partials):
                return True
            for found in _IPV4.finditer(text):
                octets = [int(part) for part in found.groups()]
                if max(octets) > 255:
                    continue
                address = ipaddress.IPv4Address(".".join(str(o) for o in octets))
                if any(address in net for net in self.networks if net.version == 4):
                    return True
            if ":" in text:
                for found in _IPV6.finditer(text):
                    try:
                        address6 = ipaddress.IPv6Address(found.group(0))
                    except ValueError:
                        continue
                    if any(address6 in net for net in self.networks if net.version == 6):
                        return True
        return False


def load_denylist(path: str | None, none_allowed: bool) -> DenyList:
    if none_allowed:
        return DenyList()
    text = None
    if path:
        source = Path(path)
    elif os.environ.get("PRIVACY_DENYLIST"):
        source = Path(os.environ["PRIVACY_DENYLIST"])
    elif os.environ.get("PRIVACY_DENYLIST_CONTENT"):
        source, text = None, os.environ["PRIVACY_DENYLIST_CONTENT"]
    else:
        source = default_denylist_path()
    if text is None:
        if not source.is_file():
            raise ConfigError("deny-list file not found (use --no-denylist to run the built-in checks only)")
        try:
            text = source.read_text(encoding="utf-8", errors="replace")
        except OSError:
            raise ConfigError("deny-list file could not be read") from None
    deny = DenyList.parse(text)
    if len(deny) == 0:
        raise ConfigError("deny-list has no entries")
    return deny


# ---------------------------------------------------------- built-in checks

_PLACEHOLDER_USERS = {"user", "username", "runner", "ubuntu", "example", "you", "name", "yourname", "app"}
_ABS_PATH = re.compile(
    r"(?<![\w.~-])(?:/h[o]me/([A-Za-z_][A-Za-z0-9_.-]*)|/Users/([A-Za-z][A-Za-z0-9_.-]*)"
    r"|[A-Za-z]:\\+Users\\+([A-Za-z0-9_.-]+))(?=[/\\\s\"'`),;:]|$)"
)
_ALLOWED_EMAILS = ("@users.noreply.github.com",)
_ALLOWED_EXACT = {"noreply@github.com", "noreply@anthropic.com"}
_TRAILER = re.compile(r"^(?:co-authored-by|signed-off-by|reviewed-by|acked-by|tested-by):.*<([^>]+)>", re.I)


def has_absolute_path(text: str) -> bool:
    for found in _ABS_PATH.finditer(text):
        name = next(group for group in found.groups() if group)
        if name.lower() not in _PLACEHOLDER_USERS:
            return True
    return False


def email_allowed(email: str) -> bool:
    lowered = email.strip().lower()
    return lowered in _ALLOWED_EXACT or lowered.endswith(_ALLOWED_EMAILS)


def check_text(text: str, deny: DenyList) -> list[str]:
    kinds = []
    if deny.matches(text):
        kinds.append("deny-list")
    if has_absolute_path(text):
        kinds.append("absolute-path")
    return kinds


# ------------------------------------------------------------------ results


@dataclass(frozen=True)
class Finding:
    """One problem. The path is kept apart so it can be hidden when it is itself private."""

    prefix: str
    path: str | None
    line: int | None
    kind: str
    suffix: str = ""
    private_path: bool = False

    def where(self, show_names: bool) -> str:
        if self.path is None:
            return f"{self.prefix}{self.suffix}"
        if self.private_path and not show_names:
            digest = hashlib.sha256(self.path.encode("utf-8", "replace")).hexdigest()[:8]
            return f"{self.prefix}<path #{digest}>{self.suffix}"
        return f"{self.prefix}{self.path}{self.suffix}"


def path_finding(prefix: str, path: str, line: int | None, kind: str, deny: DenyList, suffix: str = "") -> Finding:
    return Finding(prefix, path, line, kind, suffix, private_path=bool(check_text(path, deny)))


# ---------------------------------------------------------------------- git


GIT = shutil.which("git") or "git"


def git(repo: str, *args: str, check: bool = True) -> str:
    result = subprocess.run(  # noqa: S603  # nosec B603
        [GIT, "-c", "core.quotepath=false", *args],
        cwd=repo,
        capture_output=True,
    )
    if check and result.returncode != 0:
        raise ConfigError("a git command failed (is this a git repository?)")
    return result.stdout.decode("utf-8", errors="replace")


def added_lines(diff_text: str):
    """Yield (path, line_number, text) for every added line of a -U0 diff."""
    path, number = None, 0
    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            path = raw[6:] if raw.startswith("+++ b/") else None
        elif raw.startswith("@@"):
            found = re.match(r"@@ -\S+ \+(\d+)", raw)
            number = int(found.group(1)) if found else 0
        elif raw.startswith("+") and not raw.startswith("+++"):
            yield path, number, raw[1:]
            number += 1


DIFF_FLAGS = ("-U0", "--no-color", "--no-ext-diff", "--no-renames", "--src-prefix=a/", "--dst-prefix=b/")


def scan_diff(diff_text: str, label: str, deny: DenyList):
    for path, number, text in added_lines(diff_text):
        for kind in check_text(text, deny):
            if path is None:
                yield Finding(f"{label}(unknown file)", None, number, kind)
            else:
                yield path_finding(label, path, number, kind, deny)


def scan_tree(repo: str, deny: DenyList):
    root = git(repo, "rev-parse", "--show-toplevel").strip()
    for rel in git(repo, "ls-files", "-z").split("\0"):
        if not rel:
            continue
        for kind in check_text(rel, deny):
            yield path_finding("", rel, None, kind, deny, " (file name)")
        full = Path(root, rel)
        try:
            if full.is_symlink() or not full.is_file() or full.stat().st_size > MAX_FILE_BYTES:
                continue
            data = full.read_bytes()
        except OSError:
            continue
        if b"\0" in data[:8192]:
            continue
        for number, text in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
            for kind in check_text(text, deny):
                yield path_finding("", rel, number, kind, deny)


def scan_staged(repo: str, deny: DenyList):
    diff = git(repo, "diff", "--cached", *DIFF_FLAGS)
    yield from scan_diff(diff, "", deny)


def scan_commit(repo: str, sha: str, deny: DenyList):
    short = sha[:7]
    meta = git(repo, "log", "-1", "--format=%an%x00%ae%x00%cn%x00%ce%x00%B", sha)
    author, author_email, committer, committer_email, message = meta.split("\0", 4)
    for label, value in (
        ("author name", author),
        ("author email", author_email),
        ("committer name", committer),
        ("committer email", committer_email),
    ):
        if deny.matches(value):
            yield Finding(f"{short} (commit {label})", None, None, "deny-list")
    for label, email in (("author", author_email), ("committer", committer_email)):
        if not email_allowed(email):
            yield Finding(f"{short} (commit {label} email)", None, None, "author-email")
    for number, text in enumerate(message.splitlines(), 1):
        for kind in check_text(text, deny):
            yield Finding(f"{short} (commit message)", None, number, kind)
        trailer = _TRAILER.match(text)
        if trailer and not email_allowed(trailer.group(1)):
            yield Finding(f"{short} (commit message)", None, number, "author-email")
    diff = git(repo, "diff-tree", "-p", *DIFF_FLAGS, "--no-commit-id", "--root", "-r", sha)
    yield from scan_diff(diff, f"{short} ", deny)
    for name in git(repo, "diff-tree", "--name-only", "--no-commit-id", "--root", "-r", sha).splitlines():
        for kind in check_text(name, deny):
            yield path_finding(f"{short} ", name, None, kind, deny, " (file name)")


def rev_list(repo: str, spec: list[str]) -> list[str]:
    return git(repo, "rev-list", "--no-merges", *spec).split()


def merge_commits(repo: str, spec: list[str]) -> list[str]:
    return git(repo, "rev-list", "--merges", *spec).split()


def scan_commits(repo: str, specs: list[list[str]], deny: DenyList):
    seen: set[str] = set()
    for spec in specs:
        for sha in rev_list(repo, spec) + merge_commits(repo, spec):
            if sha in seen:
                continue
            seen.add(sha)
            yield from scan_commit(repo, sha, deny)


def pre_push_specs(stdin_text: str, remote: str | None) -> list[list[str]]:
    specs: list[list[str]] = []
    fresh = ["--not", f"--remotes={remote}"] if remote else ["--not", "--remotes"]
    for line in stdin_text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        _local_ref, local_sha, _remote_ref, remote_sha = parts[:4]
        if set(local_sha) == {"0"}:
            continue
        if set(remote_sha) == {"0"}:
            specs.append([local_sha, *fresh])
        else:
            specs.append([f"{remote_sha}..{local_sha}"])
    return specs


# ------------------------------------------------------------------- output


def report(findings: list[Finding], show_names: bool = False, out=sys.stderr) -> None:
    grouped: dict[tuple[str, str], list[int | None]] = {}
    for found in findings:
        grouped.setdefault((found.where(show_names), found.kind), []).append(found.line)
    print(f"privacy-check: {len(findings)} problem(s) in {len(grouped)} place(s)", file=out)
    for (where, kind), lines in sorted(grouped.items()):
        numbers = sorted({n for n in lines if n is not None})
        shown = ",".join(str(n) for n in numbers[:MAX_LINES_SHOWN])
        if len(numbers) > MAX_LINES_SHOWN:
            shown += f",...+{len(numbers) - MAX_LINES_SHOWN}"
        suffix = f" line {shown}" if numbers else ""
        print(f"  {where}{suffix}  [{kind}]", file=out)
    print("The text that matched is deliberately not shown. Fix the places above.", file=out)
    if not show_names and any(f.private_path for f in findings):
        print("A <path #id> is a file path that itself contains private text; run locally with --show-names.", file=out)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Keep private details out of a public repository.")
    parser.add_argument("--repo", default=".", help="the git repository to check (default: current directory)")
    parser.add_argument("--denylist", help="path to the deny-list file")
    parser.add_argument("--no-denylist", action="store_true", help="run only the built-in checks")
    parser.add_argument(
        "--show-names",
        action="store_true",
        help="print file paths even when the path itself is private (local use only, never in CI logs)",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--tree", action="store_true", help="every tracked file in the working tree")
    mode.add_argument("--staged", action="store_true", help="the changes staged for commit")
    mode.add_argument("--history", action="store_true", help="every commit in the repository")
    mode.add_argument("--commits", nargs="+", metavar="REV", help="commits in a git revision range")
    mode.add_argument("--pre-push", action="store_true", help="git pre-push hook mode (reads refs on stdin)")
    parser.add_argument("hook_args", nargs="*", help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        deny = load_denylist(args.denylist, args.no_denylist)
        if args.tree:
            found = list(scan_tree(args.repo, deny))
        elif args.staged:
            found = list(scan_staged(args.repo, deny))
        elif args.history:
            found = list(scan_commits(args.repo, [["--all"]], deny))
        elif args.commits:
            found = list(scan_commits(args.repo, [args.commits], deny))
        else:
            remote = args.hook_args[0] if args.hook_args else None
            found = list(scan_commits(args.repo, pre_push_specs(sys.stdin.read(), remote), deny))
    except ConfigError as problem:
        print(f"privacy-check: could not run: {problem}", file=sys.stderr)
        return 2
    if found:
        report(found, show_names=args.show_names)
        return 1
    print("privacy-check: no problems found", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
