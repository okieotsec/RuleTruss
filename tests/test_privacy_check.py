"""Tests for privacy/privacy_check.py. Every private value here is invented."""

from __future__ import annotations

import importlib.util
import ntpath
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "tools" / "privacy_check.py"
spec = importlib.util.spec_from_file_location("privacy_check", SCRIPT)
pc = importlib.util.module_from_spec(spec)
sys.modules["privacy_check"] = pc
spec.loader.exec_module(pc)

FAKE_SUBNET = "203.0.113.0/24"  # documentation range
FAKE_WORD = "zzfakeword"
FAKE_REGEX_HIT = "zzq7-123456"
DENYLIST_TEXT = f"""# a comment
{FAKE_SUBNET}
{FAKE_WORD}

re:zzq7-[0-9]{{6}}
"""
# Built in pieces so this file never contains a literal absolute home path.
HOME = os.sep + "home" + os.sep
USERS = os.sep + "Users" + os.sep
WIN_USERS = ntpath.sep.join(("C:", "Users", ""))
GIT = shutil.which("git") or "git"
NOREPLY = "1+someone@users.noreply.github.com"


class DenyListTests(unittest.TestCase):
    def setUp(self):
        self.deny = pc.DenyList.parse(DENYLIST_TEXT)

    def test_parses_three_kinds_and_skips_comments(self):
        self.assertEqual(len(self.deny), 3)

    def test_subnet_matches_addresses_inside_only(self):
        self.assertTrue(self.deny.matches("host at 203.0.113.31 here"))
        self.assertTrue(self.deny.matches("permit ip 203.0.113.0 0.0.0.255 any"))
        self.assertFalse(self.deny.matches("host at 203.0.114.31 here"))
        self.assertFalse(self.deny.matches("version 1203.0.113.31"))

    def test_subnet_matches_leading_zero_octet(self):
        self.assertTrue(self.deny.matches("typo 203.0.113.031 here"))

    def test_subnet_matches_partial_forms_on_octet_boundaries(self):
        self.assertTrue(self.deny.matches("range 203.0.113.x"))
        self.assertTrue(self.deny.matches("prefix 203.0.113."))
        self.assertFalse(self.deny.matches("203.0.1130.5"))

    def test_non_octet_prefix_only_matches_full_addresses(self):
        deny = pc.DenyList.parse("198.51.100.0/25")
        self.assertTrue(deny.matches("198.51.100.5"))
        self.assertFalse(deny.matches("198.51.100.200"))

    def test_single_address(self):
        deny = pc.DenyList.parse("198.51.100.7")
        self.assertTrue(deny.matches("at 198.51.100.7"))
        self.assertFalse(deny.matches("at 198.51.100.8"))

    def test_ipv6_network(self):
        deny = pc.DenyList.parse("2001:db8::/32")
        self.assertTrue(deny.matches("addr 2001:db8::1 here"))
        self.assertFalse(deny.matches("addr 2001:db9::1 here"))

    def test_literal_is_case_insensitive(self):
        self.assertTrue(self.deny.matches(f"the {FAKE_WORD.upper()} lab"))

    def test_regex_entry(self):
        self.assertTrue(self.deny.matches(f"tag {FAKE_REGEX_HIT}"))
        self.assertFalse(self.deny.matches("tag zzq7-12"))

    def test_invalid_regex_is_a_config_error_without_echoing_it(self):
        with self.assertRaises(pc.ConfigError) as caught:
            pc.DenyList.parse("re:(secretpattern")
        self.assertNotIn("secretpattern", str(caught.exception))

    def test_empty_denylist_is_an_error(self):
        with self.assertRaises(pc.ConfigError):
            pc.load_denylist("/nonexistent/path/does-not-exist.txt", False)
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp, "empty.txt")
            empty.write_text("# nothing here\n")
            with self.assertRaises(pc.ConfigError):
                pc.load_denylist(str(empty), False)


class BuiltInTests(unittest.TestCase):
    def test_absolute_home_paths_are_flagged(self):
        for text in (f"{HOME}someone/project/file", f"at {USERS}someone/code", f"{WIN_USERS}someone\\x", f"cd {HOME}someone"):
            self.assertTrue(pc.has_absolute_path(text), text)

    def test_placeholders_and_ci_paths_are_not_flagged(self):
        for text in (f"{HOME}<user>/project", f"{HOME}user/x", f"{HOME}runner/work/repo", f"{HOME}ubuntu/", "see ~/notes", "/homepage/x"):
            self.assertFalse(pc.has_absolute_path(text), text)

    def test_email_allowed(self):
        self.assertTrue(pc.email_allowed(NOREPLY))
        self.assertTrue(pc.email_allowed("noreply@github.com"))
        self.assertTrue(pc.email_allowed("noreply@anthropic.com"))
        self.assertFalse(pc.email_allowed("someone@example.org"))


class DiffParsingTests(unittest.TestCase):
    def test_only_added_lines_with_correct_numbers(self):
        diff = (
            "diff --git a/f.txt b/f.txt\n--- a/f.txt\n+++ b/f.txt\n"
            "@@ -1,2 +10,2 @@\n-old one\n-old two\n+new one\n+new two\n"
            "@@ -20 +30 @@\n-gone\n+later\n"
        )
        self.assertEqual(
            list(pc.added_lines(diff)),
            [("f.txt", 10, "new one"), ("f.txt", 11, "new two"), ("f.txt", 30, "later")],
        )

    def test_pre_push_specs(self):
        zeros = "0" * 40
        a, b = "a" * 40, "b" * 40
        stdin = f"refs/heads/x {a} refs/heads/x {zeros}\nrefs/heads/y {b} refs/heads/y {a}\nrefs/heads/z {zeros} refs/heads/z {a}\n"
        specs = pc.pre_push_specs(stdin, "origin")
        self.assertEqual(specs, [[a, "--not", "--remotes=origin"], [f"{a}..{b}"]])


def run_check(repo: str, *args: str, stdin: str | None = None, env_extra: dict | None = None):
    env = dict(os.environ, **(env_extra or {}))
    env.pop("PRIVACY_DENYLIST", None)
    env.pop("PRIVACY_DENYLIST_CONTENT", None)
    env.update(env_extra or {})
    return subprocess.run(  # noqa: S603
        [sys.executable, "-I", str(SCRIPT), "--repo", repo, *args],
        input=stdin, capture_output=True, text=True, env=env,
    )


class RepoTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = str(Path(self.tmp.name, "repo"))
        os.mkdir(self.repo)
        self.denylist = str(Path(self.tmp.name, "denylist.txt"))
        Path(self.denylist).write_text(DENYLIST_TEXT)
        self.git("init", "-q", "-b", "main")

    def git(self, *args, email=NOREPLY, name="someone"):
        env = dict(os.environ, GIT_AUTHOR_NAME=name, GIT_AUTHOR_EMAIL=email,
                   GIT_COMMITTER_NAME=name, GIT_COMMITTER_EMAIL=email,
                   GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
        result = subprocess.run([GIT, "-C", self.repo, *args], capture_output=True, text=True, env=env)  # noqa: S603
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def write(self, rel, text):
        path = Path(self.repo, rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        self.git("add", rel)

    def commit(self, message="change", **kwargs):
        self.git("commit", "-q", "-m", message, **kwargs)
        return self.git("rev-parse", "HEAD")

    def check(self, *args, **kwargs):
        return run_check(self.repo, "--denylist", self.denylist, *args, **kwargs)

    def assertNoLeak(self, result):
        combined = result.stdout + result.stderr
        for secret in (FAKE_WORD, "203.0.113", FAKE_REGEX_HIT, self.denylist):
            self.assertNotIn(secret, combined)


class TreeTests(RepoTestCase):
    def test_clean_tree_passes(self):
        self.write("a.txt", "nothing private\n")
        self.commit()
        self.assertEqual(self.check("--tree").returncode, 0)

    def test_finding_reports_file_and_line_but_not_the_text(self):
        self.write("a.txt", f"ok\nthe {FAKE_WORD} lab\nalso 203.0.113.9\n")
        self.write("b.txt", f"see {HOME}someone/x\n")
        self.commit()
        result = self.check("--tree")
        self.assertEqual(result.returncode, 1)
        self.assertIn("a.txt line 2,3  [deny-list]", result.stderr)
        self.assertIn("b.txt line 1  [absolute-path]", result.stderr)
        self.assertNoLeak(result)

    def test_file_names_are_checked_and_a_private_name_is_hidden(self):
        self.write(f"{FAKE_WORD}.txt", "fine\n")
        self.commit()
        result = self.check("--tree")
        self.assertEqual(result.returncode, 1)
        self.assertIn("(file name)", result.stderr)
        self.assertIn("<path #", result.stderr)
        self.assertNoLeak(result)

    def test_show_names_prints_a_private_name_for_local_use(self):
        self.write(f"{FAKE_WORD}.txt", "fine\n")
        self.commit()
        result = self.check("--tree", "--show-names")
        self.assertIn(f"{FAKE_WORD}.txt (file name)", result.stderr)

    def test_content_finding_in_a_privately_named_file_hides_the_name(self):
        self.write(f"docs/{FAKE_WORD}/notes.txt", f"{FAKE_WORD}\n")
        self.commit()
        result = self.check("--tree")
        self.assertEqual(result.returncode, 1)
        self.assertNoLeak(result)

    def test_history_hides_private_names_too(self):
        self.write(f"{FAKE_WORD}.txt", "fine\n")
        self.commit()
        result = self.check("--history")
        self.assertEqual(result.returncode, 1)
        self.assertNoLeak(result)

    def test_binary_files_are_skipped(self):
        Path(self.repo, "blob.bin").write_bytes(b"\0\0" + FAKE_WORD.encode())
        self.git("add", "blob.bin")
        self.commit()
        self.assertEqual(self.check("--tree").returncode, 0)


class CommitTests(RepoTestCase):
    def test_only_added_lines_count_not_removed_ones(self):
        self.write("a.txt", f"{FAKE_WORD}\n")
        first = self.commit()
        self.write("a.txt", "clean now\n")
        second = self.commit()
        result = self.check("--commits", f"{first}..{second}")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_history_finds_a_removed_secret(self):
        self.write("a.txt", f"{FAKE_WORD}\n")
        self.commit()
        self.write("a.txt", "clean now\n")
        self.commit()
        result = self.check("--history")
        self.assertEqual(result.returncode, 1)
        self.assertIn("a.txt line 1  [deny-list]", result.stderr)
        self.assertNoLeak(result)

    def test_personal_author_email_is_flagged(self):
        self.write("a.txt", "fine\n")
        self.commit(email="someone@example.org")
        result = self.check("--history")
        self.assertEqual(result.returncode, 1)
        self.assertIn("[author-email]", result.stderr)
        self.assertNotIn("example.org", result.stderr)

    def test_noreply_and_github_committer_pass(self):
        self.write("a.txt", "fine\n")
        self.commit()
        self.assertEqual(self.check("--history").returncode, 0)

    def test_commit_message_and_trailers_are_checked(self):
        self.write("a.txt", "fine\n")
        self.commit(message=f"about {FAKE_WORD}\n\nCo-Authored-By: Pal <pal@example.org>")
        result = self.check("--history")
        self.assertEqual(result.returncode, 1)
        self.assertIn("(commit message) line 1", result.stderr.replace("  ", " ") + "")
        self.assertIn("[author-email]", result.stderr)
        self.assertNoLeak(result)

    def test_ai_noreply_trailer_is_allowed(self):
        self.write("a.txt", "fine\n")
        self.commit(message="x\n\nCo-Authored-By: Claude <noreply@anthropic.com>")
        self.assertEqual(self.check("--history").returncode, 0)

    def test_author_name_on_denylist_is_flagged(self):
        self.write("a.txt", "fine\n")
        self.commit(name=FAKE_WORD)
        result = self.check("--history")
        self.assertEqual(result.returncode, 1)
        self.assertNoLeak(result)


class PrePushTests(RepoTestCase):
    def test_new_branch_push_scans_unpushed_commits(self):
        self.write("a.txt", f"{FAKE_WORD}\n")
        sha = self.commit()
        stdin = f"refs/heads/main {sha} refs/heads/main {'0' * 40}\n"
        result = self.check("--pre-push", "origin", "https://example.invalid/r.git", stdin=stdin)
        self.assertEqual(result.returncode, 1)
        self.assertNoLeak(result)
        self.assertNotIn("example.invalid", result.stderr)

    def test_update_push_scans_only_the_new_range(self):
        self.write("a.txt", f"{FAKE_WORD}\n")
        old = self.commit()
        self.write("b.txt", "clean\n")
        new = self.commit()
        stdin = f"refs/heads/main {new} refs/heads/main {old}\n"
        result = self.check("--pre-push", "origin", "url", stdin=stdin)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_branch_deletion_is_ignored(self):
        stdin = f"(delete) {'0' * 40} refs/heads/x {'a' * 40}\n"
        self.write("a.txt", "x\n")
        self.commit()
        self.assertEqual(self.check("--pre-push", "origin", "url", stdin=stdin).returncode, 0)


class StagedTests(RepoTestCase):
    def test_staged_changes_are_checked(self):
        self.write("a.txt", "fine\n")
        self.commit()
        self.write("a.txt", f"fine\n{FAKE_WORD}\n")
        result = self.check("--staged")
        self.assertEqual(result.returncode, 1)
        self.assertIn("a.txt line 2", result.stderr)

    def test_diff_prefix_settings_do_not_confuse_the_path(self):
        self.git("config", "diff.mnemonicPrefix", "true")
        self.git("config", "diff.noprefix", "true")
        self.write("a.txt", "fine\n")
        self.commit()
        self.write("a.txt", f"fine\n{FAKE_WORD}\n")
        result = self.check("--staged")
        self.assertIn("a.txt line 2", result.stderr)
        self.assertNotIn("unknown file", result.stderr)


class ConfigTests(RepoTestCase):
    def test_missing_denylist_fails_closed(self):
        self.write("a.txt", "x\n")
        self.commit()
        result = run_check(self.repo, "--denylist", str(Path(self.tmp.name, "nope.txt")), "--tree")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(self.tmp.name, result.stderr)

    def test_no_denylist_runs_builtin_checks_only(self):
        self.write("a.txt", f"{FAKE_WORD}\nsee {HOME}someone/x\n")
        self.commit()
        result = run_check(self.repo, "--no-denylist", "--tree")
        self.assertEqual(result.returncode, 1)
        self.assertIn("[absolute-path]", result.stderr)
        self.assertNotIn("[deny-list]", result.stderr)

    def test_denylist_from_environment_content(self):
        self.write("a.txt", f"{FAKE_WORD}\n")
        self.commit()
        result = run_check(self.repo, "--tree", env_extra={"PRIVACY_DENYLIST_CONTENT": DENYLIST_TEXT})
        self.assertEqual(result.returncode, 1)
        self.assertNoLeak(result)

    def test_not_a_git_repository(self):
        with tempfile.TemporaryDirectory() as plain:
            result = run_check(plain, "--no-denylist", "--tree")
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
