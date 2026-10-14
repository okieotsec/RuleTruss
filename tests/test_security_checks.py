import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("security_checks", ROOT / "tools" / "security_checks.py")
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)

# Built from pieces so this test file holds no suppression of its own.
SEMGREP, BANDIT, RUFF = "nosem" + "grep", "nos" + "ec", "no" + "qa"


class SuppressionInventoryTests(unittest.TestCase):
    """The runner's suppression gate (SSDF PW.7) and its SARIF filter."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.saved = (checks.ROOT, checks.BASELINE)
        checks.ROOT, checks.BASELINE = self.root, self.root / "baseline.json"
        self.addCleanup(lambda: (setattr(checks, "ROOT", self.saved[0]), setattr(checks, "BASELINE", self.saved[1])))
        self.out = self.root / "out"
        self.out.mkdir()

    def write(self, name, text):
        (self.root / name).write_text(text)

    def test_markers_in_comments_are_found_with_their_codes(self):
        self.write("a.py", f"x = 1  # {RUFF}: S603  # {BANDIT} B603 - reason\ny = 2  # {SEMGREP}: some-rule - why\n")
        found = {(e["marker"], tuple(e["codes"])) for e in checks.find_suppressions()}
        self.assertEqual(found, {(RUFF, ("S603",)), (BANDIT, ("B603",)), (SEMGREP, ("some-rule",))})

    def test_markers_inside_strings_are_not_suppressions(self):
        self.write("a.py", f'text = "# {BANDIT} B101"\nother = """\n# {RUFF}: E501\n"""\n')
        self.assertEqual(checks.find_suppressions(), [])

    def test_a_new_suppression_fails_until_it_is_accepted(self):
        self.write("a.py", f"x = 1  # {RUFF}: E501\n")
        self.assertEqual(checks.check_suppressions(self.out, accept=True)[0], 0)
        self.assertEqual(checks.check_suppressions(self.out, accept=False)[0], 0)
        self.write("a.py", f"x = 1  # {RUFF}: E501\ny = 2  # {RUFF}: E501\nz = 3  # {BANDIT} B101\n")
        failures, note = checks.check_suppressions(self.out, accept=False)
        self.assertEqual(failures, 2)  # one more of the same, and one of a new kind
        self.assertIn("unreviewed", note)
        self.assertEqual(checks.check_suppressions(self.out, accept=True)[0], 0)
        self.assertEqual(checks.check_suppressions(self.out, accept=False)[0], 0)

    def test_without_a_baseline_the_check_does_not_pass(self):
        self.write("a.py", "x = 1\n")
        self.assertIsNone(checks.check_suppressions(self.out, accept=False)[0])

    def test_removing_a_suppression_is_not_a_failure(self):
        self.write("a.py", f"x = 1  # {RUFF}: E501\n")
        checks.check_suppressions(self.out, accept=True)
        self.write("a.py", "x = 1\n")
        self.assertEqual(checks.check_suppressions(self.out, accept=False)[0], 0)

    def sarif(self):
        rules = [{"id": "unused", "help": {"text": "long"}}, {"id": "a", "help": {"text": "long"}, "name": "A"}, {"id": "b"}]
        results = [{"ruleId": "a", "ruleIndex": 1}, {"ruleId": "b", "ruleIndex": 2, "suppressions": [{"kind": "inSource"}]}]
        return {"runs": [{"tool": {"driver": {"rules": rules}}, "results": results}]}

    def test_trimmed_sarif_keeps_only_rules_with_results_and_no_help_text(self):
        source = self.root / "in.sarif"
        source.write_text(json.dumps(self.sarif()))
        run_ = checks.trim_sarif(source)["runs"][0]
        self.assertEqual([r["id"] for r in run_["tool"]["driver"]["rules"]], ["a", "b"])
        self.assertTrue(all("help" not in r for r in run_["tool"]["driver"]["rules"]))
        self.assertEqual([r["ruleIndex"] for r in run_["results"]], [0, 1])

    def test_suppressed_sarif_results_are_dropped_and_counted(self):
        active, removed = checks.without_suppressed(self.sarif())
        self.assertEqual(removed, 1)
        self.assertEqual([r["ruleId"] for r in active["runs"][0]["results"]], ["a"])

    def test_archived_sarif_does_not_name_where_it_was_produced(self):
        target = self.root / "out.sarif"
        checks.write_sarif({"uri": f"{self.root}/pkg/mod.py"}, target)
        text = target.read_text()
        self.assertNotIn(str(self.root), text)
        self.assertIn("./pkg/mod.py", text)


if __name__ == "__main__":
    unittest.main()
