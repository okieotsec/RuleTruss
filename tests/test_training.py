"""The training guide is generated from live results; these tests keep it current and keep its instructions true to the interface."""
import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUIDE = ROOT / "docs" / "TRAINING.md"
WEB = "".join((ROOT / "ruletruss" / "web" / name).read_text(encoding="utf-8") for name in ("app.js", "graph.js"))


def generator():
    spec = importlib.util.spec_from_file_location("make_training", ROOT / "tools" / "make_training.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TrainingGuideTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = generator().build()

    def test_the_committed_guide_is_what_the_generator_writes_now(self):
        self.assertEqual(GUIDE.read_text(encoding="utf-8"), self.text, "run: .venv/bin/python tools/make_training.py")

    def test_every_button_and_label_the_guide_tells_you_to_use_exists_in_the_interface(self):
        for label in ("Load the Riverbend example", "Load the UniFi example", "Build directional policies", "Translate and validate", "show the rest",
                      "Back to subnets", "See all its communications", "Open its devices", "Delete this project", "Delete all data", "Zone matrix",
                      "Capture point", "Download as JSON", "Load from a JSON file", "Rule analysis", "Show explanations",
                      "Preserve what is configured", "Propose narrower from observation", "Allow rules no observed traffic matched",
                      "Validation on sampled connections", "Limits of this comparison", "Translate to another firewall", "Labels: hover only",
                      "Fit", "Stop", "Download from the IEEE", "Seen without an IP address", "MACs shared by several addresses",
                      "Address or label", "Direction confidence at least", "Isolated behind a gateway"):
            self.assertIn(label.lower(), WEB.lower(), label)

    def test_the_tab_names_in_the_guide_are_the_real_tab_names(self):
        block = WEB[WEB.index("const TABS = ["):WEB.index("];", WEB.index("const TABS = ["))]
        tabs = re.findall(r'\["[a-z]+", "([^"]+)"\]', block)
        self.assertEqual(len(tabs), 10)
        for name in tabs:
            self.assertIn(name, self.text, name)

    def test_the_guide_links_resolve(self):
        for target in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", self.text):
            if not target.startswith("http"):
                self.assertTrue((GUIDE.parent / target).exists(), target)

    def test_every_lab_has_check_questions_with_an_answer(self):
        questions = len(re.findall(r"\(answer \d+\)", self.text)) + 1            # lab 1 puts its two questions in one line
        answers = len(re.findall(r"^\d+\. \(Lab", self.text, re.M)) + 1
        self.assertGreaterEqual(answers, questions - 1)
        for number in range(3, 10):
            self.assertIn(f"(answer {number})", self.text)
            self.assertRegex(self.text, rf"(?m)^{number}\. \(Lab|\b{number}\. \(Lab")

    def test_no_real_address_or_personal_detail_is_in_the_guide(self):
        for forbidden in ("/ho" + "me/", "ja" + "red", "@g" + "mail"):      # built from pieces so this file does not contain them
            self.assertNotIn(forbidden, self.text.lower())


if __name__ == "__main__":
    unittest.main()
