"""The CML test pack: small, deployable, and its expected answers match what the user's own scenario needs (phones reach cameras, not the reverse)."""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_tool():
    spec = importlib.util.spec_from_file_location("make_cml_pack", ROOT / "tools" / "make_cml_pack.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CmlPackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config, cls.rows, cls.translation = load_tool().build()
        cls.expected = {(r["from"], r["to"], r["test"]): r["expected"] for r in cls.rows}

    def test_the_example_is_deployable_and_complete(self):
        self.assertTrue(self.translation.deployable, self.translation.blockers)
        self.assertEqual(len(self.rows), 24)
        self.assertNotIn("UNDECIDED", {r["expected"] for r in self.rows})

    def test_phones_reach_cameras_and_cameras_cannot_start_the_reverse(self):
        for test in ("icmp", "tcp443"):
            self.assertEqual(self.expected[("h-wifi", "h-cam", test)], "ALLOW")
            self.assertEqual(self.expected[("h-cam", "h-wifi", test)], "DENY")

    def test_nothing_from_outside_reaches_the_inside_and_the_inside_can_go_out(self):
        for inside in ("h-lan", "h-wifi", "h-cam"):
            self.assertEqual(self.expected[("h-ext", inside, "tcp443")], "DENY")
            self.assertEqual(self.expected[(inside, "h-ext", "tcp443")], "ALLOW")

    def test_the_lab_levels_differ_and_icmp_inspection_is_in_the_configuration(self):
        levels = [line.split()[-1] for line in self.config if line.startswith(" security-level")]
        self.assertEqual(len(set(levels)), len(levels), "equal levels would block traffic between interfaces whatever the lists say")
        self.assertIn("  inspect icmp", self.config)


if __name__ == "__main__":
    unittest.main()
