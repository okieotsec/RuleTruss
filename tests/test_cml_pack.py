"""The CML test pack: small, deployable, and its expected answers match what the user's own scenario needs (phones reach cameras, not the reverse)."""
import importlib.util
import re
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

    def test_the_lab_file_has_exactly_the_keys_cml_itself_exported_and_links_the_right_ports(self):
        tool = load_tool()
        generated = tool.lab_file()

        def keys(text):
            return set(re.findall(r"^\s*(?:- )?([A-Za-z_][A-Za-z0-9_]*):", text, re.M))

        real = (ROOT / "tests" / "fixtures" / "cml-lab-export-0.3.1.yaml").read_text(encoding="utf-8")
        self.assertEqual(keys(tool.lab_file(with_host_config=False)), keys(real), "the lab file must use CML's own format, with nothing added or missing")
        self.assertEqual(keys(generated) - keys(real), {"name", "content"}, "the only addition is the node.cfg entry of a node")
        self.assertEqual(len(re.findall(r"^  - boot_disk_size:", generated, re.M)), 5)
        self.assertEqual(len(re.findall(r"^  - id: \"l\d\"", generated, re.M)), 4)
        for info in tool.LAB.values():                                    # each host is linked to the ASA port its address is configured on
            index = ["GigabitEthernet0/0", "GigabitEthernet0/1", "GigabitEthernet0/2", "GigabitEthernet0/3"].index(info["port"]) + 1
            self.assertIn(f'label: "rtasa-{info["port"]}<->{info["host"]}-eth0"', generated)
            self.assertRegex(generated, rf'i1: "i{index}"\n    i2: "i0"\n    conditioning: {{}}\n    label: "rtasa-{info["port"]}')

    def test_each_host_boot_script_sets_its_own_address_gateway_and_listener(self):
        tool = load_tool()
        generated = tool.lab_file()
        for info in tool.LAB.values():
            script = tool.host_script(info)
            self.assertIn(f"hostname {info['host']}", script)
            self.assertIn(f"ip addr add {info['ip']}/24 dev eth0", script)
            self.assertIn(f"ip route add default via {info['asa']}", script)
            self.assertIn("nc -l -p 443", script)
            self.assertIn(f"ip addr add {info['ip']}/24 dev eth0", generated.replace("\\n", "\n"))


if __name__ == "__main__":
    unittest.main()
