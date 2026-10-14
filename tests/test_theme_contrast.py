"""The page's colours meet WCAG contrast in both themes, and the brand files are the ones from the OkieOTSec kit."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSS = (ROOT / "ruletruss" / "web" / "style.css").read_text(encoding="utf-8")


def variables(block):
    return {k: v.strip() for k, v in re.findall(r"--([a-z-]+):\s*(#[0-9A-Fa-f]{6})", block)}


def luminance(hex_color):
    channels = [int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def ratio(a, b):
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


LIGHT = variables(CSS[CSS.index(":root {"):CSS.index(":root:not([data-theme")])
DARK = {**LIGHT, **variables(CSS[CSS.index("@media (prefers-color-scheme: dark)"):CSS.index("* { box-sizing")])}
TEXT_PAIRS = [("text", "bg"), ("text", "panel"), ("muted", "bg"), ("muted", "panel"), ("link", "bg"), ("link", "panel"), ("btn-text", "btn-bg"),
              ("observed", "observed-bg"), ("configured", "configured-bg"), ("proposed", "proposed-bg"), ("ok", "ok-bg"), ("warn", "warn-bg"),
              ("bad", "bad-bg"), ("text", "ok-bg"), ("text", "warn-bg"), ("text", "bad-bg")]


def palette(block):
    return {k: v.upper() for k, v in re.findall(r"--(g\d):\s*(#[0-9A-Fa-f]{6})", block)}


LIGHT_PALETTE = palette(CSS[CSS.index(":root {"):CSS.index(":root:not([data-theme")])
DARK_PALETTE = palette(CSS[CSS.index("@media (prefers-color-scheme: dark)"):CSS.index("* { box-sizing")])


class ContrastTests(unittest.TestCase):
    def test_graph_colours_are_visible_against_the_panel_and_all_different(self):
        for name, colours, theme in (("light", LIGHT_PALETTE, LIGHT), ("dark", DARK_PALETTE, DARK)):
            self.assertEqual(len(colours), 8, name)
            self.assertEqual(len(set(colours.values())), 8, name)
            for key, value in colours.items():
                self.assertGreaterEqual(ratio(value, theme["panel"]), 3.0, f"{name}: {key} {value} on the panel")

    def test_the_forced_dark_theme_repeats_the_system_dark_tokens(self):
        forced = CSS[CSS.index(':root[data-theme="dark"] {'):CSS.index("}", CSS.index(':root[data-theme="dark"] {'))]
        for key, value in variables(forced).items():
            self.assertEqual(value, DARK[key], key)
        self.assertEqual(palette(forced), DARK_PALETTE)
        self.assertTrue(set(variables(CSS[CSS.index("@media (prefers-color-scheme: dark)"):CSS.index("* { box-sizing")])) <= set(variables(forced)))

    def test_every_text_pair_meets_4_5_to_1_in_both_themes(self):
        for name, theme in (("light", LIGHT), ("dark", DARK)):
            for fg, bg in TEXT_PAIRS:
                self.assertGreaterEqual(ratio(theme[fg], theme[bg]), 4.5, f"{name}: {fg} on {bg} is {ratio(theme[fg], theme[bg]):.2f}")

    def test_focus_ring_is_visible_against_the_page(self):
        for name, theme in (("light", LIGHT), ("dark", DARK)):
            self.assertGreaterEqual(ratio(theme["focus"], theme["bg"]), 3.0, name)

    def test_brand_tokens_match_the_kit(self):
        import json
        tokens = json.loads((ROOT / "assets" / "brand" / "tokens.json").read_text(encoding="utf-8"))
        light, dark = tokens["theme"]["light"], tokens["theme"]["dark"]
        self.assertEqual((LIGHT["bg"].upper(), LIGHT["panel"].upper(), LIGHT["text"].upper()), (light["bg"], light["surface"], light["text"]))
        self.assertEqual((DARK["bg"].upper(), DARK["panel"].upper(), DARK["link"].upper()), (dark["bg"], dark["surface"], dark["link"]))

    def test_served_logos_are_byte_identical_to_the_kit(self):
        for svg in (ROOT / "ruletruss" / "web" / "brand").glob("*.svg"):
            self.assertEqual(svg.read_bytes(), (ROOT / "assets" / "brand" / "svg" / svg.name).read_bytes(), svg.name)

    def test_no_logo_file_contains_anything_active(self):
        for svg in (ROOT / "assets" / "brand" / "svg").glob("*.svg"):
            text = svg.read_text(encoding="utf-8").lower()
            for bad in ("<script", "onload", "onclick", "foreignobject", "href=", "javascript:", "<image", "@import"):
                self.assertNotIn(bad, text, f"{svg.name}: {bad}")


if __name__ == "__main__":
    unittest.main()
