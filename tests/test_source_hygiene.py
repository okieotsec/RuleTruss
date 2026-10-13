import unicodedata
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# The only non-ASCII characters source code may contain: visible interface symbols.
ALLOWED = {0x00B7, 0x2022, 0x2026, 0x25AC, 0x25B2, 0x25B8, 0x25BC, 0x25BE, 0x26A0, 0x2713, 0x2716, 0x2192}
SOURCES = sorted([*ROOT.glob("pbridge/**/*.py"), *ROOT.glob("pbridge/web/*.js"), *ROOT.glob("tools/*.py"), *ROOT.glob("tests/*.py")])
TEXT_SUFFIXES = {".py", ".md", ".json", ".html", ".yml", ".yaml", ".toml", ".txt", ".js", ".css", ".csv", ".cfg", ".conf", ".xml", ".in"}
SKIP_PARTS = {".git", "__pycache__", ".venv", ".ruff_cache", ".hypothesis", "data"}


def repo_files():
    for path in sorted(ROOT.rglob("*")):
        rel = path.relative_to(ROOT)
        if path.is_file() and path.suffix in TEXT_SUFFIXES and not (SKIP_PARTS & set(rel.parts)):
            yield path


class SourceHygieneTests(unittest.TestCase):
    """Source files must not hide characters from a reader, and the repository must stay free of personal and third-party names."""

    def test_there_are_sources_to_check(self):
        self.assertGreater(len(SOURCES), 20)

    def test_no_invisible_or_direction_changing_characters(self):
        for path in SOURCES:
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                for char in line:
                    if unicodedata.category(char) in ("Cf", "Cc", "Zl", "Zp") and char != "\t":
                        self.fail(f"{path.name}:{number} contains U+{ord(char):04X}; write it as an escape sequence")

    def test_no_look_alike_or_unreviewed_non_ascii_characters(self):
        for path in SOURCES:
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                for char in line:
                    if ord(char) > 127 and ord(char) not in ALLOWED:
                        self.fail(f"{path.name}:{number} contains U+{ord(char):04X} ({unicodedata.name(char, '?')})")

    def test_files_have_no_byte_order_mark(self):
        for path in SOURCES:
            self.assertFalse(path.read_bytes().startswith(b"\xef\xbb\xbf"), path.name)

    def test_no_personal_name_or_home_folder_path_is_in_any_file_of_the_repository(self):
        # Built from pieces so this test does not contain what it forbids. The project is published under a handle.
        forbidden = ("ja" + "red", "frit" + "ts", "/ho" + "me/")
        checked = 0
        for path in repo_files():
            checked += 1
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            for word in forbidden:
                self.assertFalse(word in text, f"{path.relative_to(ROOT)} contains {word!r}")
        self.assertGreater(checked, 30)

    def test_no_reference_to_a_vendor_this_project_is_not_affiliated_with(self):
        # The directional model is this project's own concept. Built from pieces so this test does not contain the names.
        forbidden = ("blast" + "wave", "blast" + "shield", "blast" + " shield")
        for path in repo_files():
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            for word in forbidden:
                self.assertFalse(word in text, f"{path.relative_to(ROOT)} contains {word!r}")

    def test_the_checks_themselves_catch_the_hostile_characters(self):
        for codepoint in (0x202E, 0x200B, 0xFEFF, 0x2066, 0x0410, 0xFF0F, 0x0663):
            char = chr(codepoint)
            hidden = unicodedata.category(char) in ("Cf", "Cc", "Zl", "Zp")
            self.assertTrue(hidden or codepoint not in ALLOWED, hex(codepoint))


if __name__ == "__main__":
    unittest.main()
