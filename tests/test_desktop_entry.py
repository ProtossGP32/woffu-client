"""Tests for the packaged woffu-applet.desktop launcher entry."""
from __future__ import annotations

import configparser
import unittest
from pathlib import Path

_DESKTOP_FILE = (
    Path(__file__).resolve().parent.parent / "src" / "woffu_client" /
    "data" / "woffu-applet.desktop"
)


class DesktopEntryTest(unittest.TestCase):
    """Unit tests for the shipped woffu-applet.desktop file."""

    def setUp(self):
        """Parse the .desktop file once per test."""
        self.assertTrue(
            _DESKTOP_FILE.is_file(), f"missing {_DESKTOP_FILE}",
        )
        parser = configparser.ConfigParser()
        parser.optionxform = str
        parser.read(_DESKTOP_FILE)
        self.entry = parser["Desktop Entry"]

    def test_required_keys_match_agreed_values(self):
        """Keys agreed on issue #65 are present with the right values."""
        self.assertEqual(self.entry["Type"], "Application")
        self.assertEqual(self.entry["Version"], "1.0")
        self.assertEqual(self.entry["Name"], "Woffu")
        self.assertEqual(self.entry["Exec"], "woffu-applet")
        self.assertEqual(self.entry["Icon"], "woffu")
        self.assertEqual(self.entry["Terminal"], "false")
        self.assertEqual(self.entry["Categories"], "Utility;")
        self.assertEqual(self.entry["DBusActivatable"], "false")
        self.assertEqual(self.entry["StartupNotify"], "false")

    def test_comment_is_non_empty(self):
        """A Comment is present so app grids/tooltips show a description."""
        self.assertTrue(self.entry["Comment"].strip())

    def test_omits_autostart_keys(self):
        """No autostart keys: a launcher entry, not autostart (TODO.md)."""
        self.assertNotIn("X-GNOME-Autostart-enabled", self.entry)


if __name__ == "__main__":
    unittest.main()
