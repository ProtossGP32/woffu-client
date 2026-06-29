"""Tests for the Woffu status model and parsers."""
from __future__ import annotations

import unittest

from src.woffu_client.status import parse_json
from src.woffu_client.status import parse_text
from src.woffu_client.status import WoffuStatus


class ParseJsonTest(unittest.TestCase):
    """Unit tests for status.parse_json()."""

    def test_full_payload(self):
        """A complete --json payload maps onto every field."""
        status = parse_json({
            "signed_in": True,
            "hours_worked": "06:49:39",
            "theoretical_hours": "06:30:00",
        })
        self.assertTrue(status.signed_in)
        self.assertEqual(status.hours_worked, "06:49:39")
        self.assertEqual(status.theoretical_hours, "06:30:00")
        self.assertIsNone(status.error)

    def test_null_theoretical(self):
        """A null theoretical_hours stays None."""
        status = parse_json({
            "signed_in": False,
            "hours_worked": "00:00:00",
            "theoretical_hours": None,
        })
        self.assertFalse(status.signed_in)
        self.assertIsNone(status.theoretical_hours)

    def test_missing_keys_use_defaults(self):
        """An empty dict falls back to safe defaults, not a crash."""
        status = parse_json({})
        self.assertFalse(status.signed_in)
        self.assertEqual(status.hours_worked, "00:00:00")
        self.assertIsNone(status.theoretical_hours)
        self.assertIsNone(status.error)

    def test_error_key_is_carried(self):
        """An error key is surfaced on the model."""
        status = parse_json({"error": "not configured"})
        self.assertEqual(status.error, "not configured")

    def test_configured_defaults_true(self):
        """A payload without a configured key is treated as configured."""
        status = parse_json({"signed_in": True, "hours_worked": "01:00:00"})
        self.assertTrue(status.configured)


class ParseTextTest(unittest.TestCase):
    """Unit tests for the status.parse_text() fallback."""

    SIGNED_IN = (
        "[2026-06-29 17:14:58] INFO woffu_api_client: "
        "Hours worked today: 06:44:58\n"
        "[2026-06-29 17:14:58] INFO woffu_api_client: "
        "You're currently signed in.\n"
    )
    SIGNED_OUT = (
        "[2026-06-29 18:00:00] INFO woffu_api_client: "
        "Hours worked today: 08:00:00\n"
        "[2026-06-29 18:00:00] INFO woffu_api_client: "
        "You're currently signed out.\n"
    )

    def test_signed_in_text(self):
        """'signed in' is detected and hours are extracted."""
        status = parse_text(self.SIGNED_IN)
        self.assertTrue(status.signed_in)
        self.assertEqual(status.hours_worked, "06:44:58")

    def test_signed_out_text(self):
        """'signed out' is not mistaken for signed in."""
        status = parse_text(self.SIGNED_OUT)
        self.assertFalse(status.signed_in)
        self.assertEqual(status.hours_worked, "08:00:00")

    def test_no_hours_line_defaults(self):
        """Absent an hours line, hours_worked stays at the default."""
        status = parse_text("some unrelated output\n")
        self.assertFalse(status.signed_in)
        self.assertEqual(status.hours_worked, "00:00:00")


class WoffuStatusTest(unittest.TestCase):
    """Unit tests for the WoffuStatus dataclass defaults."""

    def test_optional_fields_default(self):
        """theoretical_hours/error default to None and configured to True."""
        status = WoffuStatus(signed_in=True, hours_worked="01:00:00")
        self.assertIsNone(status.theoretical_hours)
        self.assertIsNone(status.error)
        self.assertTrue(status.configured)


if __name__ == "__main__":
    unittest.main()
