"""Tests for the Woffu status model and formatting helpers."""
from __future__ import annotations

import unittest
from datetime import timedelta

from src.woffu_client.status import format_timedelta
from src.woffu_client.status import from_client_result
from src.woffu_client.status import WoffuStatus


class FormatTimedeltaTest(unittest.TestCase):
    """Unit tests for status.format_timedelta()."""

    def test_formats_hours_minutes_seconds(self):
        """A timedelta is formatted as zero-padded HH:MM:SS."""
        self.assertEqual(
            format_timedelta(timedelta(hours=6, minutes=49, seconds=39)),
            "06:49:39",
        )

    def test_zero_timedelta(self):
        """A zero timedelta formats as 00:00:00."""
        self.assertEqual(format_timedelta(timedelta()), "00:00:00")


class FromClientResultTest(unittest.TestCase):
    """Unit tests for status.from_client_result()."""

    def test_full_result(self):
        """A signed-in result with a theoretical schedule maps every field."""
        status = from_client_result(
            timedelta(hours=6, minutes=49, seconds=39),
            True,
            timedelta(hours=6, minutes=30),
        )
        self.assertTrue(status.signed_in)
        self.assertEqual(status.hours_worked, "06:49:39")
        self.assertEqual(status.theoretical_hours, "06:30:00")
        self.assertIsNone(status.error)

    def test_zero_theoretical_time_is_none(self):
        """A zero theoretical_time (extend=False) maps to None."""
        status = from_client_result(timedelta(), False, timedelta())
        self.assertFalse(status.signed_in)
        self.assertEqual(status.hours_worked, "00:00:00")
        self.assertIsNone(status.theoretical_hours)

    def test_configured_defaults_true(self):
        """A client result always maps to a configured status."""
        status = from_client_result(timedelta(hours=1), True, timedelta())
        self.assertTrue(status.configured)


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
