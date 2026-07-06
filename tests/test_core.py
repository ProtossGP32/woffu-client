"""Tests for the UI-agnostic Woffu applet core (WoffuAPIClient wrapper)."""
from __future__ import annotations

import unittest
from datetime import timedelta
from unittest.mock import patch

import src.woffu_client.core as core


class GetStatusTest(unittest.TestCase):
    """Unit tests for core.get_status()."""

    @patch("src.woffu_client.core._is_configured", return_value=True)
    @patch("src.woffu_client.core.WoffuAPIClient")
    def test_success_builds_status_from_client(
        self, mock_client_cls, _mock_configured,
    ):
        """A successful client call is converted into a WoffuStatus."""
        mock_client_cls.return_value.get_status.return_value = (
            timedelta(hours=6, minutes=49, seconds=39),
            True,
            timedelta(hours=6, minutes=30),
        )
        status = core.get_status()
        self.assertTrue(status.signed_in)
        self.assertEqual(status.hours_worked, "06:49:39")
        self.assertEqual(status.theoretical_hours, "06:30:00")
        self.assertIsNone(status.error)

    @patch("src.woffu_client.core._is_configured", return_value=True)
    @patch("src.woffu_client.core.WoffuAPIClient")
    def test_calls_client_non_interactively_with_extend(
        self, mock_client_cls, _mock_configured,
    ):
        """get_status builds a non-interactive client and asks for extend."""
        mock_client_cls.return_value.get_status.return_value = (
            timedelta(), False, timedelta(),
        )
        core.get_status()
        _, kwargs = mock_client_cls.call_args
        self.assertFalse(kwargs["interactive"])
        mock_client_cls.return_value.get_status.assert_called_once_with(
            extend=True,
        )

    @patch("src.woffu_client.core._is_configured", return_value=True)
    @patch("src.woffu_client.core.WoffuAPIClient")
    def test_client_exception_is_error(self, mock_client_cls, _mock_cfg):
        """An exception from the client surfaces as an error status."""
        mock_client_cls.return_value.get_status.side_effect = Exception(
            "boom",
        )
        status = core.get_status()
        self.assertIsNotNone(status.error)
        self.assertIn("boom", status.error)
        self.assertFalse(status.signed_in)
        self.assertTrue(status.configured)

    @patch("src.woffu_client.core._is_configured", return_value=True)
    @patch("src.woffu_client.core.WoffuAPIClient")
    def test_failure_never_reads_as_signed_out(
        self, mock_client_cls, _mock_cfg,
    ):
        """A failed check always carries an error (regression: stale token)."""
        mock_client_cls.return_value.get_status.side_effect = Exception(
            "401 Unauthorized",
        )
        status = core.get_status()
        # The bug was returning signed_in=False with error=None, which the
        # applet rendered as a real "Signed out" state.
        self.assertIsNotNone(status.error)
        self.assertFalse(status.signed_in)

    @patch("src.woffu_client.core._is_configured", return_value=False)
    @patch("src.woffu_client.core.WoffuAPIClient")
    def test_not_configured_is_actionable(self, mock_client_cls, _mock_cfg):
        """Missing credentials yield configured=False + an actionable hint.

        No client is ever constructed (which would itself try to request
        credentials).
        """
        status = core.get_status()
        self.assertFalse(status.configured)
        self.assertFalse(status.signed_in)
        self.assertIn("request-credentials", status.error)
        mock_client_cls.assert_not_called()


class SignTest(unittest.TestCase):
    """Unit tests for core.sign_in() / core.sign_out()."""

    @patch("src.woffu_client.core._is_configured", return_value=True)
    @patch("src.woffu_client.core.WoffuAPIClient")
    def test_sign_in_calls_client(self, mock_client_cls, _mock_cfg):
        """sign_in() drives the client with type='in'."""
        core.sign_in()
        mock_client_cls.return_value.sign.assert_called_once_with(type="in")

    @patch("src.woffu_client.core._is_configured", return_value=True)
    @patch("src.woffu_client.core.WoffuAPIClient")
    def test_sign_out_calls_client(self, mock_client_cls, _mock_cfg):
        """sign_out() drives the client with type='out'."""
        core.sign_out()
        mock_client_cls.return_value.sign.assert_called_once_with(type="out")

    @patch("src.woffu_client.core._is_configured", return_value=True)
    @patch("src.woffu_client.core.WoffuAPIClient")
    def test_sign_failure_is_swallowed(self, mock_client_cls, _mock_cfg):
        """A sign failure never raises; it surfaces on the next get_status."""
        mock_client_cls.return_value.sign.side_effect = Exception("boom")
        core.sign_in()  # should not raise

    @patch("src.woffu_client.core._is_configured", return_value=False)
    @patch("src.woffu_client.core.WoffuAPIClient")
    def test_sign_skips_when_not_configured(self, mock_client_cls, _mock_cfg):
        """Signing without credentials is a no-op, no client gets built."""
        core.sign_in()
        mock_client_cls.assert_not_called()


if __name__ == "__main__":
    unittest.main()
