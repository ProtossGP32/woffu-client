"""Tests for the UI-agnostic Woffu applet core (CLI wrapper)."""
from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

import src.woffu_client.core as core


def _completed(stdout="", stderr="", returncode=0):
    """Build a CompletedProcess like subprocess.run returns."""
    return subprocess.CompletedProcess(
        args=["woffu-cli"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


class GetStatusTest(unittest.TestCase):
    """Unit tests for core.get_status()."""

    @patch("src.woffu_client.core.subprocess.run")
    def test_success_parses_json(self, mock_run):
        """A clean JSON payload is parsed into a WoffuStatus."""
        mock_run.return_value = _completed(
            stdout='{"signed_in": true, "hours_worked": "06:49:39", '
                   '"theoretical_hours": "06:30:00"}',
        )
        status = core.get_status()
        self.assertTrue(status.signed_in)
        self.assertEqual(status.hours_worked, "06:49:39")
        self.assertEqual(status.theoretical_hours, "06:30:00")
        self.assertIsNone(status.error)

    @patch("src.woffu_client.core.subprocess.run")
    def test_invokes_cli_with_json_flag(self, mock_run):
        """get_status drives the CLI non-interactively with --json."""
        mock_run.return_value = _completed(
            stdout='{"signed_in": false, "hours_worked": "00:00:00", '
                   '"theoretical_hours": null}',
        )
        core.get_status()
        args, kwargs = mock_run.call_args
        cmd = args[0]
        self.assertIn("get-status", cmd)
        self.assertIn("--json", cmd)
        self.assertIn("--non-interactive", cmd)
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["text"])

    @patch("src.woffu_client.core._is_configured", return_value=True)
    @patch("src.woffu_client.core.subprocess.run")
    def test_nonzero_exit_is_error(self, mock_run, _mock_configured):
        """A non-zero return code surfaces stderr as an error status."""
        mock_run.return_value = _completed(
            stderr="❌ Error retrieving status: boom", returncode=1,
        )
        status = core.get_status()
        self.assertIsNotNone(status.error)
        self.assertIn("boom", status.error)
        self.assertFalse(status.signed_in)
        self.assertTrue(status.configured)

    @patch("src.woffu_client.core._is_configured", return_value=True)
    @patch("src.woffu_client.core.subprocess.run")
    def test_structured_json_error_surfaced(self, mock_run, _mock_configured):
        """An {"error": ...} payload (exit 1) is surfaced, not signed-out."""
        mock_run.return_value = _completed(
            stdout='{"error": "token expired"}', returncode=1,
        )
        status = core.get_status()
        self.assertEqual(status.error, "token expired")
        self.assertFalse(status.signed_in)
        self.assertTrue(status.configured)

    @patch("src.woffu_client.core._is_configured", return_value=True)
    @patch("src.woffu_client.core.subprocess.run")
    def test_failure_never_reads_as_signed_out(self, mock_run, _mock_cfg):
        """A failed check always carries an error (regression: stale token)."""
        mock_run.return_value = _completed(
            stdout="", stderr="401 Unauthorized", returncode=1,
        )
        status = core.get_status()
        # The bug was returning signed_in=False with error=None, which the
        # applet rendered as a real "Signed out" state.
        self.assertIsNotNone(status.error)

    @patch("src.woffu_client.core._is_configured", return_value=False)
    @patch("src.woffu_client.core.subprocess.run")
    def test_not_configured_is_actionable(self, mock_run, _mock_configured):
        """Missing credentials yield configured=False + an actionable hint."""
        mock_run.return_value = _completed(
            stderr="username and password required", returncode=1,
        )
        status = core.get_status()
        self.assertFalse(status.configured)
        self.assertFalse(status.signed_in)
        self.assertIn("request-credentials", status.error)

    @patch("src.woffu_client.core.subprocess.run")
    def test_cli_not_found(self, mock_run):
        """A missing woffu-cli becomes a clear 'not found' error."""
        mock_run.side_effect = FileNotFoundError()
        status = core.get_status()
        self.assertIsNotNone(status.error)
        self.assertIn("woffu-cli not found", status.error)

    @patch("src.woffu_client.core.subprocess.run")
    def test_timeout(self, mock_run):
        """A CLI timeout becomes a timeout error status."""
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd="woffu-cli", timeout=15,
        )
        status = core.get_status()
        self.assertIsNotNone(status.error)
        self.assertIn("timed out", status.error)

    @patch("src.woffu_client.core.subprocess.run")
    def test_falls_back_to_text_on_bad_json(self, mock_run):
        """Non-JSON stdout (older CLI) falls back to text parsing."""
        mock_run.return_value = _completed(
            stdout="Hours worked today: 06:44:58\n"
                   "You're currently signed in.\n",
        )
        status = core.get_status()
        self.assertTrue(status.signed_in)
        self.assertEqual(status.hours_worked, "06:44:58")
        self.assertIsNone(status.error)


class SignTest(unittest.TestCase):
    """Unit tests for core.sign_in() / core.sign_out()."""

    @patch("src.woffu_client.core.subprocess.run")
    def test_sign_in_command(self, mock_run):
        """sign_in sends --sign-type in."""
        mock_run.return_value = _completed()
        core.sign_in()
        cmd = mock_run.call_args[0][0]
        self.assertIn("sign", cmd)
        self.assertIn("--sign-type", cmd)
        self.assertIn("in", cmd)

    @patch("src.woffu_client.core.subprocess.run")
    def test_sign_out_command(self, mock_run):
        """sign_out sends --sign-type out."""
        mock_run.return_value = _completed()
        core.sign_out()
        cmd = mock_run.call_args[0][0]
        self.assertIn("sign", cmd)
        self.assertIn("--sign-type", cmd)
        self.assertIn("out", cmd)


if __name__ == "__main__":
    unittest.main()
