import sys
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from typing import cast
import src.woffu_client.cli as cli


class WoffuCLITest(unittest.TestCase):
    """Unit tests for src/woffu_client/cli.py"""

    def setUp(self):
        # Capture stdout/stderr for assertions
        self.stdout_backup = sys.stdout
        self.stderr_backup = sys.stderr
        sys.stdout = cast(StringIO, StringIO())
        sys.stderr = cast(StringIO, StringIO())

    def tearDown(self):
        # Restore stdout/stderr
        sys.stdout = self.stdout_backup
        sys.stderr = self.stderr_backup

    @patch("src.woffu_client.cli.WoffuAPIClient")
    def test_download_all_documents_success(self, mock_client_cls):
        mock_client = mock_client_cls.return_value
        mock_client.download_all_documents.return_value = None

        test_dir = Path("/tmp/fake")
        with patch.object(sys, "argv", ["cli", "download-all-documents", "--output-dir", str(test_dir)]):
            cli.main()

        mock_client.download_all_documents.assert_called_once_with(output_dir=test_dir)
        output = cast(StringIO, sys.stdout).getvalue()
        self.assertIn("✅ Files downloaded", output)

    @patch("src.woffu_client.cli.WoffuAPIClient")
    def test_download_all_documents_failure(self, mock_client_cls):
        mock_client = mock_client_cls.return_value
        mock_client.download_all_documents.side_effect = RuntimeError("Boom!")

        test_dir = Path("/tmp/fake")
        with patch.object(sys, "argv", ["cli", "download-all-documents", "--output-dir", str(test_dir)]):
            with self.assertRaises(SystemExit):
                cli.main()

        error_output = cast(StringIO, sys.stderr).getvalue()
        self.assertIn("❌ Error downloading files: Boom!", error_output)

    @patch("src.woffu_client.cli.WoffuAPIClient")
    def test_get_status_success(self, mock_client_cls):
        mock_client = mock_client_cls.return_value
        mock_client.get_status.return_value = None

        with patch.object(sys, "argv", ["cli", "get-status"]):
            cli.main()

        mock_client.get_status.assert_called_once()

    @patch("src.woffu_client.cli.WoffuAPIClient")
    def test_get_status_failure(self, mock_client_cls):
        mock_client = mock_client_cls.return_value
        mock_client.get_status.side_effect = Exception("status failed")

        with patch.object(sys, "argv", ["cli", "get-status"]):
            cli.main()

        error_output = cast(StringIO, sys.stderr).getvalue()
        self.assertIn("❌ Error retrieving status", error_output)

    @patch("src.woffu_client.cli.WoffuAPIClient")
    def test_sign_success(self, mock_client_cls):
        mock_client = mock_client_cls.return_value
        with patch.object(sys, "argv", ["cli", "sign", "--sign-type", "in"]):
            cli.main()

        mock_client.sign.assert_called_once_with(type="in")

    @patch("src.woffu_client.cli.WoffuAPIClient")
    def test_sign_failure(self, mock_client_cls):
        mock_client = mock_client_cls.return_value
        mock_client.sign.side_effect = Exception("sign failed")

        with patch.object(sys, "argv", ["cli", "sign", "--sign-type", "out"]):
            cli.main()

        error_output = cast(StringIO, sys.stderr).getvalue()
        self.assertIn("❌ Error sending sign command", error_output)

    @patch("src.woffu_client.cli.WoffuAPIClient")
    def test_request_credentials_success(self, mock_client_cls):
        mock_client = mock_client_cls.return_value
        with patch.object(sys, "argv", ["cli", "request-credentials"]):
            cli.main()

        mock_client._request_credentials.assert_called_once()
        mock_client._save_credentials.assert_called_once()

    @patch("src.woffu_client.cli.WoffuAPIClient")
    def test_request_credentials_failure(self, mock_client_cls):
        mock_client = mock_client_cls.return_value
        mock_client._request_credentials.side_effect = Exception("auth error")

        with patch.object(sys, "argv", ["cli", "request-credentials"]):
            cli.main()

        error_output = cast(StringIO, sys.stderr).getvalue()
        self.assertIn("❌ Error requesting new credentials", error_output)

    @patch("src.woffu_client.cli.WoffuAPIClient")
    def test_summary_report_success(self, mock_client_cls):
        mock_client = mock_client_cls.return_value
        mock_client.get_summary_report.return_value = {"dummy": "report"}

        with patch.object(sys, "argv", ["cli", "summary-report", "--from-date", "2025-01-01", "--to-date", "2025-01-10"]):
            cli.main()

        mock_client.get_summary_report.assert_called_once_with(from_date="2025-01-01", to_date="2025-01-10")
        mock_client.export_summary_to_csv.assert_called_once()

    @patch("src.woffu_client.cli.WoffuAPIClient")
    def test_summary_report_failure(self, mock_client_cls):
        mock_client = mock_client_cls.return_value
        mock_client.get_summary_report.side_effect = Exception("summary failed")

        with patch.object(sys, "argv", ["cli", "summary-report", "--from-date", "2025-01-01", "--to-date", "2025-01-10"]):
            cli.main()

        error_output = cast(StringIO, sys.stderr).getvalue()
        self.assertIn("❌ Error retrieving summary report", error_output)

    def test_unknown_command(self):
        with patch.object(sys, "argv", ["cli", "unknown-command"]):
            with self.assertRaises(SystemExit) as cm:
                cli.main()
            # ✅ Assert that argparse exits with code 2
            self.assertEqual(cm.exception.code, 2)

            # ✅ Assert the error message is present in stderr
            error_output = cast(StringIO, sys.stderr).getvalue()
            self.assertIn("invalid choice", error_output)
            self.assertIn("unknown-command", error_output)
    
    # -------------------------
    # ✅ Additional coverage tests
    # -------------------------

    @patch("src.woffu_client.cli.WoffuAPIClient")
    def test_non_interactive_flag(self, mock_client_cls):
        """Ensure --non-interactive does not crash and is accepted."""
        with patch.object(sys, "argv", ["cli", "--non-interactive", "get-status"]):
            cli.main()
        mock_client_cls.assert_called_once()

    @patch("src.woffu_client.cli.WoffuAPIClient")
    def test_log_level_argument(self, mock_client_cls):
        """Ensure --log-level is accepted and passed into WoffuAPIClient."""
        with patch.object(sys, "argv", ["cli", "--log-level", "DEBUG", "get-status"]):
            cli.main()
        mock_client_cls.assert_called_once()
        _, kwargs = mock_client_cls.call_args
        # Check that log_level is being set correctly
        self.assertEqual(kwargs.get("log_level"), "DEBUG")

    def test_summary_report_missing_argument(self):
        """Missing --to-date should trigger argparse error."""
        with patch.object(sys, "argv", ["cli", "summary-report", "--from-date", "2025-01-01"]):
            with self.assertRaises(SystemExit) as cm:
                cli.main()
            self.assertEqual(cm.exception.code, 2)

    @patch("src.woffu_client.cli.WoffuAPIClient")
    def test_download_all_documents_default_output_dir(self, mock_client_cls):
        """Ensure default output dir is used when not specified."""
        mock_client = mock_client_cls.return_value
        with patch.object(sys, "argv", ["cli", "download-all-documents"]):
            cli.main()
        mock_client.download_all_documents.assert_called_once()
        # ✅ Just assert that a Path was passed (not necessarily /tmp/fake)
        called_kwargs = mock_client.download_all_documents.call_args.kwargs
        self.assertIn("output_dir", called_kwargs)
        self.assertIsInstance(called_kwargs["output_dir"], Path)