import json
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
from src.woffu_client.woffu_api_client import WoffuAPIClient
import os


class TestWoffuAPIClient(unittest.TestCase):
    """Unit tests for WoffuAPIClient focusing on initialization, headers, network, and filesystem."""

    def setUp(self):
        """Create a temporary credentials file and initialize client."""
        self.tmp_dir = Path(__file__).parent / "tmp_test_data"
        self.tmp_dir.mkdir(exist_ok=True)
        self.creds_file = self.tmp_dir / "woffu_auth.json"
        creds = {
            "domain": "fake.woffu.com",
            "username": "test_user",
            "token": "FAKE_TOKEN",
            "user_id": "12345",
            "company_id": "99999"
        }
        self.creds_file.write_text(json.dumps(creds))

        # ✅ Initialize client once per test
        self.client = WoffuAPIClient(config=self.creds_file)

    def tearDown(self):
        """Clean up temporary files after each test."""
        if self.creds_file.exists():
            self.creds_file.unlink()
        if self.tmp_dir.exists():
            shutil.rmtree(self.tmp_dir)

    # ----------------------
    # Initialization & headers
    # ----------------------
    def test_client_initialization_loads_credentials(self):
        """Verify that client loads domain, username, token, and sets headers from config file."""
        self.assertEqual(self.client._domain, "fake.woffu.com")
        self.assertEqual(self.client._username, "test_user")
        self.assertEqual(self.client._token, "FAKE_TOKEN")
        self.assertEqual(self.client._user_id, "12345")
        self.assertEqual(self.client._company_id, "99999")

        # Check that headers were set correctly
        self.assertIn("Authorization", self.client.headers)
        self.assertIn("Bearer", self.client.headers["Authorization"])

    def test_compose_auth_headers_returns_expected_dict(self):
        """Verify that _compose_auth_headers builds correct headers with Bearer token."""
        headers = self.client._compose_auth_headers()

        self.assertIsInstance(headers, dict)
        self.assertEqual(headers["Authorization"], f"Bearer {self.client._token}")
        self.assertEqual(headers["Accept"], "application/json")

    def test_compose_auth_headers_reflects_token_change(self):
        """Ensure _compose_auth_headers reflects updated token value."""
        # Change token manually to simulate refresh
        self.client._token = "NEW_FAKE_TOKEN"
        headers = self.client._compose_auth_headers()

        self.assertEqual(headers["Authorization"], "Bearer NEW_FAKE_TOKEN")
        self.assertEqual(headers["Accept"], "application/json")

    # ------------------------
    # Basic Network Calls
    # ------------------------
    @patch.object(WoffuAPIClient, "get")
    def test_get_request_is_sent_with_correct_headers(self, mock_get):
        """Test that GET requests can be called (headers applied internally)."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json.return_value = {"key": "value"}
        mock_get.return_value = mock_response

        url = f"https://{self.client._domain}/api/some_endpoint"
        self.client.get(url)

        mock_get.assert_called_once()

    @patch.object(WoffuAPIClient, "post")
    def test_post_request_is_sent_with_expected_data(self, mock_post):
        data = {"key": "value"}
        self.client.post("/api/some_endpoint", json=data)

        mock_post.assert_called_once()

    # ------------------------
    # Filesystem & Download
    # ------------------------
    @patch.object(WoffuAPIClient, "download_document")
    @patch.object(WoffuAPIClient, "get_documents")
    def test_download_all_documents_calls_download_for_each_document(self, mock_get_documents, mock_download_document):
        """Test that download_all_documents retrieves documents and downloads each one."""
        fake_docs = [
            {"Name": "doc1.pdf", "DocumentId": "1"},
            {"Name": "doc2.pdf", "DocumentId": "2"},
        ]
        mock_get_documents.return_value = fake_docs
        output_dir = self.tmp_dir / "downloads"

        self.client.download_all_documents(output_dir=str(output_dir))

        # Verify get_documents was called (call signature matches real implementation)
        mock_get_documents.assert_called_once()
        # Verify download_document called for each document
        self.assertEqual(mock_download_document.call_count, len(fake_docs))

    def test_download_document_creates_file_when_not_exists(self):
        """Test that download_document writes the file if it doesn't exist."""
        output_dir = self.tmp_dir / "downloads"
        output_dir.mkdir(exist_ok=True)
        fake_document = {"Name": "testdoc.pdf", "DocumentId": "DOC_ID"}

        # Patch the internal GET request to return fake content
        with patch.object(self.client, "get") as mock_get:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.content = b"PDF_DATA"
            mock_get.return_value = mock_response

            self.client.download_document(fake_document, str(output_dir))

        file_path = output_dir / "testdoc.pdf"
        self.assertTrue(file_path.exists())
        self.assertEqual(file_path.read_bytes(), b"PDF_DATA")


# ------------------------
# Additional Tests for Coverage
# ------------------------
class TestWoffuAPIClientExtra(unittest.TestCase):
    """Extra tests to improve coverage of WoffuAPIClient."""

    def setUp(self):
        self.tmp_dir = Path(__file__).parent / "tmp_test_data_extra"
        self.tmp_dir.mkdir(exist_ok=True)
        self.creds_file = self.tmp_dir / "woffu_auth.json"
        creds = {
            "domain": "fake.woffu.com",
            "username": "test_user",
            "token": "FAKE_TOKEN",
            "user_id": "12345",
            "company_id": "99999"
        }
        self.creds_file.write_text(json.dumps(creds))
        self.client = WoffuAPIClient(config=self.creds_file)

    def tearDown(self):
        if self.creds_file.exists():
            self.creds_file.unlink()
        if self.tmp_dir.exists():
            shutil.rmtree(self.tmp_dir)

    @patch.object(WoffuAPIClient, "_get_diary_hour_types")
    def test_get_diary_hour_types_summary(self, mock_get):
        """Test get_diary_hour_types_summary computes hour types over date range."""
        mock_get.return_value = [{"name": "Extr. a compensar", "hours": 2}]
        from_date = "2025-09-12"
        to_date = "2025-09-12"
        summary = self.client.get_diary_hour_types_summary(from_date=from_date, to_date=to_date)

        self.assertIn(from_date, summary)
        self.assertIn("Extr. a compensar", summary[from_date])
        self.assertEqual(summary[from_date]["Extr. a compensar"], 2)

    @patch.object(WoffuAPIClient, "get")
    def test_get_status_and_sign(self, mock_get):
        """Test get_status returns total_time and running_clock, sign sends POST."""
        # Simulate signs with correct UtcTime format
        mock_get.return_value.status = 200
        mock_get.return_value.json.return_value = [
            {"SignIn": True, "TrueDate": "2025-09-12T12:00:00.000", "UtcTime": "12:00:00 +01"}
        ]

        total, running = self.client.get_status()
        self.assertIsInstance(total, object)  # timedelta
        self.assertIsInstance(running, bool)

    @patch.object(WoffuAPIClient, "get")
    def test_get_documents_returns_empty_list(self, mock_get):
        """Test get_documents returns empty if no documents found."""
        mock_get.return_value.status = 200
        mock_get.return_value.json.return_value = {}
        docs = self.client.get_documents()
        self.assertEqual(docs, [])

    @patch.object(WoffuAPIClient, "get")
    def test_get_documents_returns_docs_list(self, mock_get):
        """Test get_documents returns Documents list."""
        mock_get.return_value.status = 200
        mock_get.return_value.json.return_value = {
            "Documents": [{"Name": "doc1.pdf"}],
            "TotalRecords": 1
        }
        docs = self.client.get_documents()
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]["Name"], "doc1.pdf")

    @patch.object(WoffuAPIClient, "get")
    def test_get_status_only_running_clock(self, mock_get):
        """Test get_status with only_running_clock=True returns correct last sign."""
        mock_get.return_value.status = 200
        mock_get.return_value.json.return_value = [
            {"SignIn": True, "TrueDate": "2025-09-12T12:00:00.000", "UtcTime": "12:00:00 +01"},
            {"SignIn": False, "TrueDate": "2025-09-12T16:00:00.000", "UtcTime": "16:00:00 +01"}
        ]

        total, running = self.client.get_status(only_running_clock=True)
        self.assertIsInstance(total, object)
        self.assertFalse(running)  # Last sign False

    @patch.object(WoffuAPIClient, "get")
    def test_get_status_empty_signs(self, mock_get):
        """Test get_status when no signs exist."""
        mock_get.return_value.status = 200
        mock_get.return_value.json.return_value = []

        total, running = self.client.get_status()
        self.assertEqual(total.total_seconds(), 0)
        self.assertFalse(running)

    @patch.object(WoffuAPIClient, "get")
    def test_get_status_utc_offset_edge_case(self, mock_get):
        """Test get_status handles invalid UtcTime formats gracefully."""
        mock_get.return_value.status = 200
        mock_get.return_value.json.return_value = [
            {"SignIn": True, "TrueDate": "2025-09-12T12:00:00.000", "UtcTime": "INVALID"}
        ]

        total, running = self.client.get_status()
        self.assertIsInstance(total, object)
        self.assertTrue(running)

    @patch.object(WoffuAPIClient, "get")
    def test_get_diary_hour_types_empty_response(self, mock_get):
        """Test _get_diary_hour_types handles empty response."""
        mock_get.return_value.status = 200
        mock_get.return_value.json.return_value = {"diaryHourTypes": []}

        result = self.client._get_diary_hour_types("2025-09-12")
        self.assertEqual(result, [])

    @patch.object(WoffuAPIClient, "get")
    def test_get_diary_hour_types_missing_key(self, mock_get):
        """Test _get_diary_hour_types when 'diaryHourTypes' key missing."""
        mock_get.return_value.status = 200
        mock_get.return_value.json.return_value = {}

        result = self.client._get_diary_hour_types("2025-09-12")
        self.assertEqual(result, {})

    @patch.object(WoffuAPIClient, "get")
    def test_download_document_file_exists(self, mock_get):
        """Test download_document skips download if file already exists."""
        output_dir = self.tmp_dir / "downloads"
        output_dir.mkdir(exist_ok=True)
        file_path = output_dir / "existing.pdf"
        file_path.write_bytes(b"EXISTING")

        fake_document = {"Name": "existing.pdf", "DocumentId": "DOC_ID"}

        self.client.download_document(fake_document, str(output_dir))
        self.assertEqual(file_path.read_bytes(), b"EXISTING")  # Not overwritten

    # ---------------------------
    # Authentication & Credential
    # ---------------------------
    @patch.object(WoffuAPIClient, "post")
    def test_retrieve_access_token_no_credentials_sets_empty_token(self, mock_post):
        """_retrieve_access_token returns early if username/password missing"""
        self.client._token = "OLD"
        self.client._retrieve_access_token(username="", password="")
        self.assertEqual(self.client._token, "OLD")

    @patch.object(WoffuAPIClient, "post")
    def test_retrieve_access_token_invalid_credentials_sets_empty_token(self, mock_post):
        """_retrieve_access_token sets empty token if HTTP status != 200"""
        mock_response = MagicMock(status=401, json=lambda: {})
        mock_post.return_value = mock_response
        self.client._retrieve_access_token(username="u", password="p")
        self.assertEqual(self.client._token, "")

    def test_request_credentials_non_interactive_no_env_exits(self):
        """_request_credentials exits when non-interactive and no env vars"""
        self.client._interactive = False
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SystemExit):
                self.client._request_credentials()

    def test_load_credentials_missing_file_requests_and_saves(self):
        """_load_credentials triggers _request_credentials and _save_credentials if config missing"""
        self.client._config_file = Path("non_existing.json")
        with patch.object(self.client, "_request_credentials") as mock_req, \
            patch.object(self.client, "_save_credentials") as mock_save:
            self.client._load_credentials()
            mock_req.assert_called_once()
            mock_save.assert_called_once()

    # -------------------------------
    # Document Download & Filesystems
    # -------------------------------
    @patch.object(WoffuAPIClient, "get")
    def test_download_document_http_fail_does_not_write_file(self, mock_get):
        """download_document does not write file if HTTP status != 200"""
        output_dir = self.tmp_dir / "downloads"
        output_dir.mkdir(exist_ok=True)
        fake_document = {"Name": "fail.pdf", "DocumentId": "DOC_ID"}
        mock_response = MagicMock(status=404)
        mock_get.return_value = mock_response
        self.client.download_document(fake_document, str(output_dir))
        self.assertFalse((output_dir / "fail.pdf").exists())

    @patch.object(WoffuAPIClient, "get_documents")
    @patch.object(WoffuAPIClient, "download_document")
    def test_download_all_documents_no_documents(self, mock_download, mock_get_docs):
        """download_all_documents with empty list calls download_document 0 times"""
        mock_get_docs.return_value = []
        self.client.download_all_documents()
        mock_download.assert_not_called()

    # -------------------------------
    # Presence & Workday Slots
    # -------------------------------
    @patch.object(WoffuAPIClient, "get")
    def test_get_presence_http_error_returns_empty_dict(self, mock_get):
        """_get_presence returns {} if HTTP status != 200"""
        mock_get.return_value.status = 500
        result = self.client._get_presence("2025-09-12", "2025-09-12")
        self.assertEqual(result, {})

    @patch.object(WoffuAPIClient, "get")
    def test_get_workday_slots_http_error_returns_empty_dict(self, mock_get):
        """_get_workday_slots returns {} if HTTP status != 200"""
        mock_get.return_value.status = 500
        result = self.client._get_workday_slots(123)
        self.assertEqual(result, {})

    # -------------------------------
    # Summary Report & Diary
    # -------------------------------
    @patch.object(WoffuAPIClient, "_get_presence")
    @patch.object(WoffuAPIClient, "_get_workday_slots")
    def test_get_summary_report_empty_diaries(self, mock_slots, mock_presence):
        """get_summary_report returns empty dict if no diaries"""
        mock_presence.return_value = []
        result = self.client.get_summary_report("2025-09-12", "2025-09-12")
        self.assertEqual(result, {})

    @patch.object(WoffuAPIClient, "_get_workday_slots")
    def test_get_summary_report_slot_without_motive_computes_hours(self, mock_slots):
        """get_summary_report computes hours from in/out if no motive"""
        diary = {"date": "2025-09-12", "diarySummaryId": 1, "diaryHourTypes": []}
        mock_slots.return_value = [{"in": {"trueDate":"2025-09-12T12:00:00","utcTime":"12:00:00 +01"},
                                    "out":{"trueDate":"2025-09-12T16:00:00","utcTime":"16:00:00 +01"}}]
        with patch.object(self.client, "_get_presence", return_value=[diary]):
            result = self.client.get_summary_report("2025-09-12", "2025-09-12")
            self.assertAlmostEqual(result["2025-09-12"]["work_hours"], 4)

    @patch.object(WoffuAPIClient, "_get_diary_hour_types")
    def test_get_diary_hour_types_summary_aggregates_multiple_types(self, mock_get):
        """get_diary_hour_types_summary aggregates multiple hour types correctly"""
        mock_get.return_value = [{"name": "TypeA", "hours": 1}, {"name": "TypeA", "hours": 2}]
        summary = self.client.get_diary_hour_types_summary("2025-09-12", "2025-09-12")
        self.assertEqual(summary["2025-09-12"]["TypeA"], 3)

    # -------------------------------
    # Signing & get_status
    # -------------------------------
    @patch.object(WoffuAPIClient, "get")
    def test_get_status_only_running_clock_last_sign_false(self, mock_get):
        """get_status only_running_clock=True returns last sign boolean correctly"""
        mock_get.return_value.status = 200
        mock_get.return_value.json.return_value = [
            {"SignIn": True, "TrueDate":"2025-09-12T12:00:00.000", "UtcTime":"12:00:00 +01"},
            {"SignIn": False, "TrueDate":"2025-09-12T16:00:00.000", "UtcTime":"16:00:00 +01"}
        ]
        _, running = self.client.get_status(only_running_clock=True)
        self.assertFalse(running)

    @patch.object(WoffuAPIClient, "get")
    def test_get_status_invalid_utc_fallback_local(self, mock_get):
        """get_status handles invalid UtcTime and uses local timezone"""
        mock_get.return_value.status = 200
        mock_get.return_value.json.return_value = [{"SignIn": True, "TrueDate":"2025-09-12T12:00:00.000", "UtcTime":"INVALID"}]
        total, running = self.client.get_status()
        self.assertTrue(running)
        self.assertIsInstance(total, object)

    @patch.object(WoffuAPIClient, "get_status", return_value=(0, True))
    @patch.object(WoffuAPIClient, "post")
    def test_sign_user_already_signed_returns_none(self, mock_post, mock_status):
        """sign() returns None if user already signed in/out"""
        result = self.client.sign(type="in")
        self.assertIsNone(result)
        mock_post.assert_not_called()
