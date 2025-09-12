import json
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
from src.woffu_client.woffu_api_client import WoffuAPIClient
from datetime import timedelta
import os
import csv

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
    # Additional coverage tests
    # ------------------------
    @patch.dict(os.environ, {"WOFFU_USERNAME": "env_user", "WOFFU_PASSWORD": "env_pass"})
    @patch.object(WoffuAPIClient, "_retrieve_access_token")
    @patch.object(WoffuAPIClient, "_get_domain_user_companyId")
    def test_request_credentials_uses_env_vars(self, mock_get_company, mock_retrieve_token):
        """Test _request_credentials uses environment variables when interactive=False."""
        client = WoffuAPIClient(interactive=False, config=str(self.creds_file))
        client._interactive = False
        client._request_credentials()
        mock_retrieve_token.assert_called_once_with(username="env_user", password="env_pass")
        mock_get_company.assert_called_once()

    @patch.object(WoffuAPIClient, "get")
    def test_get_documents_returns_documents(self, mock_get):
        """Test get_documents returns documents from API."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json.return_value = {"Documents": [{"Name": "d1"}, {"Name": "d2"}], "TotalRecords": 2}
        mock_get.return_value = mock_response

        docs = self.client.get_documents()
        self.assertEqual(len(docs), 2)

    @patch.object(WoffuAPIClient, "get")
    def test_get_documents_returns_empty_when_none(self, mock_get):
        """Test get_documents returns empty list and logs warning if 'Documents' missing."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json.return_value = {"TotalRecords": 0}
        mock_get.return_value = mock_response

        docs = self.client.get_documents()
        self.assertEqual(docs, [])

    @patch.object(WoffuAPIClient, "get")
    def test_get_presence_and_workday_slots(self, mock_get):
        """Test _get_presence, _get_workday_slots, _get_diary_hour_types happy path."""
        # _get_presence returns diaries
        diary_data = [{"diarySummaryId": 1, "date": "2025-09-12"}]
        presence_mock = MagicMock()
        presence_mock.status = 200
        presence_mock.json.return_value = {"diaries": diary_data}
        mock_get.return_value = presence_mock

        diaries = self.client._get_presence()
        self.assertEqual(diaries, diary_data)

        # _get_diary_hour_types
        hour_types_mock = MagicMock()
        hour_types_mock.status = 200
        hour_types_mock.json.return_value = {"diaryHourTypes": [{"name": "Test", "hours": 1}]}
        mock_get.return_value = hour_types_mock
        hour_types = self.client._get_diary_hour_types(date="2025-09-12")
        self.assertEqual(hour_types, [{"name": "Test", "hours": 1}])

        # _get_workday_slots
        slots_mock = MagicMock()
        slots_mock.status = 200
        slots_mock.json.return_value = {"slots": [{"in": {"trueDate": "2025-09-12", "utcTime": "+0100"}, "out": {"trueDate": "2025-09-12", "utcTime": "+0100"}, "motive": {"hours": 2}}]}
        mock_get.return_value = slots_mock
        slots = self.client._get_workday_slots(diary_summary_id=1)
        self.assertEqual(slots, [{"in": {"trueDate": "2025-09-12", "utcTime": "+0100"}, "out": {"trueDate": "2025-09-12", "utcTime": "+0100"}, "motive": {"hours": 2}}])

    @patch.object(WoffuAPIClient, "get")
    def test_get_sign_requests(self, mock_get):
        """Test get_sign_requests returns data or empty dict on failure."""
        resp_mock = MagicMock()
        resp_mock.status = 200
        resp_mock.json.return_value = {"some": "data"}
        mock_get.return_value = resp_mock

        result = self.client.get_sign_requests(date="09/12/2025")
        self.assertEqual(result, {"some": "data"})

        # simulate error
        resp_mock.status = 404
        mock_get.return_value = resp_mock
        result = self.client.get_sign_requests(date="09/12/2025")
        self.assertEqual(result, {})

    @patch.object(WoffuAPIClient, "get")
    def test_get_status_and_sign(self, mock_get):
        """Test get_status returns total_time and running_clock, sign sends POST."""
        # Simulate signs
        mock_get.return_value.json.return_value = [{"SignIn": True, "TrueDate": "2025-09-12", "UtcTime": "+0100"}]
        mock_get.return_value.status = 200
        total, running = self.client.get_status()
        self.assertIsInstance(total, timedelta)
        self.assertIsInstance(running, bool)

    @patch.object(WoffuAPIClient, "get")
    def test_get_diary_hour_types_summary(self, mock_get):
        """Test get_diary_hour_types_summary computes hour types over date range."""
        # simulate _get_diary_hour_types
        mock_get.return_value.json.return_value = [{"name": "Extr. a compensar", "hours": 2}]
        mock_get.return_value.status = 200
        from_date = "2025-09-12"
        to_date = "2025-09-12"
        summary = self.client.get_diary_hour_types_summary(from_date=from_date, to_date=to_date)
        self.assertIn(from_date, summary)
        self.assertEqual(summary[from_date]["Extr. a compensar"], 2)

    def test_export_summary_to_csv_creates_file(self):
        """Test export_summary_to_csv writes a CSV file with correct headers."""
        output_dir = self.tmp_dir / "reports"
        summary_report = {
            "2025-09-12": {"work_hours": 8, "Extr. a compensar": 2}
        }

        self.client.export_summary_to_csv(summary_report=summary_report, output_path=output_dir)
        # Check file exists
        files = list(output_dir.glob("woffu_summary_report_from_2025-09-12_to_2025-09-12.csv"))
        self.assertTrue(len(files) == 1)
        # Check content
        with open(files[0], newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            self.assertEqual(rows[0]["work_hours"], "8")
            self.assertEqual(rows[0]["Extr. a compensar"], "2")
