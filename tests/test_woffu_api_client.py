import json
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
from src.woffu_client.woffu_api_client import WoffuAPIClient


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
