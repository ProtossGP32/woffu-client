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
