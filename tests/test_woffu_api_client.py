import json
import shutil
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import timedelta
from src.woffu_client.woffu_api_client import WoffuAPIClient
import os
from typing import Optional, Dict
from io import StringIO
import pytest

class BaseWoffuAPITest(unittest.TestCase):
    """Base class for tests that need temporary credentials and a WoffuAPIClient."""

    def setUp(self):
        """Create a temporary credentials file and initialize client."""
        self.tmp_dir = Path(tempfile.mkdtemp())
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
        """Clean up temporary files after each test."""
        if self.tmp_dir.exists():
            shutil.rmtree(self.tmp_dir)

class TestWoffuAPIClient(BaseWoffuAPITest):

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
class TestWoffuAPINetwork(BaseWoffuAPITest):

    @patch.object(WoffuAPIClient, "get")
    def test_get_request_is_sent_with_correct_headers(self, mock_get):
        """Test that GET requests can be called (headers applied internally)."""
        mock_response = MagicMock(status=200)
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
class TestWoffuAPIDownload(BaseWoffuAPITest):

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
            mock_response = MagicMock(status=200)
            mock_response.content = b"PDF_DATA"
            mock_get.return_value = mock_response

            self.client.download_document(fake_document, str(output_dir))

        file_path = output_dir / "testdoc.pdf"
        self.assertTrue(file_path.exists())
        self.assertEqual(file_path.read_bytes(), b"PDF_DATA")

    @patch.object(WoffuAPIClient, "get")
    def test_download_document_creates_directory_if_missing(self, mock_get):
        fake_document = {"Name": "file.pdf", "DocumentId": "ID"}
        output_dir = self.tmp_dir / "new_downloads"
        mock_response = MagicMock(status=200)
        mock_response.content = b"DATA"
        mock_get.return_value = mock_response
        if output_dir.exists():
            shutil.rmtree(output_dir)
        self.client.download_document(fake_document, str(output_dir))
        file_path = output_dir / "file.pdf"
        self.assertTrue(file_path.exists())
        self.assertEqual(file_path.read_bytes(), b"DATA")

    @patch.object(WoffuAPIClient, "get")
    def test_download_document_raises_exception_skips_file(self, mock_get):
        fake_document = {"Name": "fail.pdf", "DocumentId": "ID"}
        output_dir = self.tmp_dir / "downloads"
        output_dir.mkdir(exist_ok=True)
        mock_get.side_effect = Exception("Network error")
        self.client.download_document(fake_document, str(output_dir))
        self.assertFalse((output_dir / "fail.pdf").exists())

    @patch.object(WoffuAPIClient, "get")
    @patch("src.woffu_client.woffu_api_client.logger")
    def test_download_document_http_exception_skips_file(self, mock_logger, mock_get):
        """download_document skips writing file on GET exception"""
        output_dir = self.tmp_dir / "downloads"
        output_dir.mkdir(exist_ok=True)
        fake_document = {"Name": "fail.pdf", "DocumentId": "DOC_ID"}
        mock_get.side_effect = Exception("GET failed")
        self.client.download_document(fake_document, str(output_dir))
        self.assertFalse((output_dir / "fail.pdf").exists())
        mock_logger.error.assert_called_once()

    @patch.object(WoffuAPIClient, "download_document")
    @patch.object(WoffuAPIClient, "get_documents")
    def test_download_all_documents_mixed_failures(self, mock_get_docs, mock_download):
        """download_all_documents continues if some documents fail"""
        docs = [{"Name": "a.pdf", "DocumentId": "1"}, {"Name": "b.pdf", "DocumentId": "2"}]
        mock_get_docs.return_value = docs

        def fail_on_second(*args, **kwargs):
            doc: Optional[Dict] = kwargs.get("document") or (args[0] if args else None)
            if doc is not None and doc["Name"] == "b.pdf":
                raise Exception("Download failed")

        mock_download.side_effect = fail_on_second
        self.client.download_all_documents()
        self.assertEqual(mock_download.call_count, 2)

    # --------------------------
    # Possible duplicated tests?
    # --------------------------
    @patch.object(WoffuAPIClient, "get")
    @patch("src.woffu_client.woffu_api_client.logger")
    def test_download_document_http_fail_does_not_write_file(self, mock_logger, mock_get):
        """download_document does not write file if HTTP status != 200"""
        output_dir = self.tmp_dir / "downloads"
        output_dir.mkdir(exist_ok=True)
        fake_document = {"Name": "fail.pdf", "DocumentId": "DOC_ID"}
        mock_response = MagicMock(status=404)
        mock_get.return_value = mock_response

        self.client.download_document(fake_document, str(output_dir))
        self.assertFalse((output_dir / "fail.pdf").exists())

        # ✅ Verify log recorded HTTP failure
        mock_logger.error.assert_called_once()
        args, kwargs = mock_logger.error.call_args
        self.assertIn(f"Failed to download '{fake_document['Name']}'", args[0])

    @patch.object(WoffuAPIClient, "get_documents")
    @patch.object(WoffuAPIClient, "download_document")
    def test_download_all_documents_no_documents(self, mock_download, mock_get_docs):
        """download_all_documents with empty list calls download_document 0 times"""
        mock_get_docs.return_value = []
        self.client.download_all_documents()
        mock_download.assert_not_called()

    @patch.object(WoffuAPIClient, "get_documents")
    @patch.object(WoffuAPIClient, "download_document")
    def test_download_all_documents_partial_failures(self, mock_download, mock_get_docs):
        """download_all_documents continues even if some downloads fail"""
        mock_get_docs.return_value = [
            {"Name": "a.pdf", "DocumentId": "1"},
            {"Name": "b.pdf", "DocumentId": "2"}
        ]

        def fail_on_second(*args, **kwargs):
            doc: Optional[Dict] = kwargs.get("document") or (args[0] if args else None)
            if doc is not None and doc["Name"] == "b.pdf":
                raise Exception("Download failed")

        mock_download.side_effect = fail_on_second

        # Ensure partial failures don't stop the loop
        self.client.download_all_documents()
        self.assertEqual(mock_download.call_count, 2)
    
    @patch.object(WoffuAPIClient, "get")
    def test_get_documents_returns_empty_list(self, mock_get):
        mock_get.return_value.status = 200
        mock_get.return_value.json.return_value = {}
        docs = self.client.get_documents()
        self.assertEqual(docs, [])

    @patch.object(WoffuAPIClient, "get")
    def test_get_documents_returns_docs_list(self, mock_get):
        mock_get.return_value.status = 200
        mock_get.return_value.json.return_value = {
            "Documents": [{"Name": "doc1.pdf"}], "TotalRecords": 1
        }
        docs = self.client.get_documents()
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]["Name"], "doc1.pdf")

    # ------------------------
    # Diary & Hour Types
    # ------------------------
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

    @patch.object(WoffuAPIClient, "_get_diary_hour_types")
    def test_get_diary_hour_types_summary_aggregates_multiple_types(self, mock_get):
        mock_get.return_value = [{"name": "TypeA", "hours": 1}, {"name": "TypeA", "hours": 2}]
        summary = self.client.get_diary_hour_types_summary("2025-09-12", "2025-09-12")
        self.assertEqual(summary["2025-09-12"]["TypeA"], 3)

    @patch.object(WoffuAPIClient, "get")
    def test_get_diary_hour_types_unexpected_type_returns_empty(self, mock_get):
        for bad_response in [None, "unexpected", ["not", "a", "dict"]]:
            mock_get.return_value.status = 200
            mock_get.return_value.json.return_value = bad_response
            result = self.client._get_diary_hour_types("2025-09-12")
            self.assertEqual(result, {})

    # --------------------------
    # Possible duplicated tests?
    # --------------------------
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

# -------------------------------
# Authentication & Credential
# -------------------------------
class TestWoffuAPIAuth(BaseWoffuAPITest):

    @patch.object(WoffuAPIClient, "post")
    def test_retrieve_access_token_no_credentials_sets_empty_token(self, mock_post):
        """_retrieve_access_token returns early if username/password missing"""
        self.client._token = "OLD"
        self.client._retrieve_access_token(username="", password="")
        self.assertEqual(self.client._token, "OLD")

    @patch.object(WoffuAPIClient, "post")
    @patch("src.woffu_client.woffu_api_client.logger")
    def test_retrieve_access_token_invalid_credentials_sets_empty_token(self, mock_logger, mock_post):
        """_retrieve_access_token sets empty token if HTTP status != 200"""
        mock_response = MagicMock(status=401, json=lambda: {})
        mock_post.return_value = mock_response

        self.client._retrieve_access_token(username="u", password="p")
        self.assertEqual(self.client._token, "")

        # ✅ Verify log recorded HTTP failure
        mock_logger.error.assert_called_once()
        args, kwargs = mock_logger.error.call_args
        self.assertIn("Failed to retrieve access token", args[0])

    @patch.object(WoffuAPIClient, "post")
    def test_retrieve_access_token_success_sets_token(self, mock_post):
        """_retrieve_access_token should store token when JSON is valid."""
        mock_response = MagicMock(status=200)
        mock_response.json.return_value = {"access_token": "NEW_TOKEN"}
        mock_post.return_value = mock_response

        self.client._token = "OLD"
        self.client._retrieve_access_token(username="u", password="p")

        self.assertEqual(self.client._token, "NEW_TOKEN")

    @patch.object(WoffuAPIClient, "post")
    @patch("src.woffu_client.woffu_api_client.logger")
    def test_retrieve_access_token_invalid_json_returns_empty_token(self, mock_logger, mock_post):
        """_retrieve_access_token should handle invalid JSON response gracefully and set empty token."""
        mock_response = MagicMock(status=200)
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_post.return_value = mock_response

        old_token = self.client._token
        self.client._retrieve_access_token(username="u", password="p")

        # Token must be reset to empty string
        self.assertEqual(self.client._token, "")

        # ✅ Assert logging happened
        mock_logger.error.assert_called_once()
        args, kwargs = mock_logger.error.call_args
        self.assertIn("Invalid JSON", args[0])

    @patch.object(WoffuAPIClient, "post")
    @patch("src.woffu_client.woffu_api_client.logger")
    def test_retrieve_access_token_http_error_non_200(self, mock_logger, mock_post):
        """_retrieve_access_token logs and leaves token empty if status != 200"""
        mock_response = MagicMock(status=403, json=lambda: {})
        mock_post.return_value = mock_response
        self.client._token = "OLD"
        self.client._retrieve_access_token(username="u", password="p")
        self.assertEqual(self.client._token, "")
        mock_logger.error.assert_called_once()

    @patch.object(WoffuAPIClient, "post")
    @patch("src.woffu_client.woffu_api_client.logger")
    def test_retrieve_access_token_raises_exception_resets_token(self, mock_logger, mock_post):
        """_retrieve_access_token handles exceptions gracefully and clears token"""
        mock_post.side_effect = Exception("Network down")
        self.client._token = "OLD"
        self.client._retrieve_access_token(username="u", password="p")
        self.assertEqual(self.client._token, "")
        mock_logger.error.assert_called_once()

    # --------------------------
    # Possible duplicated tests?
    # --------------------------
    @patch.object(WoffuAPIClient, "post")
    def test_retrieve_access_token_missing_credentials_logs_error(self, mock_post):
        """If username/password missing, no POST request should be sent and token remains unchanged."""
        old_token = self.client._token
        self.client._retrieve_access_token(username="", password="")
        mock_post.assert_not_called()
        self.assertEqual(self.client._token, old_token)

# -------------------------------
# Request credentials (interactive/non-interactive)
# -------------------------------
class TestWoffuAPIRequestCredentials(BaseWoffuAPITest):

    @patch("src.woffu_client.woffu_api_client.logger")
    def test_request_credentials_non_interactive_logs_error_and_exits(self, mock_logger):
        """_request_credentials logs error before exiting when non-interactive and no env vars"""
        self.client._interactive = False
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SystemExit):
                self.client._request_credentials()

        # ✅ Verify log recorded HTTP failure
        mock_logger.error.assert_called_once()
        args, kwargs = mock_logger.error.call_args
        self.assertIn("Can't request token in non-interactive method without username and password. Please provide them in WOFFU_USERNAME and WOFFU_PASSWORD.", args[0])

    @patch("builtins.input", return_value="testuser")
    @patch("src.woffu_client.woffu_api_client.getpass", return_value="testpass")
    @patch.object(WoffuAPIClient, "_retrieve_access_token")
    @patch.object(WoffuAPIClient, "_save_credentials")  # avoid writing file
    @patch.object(WoffuAPIClient, "get")  # mock HTTP GET requests
    def test_request_credentials_interactive_reads_input(self, mock_get, mock_save, mock_token, mock_getpass, mock_input):
        # Setup mock return values for HTTP GET requests
        # First call: users
        users_mock = {"UserId": "123", "CompanyId": "456"}
        company_mock = {"Domain": "example.com"}
        mock_get.side_effect = [
            MagicMock(json=lambda: users_mock),
            MagicMock(json=lambda: company_mock)
        ]

        tmp_config = Path("/tmp/woffu_auth.json")  # dummy path, won't exist

        client = WoffuAPIClient(config=str(tmp_config), interactive=True)

        # Assert _retrieve_access_token was called with the patched input values
        mock_token.assert_called_once_with(username="testuser", password="testpass")
        # Ensure the headers were composed
        self.assertIsInstance(client.headers, dict)

    def test_request_credentials_non_interactive_no_env_exits(self):
        """_request_credentials exits when non-interactive and no env vars"""
        self.client._interactive = False
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SystemExit):
                self.client._request_credentials()

# -------------------------------
# Load credentials handling
# -------------------------------
class TestWoffuAPICredentialsFile(BaseWoffuAPITest):

    def test_load_credentials_external_file(self):
        # Prepare a temporal file with the expected credentials info
        creds_json = {
            "username": "external_user",
            "token": "external_token",
            "user_id": 12345,
            "company_id": 23553,
            "domain": "external.woffu.com"
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            creds_path = Path(tmpdir) / "creds.json"
            creds_path.write_text(json.dumps(creds_json))

            self.client._load_credentials(str(creds_path))

            self.assertEqual(self.client._username, "external_user")
            self.assertEqual(self.client._token, "external_token")
            self.assertEqual(self.client._user_id, 12345)
            self.assertEqual(self.client._company_id, 23553)
            self.assertEqual(self.client._domain, "external.woffu.com")

    def test_load_credentials_missing_file_requests_and_saves(self):
        """_load_credentials triggers _request_credentials and _save_credentials if config missing"""
        self.client._interactive = True  # prevent sys.exit
        self.client._config_file = Path("non_existing.json")
        with patch.object(self.client, "_request_credentials") as mock_req, \
            patch.object(self.client, "_save_credentials") as mock_save:
            self.client._load_credentials()
            mock_req.assert_called_once()
            mock_save.assert_called_once()

    @patch.object(WoffuAPIClient, "_request_credentials")
    @patch.object(WoffuAPIClient, "_save_credentials")
    @patch("src.woffu_client.woffu_api_client.logger")
    def test_load_credentials_missing_file_logs_and_requests(self, mock_logger, mock_save, mock_req):
        """_load_credentials logs a warning, requests credentials and saves them if config is missing"""
        self.client._config_file = Path("non_existing.json")
        self.client._load_credentials()

        mock_req.assert_called_once()
        mock_save.assert_called_once()
        # ✅ Verify log recorded HTTP failure
        mock_logger.warning.assert_called_once()
        args, kwargs = mock_logger.warning.call_args
        self.assertIn(f"Config file '{self.client._config_file}' doesn't exist! Requesting authentication token...", args[0])

    @patch("pathlib.Path.open", side_effect=OSError("Can't read file"))
    def test_load_credentials_file_unreadable_raises(self, mock_open):
        """_load_credentials handles unreadable config file gracefully"""
        self.client._interactive = True  # avoid sys.exit()
        self.client._config_file = Path("/nonexistent/config.json")
        
        with self.assertRaises(OSError):
            self.client._load_credentials()

    def test_load_credentials_non_interactive_no_env_exits(self):
        """_load_credentials exits if non-interactive and no env vars"""
        self.client._interactive = False
        self.client._config_file = Path("non_existing.json")
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SystemExit):
                self.client._load_credentials()

    @patch.object(WoffuAPIClient, "_retrieve_access_token")
    @patch.object(WoffuAPIClient, "_get_domain_user_companyId")
    @patch.object(WoffuAPIClient, "_save_credentials")
    def test_load_credentials_non_interactive_with_env_sets_credentials(
        self, mock_save, mock_domain, mock_token
    ):
        """_load_credentials uses WOFFU_USERNAME/WOFFU_PASSWORD if present in env"""
        with patch.dict(os.environ, {"WOFFU_USERNAME": "env_user", "WOFFU_PASSWORD": "env_pass"}):
            mock_domain.return_value = None
            mock_save.return_value = None
            
            self.client._config_file = Path("non_existing.json")
            self.client._load_credentials()

            mock_token.assert_called_once_with(username="env_user", password="env_pass")
            mock_domain.assert_called_once()
            mock_save.assert_called_once()
            self.assertEqual(self.client._username, "env_user")

    @patch("src.woffu_client.woffu_api_client.logger")
    def test_save_credentials(self, mock_logger):
        self.client._save_credentials()

        # ✅ Verify log recorded HTTP failure
        mock_logger.info.assert_called_once()
        args, kwargs = mock_logger.info.call_args
        self.assertIn(f"✅ Credentials stored in: {self.client._config_file}", args[0])

    @patch("pathlib.Path.open", side_effect=OSError("Cannot write file"))
    def test_save_credentials_other_oserror(self, mock_open):
        """_save_credentials handles generic OSError"""
        with self.assertRaises(OSError):
            self.client._save_credentials()

    @patch("src.woffu_client.woffu_api_client.Path.open")
    def test_save_credentials_raises_oserror(self, mock_open):
        """_save_credentials should raise if writing to file fails"""
        mock_open.side_effect = OSError("Disk full")
        with self.assertRaises(OSError):
            self.client._save_credentials()


    # --------------------------
    # Possible duplicated tests?
    # --------------------------
    @patch("pathlib.Path.open", side_effect=PermissionError)
    def test_save_credentials_permission_error(self, mock_open):
        """_save_credentials handles file write permission errors"""
        with self.assertRaises(PermissionError):
            self.client._save_credentials()


# -------------------------------
# Presence & Workday slots
# -------------------------------
class TestWoffuAPIPresenceWorkday(BaseWoffuAPITest):

    @patch.object(WoffuAPIClient, "get")
    @patch("src.woffu_client.woffu_api_client.logger")
    def test_get_presence_http_error_returns_empty_dict(self, mock_logger, mock_get):
        """_get_presence returns {} if HTTP status != 200"""
        mock_get.return_value.status = 500
        result = self.client._get_presence("2025-09-12", "2025-09-12")
        self.assertEqual(result, {})

        # ✅ Verify log recorded HTTP failure
        mock_logger.error.assert_called_once()
        args, kwargs = mock_logger.error.call_args
        self.assertIn("presence", args[0])

    @patch.object(WoffuAPIClient, "get")
    @patch("src.woffu_client.woffu_api_client.logger")
    def test_get_workday_slots_http_error_returns_empty_dict(self, mock_logger, mock_get):
        """_get_workday_slots returns {} if HTTP status != 200"""
        mock_get.return_value.status = 500
        result = self.client._get_workday_slots(123)
        self.assertEqual(result, {})

        # ✅ Verify log recorded HTTP failure
        mock_logger.error.assert_called_once()
        args, kwargs = mock_logger.error.call_args
        self.assertIn("workday slots", args[0])
    
# -------------------------------
# Summary & diary computations
# -------------------------------
class TestWoffuAPISummaryDiary(BaseWoffuAPITest):

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

    @patch.object(WoffuAPIClient, "_get_presence")
    @patch.object(WoffuAPIClient, "_get_workday_slots")
    def test_get_summary_report_diary_with_missing_hours(self, mock_slots, mock_presence):
        """get_summary_report correctly handles diaryHourTypes with missing 'hours' key"""
        diary = {"date": "2025-09-12", "diarySummaryId": 1, "diaryHourTypes": [{"name": "A"}]}
        mock_presence.return_value = [diary]
        mock_slots.return_value = []

        result = self.client.get_summary_report("2025-09-12", "2025-09-12")
        self.assertAlmostEqual(result["2025-09-12"]["work_hours"], 0)

    @patch.object(WoffuAPIClient, "_get_presence")
    @patch.object(WoffuAPIClient, "_get_workday_slots")
    def test_get_summary_report_invalid_slot_times(self, mock_slots, mock_presence):
        """get_summary_report skips diary slots with invalid in/out"""
        diary = {"date": "2025-09-12", "diarySummaryId": 1, "diaryHourTypes": []}
        mock_presence.return_value = [diary]
        mock_slots.return_value = [{"in": {"trueDate": "INVALID", "utcTime": "INVALID"},
                                    "out": {"trueDate": "INVALID", "utcTime": "INVALID"}}]
        result = self.client.get_summary_report("2025-09-12", "2025-09-12")
        self.assertAlmostEqual(result["2025-09-12"]["work_hours"], 0)

    @patch.object(WoffuAPIClient, "_get_presence")
    @patch.object(WoffuAPIClient, "_get_workday_slots")
    def test_get_summary_report_missing_hours_key(self, mock_slots, mock_presence):
        """get_summary_report handles diaryHourTypes missing 'hours' key"""
        diary = {"date": "2025-09-12", "diarySummaryId": 1, "diaryHourTypes": [{"name": "A"}]}
        mock_presence.return_value = [diary]
        mock_slots.return_value = []
        result = self.client.get_summary_report("2025-09-12", "2025-09-12")
        self.assertAlmostEqual(result["2025-09-12"]["work_hours"], 0)

    # --------------------------
    # Possible duplicated tests?
    # --------------------------
    @patch.object(WoffuAPIClient, "_get_presence")
    @patch.object(WoffuAPIClient, "_get_workday_slots")
    def test_get_summary_report_invalid_slot_times_skipped(self, mock_slots, mock_presence):
        """get_summary_report skips slots with invalid in/out times"""
        diary = {"date": "2025-09-12", "diarySummaryId": 1, "diaryHourTypes": []}
        mock_presence.return_value = [diary]
        mock_slots.return_value = [
            {"in": {"trueDate": "INVALID", "utcTime": "INVALID"},
            "out": {"trueDate": "INVALID", "utcTime": "INVALID"}}
        ]

        result = self.client.get_summary_report("2025-09-12", "2025-09-12")
        # Work hours should be 0 because in/out parsing failed
        self.assertAlmostEqual(result["2025-09-12"]["work_hours"], 0)

# -------------
# Status & Sign
# -------------
class TestWoffuAPIStatusSign(BaseWoffuAPITest):

    # TODO: tests for `WoffuAPIClient._get_sign_requests`
    @patch.object(WoffuAPIClient, "get")
    def test_get_sign_requests(self, mock_get):
        """Test that get_sign_requests calls the correct URL with the right date parameter."""
        fake_response = {"Holidays": [{"date": "09/12/2025", "type": "Holiday"}]}
        mock_get.return_value = fake_response

        # Create a mock response object
        mock_response = MagicMock(status=200)
        mock_response.json.return_value = fake_response
        mock_get.return_value = mock_response

        test_date = "09/12/2025"
        result = self.client.get_sign_requests(test_date)

        # Assert get was called once with the proper URL and params
        mock_get.assert_called_once_with(
            url=f"https://{self.client._domain}/api/svc/core/diary/user/requests",
            params={"date": test_date}
        )

        # Assert the method returns the mocked response
        self.assertEqual(result, fake_response)

    @patch.object(WoffuAPIClient, "get")
    def test_get_sign_requests_invalid_response(self, mock_get):
        """Test that get_sign_requests calls the correct URL with the right date parameter."""
        fake_response = "This isn't neither a dict nor a list"
        mock_get.return_value = fake_response

        # Create a mock response object
        mock_response = MagicMock(status=200)
        mock_response.json.return_value = fake_response
        mock_get.return_value = mock_response

        test_date = "09/12/2025"
        result = self.client.get_sign_requests(test_date)

        # Assert get was called once with the proper URL and params
        mock_get.assert_called_once_with(
            url=f"https://{self.client._domain}/api/svc/core/diary/user/requests",
            params={"date": test_date}
        )

        # Assert the method returns the mocked response
        self.assertEqual(result, {})

    @patch.object(WoffuAPIClient, "get")
    @patch("src.woffu_client.woffu_api_client.logger")
    def test_get_sign_requests_bad_status(self, mock_logger, mock_get):
        """Test that get_sign_requests calls the correct URL with the right date parameter."""
        fake_response = {"Holidays": [{"date": "09/12/2025", "type": "Holiday"}]}
        mock_get.return_value = fake_response

        # Create a mock response object
        mock_response = MagicMock(status=500)
        mock_get.return_value = mock_response

        test_date = "09/12/2025"
        result = self.client.get_sign_requests(test_date)

        # Assert get was called once with the proper URL and params
        mock_get.assert_called_once_with(
            url=f"https://{self.client._domain}/api/svc/core/diary/user/requests",
            params={"date": test_date}
        )

        # Assert the method returns the mocked response
        self.assertEqual(result, {})

         # Logger should be called with the failure message
        mock_logger.error.assert_called_once()
        log_args, _ = mock_logger.error.call_args
        self.assertIn(f"Can't retrieve sign motives for date {test_date}!", log_args[0])

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
    @patch.object(WoffuAPIClient, "post")
    def test_sign_post_fails_raises_exception(self, mock_post, mock_get):
        mock_get.return_value.status = 200
        mock_get.return_value.json.return_value = [{"SignIn": False, "TrueDate": "2025-09-12T12:00:00.000", "UtcTime": "12:00:00 +01"}]
        mock_post.side_effect = Exception("POST failed")
        with self.assertRaises(Exception):
            self.client.sign(type="in")

    @patch.object(WoffuAPIClient, "get_status", return_value=(timedelta(0), True))
    @patch.object(WoffuAPIClient, "post")
    def test_sign_user_already_signed_returns_none(self, mock_post, mock_status):
        result = self.client.sign(type="in")
        self.assertIsNone(result)
        mock_post.assert_not_called()
    
    @patch.object(WoffuAPIClient, "get")
    def test_get_status_multiple_invalid_utc_formats(self, mock_get):
        """get_status handles multiple invalid UtcTime formats"""
        mock_get.return_value.status = 200
        mock_get.return_value.json.return_value = [
            {"SignIn": True, "TrueDate": "2025-09-12T12:00:00.000", "UtcTime": "BAD1"},
            {"SignIn": False, "TrueDate": "2025-09-12T16:00:00.000", "UtcTime": "BAD2"},
        ]

        total, running = self.client.get_status()
        self.assertIsInstance(total, object)
        self.assertFalse(running)

    @patch.object(WoffuAPIClient, "get")
    def test_get_status_only_running_clock_last_sign_false(self, mock_get):
        mock_get.return_value.status = 200
        mock_get.return_value.json.return_value = [
            {"SignIn": True, "TrueDate":"2025-09-12T12:00:00.000", "UtcTime":"12:00:00 +01"},
            {"SignIn": False, "TrueDate":"2025-09-12T16:00:00.000", "UtcTime":"16:00:00 +01"}
        ]
        _, running = self.client.get_status(only_running_clock=True)
        self.assertFalse(running)
    
    @patch.object(WoffuAPIClient, "get")
    def test_get_status_invalid_utc_fallback_local(self, mock_get):
        mock_get.return_value.status = 200
        mock_get.return_value.json.return_value = [{"SignIn": True, "TrueDate":"2025-09-12T12:00:00.000", "UtcTime":"INVALID"}]
        total, running = self.client.get_status()
        self.assertTrue(running)
        self.assertIsInstance(total, timedelta)

    @patch.object(WoffuAPIClient, "get")
    def test_get_status_invalid_utc_formats_mixed(self, mock_get):
        """get_status handles multiple invalid UtcTime formats and computes running correctly"""
        mock_get.return_value.status = 200
        mock_get.return_value.json.return_value = [
            {"SignIn": True, "TrueDate": "2025-09-12T12:00:00.000", "UtcTime": "BAD1"},
            {"SignIn": False, "TrueDate": "2025-09-12T16:00:00.000", "UtcTime": "BAD2"},
        ]
        total, running = self.client.get_status()
        self.assertIsInstance(total, timedelta)
        self.assertFalse(running)


class TestWoffuAPICSVExport(BaseWoffuAPITest):

    @patch("src.woffu_client.woffu_api_client.logger")
    @patch.object(Path, "mkdir")
    @patch("builtins.open", create=True)
    def test_export_summary_to_csv(self, mock_open, mock_mkdir, mock_logger):
        test_cases = [
            (
                {
                    "2025-01-01": {"Extr. a compensar": 0.5, "work_hours": 8.5},
                    "2025-01-02": {"work_hours": 7.5},
                },
                "", # from_date
                "", # to_date
                ",", # delimiter
                ["2025-01-01", "2025-01-02"],
            ),
            (
                {
                    "2025-01-01": {"Extr. a compensar": 1.5, "work_hours": 9.0},
                    "2025-01-05": {"work_hours": 6.5},
                },
                "2025-01-01",
                "2025-01-05",
                ";", # delimiter
                ["2025-01-01", "2025-01-05"],
            ),
            (
                {},
                "",
                "",
                ",", # delimiter
                [],
            ),
        ]

        for summary_report, from_date, to_date, delimiter, expected_rows in test_cases:
            fake_csv_buffer = StringIO()
            mock_open.return_value.__enter__.return_value = fake_csv_buffer
            fake_path = Path("/fake/path")

            self.client.export_summary_to_csv(
                summary_report, from_date, to_date, output_path=fake_path, delimiter=delimiter
            )

            mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)

            fake_csv_buffer.seek(0)
            csv_content = fake_csv_buffer.read()

            if expected_rows:
                for header in ["Extr. a compensar", "work_hours", "date"]:
                    self.assertIn(header, csv_content)
                for row in expected_rows:
                    self.assertIn(row, csv_content)
                # Check delimiter
                self.assertIn(delimiter, csv_content)
            else:
                self.assertTrue(csv_content.strip() == "" or csv_content.startswith(""))

            mock_logger.info.assert_called_once()
            log_msg = mock_logger.info.call_args[0][0]
            self.assertIn("✅ CSV exported to", log_msg)
            self.assertIn(str(fake_path), log_msg)

            # Reset mocks for next iteration
            mock_open.reset_mock()
            mock_mkdir.reset_mock()
            mock_logger.reset_mock()

    @patch("src.woffu_client.woffu_api_client.logger")
    @patch.object(Path, "mkdir")
    @patch("builtins.open", create=True)
    def test_export_summary_to_csv_custom_delimiter(self, mock_open, mock_mkdir, mock_logger):
        """Specifically test exporting CSV using a custom delimiter (';')."""
        summary_report = {
            "2025-01-01": {"Extr. a compensar": 0.5, "work_hours": 8.5}
        }
        fake_csv_buffer = StringIO()
        mock_open.return_value.__enter__.return_value = fake_csv_buffer
        fake_path = Path("/fake/path")

        self.client.export_summary_to_csv(
            summary_report, output_path=fake_path, delimiter=";"
        )

        fake_csv_buffer.seek(0)
        csv_content = fake_csv_buffer.read()
        self.assertIn(";", csv_content)
        self.assertIn("2025-01-01", csv_content)
        self.assertIn("Extr. a compensar", csv_content)
        self.assertIn("work_hours", csv_content)
        mock_logger.info.assert_called_once()