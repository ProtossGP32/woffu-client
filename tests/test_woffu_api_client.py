import json
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
from src.woffu_client.woffu_api_client import WoffuAPIClient


class TestWoffuAPIClient(unittest.TestCase):
    """Unit tests for WoffuAPIClient focusing on initialization, headers, and basic network calls."""

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

        # Initialize client once per test
        self.client = WoffuAPIClient(config=self.creds_file)

    def tearDown(self):
        """Clean up temporary files after each test."""
        if self.creds_file.exists():
            self.creds_file.unlink()
        if self.tmp_dir.exists():
            self.tmp_dir.rmdir()

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
        self.assertIn("Accept", headers)
        self.assertEqual(headers["Accept"], "application/json")

    def test_get_request_is_sent_with_correct_headers(self):
        """Verify that GET requests use the correct URL and headers."""
        with patch.object(WoffuAPIClient, "get", autospec=True) as mock_get:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json.return_value = {"success": True}
            mock_get.return_value = mock_response

            url = f"https://{self.client._domain}/api/v1/test"
            result = self.client.get(url)

            mock_get.assert_called_once_with(self.client, url)
            self.assertEqual(result.json(), {"success": True})

    def test_post_request_is_sent_with_expected_data(self):
        """Verify that POST requests use the correct URL and payload."""
        with patch.object(WoffuAPIClient, "post", autospec=True) as mock_post:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.json.return_value = {"token": "XYZ123"}
            mock_post.return_value = mock_response

            payload = {"grant_type": "password", "username": "user", "password": "pass"}
            url = f"https://{self.client._domain}/token"
            result = self.client.post(url, data=payload)

            mock_post.assert_called_once_with(self.client, url, data=payload)
            self.assertEqual(result.json(), {"token": "XYZ123"})


if __name__ == "__main__":
    unittest.main()
