"""Tests for HTTPRequest and Session classes."""
from __future__ import annotations

import asyncio
import json
import urllib.request
from http.client import HTTPMessage
from io import BytesIO
from typing import Any
from typing import cast
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Protocol
from typing import runtime_checkable
from typing import Union
from unittest import TestCase
from unittest.mock import Mock
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.error import URLError
from urllib.request import OpenerDirector
from urllib.request import Request

import pytest

from src.woffu_client.stdrequests_session import HTTPResponse
from src.woffu_client.stdrequests_session import Session


class DummyRawResponse:
    """Dummy HTTP Response class."""

    def __init__(
        self,
        status: int = 200,
        content: bytes = b"",
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Initialize the object."""
        self._status: int = status
        self._content: bytes = content
        self._pos: int = 0
        self._headers: Dict[str, str] = headers or {}

    def read(self, size: int = -1) -> bytes:
        """Read content of the HTTP response."""
        if size is None or size == -1:
            size = len(self._content) - self._pos
        data = self._content[self._pos: self._pos + size]  # noqa:E203
        self._pos += size
        return data

    def getcode(self) -> int:
        """Get HTTP status code."""
        return self._status

    def getheaders(self) -> list[tuple[str, str]]:
        """Get HTTP headers."""
        return list(self._headers.items())


class DummyOpener(OpenerDirector):
    """Dummy OpenerDirector class."""

    _response: Optional[object]
    called_with: Optional[Request]

    def __init__(self) -> None:
        """Initialize object."""
        super().__init__()
        self.called_with: Optional[urllib.request.Request] = None
        self._response = None

    def open(
        self,
        req: Request,
        data=None,
        timeout: Optional[Union[int, float]] = None,
    ) -> object:
        """Open object."""
        self.called_with = req
        if self._response is None:
            raise RuntimeError("No response set for DummyOpener")
        return self._response


class DummyHTTPError(HTTPError):
    """Dummy HTTPError class."""

    def __init__(
        self,
        url: str,
        code: int,
        msg: str,
        hdrs: Optional[HTTPMessage],
        fp: Optional[BytesIO] = None,
    ) -> None:
        """Initialize the class object."""
        if fp is None:
            fp = BytesIO(b"")
        # If hdrs is None, pass an empty HTTPMessage to avoid Pylance error
        hdrs_non_none = hdrs if hdrs is not None else HTTPMessage()
        super().__init__(url, code, msg, hdrs_non_none, fp)


class MalformedStr(str):
    """Helper class for malformed strings."""

    def split(self, sep=None, maxsplit=-1):
        """Split string."""
        if sep == "charset=":
            raise ValueError("forced exception")
        return super().split(sep, maxsplit)


# Define a Protocol for something that supports .read()
@runtime_checkable
class SupportsRead(Protocol):
    """Protocol class that suports read method."""

    def read(self, n: int = -1) -> bytes:
        """Fake read method."""
        ...


class TestHTTPResponse(TestCase):
    """HTTPResponse test class."""

    def test_text_and_json(self) -> None:
        """Test text and json methods."""
        content = b'{"key": "value"}'
        headers = {"Content-Type": "application/json"}
        raw = DummyRawResponse(content=content, headers=headers)
        resp = HTTPResponse(raw, 200, headers)
        self.assertEqual(resp.text(), content.decode("utf-8"))
        self.assertEqual(resp.json(), {"key": "value"})

    def test_content_and_iter_content(self) -> None:
        """Test content property and iter_content method."""
        content = b"abcdefg"
        raw = DummyRawResponse(content=content)
        resp = HTTPResponse(raw, 200, {}, stream=False)
        self.assertEqual(resp.content, content)
        chunks = list(resp.iter_content(chunk_size=3))
        self.assertEqual(b"".join(chunks), content)

    def test_iter_content_streaming_and_none_chunk_size(self) -> None:
        """Test iter content streaming and empty chunk_size value."""
        content = b"abcdefgh"
        raw = DummyRawResponse(content=content)
        resp = HTTPResponse(raw, 200, {}, stream=True)
        chunks = list(resp.iter_content(chunk_size=None))
        self.assertEqual(b"".join(chunks), content)

    def test_json_invalid_raises(self) -> None:
        """Test that invalid JSON raises an error."""
        raw = DummyRawResponse(
            content=b"not json", headers={"Content-Type": "application/json"},
        )
        resp = HTTPResponse(raw, 200, {})
        with self.assertRaises(json.JSONDecodeError):
            resp.json()

    def test_text_with_charset(self) -> None:
        """Test that text with specific charset is correct."""
        content = "café".encode("latin-1")
        raw = DummyRawResponse(
            content=content,
            headers={"Content-Type": "text/plain; charset=latin-1"},
        )
        resp = HTTPResponse(
            raw, 200, {"Content-Type": "text/plain; charset=latin-1"},
        )
        self.assertEqual(resp.text(), "café")

    def test_text_with_no_content_type_header(self) -> None:
        """Test that text with no content type header is correct."""
        content = "hello"
        raw = DummyRawResponse(content=content.encode("utf-8"))
        resp = HTTPResponse(raw, 200, {})
        self.assertEqual(resp.text(), content)

    def test_iter_content_zero_chunk_size(self) -> None:
        """Test that zero chunk-size content iteration works as expected."""
        content = b"abcdef"
        raw = DummyRawResponse(content=content)
        resp = HTTPResponse(raw, 200, {}, stream=True)
        chunks = list(resp.iter_content(chunk_size=0))
        self.assertEqual(b"".join(chunks), b"")

    def test_headers_property_returns_dict(self) -> None:
        """Test that the headers property returns a proper dictionary."""
        content = b"data"
        headers = {"X-Test": "value"}
        raw = DummyRawResponse(content=content, headers=headers)
        resp = HTTPResponse(raw, 200, headers)
        self.assertEqual(resp.headers, headers)

    def test_close_method_does_not_raise(self) -> None:
        """Test that close method does not raise an exception."""
        content = b"test"
        raw = DummyRawResponse(content=content)
        resp = HTTPResponse(raw, 200, {})
        try:
            resp.close()
        except Exception as e:
            self.fail(f"HTTPResponse.close() raised an exception: {e}")

    def test_headers_case_insensitivity(self) -> None:
        """Test that headers dict are case-sensitive or not."""
        content = b"data"
        headers = {"content-type": "application/json", "X-CUSTOM": "value"}
        raw = DummyRawResponse(content=content, headers=headers)
        resp = HTTPResponse(raw, 200, headers)
        # Should return keys as-is (dict),
        # but check lookup is case-sensitive or not
        self.assertEqual(resp.headers.get("content-type"), "application/json")
        self.assertEqual(resp.headers.get("X-CUSTOM"), "value")
        # Also check fallback when key missing returns None
        self.assertIsNone(resp.headers.get("Non-Existent"))

    def test_iter_content_with_large_chunk_size(self) -> None:
        """Test content iteration with large chunk sizes."""
        content = b"abc"
        raw = DummyRawResponse(content=content)
        resp = HTTPResponse(raw, 200, {}, stream=True)
        chunks = list(
            resp.iter_content(chunk_size=10),
        )  # chunk_size > content length
        self.assertEqual(b"".join(chunks), content)

    def test_iter_content_chunk_size_variants(self) -> None:
        """Test content iteration with different chunk sizes."""
        # _raw is None
        resp2 = HTTPResponse(None, 200, {}, stream=True)
        chunks2 = list(resp2.iter_content())
        assert chunks2 == [resp2.content]

        # chunk_size <=0 yields b""
        resp3 = HTTPResponse(DummyRawResponse(), 200, {}, stream=True)
        chunks3 = list(resp3.iter_content(chunk_size=0))
        assert chunks3 == [b""]

    def test_httpresponse_text_malformed_charset(self) -> None:
        """Test HTTPResponse text with malformed charset values."""
        headers = cast(
            dict[str, str],
            {"Content-Type": MalformedStr("text/html; charset=utf-8")},
        )
        resp = HTTPResponse(
            raw_resp=BytesIO(b"test"), status=200, headers=headers,
        )
        # It should not raise, fallback encoding 'utf-8' used
        text = resp.text()
        assert text == "test"

    def test_httpresponse_text_with_malformed_charset(self) -> None:
        """Test HTTPResponse text with malformed charset values."""
        headers = {
            "Content-Type": "text/html; charset=",
        }  # empty charset part causes split[1] to be empty string
        resp = HTTPResponse(
            DummyRawResponse(content=b"abc"), status=200, headers=headers,
        )
        # Should not raise, should fall back to default 'utf-8'
        assert resp.text() == "abc"

    def test_aiter_content_chunk_size_fallback(self) -> None:
        """Test async content iteration with chunk size fallback."""

        class DummyRaw:
            """Dummy Raw class for testing purposes."""

            def __init__(self):
                """Initialize the class."""
                self.read_calls: List[int] = []

            def read(self, size: int) -> bytes:
                """Return dummy content read."""
                self.read_calls.append(size)
                # Return empty bytes immediately to stop iteration
                return b""

        raw = DummyRaw()
        response = HTTPResponse(
            raw_resp=raw, status=200, headers={}, stream=True,
        )

        async def run_test() -> None:
            """Run async test."""
            # chunk_size = None (should fall back to 8192)
            chunks = [
                chunk
                async for chunk in response.aiter_content(chunk_size=None)
            ]
            self.assertEqual(chunks, [])
            self.assertEqual(raw.read_calls, [8192])

            # Reset calls
            raw.read_calls.clear()

            # chunk_size <= 0 (e.g., 0) (should fallback to 8192)
            chunks = [
                chunk async for chunk in response.aiter_content(chunk_size=0)
            ]
            self.assertEqual(chunks, [])
            self.assertEqual(raw.read_calls, [8192])

        asyncio.run(run_test())


class TestSession(TestCase):
    """Session test class."""

    # Helper function
    @staticmethod
    def get_request_data_bytes(req: Request) -> bytes:
        """Get request data bytes."""
        if req.data is None:
            return b""
        if isinstance(req.data, bytes):
            return req.data
        if isinstance(req.data, str):
            return req.data.encode("utf-8")
        if hasattr(req.data, "read"):
            file_like = cast(SupportsRead, req.data)
            result = file_like.read()
            if not isinstance(result, bytes):
                raise TypeError(
                    f"Expected bytes from read(), got {type(result)}",
                )
            return result
        if isinstance(req.data, Iterable):
            return b"".join(req.data)
        raise TypeError(f"Unsupported type for req.data: {type(req.data)}")

    def setUp(self) -> None:
        """Set up test class."""
        self.session: Session = Session()
        self.opener: DummyOpener = DummyOpener()
        self.session.opener = self.opener
        self.called_method: str = ""
        self.called_url: str = ""

    def _run_async(self, coro: Any) -> Any:
        """Run async coroutines in sync test methods."""
        return asyncio.run(coro)

    def _patch_async_request(
        self, return_status: int, return_text: str,
    ) -> None:
        """Replace async_request on self.session."""

        async def fake_async_request(
            method: str, url: str, **kwargs: Any,
        ) -> Any:
            """Fake an async request."""
            self.called_method = method
            self.called_url = url

            class FakeResp:
                """Fake response class."""

                status: int = return_status

                def text(self) -> str:
                    """Return the response text."""
                    return return_text

            return FakeResp()

        # Patch the method directly on the session instance
        self.session.async_request = fake_async_request  # type: ignore

    def test_request_success(self) -> None:
        """Test a successful request."""
        dummy_content = b"Hello, world!"
        dummy_headers = {"Content-Type": "text/plain"}
        dummy_response = DummyRawResponse(
            status=200, content=dummy_content, headers=dummy_headers,
        )
        self.opener._response = dummy_response

        resp = self.session.get("https://example.com")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.content, dummy_content)
        self.assertEqual(resp.headers, dummy_headers)
        assert self.opener.called_with is not None
        self.assertEqual(
            self.opener.called_with.get_full_url(), "https://example.com",
        )

    def test_http_error_response(self) -> None:
        """Test an HTTPError response."""
        dummy_headers = HTTPMessage()
        dummy_headers.add_header("Content-Type", "text/plain")
        dummy_fp = BytesIO(b"error content")
        dummy_error = DummyHTTPError(
            url="https://example.com/error",
            code=404,
            msg="Not Found",
            hdrs=dummy_headers,
            fp=dummy_fp,
        )

        def raise_http_error(
            req: Request,
            data=None,
            timeout: Optional[Union[int, float]] = None,
        ) -> None:
            raise dummy_error

        self.opener.open = raise_http_error
        resp = self.session.get("https://example.com/error")
        self.assertEqual(resp.status, 404)
        self.assertEqual(resp.content, b"error content")
        self.assertEqual(resp.headers.get("Content-Type"), "text/plain")

    def test_http_error_without_fp(self) -> None:
        """Test an HTTPError without fp."""
        dummy_headers = HTTPMessage()
        dummy_headers.add_header("X-Test", "yes")
        dummy_error = DummyHTTPError(
            url="https://example.com/error",
            code=500,
            msg="Server Error",
            hdrs=dummy_headers,
            fp=None,
        )

        def raise_http_error(
            req: Request,
            data=None,
            timeout: Optional[Union[int, float]] = None,
        ) -> None:
            """Raise a dummy HTTPError."""
            raise dummy_error

        self.opener.open = raise_http_error
        resp = self.session.get("https://example.com/error")
        self.assertEqual(resp.status, 500)
        self.assertEqual(resp.headers.get("X-Test"), "yes")

    def test_other_exception_handling(self) -> None:
        """Test other HTTP responses' exception handling."""

        def raise_generic(
            req: Request,
            data=None,
            timeout: Optional[Union[int, float]] = None,
        ) -> None:
            """Raise a ValueError exception."""
            raise ValueError("Unexpected")

        self.opener.open = raise_generic
        with self.assertRaises(ValueError):
            self.session.get("https://example.com")

    def test_post_put_delete_methods(self) -> None:
        """Test POST, PUT and DELETE methods."""
        self.opener._response = DummyRawResponse(status=201, content=b"ok")
        self.assertEqual(
            self.session.post("https://x.com", data=b"abc").status, 201,
        )
        self.assertEqual(
            self.session.put("https://x.com", data=b"abc").status, 201,
        )
        self.assertEqual(self.session.delete("https://x.com").status, 201)

    def test_streaming_request(self) -> None:
        """Test streaming GET request."""
        content = b"streamed data"
        self.opener._response = DummyRawResponse(status=200, content=content)
        resp = self.session.get("https://example.com", stream=True)
        self.assertEqual(b"".join(resp.iter_content(5)), content)

    def test_request_with_headers_and_timeout(self) -> None:
        """Test a GET request with headers and timeout values."""
        self.opener._response = DummyRawResponse(status=200, content=b"ok")
        resp = self.session.get(
            "https://example.com", headers={"X-Test": "yes"}, timeout=5,
        )
        self.assertEqual(resp.status, 200)

    def test_request_with_no_data_and_headers(self) -> None:
        """Test a POST request without data nor headers."""
        self.opener._response = DummyRawResponse(status=200, content=b"done")
        resp = self.session.post(
            "https://example.com", data=None, headers=None,
        )
        self.assertEqual(resp.status, 200)

    def test_request_timeout_argument(self) -> None:
        """Test a GET request with a timeout argument."""
        dummy_content = b"timeout test"
        dummy_response = DummyRawResponse(status=200, content=dummy_content)
        self.opener._response = dummy_response
        resp = self.session.get("https://timeout.com", timeout=10)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.content, dummy_content)

    def test_request_with_unusual_headers(self) -> None:
        """Test GET requests with unusual headers."""
        headers = {"X-Custom": "abc", "Content-Length": "10"}
        self.opener._response = DummyRawResponse(
            status=200, content=b"x" * 10, headers=headers,
        )
        resp = self.session.get("https://example.com", headers=headers)
        self.assertEqual(resp.headers.get("X-Custom"), "abc")
        self.assertEqual(resp.headers.get("Content-Length"), "10")

    def test_request_streaming_false_and_true(self) -> None:
        """Test streaming and non-streaming requests."""
        self.opener._response = DummyRawResponse(
            status=200, content=b"streamtest",
        )
        resp = self.session.get("https://example.com", stream=False)
        self.assertEqual(resp.content, b"streamtest")

        self.opener._response = DummyRawResponse(
            status=200, content=b"streamtest",
        )
        resp = self.session.get("https://example.com", stream=True)
        self.assertEqual(b"".join(resp.iter_content(5)), b"streamtest")

    def test_request_with_string_data(self) -> None:
        """Test requests with data as string."""
        self.opener._response = DummyRawResponse(status=200, content=b"ok")
        # Assuming Session supports string data and encodes it internally
        resp = self.session.post("https://example.com", data="string data")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.content, b"ok")

        # Was opener called with a Request object containing data?
        called_req = self.opener.called_with
        self.assertIsNotNone(called_req)

        data_bytes: bytes = b""
        if called_req is not None:
            raw_data: Any = called_req.data
            if raw_data is None:
                data_bytes = b""
            elif isinstance(raw_data, bytes):
                data_bytes = raw_data
            elif isinstance(raw_data, SupportsRead):
                data_bytes = raw_data.read()
            elif isinstance(raw_data, Iterable):
                data_bytes = b"".join(raw_data)
            else:
                try:
                    data_bytes = bytes(raw_data)
                except Exception:
                    data_bytes = b""

        self.assertIn(b"string data", data_bytes)

    def test_request_with_file_like_data(self) -> None:
        """Test request with file-like object and read() returning bytes."""
        file_like = BytesIO(b"file contents")
        self.opener._response = DummyRawResponse(status=200, content=b"ok")
        resp = self.session.post("https://example.com", data=file_like)
        assert resp.status == 200  # or your dummy success

    def test_request_with_file_like_read_returns_non_bytes(self) -> None:
        """Test request with file-like object returning non-bytes content."""

        class BadFileLike:
            """Dummy class that returns an incorrect file-like object."""

            def read(self):
                """Return dummy value."""
                return "not bytes"

        with pytest.raises(TypeError):
            self.session.post("https://example.com", data=BadFileLike())

    def test_request_with_empty_headers_dict(self) -> None:
        """Test a GET request with empty headers dictionary."""
        self.opener._response = DummyRawResponse(status=200, content=b"ok")
        resp = self.session.get("https://example.com", headers={})
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.content, b"ok")

    def test_request_with_multiple_headers(self) -> None:
        """Test a GET request with multiple headers."""
        # Python dict can't have duplicate keys; so simulate with
        # multiple calls or with special header format.
        # We'll test with comma-separated header value as HTTP supports that.
        headers = {"X-Test": "value1, value2"}
        self.opener._response = DummyRawResponse(
            status=200, content=b"ok", headers=headers,
        )
        resp = self.session.get("https://example.com", headers=headers)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.headers.get("X-Test"), "value1, value2")

    def test_request_with_custom_user_agent_header(self) -> None:
        """Test a GET request with custom user-agent header."""
        headers = {"User-Agent": "MyTestAgent/1.0"}
        self.opener._response = DummyRawResponse(
            status=200, content=b"ok", headers=headers,
        )
        resp = self.session.get("https://example.com", headers=headers)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.headers.get("User-Agent"), "MyTestAgent/1.0")

    def test_session_close_method_exists(self) -> None:
        """Test that the Session close method exists."""
        try:
            self.session.close()
        except Exception as e:
            self.fail(f"Session.close() raised an exception: {e}")

    def test_apply_auth_header_adds_header(self) -> None:
        """Test that authentication header is properly added to headers."""
        headers = {}
        self.session._apply_auth_header(headers, ("user", "pass"))
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")

    def test_request_data_types_and_invalid(self) -> None:
        """Test several data-types for a request, including invalid."""
        with patch.object(
            self.session.opener,
            "open",
            return_value=Mock(
                getcode=lambda: 200, getheaders=lambda: [], read=lambda: b"ok",
            ),
        ):
            # dict data
            resp = self.session.request(
                "POST", "https://example.com", data={"key": "val"},
            )
            assert resp.status == 200
            # str data
            resp = self.session.request(
                "POST", "https://example.com", data="stringdata",
            )
            assert resp.status == 200
            # bytes data
            resp = self.session.request(
                "POST", "https://example.com", data=b"bytesdata",
            )
            assert resp.status == 200
            # invalid data
            with pytest.raises(TypeError):
                self.session.request(
                    "POST",
                    "https://example.com",
                    data=12345,  # type: ignore[arg-type]
                )

    def test_request_http_error_handling(self) -> None:
        """Test error handling on an HTTP request."""
        headers = HTTPMessage()
        headers.add_header("X-Test", "1")

        error = HTTPError(
            "https://example.com", 404, "Not Found", hdrs=headers, fp=None,
        )
        with patch.object(self.session.opener, "open", side_effect=error):
            resp = self.session.request("GET", "https://example.com")
            assert resp.status == 404
            assert resp.headers.get("X-Test") == "1"

    def test_request_retries_and_raises(self) -> None:
        """Test retries on HTTPRequest and Exception raising."""
        s = Session(retries=2)
        err = URLError("fail")
        call_count = 0

        def side_effect(*args, **kwargs):
            """Raise exception."""
            nonlocal call_count
            call_count += 1
            raise err

        with patch.object(s.opener, "open", side_effect=side_effect):
            with pytest.raises(URLError):
                s.request("GET", "https://example.com")
        assert call_count == 2

    def test_async_request_methods(self):
        """Test async request methods."""
        resp_mock = Mock(status=200)

        async def run_test():
            """Run async methods."""
            with patch.object(
                self.session, "request", lambda *a, **kw: resp_mock,
            ):
                r = await self.session.async_get("https://example.com")
                self.assertEqual(r, resp_mock)

        asyncio.run(run_test())

    def test_context_manager_and_close_methods(self) -> None:
        """Test __enter__ and __exit__ methods for context manager."""
        with self.session as sess:
            assert sess is self.session

        # test close clears cookies and closes opener
        self.session._cookie_jar.set_cookie(Mock())
        close_mock = Mock()
        self.session.opener.close = close_mock
        self.session.close()
        assert close_mock.called

    def test_request_with_iterable_data(self) -> None:
        """Test requests with iterable data."""
        data = (chunk for chunk in [b"chunk1", b"chunk2"])
        self.opener._response = DummyRawResponse(status=200, content=b"ok")
        resp = self.session.post("https://example.com", data=data)
        self.assertEqual(resp.status, 200)
        called_req = self.opener.called_with
        self.assertIsNotNone(called_req)
        # The data should be bytes of concatenated chunks
        if called_req is not None:
            self.assertIn(
                b"chunk1chunk2",
                called_req.data if isinstance(called_req.data, bytes) else b"",
            )

    def test_request_with_auth_argument(self) -> None:
        """Test requests with basic authentication argument."""
        self.opener._response = DummyRawResponse(status=200, content=b"ok")
        resp = self.session.get("https://example.com", auth=("user", "pass"))
        self.assertEqual(resp.status, 200)
        called_req = self.opener.called_with
        self.assertIsNotNone(called_req)
        # Authorization header should be present in the request
        if called_req is not None:
            self.assertTrue(
                "Authorization" in called_req.headers
                or "authorization" in called_req.headers,
            )

    def test_request_passes_timeout(self) -> None:
        """Test requests with custom timeout value."""
        dummy_response = DummyRawResponse(status=200, content=b"ok")
        self.opener._response = dummy_response
        resp = self.session.request("GET", "https://example.com", timeout=7)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.content, b"ok")

    def test_request_with_headers_none(self) -> None:
        """Test requests with no headers provided."""
        self.opener._response = DummyRawResponse(status=200, content=b"ok")
        resp = self.session.request("GET", "https://example.com", headers=None)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.content, b"ok")

    def test_request_with_params(self) -> None:
        """Test requests with custom parameters."""
        called_urls: List[str] = []

        # Match the signature of OpenerDirector.open
        def fake_open(fullurl, data=None, timeout=None):
            """Fake the OpenerDirector.open() method."""
            # fullurl can be str or Request object
            url = fullurl.full_url if hasattr(fullurl, "full_url") else fullurl
            called_urls.append(url)

            class FakeRawResp:
                def getcode(self):
                    return 200

                def getheaders(self):
                    return []

                def read(self):
                    return b"{}"

            return FakeRawResp()

        # Save original method to restore later
        original_open = self.session.opener.open

        try:
            # Replace the opener.open method with our fake_open
            self.session.opener.open = fake_open

            # URL without query
            _ = self.session.request(
                "GET", "https://example.com/api", params={"a": "1", "b": "2"},
            )
            self.assertIn("?", called_urls[-1])
            self.assertIn("a=1", called_urls[-1])
            self.assertIn("b=2", called_urls[-1])

            # URL with existing query
            _ = self.session.request(
                "GET", "https://example.com/api?x=5", params={"a": "1"},
            )
            self.assertIn("&", called_urls[-1])
            self.assertIn("x=5", called_urls[-1])
        finally:
            self.session.opener.open = original_open

    def test_request_defensive_fallback_range_empty(self):
        """Test defensive fallback on requests."""
        import builtins  # noqa:F401

        with patch('builtins.range', return_value=iter(())):
            with self.assertRaises(RuntimeError):
                self.session.request("GET", "https://example.com")

    def test_http_error_with_other_codes(self) -> None:
        """Test HTTPError status codes."""
        for code in [400, 401, 500, 503]:
            headers = HTTPMessage()
            headers.add_header("X-Test", f"code-{code}")
            error = HTTPError(
                "https://example.com", code, "Error", hdrs=headers, fp=None,
            )
            with patch.object(self.session.opener, "open", side_effect=error):
                resp = self.session.request("GET", "https://example.com")
                self.assertEqual(resp.status, code)
                self.assertEqual(resp.headers.get("X-Test"), f"code-{code}")

    def test_async_get(self) -> None:
        """Test the async GET method."""
        self._patch_async_request(200, "get_ok")

        async def run_test() -> None:
            resp = await self.session.async_get("https://example.com")
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.text(), "get_ok")
            self.assertEqual(self.called_method, "GET")
            self.assertEqual(self.called_url, "https://example.com")

        self._run_async(run_test())

    def test_async_post(self) -> None:
        """Test the async POST method."""
        self._patch_async_request(201, "post_ok")

        async def run_test() -> None:
            """Run async POST request."""
            resp = await self.session.async_post(
                "https://example.com", data={"key": "value"},
            )
            self.assertEqual(resp.status, 201)
            self.assertEqual(resp.text(), "post_ok")
            self.assertEqual(self.called_method, "POST")
            self.assertEqual(self.called_url, "https://example.com")

        self._run_async(run_test())

    def test_async_put(self) -> None:
        """Test the async PUT method."""
        self._patch_async_request(202, "put_ok")

        async def run_test() -> None:
            """Run async PUT requests."""
            resp = await self.session.async_put("https://example.com")
            self.assertEqual(resp.status, 202)
            self.assertEqual(resp.text(), "put_ok")
            self.assertEqual(self.called_method, "PUT")
            self.assertEqual(self.called_url, "https://example.com")

        self._run_async(run_test())

    def test_async_patch(self) -> None:
        """Test the async PATCH method."""
        self._patch_async_request(200, "patch_ok")

        async def run_test() -> None:
            """Run async PATCH requests."""
            resp = await self.session.async_patch("https://example.com")
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.text(), "patch_ok")
            self.assertEqual(self.called_method, "PATCH")
            self.assertEqual(self.called_url, "https://example.com")

        self._run_async(run_test())

    def test_async_delete(self) -> None:
        """Test the async DELETE method."""
        self._patch_async_request(204, "delete_ok")

        async def run_test() -> None:
            """Run async DELETE requests."""
            resp = await self.session.async_delete("https://example.com")
            self.assertEqual(resp.status, 204)
            self.assertEqual(resp.text(), "delete_ok")
            self.assertEqual(self.called_method, "DELETE")
            self.assertEqual(self.called_url, "https://example.com")

        self._run_async(run_test())

    def test_patch_method_calls_request(self) -> None:
        """Test PATCH method calls request."""
        # Prepare a dummy raw response to use in DummyOpener
        self.opener._response = (
            DummyRawResponse()
        )  # set dummy response so open() won't raise

        with patch.object(
            self.session, "request", wraps=self.session.request,
        ) as mock_request:
            # Call patch
            resp = self.session.patch(
                "https://example.com/api", data={"key": "value"},
            )

            # Assert request was called once with method="PATCH"
            mock_request.assert_called_once()
            args, kwargs = mock_request.call_args
            self.assertEqual(args[0], "PATCH")  # method argument
            self.assertEqual(
                args[1], "https://example.com/api",
            )  # url argument
            self.assertIn("data", kwargs)
            self.assertEqual(kwargs["data"], {"key": "value"})

            # Since the patched request returns an HTTPResponse,
            # resp should be an HTTPResponse instance
            self.assertIsInstance(resp, HTTPResponse)

    def test_json_serialization_sets_header_and_body(self) -> None:
        """Test that JSON parameter properly sets request's header and body."""
        expected = {"hello": "world"}
        self.opener._response = DummyRawResponse(
            status=200,
            content=b"{}",
            headers={"Content-Type": "application/json"},
        )

        resp: HTTPResponse = self.session.post(
            "https://example.com", json=expected,
        )
        self.assertIsInstance(resp, HTTPResponse)

        req: Request = cast(urllib.request.Request, self.opener.called_with)
        self.assertIsNotNone(req)

        # Careful! Python's urllib.request.Request internally stores the
        # header keys with the capitalization from when they were added,
        # and `get_header()` is case-sensitive except for "Content-type",
        # which it seems to be a weird historical quirk.
        # self.assertEqual(req.get_header("Content-type"), "custom/type")

        # For robustness's sake, it's better to normalize
        # headers when asserting instead.
        headers = {k.lower(): v for k, v in req.header_items()}
        self.assertEqual(headers["content-type"], "application/json")

        # Safely get data bytes and decode
        data_bytes = self.get_request_data_bytes(req)
        self.assertEqual(data_bytes.decode(), json.dumps(expected))

    def test_json_respects_custom_header(self) -> None:
        """Test that request with JSON respects a given custom header."""
        expected = {"foo": "bar"}
        self.opener._response = DummyRawResponse(
            status=200,
            content=b"{}",
            headers={"Content-Type": "application/json"},
        )

        resp: HTTPResponse = self.session.post(
            "https://example.com",
            json=expected,
            headers={"Content-Type": "custom/type"},
        )
        self.assertIsInstance(resp, HTTPResponse)

        req: Request = cast(urllib.request.Request, self.opener.called_with)
        self.assertIsNotNone(req)

        # Careful! Python's urllib.request.Request internally stores
        # the header keys with the capitalization from when they were added,
        # and `get_header()` is case-sensitive except for "Content-type",
        # which it seems to be a weird historical quirk.
        # self.assertEqual(req.get_header("Content-type"), "custom/type")

        # For robustness's sake, it's better to normalize headers
        # when asserting instead.
        headers = {k.lower(): v for k, v in req.header_items()}
        self.assertEqual(headers["content-type"], "custom/type")

        # Safely get data bytes and decode
        data_bytes = self.get_request_data_bytes(req)
        self.assertEqual(data_bytes.decode(), json.dumps(expected))

    def test_json_none_means_no_body(self) -> None:
        """Test that a request with empty JSON doesn't generate a body."""
        self.opener._response = DummyRawResponse(
            status=200,
            content=b"{}",
            headers={"Content-Type": "application/json"},
        )

        resp = self.session.post("https://example.com", json=None)
        self.assertIsInstance(resp, HTTPResponse)

        req: Request = cast(Request, self.opener.called_with)
        self.assertIsNotNone(req)

        # Should send no body at all
        self.assertIsNone(req.data)
