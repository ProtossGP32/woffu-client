import json
from typing import Optional, Union, Dict, Iterable, Protocol, runtime_checkable, Any
from unittest import TestCase
from unittest.mock import Mock, patch
from io import BytesIO
from urllib.error import HTTPError, URLError
from http.client import HTTPMessage
from urllib.request import Request, OpenerDirector
from src.stdrequests_session import Session, HTTPResponse
import pytest
import asyncio


class DummyRawResponse:
    def __init__(self, status: int = 200, content: bytes = b"", headers: Optional[Dict[str, str]] = None) -> None:
        self._status: int = status
        self._content: bytes = content
        self._pos: int = 0
        self._headers: Dict[str, str] = headers or {}

    def read(self, size: int = -1) -> bytes:
        if size is None or size == -1:
            size = len(self._content) - self._pos
        data = self._content[self._pos : self._pos + size]
        self._pos += size
        return data

    def getcode(self) -> int:
        return self._status

    def getheaders(self) -> list[tuple[str, str]]:
        return list(self._headers.items())

    def close(self) -> None:
        pass


class DummyOpener(OpenerDirector):
    _response: Optional[object]
    called_with: Optional[Request]

    def __init__(self) -> None:
        super().__init__()
        self.called_with = None
        self._response = None

    def open(self, req: Request, timeout: Optional[Union[int, float]] = None) -> object:
        self.called_with = req
        if self._response is None:
            raise RuntimeError("No response set for DummyOpener")
        return self._response


class DummyHTTPError(HTTPError):
    def __init__(self, url: str, code: int, msg: str, hdrs: Optional[HTTPMessage], fp: Optional[BytesIO] = None) -> None:
        if fp is None:
            fp = BytesIO(b"")
        # If hdrs is None, pass an empty HTTPMessage to avoid Pylance error
        hdrs_non_none = hdrs if hdrs is not None else HTTPMessage()
        super().__init__(url, code, msg, hdrs_non_none, fp)


# Define a Protocol for something that supports .read()
@runtime_checkable
class SupportsRead(Protocol):
    def read(self, n: int = -1) -> bytes: ...


class TestHTTPResponse(TestCase):
    def test_text_and_json(self) -> None:
        content = b'{"key": "value"}'
        headers = {"Content-Type": "application/json"}
        raw = DummyRawResponse(content=content, headers=headers)
        resp = HTTPResponse(raw, 200, headers)
        self.assertEqual(resp.text(), content.decode("utf-8"))
        self.assertEqual(resp.json(), {"key": "value"})

    def test_content_and_iter_content(self) -> None:
        content = b"abcdefg"
        raw = DummyRawResponse(content=content)
        resp = HTTPResponse(raw, 200, {}, stream=False)
        self.assertEqual(resp.content(), content)
        chunks = list(resp.iter_content(chunk_size=3))
        self.assertEqual(b"".join(chunks), content)

    def test_iter_content_streaming_and_none_chunk_size(self) -> None:
        content = b"abcdefgh"
        raw = DummyRawResponse(content=content)
        resp = HTTPResponse(raw, 200, {}, stream=True)
        chunks = list(resp.iter_content(chunk_size=None))
        self.assertEqual(b"".join(chunks), content)

    def test_json_invalid_raises(self) -> None:
        raw = DummyRawResponse(content=b"not json", headers={"Content-Type": "application/json"})
        resp = HTTPResponse(raw, 200, {})
        with self.assertRaises(json.JSONDecodeError):
            resp.json()

    def test_text_with_charset(self) -> None:
        content = "café".encode("latin-1")
        raw = DummyRawResponse(content=content, headers={"Content-Type": "text/plain; charset=latin-1"})
        resp = HTTPResponse(raw, 200, {"Content-Type": "text/plain; charset=latin-1"})
        self.assertEqual(resp.text(), "café")

    def test_text_with_no_content_type_header(self) -> None:
        content = "hello"
        raw = DummyRawResponse(content=content.encode("utf-8"))
        resp = HTTPResponse(raw, 200, {})
        self.assertEqual(resp.text(), content)

    def test_iter_content_zero_chunk_size(self) -> None:
        content = b"abcdef"
        raw = DummyRawResponse(content=content)
        resp = HTTPResponse(raw, 200, {}, stream=True)
        chunks = list(resp.iter_content(chunk_size=0))
        self.assertEqual(b"".join(chunks), b"")

    def test_headers_property_returns_dict(self) -> None:
        content = b"data"
        headers = {"X-Test": "value"}
        raw = DummyRawResponse(content=content, headers=headers)
        resp = HTTPResponse(raw, 200, headers)
        self.assertEqual(resp.headers, headers)

    def test_close_method_does_not_raise(self) -> None:
        content = b"test"
        raw = DummyRawResponse(content=content)
        resp = HTTPResponse(raw, 200, {})
        try:
            resp.close()
        except Exception as e:
            self.fail(f"HTTPResponse.close() raised an exception: {e}")

    def test_headers_case_insensitivity(self) -> None:
        content = b"data"
        headers = {"content-type": "application/json", "X-CUSTOM": "value"}
        raw = DummyRawResponse(content=content, headers=headers)
        resp = HTTPResponse(raw, 200, headers)
        # Should return keys as-is (dict), but check lookup is case-sensitive or not
        self.assertEqual(resp.headers.get("content-type"), "application/json")
        self.assertEqual(resp.headers.get("X-CUSTOM"), "value")
        # Also check fallback when key missing returns None
        self.assertIsNone(resp.headers.get("Non-Existent"))

    def test_iter_content_with_large_chunk_size(self) -> None:
        content = b"abc"
        raw = DummyRawResponse(content=content)
        resp = HTTPResponse(raw, 200, {}, stream=True)
        chunks = list(resp.iter_content(chunk_size=10))  # chunk_size > content length
        self.assertEqual(b"".join(chunks), content)

    def test_httpresponse_text_with_malformed_charset(self) -> None:
        headers = {"Content-Type": "text/html; charset="}  # empty charset part causes split[1] to be empty string
        class DummyRaw:
            def read(self): return b"abc"
        resp = HTTPResponse(DummyRaw(), 200, headers)
        # Should not raise, should fallback to default 'utf-8'
        assert resp.text() == "abc"

    def test_httpresponse_content_stream_and_no_stream(self) -> None:
        class DummyRaw:
            def read(self): return b"hello"
        resp1 = HTTPResponse(DummyRaw(), 200, {}, stream=False)
        assert resp1.content() == b"hello"

        class DummyStream:
            def __init__(self):
                self.called = 0
            def read(self, n=None):
                self.called += 1
                if self.called == 1:
                    return b"chunk"
                else:
                    return b""  # EOF on second read

        dummy_stream = DummyStream()
        resp2 = HTTPResponse(dummy_stream, 200, {}, stream=True)
        assert b"chunk" in resp2.content()

    def test_iter_content_chunk_size_variants(self) -> None:
        class DummyRaw:
            def __init__(self): self.called = 0
            def read(self, n=None):
                if self.called == 0:
                    self.called += 1
                    return b"abc"
                return b""
        # stream False yields once content
        resp = HTTPResponse(DummyRaw(), 200, {}, stream=False)
        chunks = list(resp.iter_content())
        assert chunks == [resp.content()]

        # _raw is None
        resp2 = HTTPResponse(None, 200, {}, stream=True)
        chunks2 = list(resp2.iter_content())
        assert chunks2 == [resp2.content()]

        # chunk_size <=0 yields b""
        resp3 = HTTPResponse(DummyRaw(), 200, {}, stream=True)
        chunks3 = list(resp3.iter_content(chunk_size=0))
        assert chunks3 == [b""]

    def test_iter_content_raw_none_stream_true(self) -> None:
        resp = HTTPResponse(None, 200, {}, stream=True)
        chunks = list(resp.iter_content())
        # Should yield the content() which is b""
        self.assertEqual(chunks, [b""])


class TestSession(TestCase):
    def setUp(self) -> None:
        self.session: Session = Session()
        self.opener: DummyOpener = DummyOpener()
        self.session.opener = self.opener

    def test_request_success(self) -> None:
        dummy_content = b"Hello, world!"
        dummy_headers = {"Content-Type": "text/plain"}
        dummy_response = DummyRawResponse(status=200, content=dummy_content, headers=dummy_headers)
        self.opener._response = dummy_response

        resp = self.session.get("http://example.com")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.content(), dummy_content)
        self.assertEqual(resp.headers, dummy_headers)
        assert self.opener.called_with is not None
        self.assertEqual(self.opener.called_with.get_full_url(), "http://example.com")

    def test_http_error_response(self) -> None:
        dummy_headers = HTTPMessage()
        dummy_headers.add_header("Content-Type", "text/plain")
        dummy_fp = BytesIO(b"error content")
        dummy_error = DummyHTTPError(
            url="http://example.com/error",
            code=404,
            msg="Not Found",
            hdrs=dummy_headers,
            fp=dummy_fp,
        )

        def raise_http_error(req: Request, timeout: Optional[Union[int, float]] = None) -> None:
            raise dummy_error

        self.opener.open = raise_http_error
        resp = self.session.get("http://example.com/error")
        self.assertEqual(resp.status, 404)
        self.assertEqual(resp.content(), b"error content")
        self.assertEqual(resp.headers.get("Content-Type"), "text/plain")

    def test_http_error_without_fp(self) -> None:
        dummy_headers = HTTPMessage()
        dummy_headers.add_header("X-Test", "yes")
        dummy_error = DummyHTTPError(
            url="http://example.com/error",
            code=500,
            msg="Server Error",
            hdrs=dummy_headers,
            fp=None
        )

        def raise_http_error(req: Request, timeout: Optional[Union[int, float]] = None) -> None:
            raise dummy_error

        self.opener.open = raise_http_error
        resp = self.session.get("http://example.com/error")
        self.assertEqual(resp.status, 500)
        self.assertEqual(resp.headers.get("X-Test"), "yes")

    def test_other_exception_handling(self) -> None:
        def raise_generic(req: Request, timeout: Optional[Union[int, float]] = None) -> None:
            raise ValueError("Unexpected")

        self.opener.open = raise_generic
        with self.assertRaises(ValueError):
            self.session.get("http://example.com")

    def test_post_put_delete_methods(self) -> None:
        self.opener._response = DummyRawResponse(status=201, content=b"ok")
        self.assertEqual(self.session.post("http://x.com", data=b"abc").status, 201)
        self.assertEqual(self.session.put("http://x.com", data=b"abc").status, 201)
        self.assertEqual(self.session.delete("http://x.com").status, 201)

    def test_streaming_request(self) -> None:
        content = b"streamed data"
        self.opener._response = DummyRawResponse(status=200, content=content)
        resp = self.session.get("http://example.com", stream=True)
        self.assertEqual(b"".join(resp.iter_content(5)), content)

    def test_request_with_headers_and_timeout(self) -> None:
        self.opener._response = DummyRawResponse(status=200, content=b"ok")
        resp = self.session.get("http://example.com", headers={"X-Test": "yes"}, timeout=5)
        self.assertEqual(resp.status, 200)

    def test_request_with_no_data_and_headers(self) -> None:
        self.opener._response = DummyRawResponse(status=200, content=b"done")
        resp = self.session.post("http://example.com", data=None, headers=None)
        self.assertEqual(resp.status, 200)

    def test_request_timeout_argument(self) -> None:
        dummy_content = b"timeout test"
        dummy_response = DummyRawResponse(status=200, content=dummy_content)
        self.opener._response = dummy_response
        resp = self.session.get("http://timeout.com", timeout=10)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.content(), dummy_content)

    def test_request_with_unusual_headers(self) -> None:
        headers = {"X-Custom": "abc", "Content-Length": "10"}
        self.opener._response = DummyRawResponse(status=200, content=b"x" * 10, headers=headers)
        resp = self.session.get("http://example.com", headers=headers)
        self.assertEqual(resp.headers.get("X-Custom"), "abc")
        self.assertEqual(resp.headers.get("Content-Length"), "10")

    def test_request_streaming_false_and_true(self) -> None:
        self.opener._response = DummyRawResponse(status=200, content=b"streamtest")
        resp = self.session.get("http://example.com", stream=False)
        self.assertEqual(resp.content(), b"streamtest")

        self.opener._response = DummyRawResponse(status=200, content=b"streamtest")
        resp = self.session.get("http://example.com", stream=True)
        self.assertEqual(b"".join(resp.iter_content(5)), b"streamtest")

    def test_request_with_string_data(self) -> None:
        self.opener._response = DummyRawResponse(status=200, content=b"ok")
        # Assuming Session supports string data and encodes it internally
        resp = self.session.post("http://example.com", data="string data")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.content(), b"ok")

        # Check that opener was called with a Request object containing the data
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
        # file-like object with read() returning bytes
        file_like = BytesIO(b"file contents")
        self.opener._response = DummyRawResponse(status=200, content=b"ok")
        resp = self.session.post("http://example.com", data=file_like)
        assert resp.status == 200  # or your dummy success

    def test_request_with_file_like_read_returns_non_bytes(self) -> None:
        class BadFileLike:
            def read(self):
                return "not bytes"
        with pytest.raises(TypeError):
            self.session.post("http://example.com", data=BadFileLike())

    def test_request_with_empty_headers_dict(self) -> None:
        self.opener._response = DummyRawResponse(status=200, content=b"ok")
        resp = self.session.get("http://example.com", headers={})
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.content(), b"ok")

    def test_request_with_multiple_headers(self) -> None:
        headers = {"X-Test": "value1", "X-Test": "value2"}  # dict can't have duplicate keys, simulate manually
        # Python dict can't have duplicate keys; so simulate with multiple calls or with special header format
        # We'll test with comma-separated header value as HTTP supports that
        headers = {"X-Test": "value1, value2"}
        self.opener._response = DummyRawResponse(status=200, content=b"ok", headers=headers)
        resp = self.session.get("http://example.com", headers=headers)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.headers.get("X-Test"), "value1, value2")

    def test_request_with_custom_user_agent_header(self) -> None:
        headers = {"User-Agent": "MyTestAgent/1.0"}
        self.opener._response = DummyRawResponse(status=200, content=b"ok", headers=headers)
        resp = self.session.get("http://example.com", headers=headers)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.headers.get("User-Agent"), "MyTestAgent/1.0")

    def test_session_close_method_exists(self) -> None:
        # Just call close on session to check no error (assuming Session has close)
        try:
            self.session.close()
        except Exception as e:
            self.fail(f"Session.close() raised an exception: {e}")

    def test_apply_auth_header_adds_header(self) -> None:
        headers = {}
        self.session._apply_auth_header(headers, ("user", "pass"))
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")

    def test_request_data_types_and_invalid(self) -> None:
        with patch.object(self.session.opener, "open", return_value=Mock(getcode=lambda:200, getheaders=lambda:[], read=lambda: b"ok")):
            # dict data
            resp = self.session.request("POST", "http://example.com", data={"key": "val"})
            assert resp.status == 200
            # str data
            resp = self.session.request("POST", "http://example.com", data="stringdata")
            assert resp.status == 200
            # bytes data
            resp = self.session.request("POST", "http://example.com", data=b"bytesdata")
            assert resp.status == 200
            # invalid data
            with pytest.raises(TypeError):
                self.session.request("POST", "http://example.com", data=12345) # type: ignore[arg-type]
    
    def test_request_http_error_handling(self) -> None:
        
        headers = HTTPMessage()
        headers.add_header("X-Test", "1")

        error = HTTPError("http://example.com", 404, "Not Found", hdrs=headers, fp=None)
        with patch.object(self.session.opener, "open", side_effect=error):
            resp = self.session.request("GET", "http://example.com")
            assert resp.status == 404
            assert resp.headers.get("X-Test") == "1"


    def test_request_retries_and_raises(self) -> None:
        s = Session(retries=2)
        err = URLError("fail")
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            raise err

        with patch.object(s.opener, "open", side_effect=side_effect):
            with pytest.raises(URLError):
                s.request("GET", "http://example.com")
        assert call_count == 2

    def test_async_request_methods(self):
        resp_mock = Mock(status=200)
        
        async def run_test():
            with patch.object(self.session, "request", lambda *a, **kw: resp_mock):
                r = await self.session.async_get("http://example.com")
                self.assertEqual(r, resp_mock)
        
        asyncio.run(run_test())

    def test_context_manager_and_close_methods(self) -> None:
        # test __enter__ and __exit__
        with self.session as sess:
            assert sess is self.session

        # test close clears cookies and closes opener
        self.session._cookie_jar.set_cookie(Mock())
        close_mock = Mock()
        self.session.opener.close = close_mock
        self.session.close()
        assert close_mock.called

    def test_request_with_iterable_data(self) -> None:
        data = (chunk for chunk in [b"chunk1", b"chunk2"])
        self.opener._response = DummyRawResponse(status=200, content=b"ok")
        resp = self.session.post("http://example.com", data=data)
        self.assertEqual(resp.status, 200)
        called_req = self.opener.called_with
        self.assertIsNotNone(called_req)
        # The data should be bytes of concatenated chunks
        if called_req is not None:
            self.assertIn(b"chunk1chunk2", called_req.data if isinstance(called_req.data, bytes) else b"")

    def test_request_with_auth_argument(self) -> None:
        self.opener._response = DummyRawResponse(status=200, content=b"ok")
        resp = self.session.get("http://example.com", auth=("user", "pass"))
        self.assertEqual(resp.status, 200)
        called_req = self.opener.called_with
        self.assertIsNotNone(called_req)
        # Authorization header should be present in the request
        if called_req is not None:
            self.assertTrue("Authorization" in called_req.headers or "authorization" in called_req.headers)

    def test_request_passes_timeout(self) -> None:
        dummy_response = DummyRawResponse(status=200, content=b"ok")
        self.opener._response = dummy_response
        resp = self.session.request("GET", "http://example.com", timeout=7)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.content(), b"ok")


    def test_request_with_headers_none(self) -> None:
        self.opener._response = DummyRawResponse(status=200, content=b"ok")
        resp = self.session.request("GET", "http://example.com", headers=None)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.content(), b"ok")

    def test_http_error_with_other_codes(self) -> None:
        for code in [400, 401, 500, 503]:
            headers = HTTPMessage()
            headers.add_header("X-Test", f"code-{code}")
            error = HTTPError("http://example.com", code, "Error", hdrs=headers, fp=None)
            with patch.object(self.session.opener, "open", side_effect=error):
                resp = self.session.request("GET", "http://example.com")
                self.assertEqual(resp.status, code)
                self.assertEqual(resp.headers.get("X-Test"), f"code-{code}")

