import json
from unittest import TestCase
from io import BytesIO
from urllib.error import HTTPError
from http.client import HTTPMessage
from urllib.request import Request, OpenerDirector
from src.stdrequests_session import Session, HTTPResponse


class DummyRawResponse:
    def __init__(self, status=200, content=b"", headers=None):
        self._status = status
        self._content = content
        self._pos = 0
        self._headers = headers or {}

    def read(self, size: int = -1) -> bytes:
        if size == -1:
            size = len(self._content) - self._pos
        data = self._content[self._pos : self._pos + size]
        self._pos += size
        return data

    def getcode(self):
        return self._status

    def getheaders(self):
        return list(self._headers.items())

    def close(self):
        pass


class DummyOpener(OpenerDirector):
    _response: object
    called_with: Request | None

    def __init__(self):
        super().__init__()
        self.called_with = None
        self._response = None

    def open(self, req, timeout=None):
        self.called_with = req
        if self._response is None:
            raise RuntimeError("No response set for DummyOpener")
        return self._response


class DummyHTTPError(HTTPError):
    def __init__(self, url, code, msg, hdrs, fp=None):
        if fp is None:
            fp = BytesIO(b"")
        super().__init__(url, code, msg, hdrs, fp)


class TestHTTPResponse(TestCase):
    def test_text_and_json(self):
        content = b'{"key": "value"}'
        headers = {"Content-Type": "application/json"}
        raw = DummyRawResponse(content=content, headers=headers)
        resp = HTTPResponse(raw, 200, headers)
        self.assertEqual(resp.text(), content.decode("utf-8"))
        self.assertEqual(resp.json(), {"key": "value"})

    def test_content_and_iter_content(self):
        content = b"abcdefg"
        raw = DummyRawResponse(content=content)
        resp = HTTPResponse(raw, 200, {}, stream=False)
        self.assertEqual(resp.content(), content)
        chunks = list(resp.iter_content(chunk_size=3))
        self.assertEqual(b"".join(chunks), content)

    def test_iter_content_streaming_and_none_chunk_size(self):
        content = b"abcdefgh"
        raw = DummyRawResponse(content=content)
        resp = HTTPResponse(raw, 200, {}, stream=True)
        chunks = list(resp.iter_content(chunk_size=None))
        self.assertEqual(b"".join(chunks), content)

    def test_json_invalid_raises(self):
        raw = DummyRawResponse(content=b"not json", headers={"Content-Type": "application/json"})
        resp = HTTPResponse(raw, 200, {})
        with self.assertRaises(json.JSONDecodeError):
            resp.json()

    def test_text_with_charset(self):
        content = "café".encode("latin-1")
        raw = DummyRawResponse(content=content, headers={"Content-Type": "text/plain; charset=latin-1"})
        resp = HTTPResponse(raw, 200, {"Content-Type": "text/plain; charset=latin-1"})
        self.assertEqual(resp.text(), "café")


class TestSession(TestCase):
    def setUp(self):
        self.session = Session()
        self.opener = DummyOpener()
        self.session.opener = self.opener

    def test_request_success(self):
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

    def test_http_error_response(self):
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

        def raise_http_error(req, timeout=None):
            raise dummy_error

        self.opener.open = raise_http_error
        resp = self.session.get("http://example.com/error")
        self.assertEqual(resp.status, 404)
        self.assertEqual(resp.content(), b"error content")
        self.assertEqual(resp.headers.get("Content-Type"), "text/plain")

    def test_http_error_without_fp(self):
        dummy_headers = HTTPMessage()
        dummy_headers.add_header("X-Test", "yes")
        dummy_error = DummyHTTPError(
            url="http://example.com/error",
            code=500,
            msg="Server Error",
            hdrs=dummy_headers,
            fp=None
        )

        def raise_http_error(req, timeout=None):
            raise dummy_error

        self.opener.open = raise_http_error
        resp = self.session.get("http://example.com/error")
        self.assertEqual(resp.status, 500)
        self.assertEqual(resp.headers.get("X-Test"), "yes")

    def test_other_exception_handling(self):
        def raise_generic(req, timeout=None):
            raise ValueError("Unexpected")

        self.opener.open = raise_generic
        with self.assertRaises(ValueError):
            self.session.get("http://example.com")

    def test_post_put_delete_methods(self):
        self.opener._response = DummyRawResponse(status=201, content=b"ok")
        self.assertEqual(self.session.post("http://x.com", data=b"abc").status, 201)
        self.assertEqual(self.session.put("http://x.com", data=b"abc").status, 201)
        self.assertEqual(self.session.delete("http://x.com").status, 201)

    def test_streaming_request(self):
        content = b"streamed data"
        self.opener._response = DummyRawResponse(status=200, content=content)
        resp = self.session.get("http://example.com", stream=True)
        self.assertEqual(b"".join(resp.iter_content(5)), content)

    def test_request_with_headers_and_timeout(self):
        self.opener._response = DummyRawResponse(status=200, content=b"ok")
        resp = self.session.get("http://example.com", headers={"X-Test": "yes"}, timeout=5)
        self.assertEqual(resp.status, 200)
