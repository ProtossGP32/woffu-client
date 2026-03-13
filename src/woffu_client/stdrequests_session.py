"""stdrequests_session.py.

Standard HTTP requests and session module.
"""
from __future__ import annotations

import asyncio
import base64
import http.cookiejar
import json as jsonlib
import time
import urllib.parse
import urllib.request
from collections.abc import Iterable
from typing import Any
from typing import AsyncGenerator
from typing import cast
from typing import Dict
from typing import IO
from typing import Iterator
from typing import Optional
from typing import Tuple
from typing import Union
from urllib.error import HTTPError
from urllib.error import URLError


class HTTPResponse:
    """Provides the bare minimum features of an HTTP response."""

    _raw: Any
    status: int
    headers: Dict[str, str]
    _stream: bool
    _cached_content: Optional[bytes]

    def __init__(
        self,
        raw_resp: Any,
        status: int,
        headers: Dict[str, str],
        stream: bool = False,
    ) -> None:
        """Initialize the HTTPResponse object."""
        self._raw = raw_resp
        self.status = status
        self.headers = headers
        self._stream = stream
        self._cached_content = None

    def text(self) -> str:
        """Return response body decoded to text respecting charset if any."""
        encoding = "utf-8"
        content_type = self.headers.get("Content-Type", "")
        if "charset=" in content_type:
            try:
                enc = content_type.split("charset=")[1].split(";")[0].strip()
                if enc:
                    encoding = enc
            except Exception:
                pass
        return self.content.decode(encoding, errors="replace")

    def json(self) -> Any:
        """Parse response body as JSON."""
        return jsonlib.loads(self.text())

    @property
    def content(self) -> bytes:
        """Return the entire response body as bytes."""
        if self._cached_content is None:
            if self._stream:
                # Read all at once if stream=True by consuming the iterator
                self._cached_content = b"".join(self.iter_content())
            else:
                self._cached_content = self._raw.read()
        return cast(bytes, self._cached_content)

    def iter_content(
        self, chunk_size: Optional[int] = 1024,
    ) -> Iterator[bytes]:
        """Content iterator."""
        if self._raw is None:
            yield b""
            return

        if not self._stream:
            yield self.content
            return

        if chunk_size is None:
            # Read all content at once and yield it once
            chunk = self._raw.read()
            if chunk:
                yield chunk
            return

        if chunk_size <= 0:
            # Yield empty bytes and stop
            yield b""
            return

        while True:
            chunk = self._raw.read(chunk_size)
            if not chunk:
                break
            yield chunk

    async def aiter_content(
        self, chunk_size: Optional[int] = 8192,
    ) -> AsyncGenerator[bytes, None]:
        """Async chunked iterator \
            (reads in thread to avoid blocking event loop)."""
        # Defensive fallback if chunk_size is None or invalid
        if chunk_size is None or chunk_size <= 0:
            chunk_size = 8192

        while True:
            chunk = await asyncio.to_thread(self._raw.read, chunk_size)
            if not chunk:
                break
            yield chunk

    def close(self) -> None:
        """Close the underlying raw response if it supports close."""
        close_method = getattr(self._raw, "close", None)
        if callable(close_method):
            close_method()


class Session:
    """
    A session for making HTTP requests to Woffu.

    This class handles connection pooling and other session-related tasks.
    Use the 'with' statement to manage the session lifecycle.

    Example:
        with Session() as session:
            response = session.get("https://example.com")
    """

    headers: Dict[str, str]
    params: Dict[str, str]
    timeout: int
    retries: int
    stream: bool
    _cookie_jar: http.cookiejar.CookieJar
    _opener: urllib.request.OpenerDirector
    opener: urllib.request.OpenerDirector

    def __init__(
        self,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        timeout: int = 10,
        retries: int = 3,
        stream: bool = False,
    ) -> None:
        """Initialize the Session object."""
        self.headers = dict(headers or {})
        self.params = dict(params or {})
        self.timeout = timeout
        self.retries = retries
        self.stream = stream

        # Cookie handling
        self._cookie_jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._cookie_jar),
            urllib.request.HTTPRedirectHandler(),
        )

        # Allow user to set a custom opener later if desired
        self.opener = self._opener

    def _apply_auth_header(
        self, headers: Dict[str, str], auth: Optional[Tuple[str, str]],
    ) -> None:
        if auth:
            user, pwd = auth
            token = base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode(
                "ascii",
            )
            headers.setdefault("Authorization", f"Basic {token}")

    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Union[dict, str, bytes]] = None,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        retries: Optional[int] = None,
        stream: Optional[bool] = None,
        auth: Optional[Tuple[str, str]] = None,
    ) -> HTTPResponse:
        """Send an HTTP request.

        :return HTTPResponse: HTTP response object.
        """
        timeout, retries, stream = self._resolve_defaults(
            timeout, retries, stream,
        )
        url, final_headers = self._prepare_request(url, params, headers, auth)
        body_bytes = self._prepare_body(data, json, final_headers)

        return self._send_request(
            method, url, body_bytes, final_headers,
            timeout, retries, stream,
        )

    def _resolve_defaults(
        self,
        timeout: Optional[int],
        retries: Optional[int],
        stream: Optional[bool],
    ) -> tuple[int, int, bool]:
        """Return resolved timeout, retries, and stream values."""
        return (
            self.timeout if timeout is None else timeout,
            self.retries if retries is None else retries,
            self.stream if stream is None else stream,
        )

    def _prepare_request(
        self,
        url: str,
        params: Optional[Dict[str, str]],
        headers: Optional[Dict[str, str]],
        auth: Optional[Tuple[str, str]],
    ) -> tuple[str, Dict[str, str]]:
        """Prepare URL with query params and merged headers."""
        final_headers: Dict[str, str] = dict(self.headers)
        if headers:
            final_headers.update(headers)
        self._apply_auth_header(final_headers, auth)

        final_params: Dict[str, str] = dict(self.params)
        if params:
            final_params.update(params)
        if final_params:
            url += ("&" if "?" in url else "?") + \
                urllib.parse.urlencode(final_params)

        return url, final_headers

    def _prepare_body(
        self,
        data: Optional[
            Union[
                dict, str, bytes, bytearray,
                memoryview, IO[bytes], Iterable[bytes],
            ]
        ],
        json: Optional[Any],
        headers: Dict[str, str],
    ) -> Optional[bytes]:
        """Prepare the HTTP request body based on json or data."""
        if json is not None:
            headers.setdefault("Content-Type", "application/json")
            return jsonlib.dumps(json).encode("utf-8")

        if data is None:
            return None

        if isinstance(data, dict):
            headers.setdefault(
                "Content-Type", "application/x-www-form-urlencoded",
            )
            return urllib.parse.urlencode(data).encode("utf-8")
        if isinstance(data, str):
            headers.setdefault(
                "Content-Type", "application/x-www-form-urlencoded",
            )
            return data.encode("utf-8")
        if isinstance(data, (bytes, bytearray, memoryview)):
            return bytes(data)
        if isinstance(data, IO):  # <-- typed file-like
            body_bytes = data.read()
            if not isinstance(body_bytes, bytes):
                raise TypeError("file-like object's read() must return bytes")
            return body_bytes
        if isinstance(data, Iterable):
            return b"".join(data)

        raise TypeError("data must be dict, str, or bytes")

    def _send_request(
        self,
        method: str,
        url: str,
        body_bytes: Optional[bytes],
        headers: Dict[str, str],
        timeout: int,
        retries: int,
        stream: bool,
    ) -> HTTPResponse:
        """Perform the HTTP request with retries and return HTTPResponse."""
        last_exc: Optional[Exception] = None

        for attempt in range(retries):
            try:
                req = urllib.request.Request(
                    url, data=body_bytes,
                    headers=headers, method=method.upper(),
                )
                raw_resp = self.opener.open(req, timeout=timeout)
                return HTTPResponse(
                    raw_resp,
                    raw_resp.getcode(),
                    dict(raw_resp.getheaders()),
                    stream=stream,
                )
            except URLError as e:
                last_exc = e
                if isinstance(e, HTTPError):
                    raw_resp = cast(Any, e)
                    return HTTPResponse(
                        raw_resp, e.code,
                        dict(e.headers or {}), stream=stream,
                    )
                if attempt < retries - 1:
                    time.sleep(1)
                    continue
                raise last_exc

        # This should never be reached due to the logic above
        raise RuntimeError(
            "Request failed unexpectedly without raising an exception",
        )

    # Convenience sync methods
    def get(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Send a GET request."""
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Send a POST request."""
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Send a PUT request."""
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Send a PATCH request."""
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Send a DELETE request."""
        return self.request("DELETE", url, **kwargs)

    # Async wrappers using asyncio.to_thread to avoid blocking the event loop
    async def async_request(
        self, method: str, url: str, **kwargs: Any,
    ) -> HTTPResponse:
        """Async wrapper for request."""
        return await asyncio.to_thread(self.request, method, url, **kwargs)

    async def async_get(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Async wrapper for GET request."""
        return await self.async_request("GET", url, **kwargs)

    async def async_post(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Async wrapper for POST request."""
        return await self.async_request("POST", url, **kwargs)

    async def async_put(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Async wrapper for PUT request."""
        return await self.async_request("PUT", url, **kwargs)

    async def async_patch(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Async wrapper for PATCH request."""
        return await self.async_request("PATCH", url, **kwargs)

    async def async_delete(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Async wrapper for DELETE request."""
        return await self.async_request("DELETE", url, **kwargs)

    # Context manager support
    def __enter__(self) -> "Session":
        """Context manager support method."""
        return self

    def __exit__(
        self,
        exc_type: Optional[type],
        exc: Optional[BaseException],
        tb: Optional[Any],
    ) -> bool:
        """
        Exit method.

        Nothing special to close; cookiejar/opener don't need explicit close.
        """
        return False

    def close(self) -> None:
        """
        Close the session by clearing cookies and \
            closing any underlying resources.

        This is just for API consistency, this isn't \
            needed if using a Context manager.
        """
        # Clear all cookies
        self._cookie_jar.clear()

        # Try to close the opener if it has a close method \
        # (some custom openers might)
        close_method = getattr(self.opener, "close", None)
        if callable(close_method):
            close_method()
