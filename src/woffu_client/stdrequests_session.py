import urllib.request
import urllib.parse
import json as jsonlib
import time
import asyncio
import base64
from typing import Any, Optional, Dict, Union, AsyncGenerator, Tuple, cast, Iterator
from collections.abc import Iterable
import http.cookiejar
from urllib.error import URLError, HTTPError


class HTTPResponse:
    _raw: Any
    status: int
    headers: Dict[str, str]
    _stream: bool
    _cached_content: Optional[bytes]

    def __init__(self, raw_resp: Any, status: int, headers: Dict[str, str], stream: bool = False) -> None:
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


    def iter_content(self, chunk_size: Optional[int] = 1024) -> Iterator[bytes]:
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

    async def aiter_content(self, chunk_size: Optional[int] = 8192) -> AsyncGenerator[bytes, None]:
        """Async chunked iterator (reads in thread to avoid blocking event loop)."""
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

    def _apply_auth_header(self, headers: Dict[str, str], auth: Optional[Tuple[str, str]]) -> None:
        if auth:
            user, pwd = auth
            token = base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode("ascii")
            headers.setdefault("Authorization", f"Basic {token}")

    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Union[dict, str, bytes]] = None,
        json: Optional[Any] = None,  # <-- added json parameter
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        retries: Optional[int] = None,
        stream: Optional[bool] = None,
        auth: Optional[Tuple[str, str]] = None,
    ) -> HTTPResponse:
        # Merge defaults
        timeout = self.timeout if timeout is None else timeout
        retries = self.retries if retries is None else retries
        stream = self.stream if stream is None else stream

        # Build headers and params
        final_headers = dict(self.headers)  # session headers
        if headers:
            final_headers.update(headers)
        self._apply_auth_header(final_headers, auth)

        final_params = dict(self.params)
        if params:
            final_params.update(params)
        if final_params:
            url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(final_params)

        # Prepare body
        body_bytes: Optional[bytes] = None

        if json is not None:
            # JSON mode takes precedence over data
            final_headers.setdefault("Content-Type", "application/json")
            body_bytes = jsonlib.dumps(json).encode("utf-8")
        elif data is not None:
            if isinstance(data, dict):
                # Default: form-encoded
                final_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
                body_bytes = urllib.parse.urlencode(data).encode("utf-8")
            elif isinstance(data, str):
                body_bytes = data.encode("utf-8")
                final_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            elif isinstance(data, (bytes, bytearray, memoryview)):
                # Accept bytearray and memoryview as raw bytes
                body_bytes = bytes(data)  # convert to bytes if needed
            elif hasattr(data, "read") and callable(data.read):
                # Assume file-like, read bytes
                body_bytes = data.read()
                if not isinstance(body_bytes, bytes):
                    raise TypeError("file-like object's read() must return bytes")
            elif isinstance(data, Iterable):
                # Accept iterable of bytes chunks; join them
                body_bytes = b"".join(data)
            else:
                raise TypeError("data must be dict, str, or bytes")

        last_exc: Optional[Exception] = None
        for attempt in range(retries):
            try:
                req = urllib.request.Request(
                    url, data=body_bytes, headers=final_headers, method=method.upper()
                )
                raw_resp = self.opener.open(req, timeout=timeout)
                return HTTPResponse(raw_resp, raw_resp.getcode(), dict(raw_resp.getheaders()), stream=stream)
            except (HTTPError, URLError, OSError) as e:
                last_exc = e
                if isinstance(e, HTTPError):
                    raw_resp = cast(Any, e)
                    return HTTPResponse(raw_resp, e.code, dict(e.headers or {}), stream=stream)
                if attempt < retries - 1:
                    time.sleep(1)
                    continue
                raise last_exc

        # Defensive fallback (should never reach here)
        raise RuntimeError("Request failed unexpectedly without raising an exception")

    # Convenience sync methods
    def get(self, url: str, **kwargs: Any) -> HTTPResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> HTTPResponse:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> HTTPResponse:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> HTTPResponse:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> HTTPResponse:
        return self.request("DELETE", url, **kwargs)

    # Async wrappers using asyncio.to_thread to avoid blocking the event loop
    async def async_request(self, method: str, url: str, **kwargs: Any) -> HTTPResponse:
        return await asyncio.to_thread(self.request, method, url, **kwargs)

    async def async_get(self, url: str, **kwargs: Any) -> HTTPResponse:
        return await self.async_request("GET", url, **kwargs)

    async def async_post(self, url: str, **kwargs: Any) -> HTTPResponse:
        return await self.async_request("POST", url, **kwargs)

    async def async_put(self, url: str, **kwargs: Any) -> HTTPResponse:
        return await self.async_request("PUT", url, **kwargs)

    async def async_patch(self, url: str, **kwargs: Any) -> HTTPResponse:
        return await self.async_request("PATCH", url, **kwargs)

    async def async_delete(self, url: str, **kwargs: Any) -> HTTPResponse:
        return await self.async_request("DELETE", url, **kwargs)

    # Context manager support
    def __enter__(self) -> "Session":
        return self

    def __exit__(self, exc_type: Optional[type], exc: Optional[BaseException], tb: Optional[Any]) -> bool:
        # nothing special to close; cookiejar/opener don't need explicit close
        return False

    def close(self) -> None:
        """
        Close the session by clearing cookies and closing any underlying resources.
        This is just for API consistency, this isn't needed if using a Context manager"""
        # Clear all cookies
        self._cookie_jar.clear()

        # Try to close the opener if it has a close method (some custom openers might)
        close_method = getattr(self.opener, "close", None)
        if callable(close_method):
            close_method()
