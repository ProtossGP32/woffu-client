# stdrequests_session.py
import urllib.request
import urllib.parse
import json
import time
import asyncio
import base64
from typing import Any, Optional, Dict, Union, Generator, AsyncGenerator, Tuple, cast
import http.cookiejar
from http.client import HTTPResponse as _HTTPClientResponse
from urllib.error import URLError, HTTPError


class HTTPResponse:
    def __init__(self, raw_resp: Any, status: int, headers: dict, stream: bool = False):
        self._raw = raw_resp
        self.status = status
        self.headers = headers
        self._stream = stream
        self._content_cache = None

    def text(self) -> str:
        return self.content().decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text())

    def content(self) -> bytes:
        if self._stream:
            raise RuntimeError("Use iter_content() when stream=True")
        if self._content_cache is None:
            # read all
            self._content_cache = self._raw.read()
        return self._content_cache

    def iter_content(self, chunk_size: int = 8192) -> Generator[bytes, None, None]:
        """Sync chunked iterator for streaming responses."""
        if not self._stream and self._content_cache is not None:
            # yield from cache
            for i in range(0, len(self._content_cache), chunk_size):
                yield self._content_cache[i : i + chunk_size]
            return

        while True:
            chunk = self._raw.read(chunk_size)
            if not chunk:
                break
            yield chunk

    async def aiter_content(self, chunk_size: int = 8192) -> AsyncGenerator[bytes, None]:
        """Async chunked iterator (reads in thread to avoid blocking event loop)."""
        while True:
            chunk = await asyncio.to_thread(self._raw.read, chunk_size)
            if not chunk:
                break
            yield chunk


class Session:
    def __init__(
        self,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        timeout: int = 10,
        retries: int = 3,
        stream: bool = False,
    ):
        self.headers = dict(headers or {})
        self.params = dict(params or {})
        self.timeout = timeout
        self.retries = retries
        self.stream = stream

        # Cookie handling
        self._cookie_jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._cookie_jar),
            urllib.request.HTTPRedirectHandler()
        )

        # Allow user to set a custom opener later if desired
        self.opener = self._opener

    def _apply_auth_header(self, headers: Dict[str, str], auth: Optional[Tuple[str, str]]):
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
        body_bytes = None
        if data is not None:
            if isinstance(data, dict):
                final_headers.setdefault("Content-Type", "application/json")
                body_bytes = json.dumps(data).encode("utf-8")
            elif isinstance(data, str):
                body_bytes = data.encode("utf-8")
            elif isinstance(data, bytes):
                body_bytes = data
            else:
                raise TypeError("data must be dict, str, or bytes")

        last_exc = None
        for attempt in range(retries):
            try:
                req = urllib.request.Request(url, data=body_bytes, headers=final_headers, method=method.upper())
                raw_resp = self.opener.open(req, timeout=timeout)
                # raw_resp is an http.client.HTTPResponse-like object
                return HTTPResponse(raw_resp, raw_resp.getcode(), dict(raw_resp.getheaders()), stream=stream)
            except (HTTPError, URLError, OSError) as e:
                last_exc = e
                # If it's an HTTPError with a status code, return it (mimic requests behavior)
                if isinstance(e, HTTPError):
                    # Cast e to Any to satisfy type checker despite signature mismatch
                    raw_resp = cast(Any, e)
                    return HTTPResponse(raw_resp, e.code, dict(e.headers or {}), stream=stream)
                if attempt < retries - 1:
                    time.sleep(1)
                    continue
                raise last_exc

        # Defensive fallback (should never reach here)
        raise RuntimeError("Request failed unexpectedly without raising an exception")

    # Convenience sync methods
    def get(self, url: str, **kwargs) -> HTTPResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> HTTPResponse:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> HTTPResponse:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs) -> HTTPResponse:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs) -> HTTPResponse:
        return self.request("DELETE", url, **kwargs)

    # Async wrappers using asyncio.to_thread to avoid blocking the event loop
    async def async_request(self, method: str, url: str, **kwargs) -> HTTPResponse:
        return await asyncio.to_thread(self.request, method, url, **kwargs)

    async def async_get(self, url: str, **kwargs) -> HTTPResponse:
        return await self.async_request("GET", url, **kwargs)

    async def async_post(self, url: str, **kwargs) -> HTTPResponse:
        return await self.async_request("POST", url, **kwargs)

    async def async_put(self, url: str, **kwargs) -> HTTPResponse:
        return await self.async_request("PUT", url, **kwargs)

    async def async_patch(self, url: str, **kwargs) -> HTTPResponse:
        return await self.async_request("PATCH", url, **kwargs)

    async def async_delete(self, url: str, **kwargs) -> HTTPResponse:
        return await self.async_request("DELETE", url, **kwargs)

    # Context manager support
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        # nothing special to close; cookiejar/opener don't need explicit close
        return False
