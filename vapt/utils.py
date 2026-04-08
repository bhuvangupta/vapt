"""Shared utilities: HTTP client, subprocess runner, rate limiter."""

import asyncio
import ssl
import time
from contextlib import asynccontextmanager
from urllib.parse import urlparse

import httpx


class RateLimiter:
    """Token-bucket rate limiter for async requests."""

    def __init__(self, rate: float = 2.0):
        self._rate = rate
        self._tokens = rate
        self._max_tokens = rate
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        wait = 0.0
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._max_tokens, self._tokens + elapsed * self._rate)
            self._last_refill = now
            if self._tokens < 1:
                wait = (1 - self._tokens) / self._rate
                self._tokens = 0
            else:
                self._tokens -= 1
        if wait > 0:
            await asyncio.sleep(wait)


class OutOfScopeError(Exception):
    """Raised when a request URL is outside the configured scope."""


_MAX_REDIRECTS = 10
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class AsyncHttpClient:
    """Wrapper around httpx.AsyncClient with rate limiting and scope enforcement.

    Redirects are followed manually so that every hop is checked against the
    target scope.  This prevents an in-scope endpoint from bouncing the
    scanner to an out-of-scope or internal destination.
    """

    def __init__(self, timeout: int = 10, rate_limit: float = 2.0,
                 user_agent: str = "VAPT-Scanner/1.0", follow_redirects: bool = True,
                 verify_ssl: bool = True, target=None):
        self._timeout = timeout
        self._rate_limiter = RateLimiter(rate_limit)
        self._user_agent = user_agent
        self._follow_redirects = follow_redirects
        self._verify_ssl = verify_ssl
        self._client: httpx.AsyncClient | None = None
        self._target = target  # TargetConfig — used for scope enforcement

    async def __aenter__(self):
        # Always disable httpx's own redirect following — we handle it in
        # _request_with_scope_checked_redirects so every hop is validated.
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout),
            follow_redirects=False,
            verify=self._verify_ssl,
            headers={"User-Agent": self._user_agent},
            http2=True,
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    def _check_scope(self, url: str) -> None:
        """Raise OutOfScopeError if the URL is outside the target scope."""
        if self._target is not None and not self._target.is_in_scope(url):
            raise OutOfScopeError(f"URL out of scope: {url}")

    async def _follow_with_scope(self, resp: httpx.Response, method: str,
                                 req_kwargs: dict) -> httpx.Response:
        """Follow redirects while checking scope on every hop.

        Matches stock httpx semantics:
        - 301/302/303 → convert to GET, drop body.
        - 307/308 → preserve method and body.
        - Cross-host redirects strip Authorization, Cookie, and auth
          to avoid leaking credentials to a different host (even if
          it is within the configured scope).
        """
        original_host = resp.url.host
        seen = 0

        while resp.status_code in _REDIRECT_STATUSES and seen < _MAX_REDIRECTS:
            location = resp.headers.get("location")
            if not location:
                break
            next_url = str(resp.url.join(location))
            self._check_scope(next_url)
            await self._rate_limiter.acquire()

            next_host = urlparse(next_url).hostname

            # --- Determine method and body per RFC 7231 / 7538 ---
            follow_kwargs: dict = {}
            if resp.status_code in (301, 302, 303):
                # Convert to GET, drop body (standard browser behavior)
                method = "GET"
            elif resp.status_code in (307, 308):
                # Preserve method AND body
                for k in ("data", "json", "content"):
                    if k in req_kwargs:
                        follow_kwargs[k] = req_kwargs[k]

            # Carry over params (query string context)
            if "params" in req_kwargs:
                follow_kwargs["params"] = req_kwargs["params"]

            # --- Credential safety on cross-host redirects ---
            same_host = (next_host == original_host)

            if "headers" in req_kwargs:
                headers = dict(req_kwargs["headers"])
                if not same_host:
                    # Strip sensitive headers when host changes
                    for h in ("authorization", "cookie", "proxy-authorization"):
                        headers = {k: v for k, v in headers.items()
                                   if k.lower() != h}
                follow_kwargs["headers"] = headers

            if same_host:
                if "cookies" in req_kwargs:
                    follow_kwargs["cookies"] = req_kwargs["cookies"]
                if "auth" in req_kwargs:
                    follow_kwargs["auth"] = req_kwargs["auth"]
            # Cross-host: cookies and auth are intentionally NOT forwarded

            resp = await self._client.request(method, next_url, **follow_kwargs)
            seen += 1
        return resp

    async def get(self, url: str, **kwargs) -> httpx.Response:
        self._check_scope(url)
        follow = kwargs.pop("follow_redirects", self._follow_redirects)
        await self._rate_limiter.acquire()
        resp = await self._client.get(url, **kwargs)
        if follow and resp.status_code in _REDIRECT_STATUSES:
            resp = await self._follow_with_scope(resp, "GET", kwargs)
        return resp

    async def post(self, url: str, **kwargs) -> httpx.Response:
        self._check_scope(url)
        follow = kwargs.pop("follow_redirects", self._follow_redirects)
        await self._rate_limiter.acquire()
        resp = await self._client.post(url, **kwargs)
        if follow and resp.status_code in _REDIRECT_STATUSES:
            resp = await self._follow_with_scope(resp, "POST", kwargs)
        return resp

    async def put(self, url: str, **kwargs) -> httpx.Response:
        self._check_scope(url)
        follow = kwargs.pop("follow_redirects", self._follow_redirects)
        await self._rate_limiter.acquire()
        resp = await self._client.put(url, **kwargs)
        if follow and resp.status_code in _REDIRECT_STATUSES:
            resp = await self._follow_with_scope(resp, "PUT", kwargs)
        return resp

    async def delete(self, url: str, **kwargs) -> httpx.Response:
        self._check_scope(url)
        await self._rate_limiter.acquire()
        return await self._client.delete(url, **kwargs)

    async def head(self, url: str, **kwargs) -> httpx.Response:
        self._check_scope(url)
        follow = kwargs.pop("follow_redirects", self._follow_redirects)
        await self._rate_limiter.acquire()
        resp = await self._client.head(url, **kwargs)
        if follow and resp.status_code in _REDIRECT_STATUSES:
            resp = await self._follow_with_scope(resp, "HEAD", kwargs)
        return resp

    async def options(self, url: str, **kwargs) -> httpx.Response:
        self._check_scope(url)
        await self._rate_limiter.acquire()
        return await self._client.options(url, **kwargs)

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        self._check_scope(url)
        follow = kwargs.pop("follow_redirects", self._follow_redirects)
        await self._rate_limiter.acquire()
        resp = await self._client.request(method, url, **kwargs)
        if follow and resp.status_code in _REDIRECT_STATUSES:
            resp = await self._follow_with_scope(resp, method, kwargs)
        return resp


async def run_command(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run an external command asynchronously.

    Returns (returncode, stdout, stderr).
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return (
            proc.returncode or 0,
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )
    except asyncio.TimeoutError:
        proc.kill()
        return (-1, "", f"Command timed out after {timeout}s")
    except FileNotFoundError:
        return (-1, "", f"Command not found: {cmd[0]}")


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    return urlparse(url).netloc


def normalize_url(url: str) -> str:
    """Ensure URL has scheme."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")
