"""HTTP client: identifiable UA, retries with backoff, honors 429.

Two rules from the spec that are easy to get wrong:

* A ``304`` is an optimization, never the changed/unchanged verdict (§11). This
  client returns bodies and hashes; `state.py` decides what changed.
* Detection never fetches the artifact. No ISO is downloaded, and no ``HEAD`` is
  issued just to fill in an optional enclosure ``length``.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import time

import httpx

log = logging.getLogger(__name__)

# httpx logs every request at INFO, which drowns the resolver's own output.
logging.getLogger("httpx").setLevel(logging.WARNING)

RETRY_STATUS = {429, 500, 502, 503, 504}


class Response:
    __slots__ = ("url", "status_code", "text", "content")

    def __init__(self, url: str, status_code: int, content: bytes) -> None:
        self.url = url
        self.status_code = status_code
        self.content = content
        self.text = content.decode("utf-8", errors="replace")

    @property
    def hash(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


class Client:
    def __init__(
        self,
        user_agent: str,
        *,
        timeout: float = 30.0,
        retries: int = 3,
        backoff: float = 1.5,
        sleep=time.sleep,
    ) -> None:
        self.retries = retries
        self.backoff = backoff
        self._sleep = sleep
        self._http = httpx.Client(
            headers={"User-Agent": user_agent},
            timeout=timeout,
            follow_redirects=True,
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def get(self, url: str, headers: dict[str, str] | None = None) -> Response | None:
        """Return the response, or None if it never succeeded. Never raises."""
        for attempt in range(self.retries):
            try:
                r = self._http.get(url, headers=headers)
            except httpx.HTTPError as exc:
                log.warning("GET %s failed: %s", url, exc)
                self._wait(attempt, None)
                continue

            if r.status_code in RETRY_STATUS:
                log.warning("GET %s -> %s", url, r.status_code)
                self._wait(attempt, r.headers.get("Retry-After"))
                continue

            if r.status_code >= 400:
                log.info("GET %s -> %s", url, r.status_code)
                return None

            return Response(str(r.url), r.status_code, r.content)
        return None

    def exists(self, url: str) -> bool:
        """Used only for candidate probes (NixOS channels), never for artifacts."""
        try:
            r = self._http.head(url)
            if r.status_code == 405:
                r = self._http.get(url, headers={"Range": "bytes=0-0"})
            return r.status_code < 400
        except httpx.HTTPError:
            return False

    def text(self, url: str, headers: dict[str, str] | None = None) -> str | None:
        r = self.get(url, headers=headers)
        return r.text if r else None

    def _wait(self, attempt: int, retry_after: str | None) -> None:
        delay = self.backoff**attempt
        if retry_after:
            with contextlib.suppress(ValueError):
                delay = max(delay, float(retry_after))
        self._sleep(delay)
