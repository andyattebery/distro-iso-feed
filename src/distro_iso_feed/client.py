"""HTTP client: identifiable UA, retries with backoff, honors 429.

Two rules from the spec that are easy to get wrong:

* A ``304`` is an optimization, never the changed/unchanged verdict (§11). This
  client returns bodies and hashes; `state.py` decides what changed.
* Detection never fetches the artifact. No ISO is downloaded, and no ``HEAD`` is
  issued just to fill in an optional enclosure ``length``.

Two more, learned the hard way from a night when cdimage.debian.org read-timed out for 18
minutes and the run re-asked it 35 times (~100% of the run blocked on one sick host):

* **Per-host failure budget** (`host_budget`). Only a *transient* failure counts -- a 404 means
  the host is fine and the file is gone, and counting it would skip a healthy mirror's distros.
* **`get_cached`** memoizes the small sidecars fetched more than once per variant. `get` itself
  is deliberately NOT cached: `diagnose` re-fetches on purpose to observe the current outcome.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import time
from collections import Counter
from urllib.parse import urlsplit

import httpx

log = logging.getLogger(__name__)

# httpx logs every request at INFO, which drowns the resolver's own output.
logging.getLogger("httpx").setLevel(logging.WARNING)

RETRY_STATUS = {429, 500, 502, 503, 504}

# The trace outcome recorded when a host's failure budget short-circuits a fetch. It is a `str`,
# so `escalate.classify_outcomes` reads it as TRANSIENT -- which is the whole point: skipping a
# fetch must never look like a structural regression. An empty trace slice classifies STRUCTURAL,
# so returning None *without* recording this would file a bogus issue per skipped variant.
BUDGET_EXHAUSTED = "HostBudgetExhausted"

# Fully-failed (transient) fetches to one host before the rest of its URLs are skipped for the
# run. 3 x ~92s of demonstrated trouble before we stop asking; measured against the incident,
# this trips ~13 min earlier than not having it, while still tolerating a slow file or two.
DEFAULT_HOST_BUDGET = 3


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
        host_budget: int = DEFAULT_HOST_BUDGET,
        sleep=time.sleep,
    ) -> None:
        self.retries = retries
        self.backoff = backoff
        self.host_budget = host_budget
        self._sleep = sleep
        # Per-request outcome log: `(url, status_code | exception_name)`. The listers collapse a
        # 404, a 200-empty page, and a timeout all to `[]`, so this is where the *actual* outcome
        # survives -- `run_refresh.diagnose` reads it to tell a structural break (reachable, wrong
        # content) from a transient one (unreachable). In-memory only; never persisted.
        self.trace: list[tuple[str, int | str]] = []
        # netloc -> fully-failed (transient) fetches this run. Cumulative, NOT consecutive: during
        # the incident, successes were interleaved among the failures (an index here, a torrent
        # there), so a consecutive counter would have reset constantly and never tripped.
        self._host_failures: Counter[str] = Counter()
        # url -> Response, for `get_cached` only. Successes only, and never consulted by `get`.
        self._cache: dict[str, Response] = {}
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
        """Return the response, or None if it never succeeded. Never raises.

        Not cached -- `diagnose` depends on this hitting the wire (it reads `trace` for the
        *current* outcome). Use `get_cached` for a sidecar read more than once per variant.
        """
        host = urlsplit(url).netloc
        if self._host_failures[host] >= self.host_budget:
            # This host already burned its budget on transient failures. Skip without asking:
            # the trace entry keeps it classified TRANSIENT, so callers leave entries untouched
            # and retry tomorrow rather than escalating.
            self.trace.append((url, BUDGET_EXHAUSTED))
            log.info("GET %s skipped: %s over its failure budget this run", url, host)
            return None

        for attempt in range(self.retries):
            try:
                r = self._http.get(url, headers=headers)
            except httpx.HTTPError as exc:
                log.warning("GET %s failed: %s", url, exc)
                self.trace.append((url, type(exc).__name__))  # network error -> transient
                self._wait(attempt, None)
                continue

            self.trace.append((url, r.status_code))
            if r.status_code in RETRY_STATUS:
                log.warning("GET %s -> %s", url, r.status_code)
                self._wait(attempt, r.headers.get("Retry-After"))
                continue

            if r.status_code >= 400:
                # STRUCTURAL: the host answered, the file is gone. Deliberately does NOT count
                # against the budget -- several sources carry optional per-file sidecars that
                # legitimately 404, and charging those would skip a perfectly healthy mirror.
                log.info("GET %s -> %s", url, r.status_code)
                return None

            return Response(str(r.url), r.status_code, r.content)

        # Every attempt failed transiently (network error, or a retry-status that never cleared).
        self._host_failures[host] += 1
        if self._host_failures[host] == self.host_budget:
            log.warning(
                "%s: %d failed fetches this run -- skipping its remaining URLs "
                "(transient; those entries are left untouched and retried next run)",
                host,
                self.host_budget,
            )
        return None

    def get_cached(self, url: str) -> Response | None:
        """A memo for the small sidecars fetched more than once per variant.

        A SHA*SUMS is read twice: the strategy pulls the hashes out of it, then `signing`
        gpg-verifies the same file. Two GETs is both rude to the mirror and a TOCTOU -- the
        second fetch can disagree with the first, and only the first is published. (That race
        is exactly how a `checksum=None` met a *successfully* re-fetched SUMS and produced a
        bogus "rotated key" ticket.)

        Successes only: a failure must stay retryable, and it must keep reaching `get` so the
        host failure budget still sees it. Returns the same `Response`, so callers get the
        original bytes -- `verify_detached` needs them, and a decode/re-encode round-trip is
        not byte-identical for a non-UTF8 sums file.
        """
        if url in self._cache:
            return self._cache[url]
        r = self.get(url)
        if r is not None:
            self._cache[url] = r
        return r

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
