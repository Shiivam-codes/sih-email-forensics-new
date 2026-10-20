import time
from collections import defaultdict
from typing import Any

import httpx

from app.utils.budget import RequestBudget

USER_AGENT = "SIH-Email-Forensics/0.1 (defensive analysis; contact: local-demo)"


class SourceUnavailable(RuntimeError):
    def __init__(self, source: str, reason: str) -> None:
        super().__init__(f"{source}: {reason}")
        self.source = source
        self.reason = reason


class BudgetExceeded(SourceUnavailable):
    def __init__(self, source: str) -> None:
        super().__init__(source, "daily external request budget exhausted")


class HttpClient:
    def __init__(
        self,
        timeout_seconds: float = 4.0,
        offline: bool = False,
        transport: httpx.BaseTransport | None = None,
        max_failures: int = 3,
    ) -> None:
        self.offline = offline
        self.max_failures = max(1, max_failures)
        self._failures: dict[str, int] = defaultdict(int)
        self._disabled: set[str] = set()
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout_seconds, connect=min(3.0, timeout_seconds)),
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/plain"},
            transport=transport,
        )

    @property
    def disabled_sources(self) -> set[str]:
        return set(self._disabled)

    def _guard(self, source: str, budget: RequestBudget | None) -> None:
        if self.offline:
            raise SourceUnavailable(source, "offline mode")
        if source in self._disabled:
            raise SourceUnavailable(source, "circuit breaker open after repeated failures")
        if budget is not None and not budget.consume(source):
            raise BudgetExceeded(source)

    def _record_failure(self, source: str) -> None:
        self._failures[source] += 1
        if self._failures[source] >= self.max_failures:
            self._disabled.add(source)

    def _request(self, url: str, source: str, budget: RequestBudget | None) -> httpx.Response:
        self._guard(source, budget)
        last_error: Exception | None = None
        for attempt in range(2):
            try:
                response = self._client.get(url)
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt == 0:
                    time.sleep(0.15)
                    continue
                break
            if response.status_code >= 500 or response.status_code == 429:
                last_error = SourceUnavailable(source, f"HTTP {response.status_code}")
                if attempt == 0:
                    time.sleep(0.15)
                    continue
                self._record_failure(source)
                raise SourceUnavailable(source, f"HTTP {response.status_code}")
            self._failures[source] = 0
            return response
        self._record_failure(source)
        reason = str(last_error) if last_error else "request failed"
        raise SourceUnavailable(source, reason)

    def get_json(
        self,
        url: str,
        source: str,
        budget: RequestBudget | None = None,
        allow_404: bool = False,
    ) -> dict[str, Any] | None:
        response = self._request(url, source, budget)
        if response.status_code == 404 and allow_404:
            return None
        if response.status_code >= 400:
            self._record_failure(source)
            raise SourceUnavailable(source, f"HTTP {response.status_code}")
        try:
            payload = response.json()
        except ValueError as exc:
            self._record_failure(source)
            raise SourceUnavailable(source, "invalid JSON response") from exc
        if not isinstance(payload, dict):
            self._record_failure(source)
            raise SourceUnavailable(source, "unexpected JSON response")
        return payload

    def get_text(
        self,
        url: str,
        source: str,
        budget: RequestBudget | None = None,
        allow_404: bool = False,
    ) -> str | None:
        response = self._request(url, source, budget)
        if response.status_code == 404 and allow_404:
            return None
        if response.status_code >= 400:
            self._record_failure(source)
            raise SourceUnavailable(source, f"HTTP {response.status_code}")
        return response.text

    def close(self) -> None:
        self._client.close()
