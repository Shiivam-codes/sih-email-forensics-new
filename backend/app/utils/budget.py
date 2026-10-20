import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from app.utils.cache import TTLCache


class RequestBudget:
    def __init__(
        self,
        cache: TTLCache,
        daily_limit: int,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.cache = cache
        self.daily_limit = max(0, daily_limit)
        self._now = now or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()

    def _key(self) -> str:
        return f"budget:{self._now().date().isoformat()}"

    def _ttl_seconds(self) -> int:
        current = self._now()
        tomorrow = datetime.combine(
            current.date() + timedelta(days=1), datetime.min.time(), tzinfo=UTC
        )
        return max(60, int((tomorrow - current).total_seconds()) + 60)

    def consume(self, source: str) -> bool:
        with self._lock:
            record = self.cache.get(self._key()) or {"count": 0, "sources": {}}
            count = int(record.get("count", 0))
            if count >= self.daily_limit:
                return False
            record["count"] = count + 1
            sources = record.setdefault("sources", {})
            sources[source] = int(sources.get(source, 0)) + 1
            self.cache.set(self._key(), record, self._ttl_seconds())
            return True

    def remaining(self) -> int:
        record = self.cache.get(self._key()) or {"count": 0}
        return max(0, self.daily_limit - int(record.get("count", 0)))
