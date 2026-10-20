import json
import threading
import time
from pathlib import Path
from typing import Any

from diskcache import Cache as DiskCache


class _MemoryCache:
    def __init__(self) -> None:
        self._data: dict[str, tuple[float, str]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            expires_at, payload = item
            if expires_at and expires_at <= time.monotonic():
                self._data.pop(key, None)
                return None
        return json.loads(payload)

    def set(self, key: str, value: Any, expire: int | float | None = None) -> None:
        serialized = json.dumps(value, ensure_ascii=False, default=str)
        expires_at = time.monotonic() + float(expire) if expire else 0.0
        with self._lock:
            self._data[key] = (expires_at, serialized)

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def close(self) -> None:
        return None


class TTLCache:
    def __init__(self, path: str) -> None:
        self.path = path
        self.backend = "memory"
        self._cache: DiskCache | _MemoryCache
        try:
            Path(path).mkdir(parents=True, exist_ok=True)
            self._cache = DiskCache(path)
            self.backend = "diskcache"
        except OSError:
            self._cache = _MemoryCache()

    def get(self, key: str) -> Any | None:
        return self._cache.get(key)

    def set(self, key: str, value: Any, ttl_seconds: int | float) -> None:
        self._cache.set(key, value, expire=ttl_seconds)

    def delete(self, key: str) -> None:
        self._cache.delete(key)

    def clear(self) -> None:
        self._cache.clear()

    def close(self) -> None:
        self._cache.close()
