"""In-memory TTL cache for enrichment results."""

import time
from typing import Any, Optional


class EnrichmentCache:
    """Simple in-memory cache with TTL expiration for enrichment lookups."""

    def __init__(self, default_ttl: int = 3600, max_size: int = 10000):
        self._cache: dict[str, tuple[float, Any]] = {}
        self._default_ttl = default_ttl
        self._max_size = max_size

    def _make_key(self, source: str, ioc_type: str, ioc_value: str) -> str:
        return f"{source}:{ioc_type}:{ioc_value}"

    def get(self, source: str, ioc_type: str, ioc_value: str) -> Optional[Any]:
        """Retrieve cached result, or None if missing/expired."""
        key = self._make_key(source, ioc_type, ioc_value)
        entry = self._cache.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if time.monotonic() > expires_at:
            del self._cache[key]
            return None
        return value

    def set(self, source: str, ioc_type: str, ioc_value: str,
            value: Any, ttl: Optional[int] = None) -> None:
        """Store a result in the cache."""
        if len(self._cache) >= self._max_size:
            self._evict_expired()
            if len(self._cache) >= self._max_size:
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]

        key = self._make_key(source, ioc_type, ioc_value)
        expires_at = time.monotonic() + (ttl if ttl is not None else self._default_ttl)
        self._cache[key] = (expires_at, value)

    def _evict_expired(self) -> int:
        """Remove all expired entries. Returns count removed."""
        now = time.monotonic()
        expired = [k for k, (exp, _) in self._cache.items() if now > exp]
        for k in expired:
            del self._cache[k]
        return len(expired)

    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()

    @property
    def size(self) -> int:
        return len(self._cache)


_cache_instance: Optional[EnrichmentCache] = None


def get_enrichment_cache() -> EnrichmentCache:
    """Get the global enrichment cache singleton."""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = EnrichmentCache()
    return _cache_instance
