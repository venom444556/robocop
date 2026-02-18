"""Tests for enrichment result cache."""

import time
from unittest.mock import patch
import pytest

from enrichment.cache import EnrichmentCache, get_enrichment_cache


class TestEnrichmentCache:
    def test_set_and_get(self):
        cache = EnrichmentCache()
        cache.set("virustotal", "ip", "8.8.8.8", {"found": True, "score": 5})
        result = cache.get("virustotal", "ip", "8.8.8.8")
        assert result is not None
        assert result["found"] is True
        assert result["score"] == 5

    def test_get_missing_returns_none(self):
        cache = EnrichmentCache()
        assert cache.get("virustotal", "ip", "1.1.1.1") is None

    def test_expired_entry_returns_none(self):
        cache = EnrichmentCache(default_ttl=0)
        cache.set("shodan", "ip", "8.8.8.8", {"found": True})
        time.sleep(0.01)
        assert cache.get("shodan", "ip", "8.8.8.8") is None

    def test_custom_ttl(self):
        cache = EnrichmentCache(default_ttl=3600)
        cache.set("greynoise", "ip", "8.8.8.8", {"noise": True}, ttl=0)
        time.sleep(0.01)
        assert cache.get("greynoise", "ip", "8.8.8.8") is None

    def test_max_size_eviction(self):
        cache = EnrichmentCache(max_size=3)
        cache.set("a", "ip", "1", {"v": 1})
        cache.set("b", "ip", "2", {"v": 2})
        cache.set("c", "ip", "3", {"v": 3})
        assert cache.size == 3
        cache.set("d", "ip", "4", {"v": 4})
        assert cache.size == 3  # oldest evicted

    def test_clear(self):
        cache = EnrichmentCache()
        cache.set("a", "ip", "1", {"v": 1})
        cache.set("b", "ip", "2", {"v": 2})
        cache.clear()
        assert cache.size == 0
        assert cache.get("a", "ip", "1") is None

    def test_key_isolation(self):
        cache = EnrichmentCache()
        cache.set("virustotal", "ip", "8.8.8.8", {"source": "vt"})
        cache.set("shodan", "ip", "8.8.8.8", {"source": "shodan"})
        cache.set("virustotal", "domain", "8.8.8.8", {"source": "vt_domain"})

        assert cache.get("virustotal", "ip", "8.8.8.8")["source"] == "vt"
        assert cache.get("shodan", "ip", "8.8.8.8")["source"] == "shodan"
        assert cache.get("virustotal", "domain", "8.8.8.8")["source"] == "vt_domain"

    def test_evict_expired(self):
        cache = EnrichmentCache(default_ttl=0)
        cache.set("a", "ip", "1", {"v": 1})
        cache.set("b", "ip", "2", {"v": 2})
        time.sleep(0.01)
        removed = cache._evict_expired()
        assert removed == 2
        assert cache.size == 0


class TestGetEnrichmentCache:
    def test_returns_singleton(self):
        # Reset singleton for test isolation
        import enrichment.cache as cache_mod
        cache_mod._cache_instance = None

        c1 = get_enrichment_cache()
        c2 = get_enrichment_cache()
        assert c1 is c2

        # Clean up
        cache_mod._cache_instance = None
