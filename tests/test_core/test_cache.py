"""Tests for cache."""

from deeplook.core.cache import ResultCache


class TestResultCache:
    def test_set_and_get(self, tmp_path):
        cache = ResultCache(base_dir=tmp_path, ttl_hours=24)
        cache.set("test-plugin", "example.com", {"entities": 5})
        result = cache.get("test-plugin", "example.com")
        assert result is not None
        assert result["entities"] == 5
        cache.close()

    def test_cache_miss(self, tmp_path):
        cache = ResultCache(base_dir=tmp_path, ttl_hours=24)
        result = cache.get("test-plugin", "nonexistent.com")
        assert result is None
        cache.close()

    def test_invalidate(self, tmp_path):
        cache = ResultCache(base_dir=tmp_path, ttl_hours=24)
        cache.set("test-plugin", "example.com", {"entities": 5})
        count = cache.invalidate("test-plugin")
        assert count == 1
        result = cache.get("test-plugin", "example.com")
        assert result is None
        cache.close()

    def test_stats(self, tmp_path):
        cache = ResultCache(base_dir=tmp_path, ttl_hours=24)
        cache.set("test-plugin", "example.com", {"entities": 5})
        stats = cache.stats()
        assert stats["total_entries"] == 1
        cache.close()
