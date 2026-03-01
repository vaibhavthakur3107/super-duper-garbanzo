"""
Smart Caching System
Intelligent result caching with LRU eviction for tool results,
scan data, and CVE lookups. Inspired by hexstrike-ai caching engine.
"""

import hashlib
import json
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class _CacheEntry:
    """Internal wrapper around a cached value with expiry metadata."""

    value: Any
    created_at: float = field(default_factory=time.time)
    ttl: Optional[float] = None

    @property
    def expired(self) -> bool:
        if self.ttl is None:
            return False
        return (time.time() - self.created_at) >= self.ttl


class SmartCache:
    """
    Thread-safe LRU cache with per-entry TTL support.

    Parameters
    ----------
    max_size : int
        Maximum number of entries before LRU eviction kicks in.
    default_ttl : float | None
        Default time-to-live in seconds.  ``None`` means entries never expire
        unless an explicit *ttl* is passed to :meth:`set`.
    """

    def __init__(self, max_size: int = 1024, default_ttl: Optional[float] = None):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._store: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._lock = threading.Lock()

        # stats
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    # ── Public API ───────────────────────────────────────────────────────────

    def get(self, key: str) -> Optional[Any]:
        """Return cached value or ``None`` if missing / expired."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None
            if entry.expired:
                self._store.pop(key, None)
                self._misses += 1
                return None
            # Mark as recently used
            self._store.move_to_end(key)
            self._hits += 1
            return entry.value

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Insert or update a cache entry, evicting LRU items if necessary."""
        effective_ttl = ttl if ttl is not None else self.default_ttl
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
                self._store[key] = _CacheEntry(value=value, ttl=effective_ttl)
            else:
                if len(self._store) >= self.max_size:
                    self._store.popitem(last=False)
                    self._evictions += 1
                self._store[key] = _CacheEntry(value=value, ttl=effective_ttl)

    def invalidate(self, key: str) -> bool:
        """Remove a single key.  Returns ``True`` if the key existed."""
        with self._lock:
            return self._store.pop(key, None) is not None

    def clear(self) -> None:
        """Drop all entries and reset statistics."""
        with self._lock:
            self._store.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0

    def get_stats(self) -> dict:
        """Return cache performance statistics."""
        with self._lock:
            total = self._hits + self._misses
            return {
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "size": len(self._store),
                "max_size": self.max_size,
                "hit_rate": (self._hits / total) if total else 0.0,
            }

    # ── Tool-result helpers ──────────────────────────────────────────────────

    @staticmethod
    def _make_key(tool_name: str, target: str, params: Optional[dict] = None) -> str:
        """Deterministic key from tool invocation parameters."""
        raw = json.dumps(
            {"tool": tool_name, "target": target, "params": params or {}},
            sort_keys=True,
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    def cache_tool_result(
        self,
        tool_name: str,
        target: str,
        params: Optional[dict],
        result: Any,
        ttl: Optional[float] = None,
    ) -> None:
        """Cache the result of a security-tool invocation."""
        key = self._make_key(tool_name, target, params)
        self.set(key, result, ttl=ttl)

    def get_cached_result(
        self,
        tool_name: str,
        target: str,
        params: Optional[dict] = None,
    ) -> Optional[Any]:
        """Retrieve a previously cached tool result."""
        key = self._make_key(tool_name, target, params)
        return self.get(key)


# Module-level default instance
tool_cache = SmartCache(max_size=1024, default_ttl=600)
