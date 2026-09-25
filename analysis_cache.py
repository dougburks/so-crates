"""In-memory caches of per-analysis query results.

Cache of the unfiltered (no search query) Sankey/aggregation result per
(md5, event_type) - the events table is written once by create_sqlite_db
and never mutated afterward except by delete/reanalyze (both evict), so
caching it is safe and turns every repeat tab-view after the first into a
no-op instead of a multi-hundred-ms SQL recomputation.
"""

import threading

from db import AGGREGATION_JSON_PATHS, REAL_AGGREGATION_COLUMNS

SANKEY_CACHE = {}
AGGREGATION_CACHE = {}
AGGREGATION_TOTALS_CACHE = {}
# Single source of truth for "every analysis-result cache": evict_analysis_cache
# and the delete-all handler must always cover the same set, so a new cache
# added here is automatically evicted/cleared in both places.
ALL_CACHES = (SANKEY_CACHE, AGGREGATION_CACHE, AGGREGATION_TOTALS_CACHE)
CACHE_LOCK = threading.Lock()
# Backstop against cache-fill abuse: cache keys include client-supplied
# strings, so even with per-key validation the total entry count is bounded.
CACHE_MAX_ENTRIES = 2048


def evict_analysis_cache(md5):
    with CACHE_LOCK:
        for cache in ALL_CACHES:
            for key in [k for k in cache if k[0] == md5]:
                del cache[key]


def cache_put(cache, key, value):
    """Insert into an analysis cache; caller must hold CACHE_LOCK."""
    if len(cache) >= CACHE_MAX_ENTRIES:
        cache.clear()
    cache[key] = value


def cacheable_aggregation_key(event_type, column=None):
    """Only cache keys built from recognized event types/columns - arbitrary
    client strings must not become permanent cache entries (memory DoS)."""
    if event_type is not None and event_type not in AGGREGATION_JSON_PATHS:
        return False
    if column is None:
        return True
    if column in REAL_AGGREGATION_COLUMNS:
        return True
    if event_type is None:
        return column in ('Type', 'Detail')
    return column in AGGREGATION_JSON_PATHS[event_type]
