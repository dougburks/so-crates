# Database

## SQLite Schema

```sql
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    timestamp TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dest_ip TEXT,
    dest_port INTEGER,
    protocol TEXT,
    app_proto TEXT,
    json_data TEXT          -- Full original eve.json line
);
CREATE INDEX idx_event_type ON events(event_type);
CREATE INDEX idx_timestamp ON events(timestamp);
CREATE INDEX idx_event_type_timestamp ON events(event_type, timestamp);

-- Composite indexes for Sankey/aggregation GROUP BY queries. event_type
-- leads every one so a single index serves both a specific-type-filtered
-- query and the merged "all events" view (see db.py's _ensure_ip_port_indexes)
CREATE INDEX idx_src_dest_ip ON events(event_type, src_ip, dest_ip);
CREATE INDEX idx_dest_ip_port ON events(event_type, dest_ip, dest_port);
CREATE INDEX idx_dest_port ON events(event_type, dest_port);
CREATE INDEX idx_src_port ON events(event_type, src_port);

-- Expression indexes for flow's JSON-extracted aggregation columns
-- (Pkts/Bytes/State/Alerted) - built dynamically from the same SQL
-- expression the query itself uses, so they can never drift out of sync
-- (see db.py's _ensure_flow_json_indexes). CAST(...AS TEXT) is required
-- for SQLite to treat the index as covering - a bare json_extract() has
-- no stable type affinity and gets re-verified against the row anyway.
CREATE INDEX idx_flow_pkts_toserver ON events(event_type, CAST(COALESCE(json_extract(json_data, '$.flow.pkts_toserver'), 0) AS TEXT));
CREATE INDEX idx_flow_pkts_toclient ON events(event_type, CAST(COALESCE(json_extract(json_data, '$.flow.pkts_toclient'), 0) AS TEXT));
CREATE INDEX idx_flow_bytes_toserver ON events(event_type, CAST(COALESCE(json_extract(json_data, '$.flow.bytes_toserver'), 0) AS TEXT));
CREATE INDEX idx_flow_bytes_toclient ON events(event_type, CAST(COALESCE(json_extract(json_data, '$.flow.bytes_toclient'), 0) AS TEXT));
CREATE INDEX idx_flow_state ON events(event_type, CAST(json_extract(json_data, '$.flow.state') AS TEXT));
CREATE INDEX idx_flow_alerted ON events(event_type, CASE WHEN CAST(json_extract(json_data, '$.flow.alerted') AS TEXT) THEN 'Yes' ELSE 'No' END);

-- FTS5 virtual table for full-text search (created when FTS5 is available)
CREATE VIRTUAL TABLE events_fts USING fts5(
    json_data,
    content='events',
    content_rowid='id'
);

-- Sigma detections (log-file analyses only, populated by importing Zircolite's output)
CREATE TABLE sigma_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    rule_title TEXT,
    rule_id TEXT,
    severity TEXT,
    level TEXT,
    logsource TEXT,
    tags TEXT,
    mitre_techniques TEXT,
    original_log TEXT,
    json_data TEXT
);
CREATE INDEX idx_sigma_severity ON sigma_alerts(severity);
CREATE INDEX idx_sigma_timestamp ON sigma_alerts(timestamp);
CREATE INDEX idx_sigma_rule_id ON sigma_alerts(rule_id);

-- One optional analyst note per row of events/sigma_alerts, keyed by a
-- (source_table, row_id) pair rather than a real FOREIGN KEY (SQLite
-- can't express a polymorphic FK against two different parent tables).
-- UNIQUE(source_table, row_id) both enforces one note per row and gives
-- SQLite's auto-created covering index for the row_id IN (...) per-page
-- lookup, so no separate CREATE INDEX is needed.
CREATE TABLE row_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_table TEXT NOT NULL CHECK (source_table IN ('events', 'sigma_alerts')),
    row_id INTEGER NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(source_table, row_id)
);

-- Same polymorphic (source_table, row_id) keying as row_notes above -
-- presence of a row means acknowledged, not a boolean column, so
-- un-acknowledging is a plain DELETE rather than an UPDATE.
CREATE TABLE acknowledged_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_table TEXT NOT NULL CHECK (source_table IN ('events', 'sigma_alerts')),
    row_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(source_table, row_id)
);

-- Performance pragmas
PRAGMA journal_mode = WAL;      -- Better concurrency between readers and writers
PRAGMA synchronous = NORMAL;    -- Faster writes with WAL crash safety
PRAGMA busy_timeout = 30000;    -- Retry for 30s when database is locked
PRAGMA optimize;                -- Gather stats for query planner after bulk load
```

The `json_data` column stores the complete original event, allowing the server to return full eve.json objects without re-parsing the source file. An optional `events_fts` virtual table enables fast full-text search over all event data. If FTS5 is unavailable, searches fall back to `json_data LIKE '%term%'`. `row_notes` backs the per-row notes feature (`POST /api/row-note`, see [API Reference](../api.md)) - separate from the whole-analysis `notes.txt` file, and lost on reanalyze along with the rest of `events.db`. `acknowledged_alerts` backs the Acknowledge Alerts feature (`POST /api/acknowledge-alert`/`POST /api/acknowledge-alerts-bulk`) - every `events`/`sigma_alerts` query excludes a row present here by default (`_build_where_conditions`/`_sigma_alert_where` in `db.py`), which is what makes acknowledging remove a row from view instead of just flagging it; the `acknowledged=only` query param flips that to include *only* acknowledged rows, for the Acknowledged Alerts tab's own fetches. Lost on reanalyze along with the rest of `events.db`, same as `row_notes`.

The composite and expression indexes above are backfilled lazily (`CREATE INDEX IF NOT EXISTS`) onto pre-existing databases the first time `get_sankey_data_sqlite`/`get_aggregation_data_sqlite` runs against them, so upgrading never requires a migration step. Each backfill also re-runs `PRAGMA optimize` to keep the query planner's statistics current - without it, a planner working from stale/missing stats can pick an unhelpful index even for unrelated queries once several indexes share `event_type` as a leading column.

## Query Performance

`get_sankey_data_sqlite` and `get_aggregation_data_sqlite` (`db.py`) run their independent `GROUP BY` queries concurrently via `ThreadPoolExecutor` - one SQLite connection per worker (connections aren't thread-safe to share), safe under WAL mode's multiple-simultaneous-readers guarantee.

Unfiltered (no search query) results from both functions are cached in-memory in `socrates.py` (`_SANKEY_CACHE`, keyed by `(md5, event_type)`; `_AGGREGATION_CACHE`, keyed by `(md5, event_type, column, page, page_size)`; plus `_AGGREGATION_TOTALS_CACHE` for the per-column distinct-value counts - all guarded by a lock), since the underlying data never changes once an analysis finishes ingesting. All three caches are evicted per-analysis (`_evict_analysis_cache`) on `/api/delete-analysis`/`/api/reanalyze` and cleared entirely on `/api/delete-all-analyses`. Search-filtered requests are never cached.

### Known Limitations / Future Work

- **Arbitrary JSON-blob field filter/sort/aggregation scaling.** Fast server-side sort/filter only has real indexed-column support for `event_type`, `timestamp`, IP, port, and severity. Every other field (e.g. `alert.category`, `dns.rrname`, `http.url`) lives inside the shared `json_data` blob column and is only reachable via `json_extract()` at query time, which doesn't scale the way an index does as row counts grow. A per-field fix (generated/indexed columns added one at a time) compounds in migration complexity with each field added; the architecturally correct fix is splitting `events` into separate, properly-typed tables per event type, but that's a real migration touching ingestion (`suricata_analyzer.py`, `sigma_analyzer.py`, `db.py`), every query function, and every event type's column mapping - a multi-week project in its own right, not undertaken without a concrete use case driving it.
- **JSON-column sort tiebreaker on near-single-valued fields.** Sorting by a field with very low value diversity (e.g. `flow.state`, which is almost always the same handful of values) stays slow even after `PRAGMA optimize`, because the secondary `timestamp` tiebreaker still forces SQLite to sort the tied rows directly rather than use an index. This showed up against synthetic test data (1M rows, `State` column); it's unconfirmed whether real Suricata captures have enough value diversity in these fields for it to matter in practice. Not worth addressing without real-data evidence that it does.
