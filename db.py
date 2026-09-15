#!/usr/bin/env python3
"""SQLite database layer for SO-CRATES."""

import concurrent.futures
import json
import os
import sqlite3
import subprocess
from contextlib import contextmanager
from datetime import datetime, timezone

from models import (
    get_app_proto,
    get_dest_ip,
    get_dest_port,
    get_protocol,
    get_src_ip,
    get_src_port,
    get_timestamp,
)
import config
from suricata_sid_ranges import sid_ranges_sql_case


def _related_file_path(db_path, filename):
    """Build the path for a file sibling to events.db."""
    return os.path.join(os.path.dirname(db_path), filename)


# Composite indexes for the Sankey/aggregation GROUP BY queries (src_ip/
# dest_ip/dest_port/src_port) - shared between SQLITE_SCHEMA (new databases)
# and _ensure_ip_port_indexes (backfilled onto pre-existing ones) so the two
# can't drift apart. event_type leads every index because every query (via
# _build_where_conditions) always excludes the internal 'stats' row
# (`event_type != 'stats'`), and the 10 per-type tabs additionally filter on
# a specific `event_type = ?`. event_type leading lets SQLite use a
# covering-index SEARCH for the equality-filtered per-type case (instead of
# falling back to idx_event_type - correct on cardinality, but not covering,
# since it lacks these columns, forcing a full row lookup per match) while
# leftmost-prefix still lets each index also cover its second column alone
# (src_ip, dest_ip) for the merged 'all' view's single-column queries.
_IP_PORT_INDEXES = (
    ('idx_src_dest_ip', 'event_type, src_ip, dest_ip'),
    ('idx_dest_ip_port', 'event_type, dest_ip, dest_port'),
    ('idx_dest_port', 'event_type, dest_port'),
    ('idx_src_port', 'event_type, src_port'),
)
_IP_PORT_INDEX_SQL = '\n'.join(
    f'CREATE INDEX IF NOT EXISTS {name} ON events({cols});' for name, cols in _IP_PORT_INDEXES
)

SQLITE_SCHEMA = f'''
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    timestamp TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dest_ip TEXT,
    dest_port INTEGER,
    protocol TEXT,
    app_proto TEXT,
    json_data TEXT
);
CREATE INDEX IF NOT EXISTS idx_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_event_type_timestamp ON events(event_type, timestamp);
{_IP_PORT_INDEX_SQL}

CREATE TABLE IF NOT EXISTS sigma_alerts (
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
CREATE INDEX IF NOT EXISTS idx_sigma_severity ON sigma_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_sigma_timestamp ON sigma_alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_sigma_rule_id ON sigma_alerts(rule_id);

-- One optional note per row of events/sigma_alerts, keyed by a
-- (source_table, row_id) pair rather than a real FOREIGN KEY - SQLite
-- can't express a polymorphic FK against two different parent tables,
-- and this file never turns on PRAGMA foreign_keys anyway, so a plain
-- integer with an app-level invariant matches how the rest of this
-- schema already trusts the app layer. UNIQUE(source_table, row_id)
-- both enforces one note per row and gives SQLite's auto-created
-- covering index for the row_id IN (...) per-page lookup, so no
-- separate CREATE INDEX is needed here.
CREATE TABLE IF NOT EXISTS row_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_table TEXT NOT NULL CHECK (source_table IN ('events', 'sigma_alerts')),
    row_id INTEGER NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(source_table, row_id)
);

-- Presence of a row = acknowledged, same polymorphic (source_table,
-- row_id) keying as row_notes above (and the same reasoning for why it's
-- a plain integer with an app-level invariant, not a real FOREIGN KEY) -
-- no note text needed here, just existence. Every alert-bearing query
-- (_build_where_conditions/_sigma_alert_where) excludes rows present here
-- by default, so acknowledging removes a row from every normal view, not
-- just marks it - see get_acknowledged_alert_ids below.
CREATE TABLE IF NOT EXISTS acknowledged_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_table TEXT NOT NULL CHECK (source_table IN ('events', 'sigma_alerts')),
    row_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(source_table, row_id)
);
'''


def _has_fts5(conn):
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events_fts'")
    return cursor.fetchone() is not None


def _ensure_ip_port_indexes(conn):
    """Backfill the src_ip/dest_ip/dest_port/src_port indexes (see
    SQLITE_SCHEMA) onto databases created before these indexes existed.
    IF NOT EXISTS makes this a cheap no-op for already-upgraded or
    freshly-created databases; a one-time index build otherwise. Called
    before any per-query connections are opened, so there's no read/write
    contention with the parallel GROUP BY queries that follow.

    event_type leads every index - see the matching comment above these
    same 4 statements in SQLITE_SCHEMA.

    PRAGMA optimize refreshes the query planner's stats (sqlite_stat1)
    afterward - a backfilled database's stats otherwise stay stale from
    before these indexes existed, and with several indexes now sharing
    event_type as a leading column, a planner working from stale/missing
    stats can pick an unhelpful one even for unrelated queries (measured: a
    plain "sort by time" query regressed 17x, 1.72s -> 0.1s once corrected).
    Cheap even the first time (~0.1s at 1M rows) and a ~0ms no-op once
    stats are already current, so safe to call unconditionally here.
    """
    for name, cols in _IP_PORT_INDEXES:
        conn.execute(f'CREATE INDEX IF NOT EXISTS {name} ON events({cols})')
    conn.execute('PRAGMA optimize;')


def _sanitize_like(term):
    return '%' + term.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'


def _escape_fts5(term):
    tokens = term.split()
    return ' '.join('"' + t.replace('"', '""') + '"' for t in tokens)


def _build_search_terms(q):
    if q is None:
        return []
    if isinstance(q, str):
        return [q.strip()[:config.MAX_SEARCH_TERM_LENGTH]] if q.strip() else []
    if isinstance(q, list):
        return [x.strip()[:config.MAX_SEARCH_TERM_LENGTH] for x in q if x.strip()]
    return []


@contextmanager
def _db_connection(db_path):
    conn = sqlite3.connect(db_path, timeout=config.SQLITE_TIMEOUT_SECONDS)
    conn.execute('PRAGMA busy_timeout = 30000;')
    try:
        yield conn
    finally:
        conn.close()


def _init_db(conn):
    """Initialize SQLite schema, PRAGMAs, and FTS5.

    Returns True if FTS5 is available, False otherwise.
    """
    conn.execute('PRAGMA journal_mode = WAL;')
    conn.execute('PRAGMA synchronous = NORMAL;')
    conn.executescript(SQLITE_SCHEMA)

    try:
        conn.execute('''
            CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                json_data,
                content='events',
                content_rowid='id'
            )
        ''')
        return True
    except Exception:
        return False


def _insert_event(conn, event_dict, has_fts):
    """Insert an event dict into events and optionally index in FTS5.

    Returns the rowid of the inserted event.
    """
    line = json.dumps(event_dict, separators=(',', ':'))
    cur = conn.execute(
        '''INSERT INTO events (event_type, timestamp, src_ip, src_port, dest_ip, dest_port, protocol, app_proto, json_data)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (
            event_dict.get('event_type', ''),
            event_dict.get('timestamp', ''),
            event_dict.get('src_ip', ''),
            event_dict.get('src_port', 0),
            event_dict.get('dest_ip', ''),
            event_dict.get('dest_port', 0),
            event_dict.get('proto') or event_dict.get('protocol', ''),
            event_dict.get('app_proto', ''),
            line,
        )
    )
    if has_fts:
        conn.execute(
            'INSERT INTO events_fts (rowid, json_data) VALUES (?, ?)',
            (cur.lastrowid, line)
        )
    return cur.lastrowid


def create_sqlite_db(db_path, eve_file):
    with _db_connection(db_path) as conn:
        has_fts = _init_db(conn)

        fileinfo_by_sha256 = {}
        fileinfo_rowids = {}

        with open(eve_file, 'r', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        # A line can be syntactically valid JSON (a bare
                        # number/string/array) without being an event
                        # object - e.g. a truncated/corrupted eve.json.
                        # event.get(...) below would raise AttributeError
                        # for anything non-dict, aborting ingestion of the
                        # whole file instead of just skipping this one bad
                        # line, which is what the JSONDecodeError handling
                        # just below already does for a malformed line.
                        continue
                    # Suricata's own built-in protocol-command-decode rules
                    # (opt-in via show_protocol_decode_alerts) are noise, not
                    # threat detections - reclassify into a dedicated
                    # synthetic type so they get their own tab instead of
                    # diluting Network Alerts. classtype protocol-command-decode
                    # maps to exactly this category string, confirmed against
                    # ~/socrates-data/suricata/classification.config.
                    if event.get('event_type') == 'alert' and event.get('alert', {}).get('category') == 'Generic Protocol Command Decode':
                        event['event_type'] = 'protocol_decode'
                    rowid = _insert_event(conn, event, has_fts)

                    # Index fileinfo events by SHA256 for YARA correlation
                    if event.get('event_type') == 'fileinfo':
                        sha256 = event.get('fileinfo', {}).get('sha256')
                        if sha256:
                            fileinfo_by_sha256[sha256] = event
                            fileinfo_rowids[sha256] = rowid
                except json.JSONDecodeError:
                    continue

        # Create synthetic filealerts events from YARA matches correlated with fileinfo
        yara_file = _related_file_path(db_path, 'yara_matches.json')
        if os.path.exists(yara_file) and fileinfo_by_sha256:
            try:
                with open(yara_file, 'r') as f:
                    yara_matches = json.load(f)
                for match in yara_matches:
                    sha256 = match.get('sha256', '')
                    fileinfo = fileinfo_by_sha256.get(sha256)
                    if not fileinfo:
                        continue
                    synthetic_event = {
                        'event_type': 'filealerts',
                        'timestamp': get_timestamp(fileinfo),
                        'src_ip': get_src_ip(fileinfo),
                        'src_port': get_src_port(fileinfo),
                        'dest_ip': get_dest_ip(fileinfo),
                        'dest_port': get_dest_port(fileinfo),
                        'proto': get_protocol(fileinfo),
                        'app_proto': get_app_proto(fileinfo),
                        'filealerts': {
                            'rule_name': match.get('rule_name', ''),
                            'tags': match.get('tags', []),
                            'author': match.get('meta', {}).get('author', ''),
                            'sha256': sha256,
                            'file_id': match.get('file_id', ''),
                            'strings': match.get('strings', []),
                            'meta': match.get('meta', {}),
                        },
                    }
                    _insert_event(conn, synthetic_event, has_fts)
            except (json.JSONDecodeError, TypeError) as e:
                print(f'Warning: could not parse YARA matches: {e}')

        # Merge file metadata for zero-YARA-match files
        meta_file = _related_file_path(db_path, 'file_metadata.json')
        if os.path.exists(meta_file) and fileinfo_by_sha256:
            try:
                with open(meta_file, 'r') as f:
                    file_metadata = json.load(f)
                for sha256, metadata in file_metadata.items():
                    fileinfo = fileinfo_by_sha256.get(sha256)
                    rowid = fileinfo_rowids.get(sha256)
                    if fileinfo and rowid:
                        # events_fts uses content='events' (external content) -
                        # it does NOT auto-sync when the content table is
                        # modified directly like this; per SQLite's own FTS5
                        # docs, that requires explicitly telling the FTS5
                        # table what the old indexed value was ('delete'
                        # with the *original* json_data) before indexing the
                        # new one. Skipping this left the merged metadata
                        # searchable via events.json_data/LIKE fallback, but
                        # never findable via an FTS5 MATCH search.
                        old_json = None
                        if has_fts:
                            old_row = conn.execute(
                                'SELECT json_data FROM events WHERE id = ?', (rowid,)
                            ).fetchone()
                            old_json = old_row[0] if old_row else None
                        fileinfo.setdefault('fileinfo', {})['metadata'] = metadata
                        updated_json = json.dumps(fileinfo, separators=(',', ':'))
                        conn.execute(
                            'UPDATE events SET json_data = ? WHERE id = ?',
                            (updated_json, rowid)
                        )
                        if has_fts and old_json is not None:
                            conn.execute(
                                "INSERT INTO events_fts(events_fts, rowid, json_data) VALUES('delete', ?, ?)",
                                (rowid, old_json)
                            )
                            conn.execute(
                                'INSERT INTO events_fts(rowid, json_data) VALUES (?, ?)',
                                (rowid, updated_json)
                            )
            except (json.JSONDecodeError, TypeError) as e:
                print(f'Warning: could not parse file_metadata.json: {e}')

        # Built after the bulk insert, not before - incrementally maintaining
        # 6 extra indexes across a million single-row inserts is much slower
        # than one bulk build at the end (measured ~9.8s for all 6 on 1M rows).
        _ensure_flow_json_indexes(conn)
        conn.execute('PRAGMA optimize;')
        conn.commit()


def create_file_analysis_db(db_path, file_path, yara_matches, file_md5, file_sha1, file_sha256, magic_desc='', metadata=None):
    """Create events.db for a standalone file scan (non-PCAP).

    Inserts one synthetic fileinfo event and zero or more filealerts events
    correlated by SHA256.
    """
    if not magic_desc:
        try:
            result = subprocess.run(
                ['file', '--brief', file_path],
                capture_output=True, text=True, timeout=config.FILE_COMMAND_TIMEOUT
            )
            if result.returncode == 0:
                magic_desc = result.stdout.strip()
        except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired) as e:
            print(f'Warning: could not run file command: {e}')

    timestamp = datetime.now(timezone.utc).isoformat()
    filename = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)

    with _db_connection(db_path) as conn:
        has_fts = _init_db(conn)

        # Insert synthetic fileinfo event
        fileinfo_event = {
            'event_type': 'fileinfo',
            'timestamp': timestamp,
            'src_ip': '',
            'src_port': 0,
            'dest_ip': '',
            'dest_port': 0,
            'proto': '',
            'app_proto': '',
            'fileinfo': {
                'filename': filename,
                'size': file_size,
                'md5': file_md5,
                'sha1': file_sha1,
                'sha256': file_sha256,
                'magic': magic_desc,
                **({'metadata': metadata} if metadata else {}),
            },
        }
        _insert_event(conn, fileinfo_event, has_fts)

        # Insert synthetic filealerts events from YARA matches
        for match in yara_matches:
            synthetic_event = {
                'event_type': 'filealerts',
                'timestamp': timestamp,
                'src_ip': '',
                'src_port': 0,
                'dest_ip': '',
                'dest_port': 0,
                'proto': '',
                'app_proto': '',
                'filealerts': {
                    'rule_name': match.get('rule_name', ''),
                    'tags': match.get('tags', []),
                    'author': match.get('meta', {}).get('author', ''),
                    'sha256': file_sha256,
                    'file_id': '',
                    'strings': match.get('strings', []),
                    'meta': match.get('meta', {}),
                },
            }
            _insert_event(conn, synthetic_event, has_fts)

        conn.execute('PRAGMA optimize;')
        conn.commit()


def _build_where_conditions(has_acknowledged_table, terms, has_fts, event_type, event_type_col, acknowledged_only=False):
    """Build WHERE conditions and parameters for event queries.

    Args:
        has_acknowledged_table: Whether acknowledged_alerts actually exists
            yet - an events.db from before this feature shipped has an
            events table but no acknowledged_alerts table, and nothing on
            this read path calls _init_db to lazily create it (that's a
            write-path-only convention, see get_row_notes). Without this
            check, every query against such a database would hit "no such
            table: acknowledged_alerts" and silently return empty results
            (callers catch sqlite3.OperationalError broadly around the
            whole query, not just this condition). Callers compute this
            once on their own already-scoped connection and pass the plain
            bool through rather than passing conn itself - some callers
            (get_sankey_data_sqlite, get_aggregation_data_sqlite) build
            these conditions inside a ThreadPoolExecutor worker, and
            sqlite3 connections can only be used on the thread that
            created them, so re-checking via conn.execute() from inside
            the worker would raise sqlite3.ProgrammingError.
        terms: List of search terms (from _build_search_terms).
        has_fts: Whether FTS5 is available.
        event_type: Optional event_type filter value.
        event_type_col: Column reference ('event_type' or 'e.event_type').
        acknowledged_only: False (default) excludes acknowledged rows from
            every normal query - this is what makes acknowledging an alert
            remove it from view rather than just flag it. True flips the
            condition to include *only* acknowledged rows - used solely by
            the Acknowledged Alerts tab's own fetches. Harmless for
            non-alert event_types either way: nothing but 'alert' rows can
            ever be in acknowledged_alerts, so this condition simply never
            matches (and never excludes anything) for e.g. dns/http/tls.

    Returns:
        (conditions_list, params_list)
    """
    conditions = []
    params = []

    if terms and has_fts:
        fts_q = ' '.join(_escape_fts5(term) for term in terms)
        conditions.append('events_fts MATCH ?')
        params.append(fts_q)
    elif terms:
        for term in terms:
            conditions.append("json_data LIKE ? ESCAPE '\\'")
            params.append(_sanitize_like(term))

    if event_type:
        conditions.append(f'{event_type_col} = ?')
        params.append(event_type)
    else:
        # 'stats' is an internal per-analysis summary row, not a displayable
        # event - only relevant to exclude for the merged "all types" query,
        # since a specific event_type filter never matches it anyway.
        conditions.append(f"{event_type_col} != 'stats'")

    if has_acknowledged_table:
        # Must be a fully-qualified reference (events.id / e.id), never a
        # bare 'id' - acknowledged_alerts has its own autoincrement 'id'
        # column, so an unqualified 'id' inside the subquery below resolves
        # to THAT column (innermost scope wins) instead of correlating to
        # the outer events row at all, silently turning this into an
        # uncorrelated subquery whose result is the same for every outer
        # row - excluding either everything or nothing depending on data,
        # not just the acknowledged rows. event_type_col is normally
        # exactly 'event_type' or 'e.event_type' (see _events_select), so
        # checking its prefix is enough to know which alias this query
        # uses - guarded with `or ''` since a test double can hand this a
        # deliberately-broken None to simulate a malformed query.
        id_col = 'e.id' if (event_type_col or '').startswith('e.') else 'events.id'
        exists_or_not = 'EXISTS' if acknowledged_only else 'NOT EXISTS'
        conditions.append(
            f"{exists_or_not} (SELECT 1 FROM acknowledged_alerts aa WHERE aa.source_table = 'events' AND aa.row_id = {id_col})"
        )
    elif acknowledged_only:
        # No acknowledged_alerts table yet means nothing has ever been
        # acknowledged - an "only acknowledged" query must return nothing,
        # not silently fall back to "every row" by omitting the condition.
        conditions.append('0')

    return conditions, params


def _has_events_table(conn):
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
    return cursor.fetchone() is not None


def _has_acknowledged_alerts_table(conn):
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='acknowledged_alerts'")
    return cursor.fetchone() is not None


def _events_select(terms, has_fts, plain_cols, fts_cols):
    """Build the SELECT ... FROM portion of an events query.

    Returns (select_sql, event_type_col). When search terms are present and
    FTS5 is available, the query joins against the events_fts index and
    column references must use the 'e.' alias for the events table.
    """
    if terms and has_fts:
        return (f'SELECT {fts_cols} FROM events_fts JOIN events e ON events_fts.rowid = e.id',
                'e.event_type')
    return f'SELECT {plain_cols} FROM events', 'event_type'


def init_empty_db(db_path):
    """Create an empty events.db with the full schema (no events).

    Used when an analysis pipeline cannot run (e.g. an optional analyzer is
    unavailable) so the UI still sees a 'ready' database.
    """
    with _db_connection(db_path) as conn:
        _init_db(conn)
        conn.commit()


def _build_events_query(conn, event_type, offset, limit, q, order_by, sort_dir, acknowledged_only=False):
    """Shared SQL-building logic for query_events_sqlite / query_events_sqlite_json."""
    terms = _build_search_terms(q)
    has_fts = _has_fts5(conn) if terms else False
    select, event_type_col = _events_select(terms, has_fts, 'id, json_data', 'e.id, e.json_data')
    conditions, params = _build_where_conditions(_has_acknowledged_alerts_table(conn), terms, has_fts, event_type, event_type_col, acknowledged_only)
    sql = select
    if conditions:
        sql += ' WHERE ' + ' AND '.join(conditions)
    order_expr = None
    if order_by:
        prefix = 'e.' if (terms and has_fts) else ''
        order_expr = _sort_expr(event_type, order_by, prefix=prefix)
    if order_expr:
        direction = 'DESC' if sort_dir == 'desc' else 'ASC'
        sql += f' ORDER BY {order_expr} {direction}, timestamp'
    else:
        sql += ' ORDER BY timestamp'
    sql += ' LIMIT ? OFFSET ?'
    return sql, list(params) + [limit, offset]


def query_events_sqlite(db_path, event_type=None, offset=0, limit=1000, q=None, order_by=None, sort_dir='asc', acknowledged_only=False):
    """Same query/results as query_events_sqlite_json, as a ready-to-use
    list[dict] instead of a pre-serialized JSON string - not used by the
    running app (socrates.py only ever calls the _json variant, the fast
    path for real HTTP responses), kept only because a list[dict] is more
    convenient to assert against directly in tests than a JSON string.
    A thin wrapper rather than its own hand-rolled row-processing loop, so
    the id/row_note-merge/malformed-blob-fallback logic only exists in one
    place and can't drift between the two.
    """
    json_str, _ids = query_events_sqlite_json(db_path, event_type, offset, limit, q, order_by, sort_dir, acknowledged_only)
    return json.loads(json_str)


def query_events_sqlite_json(db_path, event_type=None, offset=0, limit=1000, q=None, order_by=None, sort_dir='asc', acknowledged_only=False):
    """Same query as query_events_sqlite, but returns a ready-to-send JSON
    array string built directly from the stored json_data blobs, skipping
    the parse-then-reserialize round trip. json_data is always produced by
    json.dumps at insert time (_insert_event is the only writer), so each
    value is already complete, valid JSON in the overwhelming common case -
    but a cheap shape check (not a full parse, which would defeat the point
    of this fast path) guards against a corrupted/malformed blob silently
    breaking the entire response, matching query_events_sqlite's own
    graceful-degradation behavior for that case. ~5x faster than
    query_events_sqlite + json.dumps for large result sets (measured:
    4.8s -> 0.9s at 500,000 rows).

    Returns (json_str, ids) - ids is the row's SQL id for each event in the
    same order as json_str's array, captured for free during the fetchall()
    loop this function already does. Callers (e.g. for a row-notes lookup)
    need the page's ids before the *next* thing they do, and re-parsing
    json_str just to recover them would defeat this function's whole
    reason for existing.

    The row's own "id" key is appended just before each object's closing
    '}' rather than prepended - some ingested log formats already have
    their own 'id' field in json_data (see LOG_NOISE_FIELDS in
    static/socrates.js, which already has to filter one out of the detail
    view), and JSON parsers resolve duplicate keys by taking the *last*
    occurrence, so appending guarantees this id always wins regardless of
    what a given blob already contains.

    A row_note key is appended the same way for any row with a saved note
    (get_row_notes, one extra query against this same events.db - cheap
    and indexed, bounded to this page's ids). Spliced in by list index
    before the parts are joined, not via a substring search over the
    already-joined string - a row's own json_data could in principle
    contain literal text that looks like another row's id marker, so
    string-searching the joined output for it isn't safe, while indexing
    into the not-yet-joined parts list is exact by construction.
    """
    with _db_connection(db_path) as conn:
        if not _has_events_table(conn):
            return '[]', []
        sql, params = _build_events_query(conn, event_type, offset, limit, q, order_by, sort_dir, acknowledged_only)
        try:
            cursor = conn.execute(sql, params)
            parts = []
            ids = []
            for row in cursor.fetchall():
                row_id, blob = row[0], row[1]
                ids.append(row_id)
                stripped = blob.strip() if blob else ''
                if stripped.startswith('{') and stripped.endswith('}'):
                    parts.append(stripped[:-1] + ',"id":' + str(row_id) + '}')
                else:
                    parts.append('{"id":' + str(row_id) + '}')

            notes = get_row_notes(db_path, 'events', ids)
            if notes:
                for i, row_id in enumerate(ids):
                    note = notes.get(row_id)
                    if note is not None:
                        parts[i] = parts[i][:-1] + ',"row_note":' + json.dumps(note) + '}'

            return '[' + ','.join(parts) + ']', ids
        except sqlite3.OperationalError:
            return '[]', []


def has_row_notes(db_path):
    """True if this analysis has at least one row-level note, across
    either source_table. Used to conditionally warn before reanalyze,
    which deletes events.db (and therefore every row_notes row) entirely -
    see socrates.py's handle_get_status. Same read-path convention as
    get_row_notes: no _init_db call, since a missing/empty events.db or a
    row_notes-less old one both just mean no notes yet, not an error.

    The os.path.exists guard is required, not just an optimization:
    sqlite3.connect() creates an empty file at db_path as a side effect
    if it doesn't exist yet, even for a connection that's only ever read
    from - _db_connection() below has no way to open read-only. A caller
    hitting this while an analysis is still mid-ingest (real bug report:
    /api/status, polled during processing, called this unconditionally)
    would pre-create events.db before create_sqlite_db() gets a chance
    to, and that function's own `not os.path.exists(db_file)` guard would
    then skip real ingestion entirely - silently leaving a permanently
    empty database behind."""
    if not os.path.exists(db_path):
        return False
    with _db_connection(db_path) as conn:
        try:
            cursor = conn.execute('SELECT 1 FROM row_notes LIMIT 1')
            return cursor.fetchone() is not None
        except sqlite3.OperationalError:
            return False


def get_row_notes(db_path, source_table, row_ids):
    """Look up existing notes for a bounded set of row ids (one page's
    worth, e.g. <=100) in a single query. Returns {row_id: note}, omitting
    any row_id with no note - "has a note" is a plain row-exists check
    everywhere, not a note != '' filter.

    Read path (unlike set_row_note below): doesn't call _init_db, since
    that's a write-path convention here - a row_notes-less old events.db
    simply has no notes yet, which is exactly what an empty dict already
    means to every caller.
    """
    if not row_ids:
        return {}
    with _db_connection(db_path) as conn:
        placeholders = ','.join('?' * len(row_ids))
        try:
            cursor = conn.execute(
                f'SELECT row_id, note FROM row_notes WHERE source_table = ? AND row_id IN ({placeholders})',
                [source_table] + list(row_ids)
            )
            return {row[0]: row[1] for row in cursor.fetchall()}
        except sqlite3.OperationalError:
            return {}


def set_row_note(db_path, source_table, row_id, note):
    """Create, overwrite, or (if note is empty) clear the note on one row.

    Mirrors notes.txt's clear-on-empty convention: an empty note deletes
    the row entirely rather than storing an empty string, so every other
    reader can keep treating "row exists in row_notes" as the has-a-note
    signal.
    """
    with _db_connection(db_path) as conn:
        _init_db(conn)
        if note:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                '''INSERT INTO row_notes (source_table, row_id, note, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(source_table, row_id)
                   DO UPDATE SET note = excluded.note, updated_at = excluded.updated_at''',
                (source_table, row_id, note, now, now)
            )
        else:
            conn.execute(
                'DELETE FROM row_notes WHERE source_table = ? AND row_id = ?',
                (source_table, row_id)
            )
        conn.commit()


def set_acknowledged(db_path, source_table, row_id, acknowledged):
    """Acknowledge or un-acknowledge one row. Unlike set_row_note there's
    no text to overwrite - insert if acknowledged, delete otherwise (same
    presence-is-the-signal convention row_notes uses for "has a note",
    just without ever needing an UPDATE branch).
    """
    with _db_connection(db_path) as conn:
        _init_db(conn)
        if acknowledged:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                '''INSERT INTO acknowledged_alerts (source_table, row_id, created_at)
                   VALUES (?, ?, ?)
                   ON CONFLICT(source_table, row_id) DO NOTHING''',
                (source_table, row_id, now)
            )
        else:
            conn.execute(
                'DELETE FROM acknowledged_alerts WHERE source_table = ? AND row_id = ?',
                (source_table, row_id)
            )
        conn.commit()


def set_acknowledged_bulk(db_path, source_table, row_ids):
    """Acknowledge every id in row_ids in one transaction - the "all
    instances of this alert" bulk path. INSERT OR IGNORE (not the
    ON CONFLICT...DO NOTHING set_acknowledged uses) since this is a plain
    executemany over a list, not a single values tuple - both express the
    same "skip already-acknowledged rows" intent, this is just the
    idiomatic form for an executemany batch.
    """
    if not row_ids:
        return
    with _db_connection(db_path) as conn:
        _init_db(conn)
        now = datetime.now(timezone.utc).isoformat()
        conn.executemany(
            'INSERT OR IGNORE INTO acknowledged_alerts (source_table, row_id, created_at) VALUES (?, ?, ?)',
            [(source_table, row_id, now) for row_id in row_ids]
        )
        conn.commit()


def get_event_count_sqlite(db_path, event_type=None, q=None, acknowledged_only=False):
    with _db_connection(db_path) as conn:
        if not _has_events_table(conn):
            return 0

        terms = _build_search_terms(q)
        has_fts = _has_fts5(conn) if terms else False

        select, event_type_col = _events_select(terms, has_fts, 'COUNT(*)', 'COUNT(*)')
        conditions, params = _build_where_conditions(_has_acknowledged_alerts_table(conn), terms, has_fts, event_type, event_type_col, acknowledged_only)

        sql = select
        if conditions:
            sql += ' WHERE ' + ' AND '.join(conditions)

        try:
            cursor = conn.execute(sql, params)
            return cursor.fetchone()[0]
        except sqlite3.OperationalError:
            return 0


def get_event_types_sqlite(db_path, q=None):
    with _db_connection(db_path) as conn:
        if not _has_events_table(conn):
            return {}

        conn.row_factory = sqlite3.Row

        terms = _build_search_terms(q)
        has_fts = _has_fts5(conn) if terms else False

        select, event_type_col = _events_select(terms, has_fts, 'event_type, COUNT(*) as cnt', 'e.event_type, COUNT(*) as cnt')
        conditions, params = _build_where_conditions(_has_acknowledged_alerts_table(conn), terms, has_fts, None, event_type_col)

        sql = select
        if conditions:
            sql += ' WHERE ' + ' AND '.join(conditions)
        sql += f' GROUP BY {event_type_col} ORDER BY cnt DESC, {event_type_col}'  # deterministic tie order

        try:
            cursor = conn.execute(sql, params)
            return {row['event_type']: row['cnt'] for row in cursor.fetchall()}
        except sqlite3.OperationalError:
            return {}


def get_event_date_range_sqlite(db_path, q=None):
    """MIN/MAX timestamp across all non-'stats' events, honoring the same
    search-term filtering as get_event_types_sqlite. Reuses the existing
    timestamp index."""
    with _db_connection(db_path) as conn:
        if not _has_events_table(conn):
            return {'min': None, 'max': None}

        conn.row_factory = sqlite3.Row

        terms = _build_search_terms(q)
        has_fts = _has_fts5(conn) if terms else False

        select, event_type_col = _events_select(
            terms, has_fts,
            'MIN(timestamp) as min_ts, MAX(timestamp) as max_ts',
            'MIN(e.timestamp) as min_ts, MAX(e.timestamp) as max_ts',
        )
        conditions, params = _build_where_conditions(_has_acknowledged_alerts_table(conn), terms, has_fts, None, event_type_col)

        sql = select
        if conditions:
            sql += ' WHERE ' + ' AND '.join(conditions)

        try:
            row = conn.execute(sql, params).fetchone()
            if row:
                return {'min': row['min_ts'], 'max': row['max_ts']}
        except sqlite3.OperationalError:
            pass
        return {'min': None, 'max': None}


# Must match CONFIG.SANKEY_MAX_NODES_PER_COLUMN in static/socrates.js.
SANKEY_MAX_NODES_PER_COLUMN = 50


def get_sankey_data_sqlite(db_path, event_type=None, q=None, max_nodes_per_column=SANKEY_MAX_NODES_PER_COLUMN):
    """Server-side equivalent of buildSankeyData()/capColumn() in socrates.js:
    a {nodes, links} Sankey diagram over Source IP -> Dest IP -> Dest Port,
    each column capped to the top max_nodes_per_column values by event count
    with the remainder bucketed into a synthetic 'Other' node - so the
    payload stays small regardless of how many events match, without giving
    up the diagram's default visibility.

    IP/port normalization matches the client's fallback rules exactly so
    node identities line up between the node-total and link queries:
    missing/empty IPs and missing/zero ports both become '?'.
    """
    with _db_connection(db_path) as conn:
        if not _has_events_table(conn):
            return {'nodes': [], 'links': []}

        _ensure_ip_port_indexes(conn)

        terms = _build_search_terms(q)
        has_fts = _has_fts5(conn) if terms else False
        # Computed once here on the main thread, not inside run() below -
        # run() executes inside a ThreadPoolExecutor worker, and sqlite3
        # connections can only be used on the thread that created them.
        has_acknowledged_table = _has_acknowledged_alerts_table(conn)

        def norm_ip(col):
            return f"CASE WHEN {col} IS NULL OR {col} = '' THEN '?' ELSE {col} END"

        def norm_port(col):
            return f"CASE WHEN {col} IS NULL OR {col} = 0 THEN '?' ELSE CAST({col} AS TEXT) END"

        def run(select_cols_plain, select_cols_fts, group_by):
            select, event_type_col = _events_select(terms, has_fts, select_cols_plain, select_cols_fts)
            conditions, params = _build_where_conditions(has_acknowledged_table, terms, has_fts, event_type, event_type_col)
            sql = select
            if conditions:
                sql += ' WHERE ' + ' AND '.join(conditions)
            sql += f' GROUP BY {group_by} ORDER BY cnt DESC, {group_by}'  # deterministic tie order (see the paginated query's comment)
            try:
                with _db_connection(db_path) as thread_conn:
                    thread_conn.row_factory = sqlite3.Row
                    return thread_conn.execute(sql, params).fetchall()
            except sqlite3.OperationalError:
                return []

        prefix = 'e.' if (terms and has_fts) else ''
        src_ip_plain, dest_ip_plain, dest_port_plain = norm_ip('src_ip'), norm_ip('dest_ip'), norm_port('dest_port')
        src_ip_fts = norm_ip(f'{prefix}src_ip')
        dest_ip_fts = norm_ip(f'{prefix}dest_ip')
        dest_port_fts = norm_port(f'{prefix}dest_port')

        query_specs = [
            (f'{src_ip_plain} AS node, COUNT(*) AS cnt', f'{src_ip_fts} AS node, COUNT(*) AS cnt', 'node'),
            (f'{dest_ip_plain} AS node, COUNT(*) AS cnt', f'{dest_ip_fts} AS node, COUNT(*) AS cnt', 'node'),
            (f'{dest_port_plain} AS node, COUNT(*) AS cnt', f'{dest_port_fts} AS node, COUNT(*) AS cnt', 'node'),
            (
                f'{src_ip_plain} AS src, {dest_ip_plain} AS dst, COUNT(*) AS cnt',
                f'{src_ip_fts} AS src, {dest_ip_fts} AS dst, COUNT(*) AS cnt',
                'src, dst',
            ),
            (
                f'{dest_ip_plain} AS src, {dest_port_plain} AS dst, COUNT(*) AS cnt',
                f'{dest_ip_fts} AS src, {dest_port_fts} AS dst, COUNT(*) AS cnt',
                'src, dst',
            ),
        ]
        max_workers = min(len(query_specs), os.cpu_count() or 4)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            col0_rows, col1_rows, col2_rows, link0_rows, link1_rows = executor.map(
                lambda spec: run(*spec), query_specs
            )

        columns = [col0_rows, col1_rows, col2_rows]
        kept = []      # per column: set of kept node values
        dropped = []   # per column: set of dropped node values
        nodes = []
        for col_idx, rows in enumerate(columns):
            kept_values = {row['node'] for row in rows[:max_nodes_per_column]}
            dropped_values = {row['node'] for row in rows[max_nodes_per_column:]}
            kept.append(kept_values)
            dropped.append(dropped_values)
            for value in kept_values:
                nodes.append({'id': f'{col_idx}:{value}', 'name': value, 'column': col_idx})
            if dropped_values:
                nodes.append({'id': f'{col_idx}:Other', 'name': 'Other', 'column': col_idx})

        def remap(value, col_idx):
            return f'{col_idx}:Other' if value in dropped[col_idx] else f'{col_idx}:{value}'

        links_acc = {}
        for row in link0_rows:
            key = (remap(row['src'], 0), remap(row['dst'], 1))
            links_acc[key] = links_acc.get(key, 0) + row['cnt']
        for row in link1_rows:
            key = (remap(row['src'], 1), remap(row['dst'], 2))
            links_acc[key] = links_acc.get(key, 0) + row['cnt']

        links = [{'source': s, 'target': t, 'value': v} for (s, t), v in links_acc.items()]
        return {'nodes': nodes, 'links': links}


# Must match AGG_PAGE_SIZE in static/socrates.js - the fixed page size for
# every Aggregation Table (not client-controllable; only the page number is).
AGGREGATION_TOP_N = 10

# Real, already-populated columns aggregated for every event type (same
# columns get_sankey_data_sqlite already GROUP BYs on for src_ip/dest_ip/
# dest_port). Value is (column_name, needs_cast_to_text).
REAL_AGGREGATION_COLUMNS = {
    'Protocol': ('protocol', False),
    'Source IP': ('src_ip', False),
    'Source Port': ('src_port', True),
    'Dest IP': ('dest_ip', False),
    'Dest Port': ('dest_port', True),
}

# JSON-blob columns per event type, mirroring extractValue()'s switch in
# static/socrates.js exactly (after fixing 3 pre-existing bugs there - see
# modbus 'Category', dnp3 'Type', pgsql 'Query' below). A list of more than
# one path means COALESCE across fallback shapes, matching extractValue's
# own chained fallback checks (e.g. dnp3's nested request/response shapes).
AGGREGATION_JSON_PATHS = {
    'alert': {
        'Alert': ['$.alert.signature'],
        'Category': ['$.alert.category'],
        'Severity': ['$.alert.severity'],
        'Ruleset': ['$.alert.signature_id'],
    },
    # Reclassified from 'alert' at ingestion (see create_sqlite_db) - same
    # underlying JSON shape, so the same paths apply.
    'protocol_decode': {
        'Alert': ['$.alert.signature'],
        'Category': ['$.alert.category'],
        'Severity': ['$.alert.severity'],
        'Ruleset': ['$.alert.signature_id'],
    },
    'dns': {
        # Suricata 8's new V3 DNS logging format (the new default - see
        # rust/src/dns/log.rs) moved rrname/rrtype off the top level into
        # queries[0] entirely. Confirmed against real Suricata 8.0.6 output:
        # every DNS row's Query/Type aggregated to nothing but '(empty)'
        # before this fix. The first path covers any previously-stored
        # Suricata 7 (V1/V2 format) analyses; the second covers current V3.
        'Query': ['$.dns.rrname', '$.dns.queries[0].rrname'],
        'Type': ['$.dns.rrtype', '$.dns.queries[0].rrtype'],
    },
    'http': {
        'Method': ['$.http.http_method'],
        'Host': ['$.http.hostname'],
        'URL': ['$.http.url'],
        'Status': ['$.http.status'],
        'User-Agent': ['$.http.http_user_agent'],
    },
    'tls': {
        'SNI / Host': ['$.tls.sni'],
        'Version': ['$.tls.version'],
        'Subject': ['$.tls.subject'],
        'Issuer': ['$.tls.issuerdn'],
    },
    'flow': {
        'Pkts →': ['$.flow.pkts_toserver'],
        'Pkts ←': ['$.flow.pkts_toclient'],
        'Bytes →': ['$.flow.bytes_toserver'],
        'Bytes ←': ['$.flow.bytes_toclient'],
        'State': ['$.flow.state'],
        'Alerted': ['$.flow.alerted'],
    },
    'fileinfo': {
        'Filename': ['$.fileinfo.filename'],
    },
    'filealerts': {
        'Rule Name': ['$.filealerts.rule_name'],
        'Tags': ['$.filealerts.tags'],
    },
    'modbus': {
        'Function': ['$.modbus.request.function_code'],
        'Unit ID': ['$.modbus.request.unit_id'],
        'Access Type': ['$.modbus.request.access_type'],
        'Category': ['$.modbus.request.category'],
        'Error Flags': ['$.modbus.request.error_flags'],
    },
    'dnp3': {
        'Type': ['$.dnp3.type'],
        'Source Addr': ['$.dnp3.src', '$.dnp3.request.src'],
        'Dest Addr': ['$.dnp3.dst', '$.dnp3.request.dst'],
        'Function': ['$.dnp3.application.function_code',
                      '$.dnp3.request.application.function_code',
                      '$.dnp3.response.application.function_code'],
    },
    'pgsql': {
        'Query': ['$.pgsql.request.simple_query'],
        'Command': ['$.pgsql.response.command_completed'],
        'Rows': ['$.pgsql.response.data_rows'],
        'SSL': ['$.pgsql.response.ssl_accepted'],
    },
    'quic': {
        'SNI': ['$.quic.sni'],
        'QUIC Version': ['$.quic.version'],
        'JA3': ['$.quic.ja3.hash'],
        'JA3S': ['$.quic.ja3s.hash'],
    },
    'dhcp': {
        'DHCP Type': ['$.dhcp.dhcp_type', '$.dhcp.type'],
        'Client MAC': ['$.dhcp.client_mac'],
        'Assigned IP': ['$.dhcp.assigned_ip'],
        'Hostname': ['$.dhcp.hostname'],
    },
    'ftp_data': {
        'FTP Command': ['$.ftp_data.command'],
        'Filename': ['$.ftp_data.filename'],
    },
    'smb': {
        'SMB Command': ['$.smb.command'],
        'Filename': ['$.smb.filename'],
        'Share': ['$.smb.share'],
        'SMB User': ['$.smb.ntlmssp.user', '$.smb.kerberos.cname'],
    },
    'ssh': {
        'Client Version': ['$.ssh.client.software_version'],
        'Server Version': ['$.ssh.server.software_version'],
    },
    'krb5': {
        'Client': ['$.krb5.cname'],
        'Service': ['$.krb5.sname'],
        'Realm': ['$.krb5.realm'],
        'Error Code': ['$.krb5.error_code'],
    },
    'sip': {
        'SIP Method': ['$.sip.method'],
        'URI': ['$.sip.uri'],
        'SIP Code': ['$.sip.code'],
        'Reason': ['$.sip.reason'],
    },
    'snmp': {
        'SNMP Version': ['$.snmp.version'],
        'PDU Type': ['$.snmp.pdu_type'],
        'Community': ['$.snmp.community'],
    },
    # 'mqtt' intentionally has no entry here: its fields are dynamically
    # keyed by message subtype (connect/publish/subscribe/...), which
    # extractValue() handles in JS via Object.keys(e.mqtt)[0] - there is no
    # static JSON path that can express "whichever subtype key is present"
    # the way every other protocol's fixed field layout can. Same category
    # of exclusion as 'log'/'sigmaalert' (see get_aggregation_data_sqlite).
    #
    # 'http2' also intentionally has no entry: Suricata's http2 logger
    # (rust/src/http2/logger.rs) always logs under event_type 'http', reusing
    # the same http_method/hostname/url/status field names as HTTP/1.1 - it
    # never emits event_type 'http2'. Real HTTP/2 (including cleartext h2c)
    # traffic is already aggregated correctly by the 'http' entry above.
    'dcerpc': {
        'Interface UUID': ['$.dcerpc.interfaces[0].uuid'],
        'Opnum': ['$.dcerpc.req.opnum', '$.dcerpc.request.opnum'],
        'Call ID': ['$.dcerpc.call_id'],
    },
    'rdp': {
        'RDP Event': ['$.rdp.event_type'],
        'Cookie': ['$.rdp.cookie'],
        'Client Name': ['$.rdp.client_name'],
    },
    'tftp': {
        'Packet': ['$.tftp.packet'],
        'File': ['$.tftp.file'],
        'Mode': ['$.tftp.mode'],
    },
    'ike': {
        'Exchange Type': ['$.ike.exchange_type'],
        # IKE Version groups by major version only (e.g. "2"), unlike the
        # per-row table's "2.0" (version_major + '.' + version_minor) -
        # AGGREGATION_VALUE_TRANSFORMS operates on one already-built
        # expression string, not a second independent JSON path, so
        # concatenating a separate version_minor field in isn't a natural
        # fit here. Grouping by major version alone is still meaningful.
        'IKE Version': ['$.ike.version_major'],
        'Init SPI': ['$.ike.init_spi'],
    },
    'nfs': {
        'Procedure': ['$.nfs.procedure'],
        'Filename': ['$.nfs.filename'],
    },
    'rfb': {
        # client/server_protocol_version are {major, minor} objects in
        # Suricata's real eve.json (rust/src/rfb/logger.rs), not flat
        # strings - confirmed against real traffic. The per-row table shows
        # "major.minor" (e.g. "003.008"), but AGGREGATION_VALUE_TRANSFORMS
        # operates on one already-built expression, not concatenation of two
        # independent JSON paths (same limitation as 'ike'/'IKE Version'
        # above), so this groups by major version alone - still meaningful.
        'Client Version': ['$.rfb.client_protocol_version.major'],
        'Server Version': ['$.rfb.server_protocol_version.major'],
        # security_type is nested under 'authentication', not top-level.
        'Security Type': ['$.rfb.authentication.security_type'],
    },
    'bittorrent_dht': {
        'Request Type': ['$.bittorrent_dht.request_type', '$.bittorrent_dht.request.request_type'],
        'Info Hash': ['$.bittorrent_dht.info_hash', '$.bittorrent_dht.request.info_hash'],
    },
    'smtp': {
        'Helo': ['$.smtp.helo'],
        'Mail From': ['$.smtp.mail_from'],
        'Rcpt To': ['$.smtp.rcpt_to'],
    },
    'ftp': {
        'Command': ['$.ftp.command'],
        'Command Data': ['$.ftp.command_data'],
        'Completion Code': ['$.ftp.completion_code'],
        'Reply': ['$.ftp.reply'],
    },
    'anomaly': {
        'Event': ['$.anomaly.event'],
        'Type': ['$.anomaly.type'],
        'Layer': ['$.anomaly.layer'],
        'App Proto': ['$.anomaly.app_proto'],
    },
    'enip': {
        'Command': ['$.enip.request.command', '$.enip.response.command'],
        'Status': ['$.enip.response.status', '$.enip.request.status'],
    },
    'ntp': {
        'Version': ['$.ntp.version'],
        'Mode': ['$.ntp.mode'],
        'Stratum': ['$.ntp.stratum'],
        'Reference ID': ['$.ntp.reference_id'],
    },
    'websocket': {
        'Opcode': ['$.websocket.opcode'],
        'Fin': ['$.websocket.fin'],
    },
    'pop3': {
        'Command': ['$.pop3.request.command'],
        'Status': ['$.pop3.response.status'],
    },
    'mdns': {
        'Query': ['$.mdns.queries[0].rrname'],
        'Type': ['$.mdns.queries[0].rrtype'],
    },
    # 'ldap' intentionally has no entry here: like mqtt, its request/response
    # detail lives under a differently-named sub-object per operation type
    # (bind_request/search_request/modify_request/.../bind_response/
    # search_result_done/...), which extractValue() handles in JS by
    # scanning for whichever key is present - there is no static JSON path
    # that can express that the way every other protocol's fixed field
    # layout can. Same category of exclusion as mqtt (see
    # get_aggregation_data_sqlite) and http2 (see the note above).
    'arp': {
        'Opcode': ['$.arp.opcode'],
        'Src MAC': ['$.arp.src_mac'],
        'Dest MAC': ['$.arp.dest_mac'],
    },
}

# Non-generic defaults - i.e. NOT the generic "NULL/'' -> (empty)" handling
# get_aggregation_data_sqlite applies to every column. Matches extractValue's
# own `|| '-'` / `|| 0` fallbacks exactly (TLS fields default to the literal
# string '-', flow packet/byte counters default to 0, not empty).
AGGREGATION_DEFAULTS = {
    ('tls', 'SNI / Host'): "'-'",
    ('tls', 'Version'): "'-'",
    ('tls', 'Subject'): "'-'",
    ('tls', 'Issuer'): "'-'",
    ('flow', 'Pkts →'): '0',
    ('flow', 'Pkts ←'): '0',
    ('flow', 'Bytes →'): '0',
    ('flow', 'Bytes ←'): '0',
}

# SUBSTR truncation matching extractValue's .slice() calls exactly.
# CONFIG.USER_AGENT_MAX_LENGTH=50, CONFIG.TLS_SUBJECT_MAX_LENGTH=40 -
# confirmed directly in extractValue's own code (buildRowForEvent, a
# separate table-cell renderer, truncates Issuer differently - not the
# function used for aggregation, so not the value to match here).
AGGREGATION_TRUNCATE = {
    ('http', 'User-Agent'): 50,
    ('tls', 'Subject'): 40,
    ('tls', 'Issuer'): 40,
}

# Value transforms beyond plain extraction, matching extractValue's own
# formatting exactly (e.g. "Sev " + severity, or a boolean -> Yes/No).
AGGREGATION_VALUE_TRANSFORMS = {
    ('alert', 'Severity'): lambda expr: f"'Sev ' || COALESCE({expr}, 0)",
    # Classifies signature_id into the curated ruleset it most likely came
    # from - see suricata_sid_ranges.py for how SURICATA_SID_RANGES was
    # derived. Generated from that same table (not hand-duplicated SQL) so
    # this can never drift from classify_alert_ruleset(), the Python
    # equivalent used by extractValue()'s client-side fallback path.
    ('alert', 'Ruleset'): lambda expr: sid_ranges_sql_case(f'CAST({expr} AS INTEGER)'),
    # protocol_decode is reclassified from 'alert' at ingestion (see
    # create_sqlite_db) with the same alert.* JSON shape - same transforms.
    ('protocol_decode', 'Severity'): lambda expr: f"'Sev ' || COALESCE({expr}, 0)",
    ('protocol_decode', 'Ruleset'): lambda expr: sid_ranges_sql_case(f'CAST({expr} AS INTEGER)'),
    ('flow', 'Alerted'): lambda expr: f"CASE WHEN {expr} THEN 'Yes' ELSE 'No' END",
    ('pgsql', 'SSL'): lambda expr: f"CASE WHEN {expr} IS NULL THEN '' WHEN {expr} THEN 'Yes' ELSE 'No' END",
    # extractValue does String(e.websocket.fin) -> the literal "true"/"false"
    # (not "Yes"/"No" like flow.Alerted/pgsql.SSL) - fin is always set in
    # Suricata's real schema, so no NULL/'' case to handle here.
    ('websocket', 'Fin'): lambda expr: f"CASE WHEN {expr} THEN 'true' ELSE 'false' END",
}

# Columns needing CAST(...AS TEXT) - numeric JSON fields extractValue
# renders via String()/!==undefined rather than a bare number. ('flow',
# 'State')/('flow', 'Alerted') are added purely so their expression indexes
# (_ensure_flow_json_indexes) can be trusted as covering by SQLite's query
# planner - a bare json_extract() has no stable type affinity and gets
# re-verified against the main table row even with a matching index; an
# explicit CAST does. Output is unchanged either way (verified identical
# for Alerted's true/false/missing cases).
AGGREGATION_CAST_TEXT = {
    ('http', 'Status'), ('pgsql', 'Rows'), ('modbus', 'Unit ID'),
    ('dnp3', 'Source Addr'), ('dnp3', 'Dest Addr'), ('dnp3', 'Function'),
    ('flow', 'Pkts →'), ('flow', 'Pkts ←'),
    ('flow', 'Bytes →'), ('flow', 'Bytes ←'),
    ('flow', 'State'), ('flow', 'Alerted'),
    ('sip', 'SIP Code'), ('snmp', 'SNMP Version'),
    ('dcerpc', 'Opnum'), ('dcerpc', 'Call ID'),
    ('ike', 'Exchange Type'), ('rfb', 'Security Type'),
    ('ntp', 'Version'), ('ntp', 'Mode'), ('ntp', 'Stratum'),
}

# Array-valued columns needing json_each + group_concat instead of a plain
# json_extract (filealerts.tags is a JSON array, not a scalar).
AGGREGATION_ARRAY_JOIN_COLUMNS = {
    ('filealerts', 'Tags'), ('smtp', 'Rcpt To'),
    ('ftp', 'Completion Code'), ('ftp', 'Reply'),
}


def _aggregation_expr(event_type, label, paths, prefix=''):
    """Builds the SQL expression for one aggregation column: a plain
    json_extract, a COALESCE across multiple paths (when extractValue()
    itself falls back across several possible JSON shapes), or a
    json_each/group_concat join for the one array-valued column - plus
    whatever default/cast/truncate/transform that column needs to exactly
    match extractValue()'s own formatting.
    """
    if (event_type, label) in AGGREGATION_ARRAY_JOIN_COLUMNS:
        expr = f"(SELECT group_concat(value, ', ') FROM json_each({prefix}json_data, '{paths[0]}'))"
    else:
        parts = [f"json_extract({prefix}json_data, '{p}')" for p in paths]
        expr = parts[0] if len(parts) == 1 else f"COALESCE({', '.join(parts)})"

    default = AGGREGATION_DEFAULTS.get((event_type, label))
    if default is not None:
        expr = f"COALESCE({expr}, {default})"
    if (event_type, label) in AGGREGATION_CAST_TEXT:
        expr = f"CAST({expr} AS TEXT)"
    truncate_len = AGGREGATION_TRUNCATE.get((event_type, label))
    if truncate_len is not None:
        expr = f"SUBSTR({expr}, 1, {truncate_len})"
    transform = AGGREGATION_VALUE_TRANSFORMS.get((event_type, label))
    if transform:
        expr = transform(expr)
    return expr


# Index name per flow JSON aggregation column - see _ensure_flow_json_indexes.
_FLOW_JSON_INDEX_NAMES = {
    'Pkts →': 'idx_flow_pkts_toserver', 'Pkts ←': 'idx_flow_pkts_toclient',
    'Bytes →': 'idx_flow_bytes_toserver', 'Bytes ←': 'idx_flow_bytes_toclient',
    'State': 'idx_flow_state', 'Alerted': 'idx_flow_alerted',
}


def _ensure_flow_json_indexes(conn):
    """Backfill covering indexes for flow's 6 JSON-extracted aggregation
    columns (Pkts/Bytes/State/Alerted) - measured as the standout bottleneck
    at 1M+ rows (~2s per column, unindexed json_extract() over the full
    json_data blob). event_type leads each index, matching the real-column
    fix in _ensure_ip_port_indexes. Built from the real _aggregation_expr()
    output (not hand-duplicated SQL) so the index can never drift out of
    sync with the query it's meant to cover.

    One column's index failing to build (e.g. a malformed expression) must
    not prevent the others from being created - mirrors the per-column
    resilience already guaranteed for the queries themselves.

    Ends with PRAGMA optimize - see the matching comment in
    _ensure_ip_port_indexes for why a backfilled database's stale/missing
    query-planner stats need refreshing here too, not just after ingest.
    """
    for label, paths in AGGREGATION_JSON_PATHS['flow'].items():
        expr = _aggregation_expr('flow', label, paths)
        name = _FLOW_JSON_INDEX_NAMES[label]
        try:
            conn.execute(f'CREATE INDEX IF NOT EXISTS {name} ON events(event_type, {expr})')
        except sqlite3.OperationalError:
            continue
    conn.execute('PRAGMA optimize;')


def _all_events_detail_expr(prefix=''):
    """SQL equivalent of extractValue's 'Detail' case for the merged 'all'
    events view (static/socrates.js, buildRowForEvent's 'Detail' case) - covers every event_type
    that can appear in the events table in pcap mode. 'log'/'sigmaalert'
    never appear here (log is a separate mode; sigma_alerts is a separate
    table), so they need no branch. filealerts has no JS branch either
    (falls through to '') - matched here exactly, not "fixed", to avoid
    changing displayed behavior beyond what this helper is for. 'mqtt' is
    also intentionally omitted (falls to ELSE '') - its fields are
    dynamically keyed by message subtype, which (like AGGREGATION_JSON_PATHS
    above) has no static JSON path representation, even though its JS
    Detail branch can do this trivially via Object.keys(e.mqtt)[0]. 'http2'
    has no branch of its own either: Suricata always logs it under
    event_type 'http' (confirmed against rust/src/http2/logger.rs and real
    h2c traffic), reusing the same http_method/url field names as HTTP/1.1,
    so the existing 'http' branch already covers it.
    """
    jd = f'{prefix}json_data'

    def port_expr(col):
        return f"CASE WHEN {prefix}{col} = 0 THEN '' ELSE CAST({prefix}{col} AS TEXT) END"

    return f'''CASE {prefix}event_type
        WHEN 'alert' THEN COALESCE(json_extract({jd}, '$.alert.signature'), '')
        WHEN 'protocol_decode' THEN COALESCE(json_extract({jd}, '$.alert.signature'), '')
        WHEN 'dns' THEN COALESCE(json_extract({jd}, '$.dns.rrname'), json_extract({jd}, '$.dns.queries[0].rrname'), '')
        WHEN 'http' THEN COALESCE(json_extract({jd}, '$.http.http_method'), '') || ' ' || COALESCE(json_extract({jd}, '$.http.url'), '')
        WHEN 'tls' THEN COALESCE(json_extract({jd}, '$.tls.sni'), '')
        WHEN 'flow' THEN COALESCE({prefix}src_ip, '') || ':' || {port_expr('src_port')} || ' → ' || COALESCE({prefix}dest_ip, '') || ':' || {port_expr('dest_port')}
        WHEN 'ftp' THEN COALESCE(json_extract({jd}, '$.ftp.command'), (SELECT value FROM json_each({jd}, '$.ftp.reply') LIMIT 1), '')
        -- BUGFIX: was '$.anomaly.message', a field that has never existed in
        -- Suricata's eve.json anomaly schema (real field is 'event', e.g.
        -- "APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION") - always silently
        -- returned '' before.
        WHEN 'anomaly' THEN COALESCE(json_extract({jd}, '$.anomaly.event'), '')
        WHEN 'fileinfo' THEN COALESCE(json_extract({jd}, '$.fileinfo.filename'), '')
        WHEN 'modbus' THEN COALESCE(json_extract({jd}, '$.modbus.request.function_code'), '')
        WHEN 'dnp3' THEN COALESCE(json_extract({jd}, '$.dnp3.type'), json_extract({jd}, '$.dnp3.request.type'), json_extract({jd}, '$.dnp3.response.type'), '')
        WHEN 'pgsql' THEN COALESCE(json_extract({jd}, '$.pgsql.request.simple_query'), json_extract({jd}, '$.pgsql.response.command_completed'), '')
        WHEN 'enip' THEN COALESCE(json_extract({jd}, '$.enip.request.command'), json_extract({jd}, '$.enip.response.command'), '')
        WHEN 'ntp' THEN CASE WHEN json_extract({jd}, '$.ntp.version') IS NOT NULL
            THEN 'v' || CAST(json_extract({jd}, '$.ntp.version') AS TEXT) || ' mode ' || COALESCE(CAST(json_extract({jd}, '$.ntp.mode') AS TEXT), '') ELSE '' END
        WHEN 'websocket' THEN COALESCE(json_extract({jd}, '$.websocket.opcode'), '')
        WHEN 'pop3' THEN COALESCE(json_extract({jd}, '$.pop3.request.command'), json_extract({jd}, '$.pop3.response.status'), '')
        WHEN 'mdns' THEN COALESCE(json_extract({jd}, '$.mdns.queries[0].rrname'), '')
        WHEN 'ldap' THEN COALESCE(json_extract({jd}, '$.ldap.request.operation'), json_extract({jd}, '$.ldap.responses[0].operation'), '')
        WHEN 'arp' THEN COALESCE(json_extract({jd}, '$.arp.opcode'), '') || ' ' || COALESCE(json_extract({jd}, '$.arp.src_mac'), '') || ' → ' || COALESCE(json_extract({jd}, '$.arp.dest_mac'), '')
        WHEN 'quic' THEN COALESCE(json_extract({jd}, '$.quic.sni'), '')
        WHEN 'dhcp' THEN COALESCE(json_extract({jd}, '$.dhcp.dhcp_type'), json_extract({jd}, '$.dhcp.type'), '') || ' ' || COALESCE(json_extract({jd}, '$.dhcp.assigned_ip'), '')
        WHEN 'ftp_data' THEN COALESCE(json_extract({jd}, '$.ftp_data.command'), '') || ' ' || COALESCE(json_extract({jd}, '$.ftp_data.filename'), '')
        WHEN 'smb' THEN COALESCE(json_extract({jd}, '$.smb.command'), '') || ' ' || COALESCE(json_extract({jd}, '$.smb.filename'), '')
        WHEN 'ssh' THEN COALESCE(json_extract({jd}, '$.ssh.client.software_version'), json_extract({jd}, '$.ssh.server.software_version'), '')
        WHEN 'krb5' THEN COALESCE(json_extract({jd}, '$.krb5.cname'), '') || ' → ' || COALESCE(json_extract({jd}, '$.krb5.sname'), '')
        WHEN 'sip' THEN CASE WHEN json_extract({jd}, '$.sip.method') IS NOT NULL
            THEN COALESCE(json_extract({jd}, '$.sip.method'), '') || ' ' || COALESCE(json_extract({jd}, '$.sip.uri'), '')
            ELSE COALESCE(CAST(json_extract({jd}, '$.sip.code') AS TEXT), '') || ' ' || COALESCE(json_extract({jd}, '$.sip.reason'), '') END
        WHEN 'snmp' THEN COALESCE(json_extract({jd}, '$.snmp.pdu_type'), '')
        WHEN 'dcerpc' THEN COALESCE(json_extract({jd}, '$.dcerpc.interfaces[0].uuid'), '')
        WHEN 'rdp' THEN COALESCE(json_extract({jd}, '$.rdp.event_type'), '')
        WHEN 'tftp' THEN COALESCE(json_extract({jd}, '$.tftp.packet'), '') || ' ' || COALESCE(json_extract({jd}, '$.tftp.file'), '')
        WHEN 'ike' THEN COALESCE(CAST(json_extract({jd}, '$.ike.exchange_type') AS TEXT), '')
        WHEN 'nfs' THEN COALESCE(json_extract({jd}, '$.nfs.procedure'), '') || ' ' || COALESCE(json_extract({jd}, '$.nfs.filename'), '')
        WHEN 'rfb' THEN COALESCE(CAST(json_extract({jd}, '$.rfb.authentication.security_type') AS TEXT), '')
        WHEN 'bittorrent_dht' THEN COALESCE(json_extract({jd}, '$.bittorrent_dht.request_type'), json_extract({jd}, '$.bittorrent_dht.request.request_type'), '')
        WHEN 'smtp' THEN COALESCE(json_extract({jd}, '$.smtp.mail_from'), '')
        ELSE ''
    END'''


def _sort_expr(event_type, label, prefix=''):
    """Maps a user-facing column label to a safe ORDER BY expression for
    event_type, reusing the same expression logic as /api/aggregation-data
    so sort order matches what the column displays. Returns None if label
    isn't recognized - callers must fall back to the default timestamp
    order; the raw label must never be interpolated into SQL directly.
    """
    if label == 'Time':
        return f'{prefix}timestamp'
    if label in REAL_AGGREGATION_COLUMNS:
        # cast_text (used by _aggregation_expr's GROUP BY, below) exists
        # only so the aggregation table's returned value is uniformly a
        # string, matching every other aggregation column's shape - it says
        # nothing about the column's actual storage type. src_port/dest_port
        # are real INTEGER columns, so ORDER BY must sort them numerically;
        # casting to TEXT here would sort "3306" before "443" before "80".
        col, _cast_text = REAL_AGGREGATION_COLUMNS[label]
        return f'{prefix}{col}'
    if event_type in AGGREGATION_JSON_PATHS and label in AGGREGATION_JSON_PATHS[event_type]:
        return _aggregation_expr(event_type, label, AGGREGATION_JSON_PATHS[event_type][label], prefix=prefix)
    if event_type is None:
        # Merged 'all events' view only - 'Type'/'Detail' aren't real columns
        # of any specific event_type, so this must never fire for a specific
        # event_type (e.g. dns/dnp3 both already have their own real,
        # JSON-path-backed 'Type' column via AGGREGATION_JSON_PATHS above,
        # which must keep taking precedence over this branch).
        if label == 'Type':
            return f'UPPER({prefix}event_type)'
        if label == 'Detail':
            return _all_events_detail_expr(prefix=prefix)
    return None


def _aggregation_column_specs(event_type, prefix):
    """The (label, plain_expr, fts_expr) tuples get_aggregation_data_sqlite
    and get_aggregation_totals_sqlite both need - factored out so the two
    can never drift on which columns/expressions they aggregate over.
    Returns None if event_type isn't one of the supported per-type tabs (and
    isn't the merged 'all events' view, event_type=None)."""
    if event_type is not None and event_type not in AGGREGATION_JSON_PATHS:
        return None
    column_specs = []
    for label, (col, cast_text) in REAL_AGGREGATION_COLUMNS.items():
        plain = f'CAST({col} AS TEXT)' if cast_text else col
        fts = f'CAST({prefix}{col} AS TEXT)' if cast_text else f'{prefix}{col}'
        column_specs.append((label, plain, fts))
    if event_type is None:
        column_specs.append(('Type', 'UPPER(event_type)', f'UPPER({prefix}event_type)'))
        column_specs.append(('Detail', _all_events_detail_expr(), _all_events_detail_expr(prefix=prefix)))
    else:
        for label, paths in AGGREGATION_JSON_PATHS[event_type].items():
            column_specs.append((
                label,
                _aggregation_expr(event_type, label, paths),
                _aggregation_expr(event_type, label, paths, prefix='e.'),
            ))
    return column_specs


def get_aggregation_data_sqlite(db_path, event_type, q=None, top_n=AGGREGATION_TOP_N, offset=0, column=None):
    """Server-side equivalent of buildAggregationTablesCore()/extractValue()
    in socrates.js, for the 10 per-type pcap tabs that share that code path
    (alert/dns/http/tls/flow/fileinfo/filealerts/modbus/dnp3/pgsql), plus the
    merged 'all events' view when event_type is None (Type/Detail computed
    via _all_events_detail_expr instead of a per-type AGGREGATION_JSON_PATHS
    lookup). 'log'/'sigmaalert' are still not supported here (see
    canUseServerAggregation() in socrates.js, which keeps those fully
    client-side). Returns {column_label: [{value, count}, ...]}, already
    sorted descending and capped to top_n, matching CONFIG.AGGREGATION_TOP_N's
    client-side render-time cap.

    `offset` supports Prev/Next pagination through a single column's values
    (paired with `column` to restrict the query to just that one label -
    the initial/bulk fetch that populates every column at once always uses
    offset=0, column=None). See get_aggregation_totals_sqlite for the
    matching distinct-value COUNT a client needs to compute page counts -
    deliberately a separate function/query rather than folding a total into
    every row here, so this function's shape (and every existing caller/
    test built around it) doesn't have to change for pagination to work.

    Each column is an independent read-only GROUP BY query, so they run
    concurrently (one connection per worker - sqlite3 connections aren't
    thread-safe to share, and WAL mode, already enabled by _init_db, allows
    multiple simultaneous readers without blocking each other). Measured
    ~3.8x faster than the previous serial loop at 250,000 rows (3.4s -> 0.9s).
    Column order is preserved in the result regardless of completion order.
    """
    with _db_connection(db_path) as conn:
        if not _has_events_table(conn):
            return {}

        _ensure_ip_port_indexes(conn)
        _ensure_flow_json_indexes(conn)

        terms = _build_search_terms(q)
        has_fts = _has_fts5(conn) if terms else False

        prefix = 'e.' if (terms and has_fts) else ''
        column_specs = _aggregation_column_specs(event_type, prefix)
        if column_specs is None:
            return {}
        if column is not None:
            column_specs = [spec for spec in column_specs if spec[0] == column]

        # Computed once here on the main thread, not inside run_column()
        # below - run_column() executes inside a ThreadPoolExecutor worker,
        # and sqlite3 connections can only be used on the thread that
        # created them.
        has_acknowledged_table = _has_acknowledged_alerts_table(conn)

        def run_column(label, plain_expr, fts_expr):
            select, event_type_col = _events_select(
                terms, has_fts,
                f'{plain_expr} AS val, COUNT(*) AS cnt',
                f'{fts_expr} AS val, COUNT(*) AS cnt',
            )
            conditions, params = _build_where_conditions(has_acknowledged_table, terms, has_fts, event_type, event_type_col)
            sql = select
            if conditions:
                sql += ' WHERE ' + ' AND '.join(conditions)
            # 'val' as the tie-break: bare ORDER BY cnt DESC leaves the
            # order of equal counts up to SQLite - nondeterministic across
            # queries, which matters here because each page is its own
            # query. Without a stable total order, a tied row can appear
            # on two pages or on neither as the user pages through.
            sql += ' GROUP BY val ORDER BY cnt DESC, val LIMIT ? OFFSET ?'
            try:
                with _db_connection(db_path) as thread_conn:
                    rows = thread_conn.execute(sql, list(params) + [top_n, offset]).fetchall()
            except sqlite3.OperationalError:
                return label, None
            entries = [
                {'value': (row[0] if row[0] not in (None, '') else '(empty)'), 'count': row[1]}
                for row in rows
            ]
            return label, (entries if entries else None)

        result = {}
        max_workers = min(len(column_specs), os.cpu_count() or 4) if column_specs else 1
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(run_column, label, plain, fts) for label, plain, fts in column_specs]
            for future in futures:
                label, entries = future.result()
                if entries:
                    result[label] = entries

        return result


def get_aggregation_totals_sqlite(db_path, event_type, q=None, column=None):
    """Distinct-value COUNT per aggregation column, matching the same
    column set/WHERE-filtering as get_aggregation_data_sqlite - lets a
    client compute Prev/Next page counts without the page data itself
    revealing the true total (a page can come back shorter than top_n
    purely because its offset is near the end, not because that's the
    overall total). Returns {column_label: total_count}.
    """
    with _db_connection(db_path) as conn:
        if not _has_events_table(conn):
            return {}

        _ensure_ip_port_indexes(conn)
        _ensure_flow_json_indexes(conn)

        terms = _build_search_terms(q)
        has_fts = _has_fts5(conn) if terms else False

        prefix = 'e.' if (terms and has_fts) else ''
        column_specs = _aggregation_column_specs(event_type, prefix)
        if column_specs is None:
            return {}
        if column is not None:
            column_specs = [spec for spec in column_specs if spec[0] == column]

        has_acknowledged_table = _has_acknowledged_alerts_table(conn)

        def run_column(label, plain_expr, fts_expr):
            select, event_type_col = _events_select(
                terms, has_fts,
                f'{plain_expr} AS val',
                f'{fts_expr} AS val',
            )
            conditions, params = _build_where_conditions(has_acknowledged_table, terms, has_fts, event_type, event_type_col)
            sql = select
            if conditions:
                sql += ' WHERE ' + ' AND '.join(conditions)
            sql += ' GROUP BY val'
            try:
                with _db_connection(db_path) as thread_conn:
                    count = thread_conn.execute(f'SELECT COUNT(*) FROM ({sql})', params).fetchone()[0]
            except sqlite3.OperationalError:
                return label, 0
            return label, count

        result = {}
        max_workers = min(len(column_specs), os.cpu_count() or 4) if column_specs else 1
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(run_column, label, plain, fts) for label, plain, fts in column_specs]
            for future in futures:
                label, count = future.result()
                if count:
                    result[label] = count

        return result


def _has_sigma_alerts_table(conn):
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sigma_alerts'")
    return cursor.fetchone() is not None


def _sigma_alert_where(has_acknowledged_table, q, severity, acknowledged_only=False):
    """Build WHERE conditions and params for sigma_alerts queries.

    Returns (conditions_list, params_list). Each search term is matched
    (LIKE, escaped) against rule title, rule id, and both log payloads.

    has_acknowledged_table: same meaning/rationale as
    _build_where_conditions' own param of the same name - guards against
    "no such table: acknowledged_alerts" on a sigma_alerts table that
    predates this feature.

    acknowledged_only: same meaning as _build_where_conditions' own param -
    False (default) excludes acknowledged alerts from every normal query,
    True (the Acknowledged Alerts tab's own fetches) includes only them.
    Every sigma_alerts row is acknowledgeable (unlike events, where this is
    a no-op for non-alert types), so this always adds a real condition here.
    """
    conditions = []
    params = []

    if severity:
        conditions.append('severity = ?')
        params.append(severity)

    for term in _build_search_terms(q):
        conditions.append(
            "(rule_title LIKE ? ESCAPE '\\' OR rule_id LIKE ? ESCAPE '\\' OR json_data LIKE ? ESCAPE '\\' OR original_log LIKE ? ESCAPE '\\')"
        )
        like = _sanitize_like(term)
        params.extend([like, like, like, like])

    # sigma_alerts.id must stay qualified for the same reason as the events
    # side's own id_col comment above - acknowledged_alerts has its own
    # 'id' column that a bare 'id' reference here would shadow instead of
    # correlating to the outer sigma_alerts row.
    if has_acknowledged_table:
        exists_or_not = 'EXISTS' if acknowledged_only else 'NOT EXISTS'
        conditions.append(
            f"{exists_or_not} (SELECT 1 FROM acknowledged_alerts aa WHERE aa.source_table = 'sigma_alerts' AND aa.row_id = sigma_alerts.id)"
        )
    elif acknowledged_only:
        conditions.append('0')

    return conditions, params


def insert_sigma_alerts(db_path, alerts):
    """Insert Sigma alert dicts into the sigma_alerts table."""
    with _db_connection(db_path) as conn:
        _init_db(conn)
        for alert in alerts:
            try:
                conn.execute(
                    '''INSERT INTO sigma_alerts
                       (timestamp, rule_title, rule_id, severity, level, logsource, tags, mitre_techniques, original_log, json_data)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (
                        alert.get('timestamp', ''),
                        alert.get('rule_title', ''),
                        alert.get('rule_id', ''),
                        alert.get('severity', ''),
                        alert.get('level', ''),
                        alert.get('logsource', ''),
                        json.dumps(alert.get('tags', [])),
                        json.dumps(alert.get('mitre_techniques', [])),
                        alert.get('original_log', ''),
                        alert.get('json_data', ''),
                    )
                )
            except (sqlite3.Error, TypeError) as e:
                print(f'Warning: skipping malformed sigma alert: {e}')
                continue
        conn.commit()


def query_sigma_alerts_sqlite(db_path, offset=0, limit=1000, q=None, severity=None, acknowledged_only=False):
    with _db_connection(db_path) as conn:
        if not _has_sigma_alerts_table(conn):
            return []

        conn.row_factory = sqlite3.Row
        conditions, params = _sigma_alert_where(_has_acknowledged_alerts_table(conn), q, severity, acknowledged_only)

        sql = 'SELECT * FROM sigma_alerts'
        if conditions:
            sql += ' WHERE ' + ' AND '.join(conditions)
        sql += ' ORDER BY CASE severity WHEN \'critical\' THEN 1 WHEN \'high\' THEN 2 WHEN \'medium\' THEN 3 WHEN \'low\' THEN 4 ELSE 5 END, timestamp DESC LIMIT ? OFFSET ?'
        params = list(params) + [limit, offset]

        try:
            cursor = conn.execute(sql, params)
            alerts = [dict(row) for row in cursor.fetchall()]
        except sqlite3.OperationalError:
            return []

        notes = get_row_notes(db_path, 'sigma_alerts', [a['id'] for a in alerts])
        for a in alerts:
            note = notes.get(a['id'])
            if note is not None:
                a['row_note'] = note

        return alerts


def get_sigma_alert_count_sqlite(db_path, q=None, severity=None, acknowledged_only=False):
    with _db_connection(db_path) as conn:
        if not _has_sigma_alerts_table(conn):
            return 0

        conditions, params = _sigma_alert_where(_has_acknowledged_alerts_table(conn), q, severity, acknowledged_only)

        sql = 'SELECT COUNT(*) FROM sigma_alerts'
        if conditions:
            sql += ' WHERE ' + ' AND '.join(conditions)

        try:
            cursor = conn.execute(sql, params)
            return cursor.fetchone()[0]
        except sqlite3.OperationalError:
            return 0


def import_log_events(db_path, events):
    """Bulk import log events into the events table.

    Args:
        db_path: Path to the SO-CRATES events.db.
        events: List of event dicts with keys:
            event_type, timestamp, src_ip, src_port, dest_ip, dest_port,
            protocol, app_proto, json_data
    """
    with _db_connection(db_path) as conn:
        has_fts = _init_db(conn)
        for event in events:
            _insert_event(conn, event, has_fts)
        conn.commit()


def get_sigma_stats_sqlite(db_path):
    with _db_connection(db_path) as conn:
        if not _has_sigma_alerts_table(conn):
            return {}

        conn.row_factory = sqlite3.Row
        stats = {}

        # Count by severity
        try:
            cursor = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM sigma_alerts GROUP BY severity ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
            )
            stats['by_severity'] = {row['severity']: row['cnt'] for row in cursor.fetchall()}
        except sqlite3.OperationalError:
            stats['by_severity'] = {}

        # Total count
        try:
            cursor = conn.execute('SELECT COUNT(*) FROM sigma_alerts')
            stats['total'] = cursor.fetchone()[0]
        except sqlite3.OperationalError:
            stats['total'] = 0

        # Unique MITRE techniques
        try:
            cursor = conn.execute("SELECT mitre_techniques FROM sigma_alerts WHERE mitre_techniques != '[]'")
            techniques = set()
            for row in cursor.fetchall():
                try:
                    techs = json.loads(row[0])
                    for t in techs:
                        techniques.add(t)
                except (json.JSONDecodeError, TypeError):
                    pass
            stats['mitre_techniques'] = sorted(techniques)
        except sqlite3.OperationalError:
            stats['mitre_techniques'] = []

        return stats



