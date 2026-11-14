#!/usr/bin/env python3
"""The Traffic Map's data: an analysis's flows and alerts by country over time.

Flows are Suricata's flow records, placed at their start and grouped into
(time bin, source country, destination country) buckets, so a capture of
hundreds of thousands of flows stays a small payload. Alerts are kept one
by one (the most severe, up to MAX_ALERTS). Both honor a search the way
every other view does - including country: terms (db.py). Countries come
from geo_lookup.country().

Given a record type (the tab the analysis shows), the map follows it, as
the Sankey Diagram does: that type's records, placed at their timestamp,
take the flows' place, with byte counts only for a flow-shaped type
(`hasBytes`: tshark's connection rows), and the alerts stay over them -
the alert type's records are its alerts, so its map is its alerts alone.
"""

import sqlite3
from datetime import datetime

import findings
import geo_lookup
from db import (
    CONNECTION_TYPE_PREFIX,
    _build_search_terms,
    _build_where_conditions,
    _db_connection,
    _events_select,
    _has_acknowledged_alerts_table,
    _has_events_table,
    _has_fts5,
    _iso_epoch,
)

# not record types: the records a Findings rule matches (findings.py), and
# every event All Events lists - but the alerts, which fly over every map
# anyway, so its records and alerts add up to its count. Their flows keep
# their bytes.
FINDINGS = 'findings'
ALL_EVENTS = 'all'

BINS = 1200          # the timeline's resolution - must match the client's histogram
MAX_ALERTS = 2000


def _epoch(text):
    try:
        return datetime.fromisoformat(text).timestamp()
    except (TypeError, ValueError):
        return _iso_epoch(text)   # Python before 3.11 can't read +0000


def _rows(conn, terms, has_fts, event_type, plain_cols, fts_cols, but_alerts=False):
    select, type_col = _events_select(terms, has_fts, plain_cols, fts_cols)
    conditions, params = _build_where_conditions(_has_acknowledged_alerts_table(conn), terms, has_fts,
                                                 event_type, type_col)
    if but_alerts:
        conditions.append(f"{type_col} != 'alert'")
    sql = select + (' WHERE ' + ' AND '.join(conditions) if conditions else '')
    try:
        return conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []


def _flow_shaped(event_type):
    """Suricata's flows, or tshark's connection rows - with flow's fields
    (or All Events', of which the flows have bytes)."""
    return event_type in (None, ALL_EVENTS) or event_type.startswith(CONNECTION_TYPE_PREFIX)


def empty_traffic_map(event_type=None):
    return {'start': None, 'span': 0, 'bins': BINS, 'buckets': [], 'alerts': [], 'totals': {},
            'flows': 0, 'alertCount': 0, 'type': event_type, 'hasBytes': _flow_shaped(event_type),
            'geo': geo_lookup.info()}


def get_traffic_map_data(db_path, q=None, event_type=None):
    """The map's data for a search (`q`) and a record type: None (or
    'flow') is every flow and the alerts, and any other type that type's
    records and the alerts ('alert': the alerts alone; FINDINGS: the
    records the Findings rules match; ALL_EVENTS: every event All Events
    lists but the alerts)."""
    if event_type == 'flow':
        event_type = None
    with _db_connection(db_path) as conn:
        if not _has_events_table(conn):
            return empty_traffic_map(event_type)
        terms = _build_search_terms(q)
        has_fts = _has_fts5(conn) if terms else False

        def cols(prefix):
            return (f"{prefix}src_ip, {prefix}dest_ip, json_extract({prefix}json_data, '$.flow.start'), "
                    f"coalesce(json_extract({prefix}json_data, '$.flow.bytes_toserver'), 0) + "
                    f"coalesce(json_extract({prefix}json_data, '$.flow.bytes_toclient'), 0), {prefix}timestamp")

        def record_cols(prefix):
            return f"{prefix}src_ip, {prefix}dest_ip, NULL, 0, {prefix}timestamp"
        if event_type == FINDINGS:
            flow_rows = [(src, dst, None, 0, ts) for src, dst, ts in findings.matching_records(conn, terms, has_fts)]
        elif event_type == ALL_EVENTS:
            # Only a flow's own start and bytes: a decoder alert carries its
            # flow's too, which would count them twice
            def all_cols(prefix):
                flow = f"{prefix}event_type = 'flow'"
                return (f"{prefix}src_ip, {prefix}dest_ip, "
                        f"CASE WHEN {flow} THEN json_extract({prefix}json_data, '$.flow.start') END, "
                        f"CASE WHEN {flow} THEN coalesce(json_extract({prefix}json_data, '$.flow.bytes_toserver'), 0) + "
                        f"coalesce(json_extract({prefix}json_data, '$.flow.bytes_toclient'), 0) ELSE 0 END, "
                        f"{prefix}timestamp")
            flow_rows = _rows(conn, terms, has_fts, None, all_cols(''), all_cols('e.'), but_alerts=True)
        elif _flow_shaped(event_type):
            flow_rows = _rows(conn, terms, has_fts, event_type or 'flow', cols(''), cols('e.'))
        else:
            flow_rows = _rows(conn, terms, has_fts, event_type, record_cols(''), record_cols('e.'))

        def alert_cols(prefix):
            return (f"{prefix}timestamp, {prefix}src_ip, {prefix}dest_ip, "
                    f"json_extract({prefix}json_data, '$.alert.severity'), "
                    f"json_extract({prefix}json_data, '$.alert.signature')")
        alert_rows = _rows(conn, terms, has_fts, 'alert', alert_cols(''), alert_cols('e.'))

    country = geo_lookup.country
    flows = []
    for src, dst, start, nbytes, ts in flow_rows:
        if not src and not dst:
            continue   # a record with no addresses has nowhere to go
        t = _epoch(start) if start else None
        if t is None:
            t = _epoch(ts)
        if t is None:
            continue
        flows.append((t, country(src), country(dst), int(nbytes or 0)))
    alerts = []
    for ts, src, dst, sev, sig in alert_rows:
        t = _epoch(ts)
        if t is None:
            continue
        try:
            sev = int(sev)
        except (TypeError, ValueError):
            sev = 3
        alerts.append((t, country(src), country(dst), sev, sig or '', src or '', dst or ''))

    times = [f[0] for f in flows] + [a[0] for a in alerts]
    if not times:
        return empty_traffic_map(event_type)
    t0, t1 = min(times), max(times)
    span = max(t1 - t0, 1.0)
    width = span / BINS

    buckets, totals = {}, {}
    for t, s, d, nbytes in flows:
        key = (min(int((t - t0) / width), BINS - 1), s, d)
        b = buckets.get(key)
        if b is None:
            buckets[key] = [1, nbytes]
        else:
            b[0] += 1
            b[1] += nbytes
        for cc in {s, d}:
            tot = totals.setdefault(cc, [0, 0])
            tot[0] += 1
            tot[1] += nbytes

    alert_count = len(alerts)
    if alert_count > MAX_ALERTS:
        alerts = sorted(alerts, key=lambda a: (a[3], a[0]))[:MAX_ALERTS]
    alerts.sort(key=lambda a: a[0])

    return {
        'start': t0,
        'span': span,
        'bins': BINS,
        'buckets': [[k[0], k[1], k[2], v[0], v[1]] for k, v in sorted(buckets.items())],
        'alerts': [[round(a[0] - t0, 3), *a[1:]] for a in alerts],
        'totals': totals,
        'flows': len(flows),
        'alertCount': alert_count,
        'type': event_type,
        'hasBytes': _flow_shaped(event_type),
        'geo': geo_lookup.info(),
    }
