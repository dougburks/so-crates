#!/usr/bin/env python3
"""The Traffic Map's data: an analysis's flows and alerts by country over time.

Flows are Suricata's flow records, placed at their start and grouped into
(time bin, source country, destination country) buckets, so a capture of
hundreds of thousands of flows stays a small payload. Alerts are kept one
by one (the most severe, up to MAX_ALERTS). Both honor a search the way
every other view does - including country: terms (db.py). Countries come
from geo_lookup.country().
"""

import sqlite3
from datetime import datetime

import geo_lookup
from db import (
    _build_search_terms,
    _build_where_conditions,
    _db_connection,
    _events_select,
    _has_acknowledged_alerts_table,
    _has_events_table,
    _has_fts5,
    _iso_epoch,
)

BINS = 1200          # the timeline's resolution - must match the client's histogram
MAX_ALERTS = 2000


def _epoch(text):
    try:
        return datetime.fromisoformat(text).timestamp()
    except (TypeError, ValueError):
        return _iso_epoch(text)   # Python before 3.11 can't read +0000


def _rows(conn, terms, has_fts, event_type, plain_cols, fts_cols):
    select, type_col = _events_select(terms, has_fts, plain_cols, fts_cols)
    conditions, params = _build_where_conditions(_has_acknowledged_alerts_table(conn), terms, has_fts,
                                                 event_type, type_col)
    sql = select + (' WHERE ' + ' AND '.join(conditions) if conditions else '')
    try:
        return conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []


def empty_traffic_map():
    return {'start': None, 'span': 0, 'bins': BINS, 'buckets': [], 'alerts': [], 'totals': {},
            'flows': 0, 'alertCount': 0, 'geo': geo_lookup.info()}


def get_traffic_map_data(db_path, q=None):
    with _db_connection(db_path) as conn:
        if not _has_events_table(conn):
            return empty_traffic_map()
        terms = _build_search_terms(q)
        has_fts = _has_fts5(conn) if terms else False

        def cols(prefix):
            return (f"{prefix}src_ip, {prefix}dest_ip, json_extract({prefix}json_data, '$.flow.start'), "
                    f"coalesce(json_extract({prefix}json_data, '$.flow.bytes_toserver'), 0) + "
                    f"coalesce(json_extract({prefix}json_data, '$.flow.bytes_toclient'), 0), {prefix}timestamp")
        flow_rows = _rows(conn, terms, has_fts, 'flow', cols(''), cols('e.'))

        def alert_cols(prefix):
            return (f"{prefix}timestamp, {prefix}src_ip, {prefix}dest_ip, "
                    f"json_extract({prefix}json_data, '$.alert.severity'), "
                    f"json_extract({prefix}json_data, '$.alert.signature')")
        alert_rows = _rows(conn, terms, has_fts, 'alert', alert_cols(''), alert_cols('e.'))

    country = geo_lookup.country
    flows = []
    for src, dst, start, nbytes, ts in flow_rows:
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
        return empty_traffic_map()
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
        'geo': geo_lookup.info(),
    }
