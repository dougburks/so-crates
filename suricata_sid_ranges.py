#!/usr/bin/env python3
"""Best-effort mapping of a Suricata alert's signature_id (SID) to the
curated ruleset (see suricata_analyzer.SURICATA_RULE_SOURCES) it most
likely came from.

Deliberately has ZERO imports from the rest of this app.
suricata_analyzer.py already does `from db import create_sqlite_db`, so
db.py (which needs SURICATA_SID_RANGES for its SQL CASE generation) cannot
import suricata_analyzer.py or anything that imports it without creating a
cycle. Each source's label is duplicated here as a plain string rather than
imported from suricata_analyzer.SURICATA_RULE_SOURCES - kept in sync by
tests/test_suricata_sid_ranges.py's consistency check, not by import.

SURICATA_SID_RANGES was derived empirically on 2026-08-05, not from
community folklore about "official" SID allocations (several of these
curated sources - abuse.ch's feeds, pawpatrules, etc. - predate/postdate
any registry and don't follow one): every curated source was enabled
individually and fetched with `suricata-update --no-merge --data-dir
<tmp> --output <tmp>`, which writes one file per source instead of a
single merged suricata.rules, then every `sid:` value in each resulting
file was extracted directly. No two curated sources share a SID. et/open
does ship copies of Suricata's own built-in decoder/stream/app-layer event
rules (2200000-2299999, same SIDs - re-checked 2026-09-25: 440 of them),
which is why those are classified as built-in first - see
SURICATA_BUILTIN_SID_RANGES. This is a snapshot, not a guarantee - a source's rules could in
principle drift outside its recorded range as it's updated over time; an
unexpected rise in 'Other / Unrecognized' classifications is the signal
that re-deriving this table (same method) may be due.
"""

# (min_sid, max_sid_or_None, slug, label). max_sid=None means truly
# open-ended - reserved for a source with no other curated range anywhere
# above it, since a linear "first range containing sid wins" scan can't be
# fixed by reordering once a range is genuinely unbounded: an unbounded
# entry absorbs every sid above its floor regardless of scan position,
# including ranges listed after it. abuse.ch/urlhaus IS a live,
# daily-growing counter with no natural ceiling, but three curated ranges
# sit numerically above its floor (oisf/trafficid at 300000000+,
# abuse.ch/feodotracker and abuse.ch/sslbl-* at 900000000+) - giving it
# max=None would silently swallow all three. Instead it gets a concrete,
# very generous ceiling (200000000 - ~115M of headroom above its observed
# max of ~84.76M, comfortably below oisf/trafficid's 300000000 floor).
SURICATA_SID_RANGES = [
    (2000005, 2527021, 'et/open', 'Emerging Threats Open'),
    (2610178, 2610881, 'tgreen/hunting', 'Threat Hunting Rules (tgreen)'),
    (3115102, 3115668, 'stamus/lateral', 'Stamus Lateral Movement'),
    (3300003, 3321492, 'pawpatrules', 'PAW Patrules'),
    (3400001, 3400021, 'aleksibovellan/nmap', 'NMAP Scan Detection'),
    (3500000, 3500201, 'the-hunters-ledger/open', "The Hunter's Ledger"),
    (5000000, 5000020, 'etnetera/aggressive', 'Etnetera Aggressive IP Blacklist'),
    (6000000, 6013663, 'julioliraup/antiphishing', 'Antiphishing'),
    (10000035, 11004724, 'ptrules/open', 'Positive Technologies PT Rules (Open)'),
    (12000801, 12002504, 'ipfire/dbl', 'IPFire DBL'),
    (80878811, 200000000, 'abuse.ch/urlhaus', 'Abuse.ch URLhaus'),
    (300000000, 300000033, 'oisf/trafficid', 'Suricata Traffic ID'),
    (900509159, 900513704, 'abuse.ch/feodotracker', 'Abuse.ch Feodo Tracker'),
    (903200000, 903210275, 'abuse.ch/sslbl-blacklist', 'Abuse.ch SSL Blacklist'),
    (906200000, 906200096, 'abuse.ch/sslbl-ja3', 'Abuse.ch JA3 Fingerprints'),
]

# Suricata's own bundled decoder/stream/app-layer/file rules - always
# loaded from /etc/suricata/rules/* regardless of which curated online
# sources are enabled, so not a "ruleset" in SURICATA_RULE_SOURCES at all.
# Checked FIRST, before SURICATA_SID_RANGES: the 2200000-2299999 block sits
# inside et/open's span, and et/open even ships copies of these same rules,
# so checking et/open first labelled essentially every protocol-decode
# alert "Emerging Threats Open". Two exact ranges, not one span from 1:
# the low one ends below et/open's floor (2000005), so no et/open rule
# outside the event-rule block is ever claimed as built-in.
SURICATA_BUILTIN_SID_RANGES = [(1, 1999999), (2200000, 2299999)]
SURICATA_BUILTIN_LABEL = 'Suricata (built-in)'

OTHER_RULESET_LABEL = 'Other / Unrecognized'


def classify_alert_ruleset(sid):
    """Return the display label of the curated ruleset (or
    SURICATA_BUILTIN_LABEL, or OTHER_RULESET_LABEL) a signature_id most
    likely came from. Never raises - None or a non-numeric sid maps to
    OTHER_RULESET_LABEL."""
    try:
        sid = int(sid)
    except (TypeError, ValueError):
        return OTHER_RULESET_LABEL
    for builtin_min, builtin_max in SURICATA_BUILTIN_SID_RANGES:
        if builtin_min <= sid <= builtin_max:
            return SURICATA_BUILTIN_LABEL
    for min_sid, max_sid, _slug, label in SURICATA_SID_RANGES:
        if sid >= min_sid and (max_sid is None or sid <= max_sid):
            return label
    return OTHER_RULESET_LABEL


def sid_ranges_sql_case(expr):
    """Build a SQL CASE expression classifying expr (a SQL expression
    yielding a signature_id) the same way classify_alert_ruleset() does in
    Python, generated from the exact same table so the two can never
    independently drift apart. expr is interpolated as-is - callers must
    never pass anything derived from untrusted input."""
    builtin_escaped = SURICATA_BUILTIN_LABEL.replace("'", "''")
    parts = [f"WHEN {expr} BETWEEN {builtin_min} AND {builtin_max} THEN '{builtin_escaped}'"
             for builtin_min, builtin_max in SURICATA_BUILTIN_SID_RANGES]
    for min_sid, max_sid, _slug, label in SURICATA_SID_RANGES:
        escaped = label.replace("'", "''")
        if max_sid is None:
            parts.append(f"WHEN {expr} >= {min_sid} THEN '{escaped}'")
        else:
            parts.append(f"WHEN {expr} BETWEEN {min_sid} AND {max_sid} THEN '{escaped}'")
    other_escaped = OTHER_RULESET_LABEL.replace("'", "''")
    return 'CASE ' + ' '.join(parts) + f" ELSE '{other_escaped}' END"
