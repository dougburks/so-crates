#!/usr/bin/env python3
"""Tests for suricata_sid_ranges.py: classify_alert_ruleset(),
sid_ranges_sql_case(), and a consistency check against
suricata_analyzer.SURICATA_RULE_SOURCES (whose labels are intentionally
duplicated in suricata_sid_ranges.py to avoid a circular import - see that
module's docstring)."""

import os
import sqlite3
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import suricata_sid_ranges as sr


# One representative real SID per curated source, taken from the actual
# --no-merge-derived data used to build SURICATA_SID_RANGES.
SAMPLE_SIDS = {
    'et/open': 2010957,
    'tgreen/hunting': 2610500,
    'stamus/lateral': 3115300,
    'pawpatrules': 3310000,
    'aleksibovellan/nmap': 3400010,
    'the-hunters-ledger/open': 3500100,
    'etnetera/aggressive': 5000010,
    'julioliraup/antiphishing': 6005000,
    'ptrules/open': 10500000,
    'ipfire/dbl': 12001000,
    'abuse.ch/urlhaus': 84760628,
    'oisf/trafficid': 300000010,
    'abuse.ch/feodotracker': 900510000,
    'abuse.ch/sslbl-blacklist': 903205000,
    'abuse.ch/sslbl-ja3': 906200050,
}


class TestClassifyAlertRuleset(unittest.TestCase):
    def test_each_curated_source_sample_sid_classifies_correctly(self):
        by_slug = {slug: label for _min, _max, slug, label in sr.SURICATA_SID_RANGES}
        for slug, sid in SAMPLE_SIDS.items():
            self.assertEqual(sr.classify_alert_ruleset(sid), by_slug[slug], slug)

    def test_builtin_range(self):
        self.assertEqual(sr.classify_alert_ruleset(1), sr.SURICATA_BUILTIN_LABEL)
        self.assertEqual(sr.classify_alert_ruleset(500000), sr.SURICATA_BUILTIN_LABEL)

    def test_builtin_event_rules_inside_et_open_span(self):
        """REGRESSION: Suricata's own decoder/stream/app-layer event rules
        (2200000-2299999) sit inside et/open's span - et/open was checked
        first, so essentially every protocol-decode alert said 'Emerging
        Threats Open'. 2210054 is a real stream-events rule; 2290021 is a
        real built-in rule just past the old single range's end."""
        for sid in (2200000, 2210054, 2260000, 2290021, 2299999):
            self.assertEqual(sr.classify_alert_ruleset(sid), sr.SURICATA_BUILTIN_LABEL, sid)
        # et/open either side of the event-rule block is still et/open.
        self.assertEqual(sr.classify_alert_ruleset(2199999), 'Emerging Threats Open')
        self.assertEqual(sr.classify_alert_ruleset(2300000), 'Emerging Threats Open')

    def test_builtin_ranges_never_cover_a_curated_floor(self):
        """Checked first, so a built-in range must not swallow the start of
        any curated source's own range."""
        for min_sid, _max, slug, label in sr.SURICATA_SID_RANGES:
            self.assertEqual(sr.classify_alert_ruleset(min_sid), label, slug)

    def test_unmatched_sid_is_other(self):
        # Genuine gaps between known ranges.
        self.assertEqual(sr.classify_alert_ruleset(2600000), sr.OTHER_RULESET_LABEL, 'gap between et/open and tgreen/hunting')
        self.assertEqual(sr.classify_alert_ruleset(7000000), sr.OTHER_RULESET_LABEL, 'gap between antiphishing and ptrules/open')

    def test_boundary_edges(self):
        for min_sid, max_sid, slug, label in sr.SURICATA_SID_RANGES:
            self.assertEqual(sr.classify_alert_ruleset(min_sid), label, f'{slug} min')
            # Not necessarily 'Other' one below the floor - et/open's own
            # min-1 (2000004) falls inside the low built-in range - only
            # assert it stops being *this* source, not what it becomes.
            self.assertNotEqual(sr.classify_alert_ruleset(min_sid - 1), label, f'{slug} min-1 must not still classify as {slug}')
            if max_sid is not None:
                self.assertEqual(sr.classify_alert_ruleset(max_sid), label, f'{slug} max')

    def test_urlhaus_generous_headroom_but_not_unbounded(self):
        """abuse.ch/urlhaus is a live, daily-growing counter, so it gets a
        very generous ceiling (200000000, ~115M above its observed max of
        ~84.76M) rather than being genuinely unbounded - an unbounded range
        would silently swallow every curated range numerically above it
        (oisf/trafficid, abuse.ch/feodotracker, abuse.ch/sslbl-*), since a
        linear first-match scan can't be fixed by reordering once one
        range has no ceiling at all. A sid well within that headroom must
        still classify as urlhaus; a sid at/past its ceiling must not."""
        self.assertEqual(sr.classify_alert_ruleset(150000000), 'Abuse.ch URLhaus')
        self.assertEqual(sr.classify_alert_ruleset(200000001), sr.OTHER_RULESET_LABEL)

    def test_open_ended_range_capability_still_works_generically(self):
        """No entry in the real SURICATA_SID_RANGES table currently uses
        max_sid=None (see its comment for why), but the capability itself
        must still work correctly wherever it might be used - verified
        directly against classify_alert_ruleset's logic with a synthetic
        entry rather than via the real (bounded) table. Also patches
        SURICATA_BUILTIN_SID_RANGES out of the way (to something disjoint
        from every test value here) since it's separate, always-active and
        not part of SURICATA_SID_RANGES."""
        import unittest.mock
        synthetic = [(1000, None, 'fake/source', 'Fake Source')]
        with unittest.mock.patch.object(sr, 'SURICATA_SID_RANGES', synthetic), \
             unittest.mock.patch.object(sr, 'SURICATA_BUILTIN_SID_RANGES', [(99990000, 99999999)]):
            self.assertEqual(sr.classify_alert_ruleset(1000), 'Fake Source')
            self.assertEqual(sr.classify_alert_ruleset(999999999999), 'Fake Source')
            self.assertEqual(sr.classify_alert_ruleset(999), sr.OTHER_RULESET_LABEL)

    def test_none_and_non_numeric_sid_is_other(self):
        self.assertEqual(sr.classify_alert_ruleset(None), sr.OTHER_RULESET_LABEL)
        self.assertEqual(sr.classify_alert_ruleset('not-a-number'), sr.OTHER_RULESET_LABEL)
        self.assertEqual(sr.classify_alert_ruleset('2010957'), 'Emerging Threats Open',
                          'a numeric string must still classify correctly')


class TestSidRangesSqlCase(unittest.TestCase):
    """Round-trip check: for every sample sid, the generated SQL CASE
    expression evaluated by real sqlite3 must return exactly what
    classify_alert_ruleset() returns in Python - guarantees SQL/Python
    parity by construction, not just by inspection."""

    def test_sql_matches_python_for_all_sample_sids(self):
        # expr appears once per WHEN clause in the generated CASE, so a
        # positional '?' would need one binding per occurrence - a named
        # parameter lets the same value satisfy every occurrence with a
        # single binding.
        case_sql = sr.sid_ranges_sql_case(':sid')
        conn = sqlite3.connect(':memory:')
        try:
            all_sids = list(SAMPLE_SIDS.values()) + [
                1, 2210054, 2290020, 2290021, 2199999, 2300000, 999999999, -5,
            ]
            for sid in all_sids:
                row = conn.execute(f'SELECT {case_sql}', {'sid': sid}).fetchone()
                self.assertEqual(row[0], sr.classify_alert_ruleset(sid), sid)
        finally:
            conn.close()

    def test_sql_case_is_syntactically_valid_standalone(self):
        case_sql = sr.sid_ranges_sql_case('42')
        conn = sqlite3.connect(':memory:')
        try:
            row = conn.execute(f'SELECT {case_sql}').fetchone()
            self.assertEqual(row[0], sr.SURICATA_BUILTIN_LABEL)
        finally:
            conn.close()


class TestConsistencyWithSuricataAnalyzer(unittest.TestCase):
    """suricata_sid_ranges.py deliberately duplicates each source's label
    string (not the whole SURICATA_RULE_SOURCES dict) to avoid a circular
    import (db.py -> suricata_sid_ranges.py must not transitively reach
    suricata_analyzer.py, which imports db.py). This test is the only
    thing keeping the two in sync - it may safely import both, since only
    the production modules have the circularity constraint."""

    def test_every_slug_exists_in_suricata_rule_sources(self):
        import suricata_analyzer
        for _min, _max, slug, _label in sr.SURICATA_SID_RANGES:
            self.assertIn(slug, suricata_analyzer.SURICATA_RULE_SOURCES, slug)

    def test_every_curated_source_has_a_range(self):
        """The other direction: a source with no range here shows all its
        alerts as 'Other / Unrecognized' - The Hunter's Ledger did."""
        import suricata_analyzer
        ranged = {slug for _min, _max, slug, _label in sr.SURICATA_SID_RANGES}
        for slug in suricata_analyzer.SURICATA_RULE_SOURCES:
            self.assertIn(slug, ranged, slug)

    def test_labels_match_suricata_rule_sources_exactly(self):
        import suricata_analyzer
        for _min, _max, slug, label in sr.SURICATA_SID_RANGES:
            self.assertEqual(label, suricata_analyzer.SURICATA_RULE_SOURCES[slug]['label'], slug)


if __name__ == '__main__':
    unittest.main()
