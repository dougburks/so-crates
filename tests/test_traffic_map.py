#!/usr/bin/env python3
import json
import os
import shutil
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import db
import geo_lookup
import traffic_map
from tests.geo_fixtures import build_geoip_dir


def _flow(src, dst, start, toserver=100, toclient=50, n=0):
    return {'event_type': 'flow', 'timestamp': '2026-01-01T01:00:00.000000+0000', 'src_ip': src, 'src_port': 40000 + n,
            'dest_ip': dst, 'dest_port': 443, 'proto': 'TCP',
            'flow': {'start': start, 'end': start, 'bytes_toserver': toserver, 'bytes_toclient': toclient}}


def _alert(src, dst, ts, severity, signature):
    return {'event_type': 'alert', 'timestamp': ts, 'src_ip': src, 'src_port': 40000, 'dest_ip': dst,
            'dest_port': 80, 'proto': 'TCP', 'alert': {'severity': severity, 'signature': signature, 'signature_id': 1}}


class _GeoCase(unittest.TestCase):
    """Countries from the fixture index: 8.x US, 9-100.x DE, 200+.x FR, 10.x local."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, True)
        geoip = build_geoip_dir(os.path.join(self.tmpdir, 'geoip'))
        patcher = unittest.mock.patch.object(geo_lookup, 'GEOIP_DIR', geoip)
        patcher.start()
        self.addCleanup(patcher.stop)
        geo_lookup.clear_cache()
        self.addCleanup(geo_lookup.clear_cache)

    def _db(self, events):
        eve = os.path.join(self.tmpdir, 'eve.json')
        with open(eve, 'w') as f:
            for e in events:
                f.write(json.dumps(e) + '\n')
        path = os.path.join(self.tmpdir, 'events.db')
        db.create_sqlite_db(path, eve)
        return path


EVENTS = [
    _flow('8.8.8.8', '10.0.0.5', '2026-01-01T00:00:00.000000+0000', n=1),
    _flow('8.8.8.9', '10.0.0.5', '2026-01-01T00:00:00.500000+0000', n=2),
    _flow('210.1.1.1', '10.0.0.5', '2026-01-01T00:10:00.000000+0000', n=3),
    _flow('10.0.0.5', '50.1.1.1', '2026-01-01T00:20:00.000000+0000', toserver=1000, toclient=0, n=4),
    _alert('210.1.1.1', '10.0.0.5', '2026-01-01T00:10:01.000000+0000', 1, 'ET EXPLOIT something'),
    _alert('8.8.8.8', '10.0.0.5', '2026-01-01T00:00:00.000000+0000', 3, 'ET INFO lookup'),
    {'event_type': 'dns', 'timestamp': '2026-01-01T00:05:00.000000+0000', 'src_ip': '10.0.0.5', 'dest_ip': '8.8.8.8',
     'dest_port': 53, 'proto': 'UDP', 'dns': {'rrname': 'example.com'}},
]


class TestTrafficMapData(_GeoCase):
    def test_buckets_totals_and_alerts(self):
        data = traffic_map.get_traffic_map_data(self._db(EVENTS))
        self.assertEqual(data['flows'], 4)
        self.assertEqual(data['bins'], traffic_map.BINS)
        self.assertAlmostEqual(data['span'], 1200.0, places=3)   # first flow to last flow
        self.assertEqual(data['geo']['date'], '2026-11')
        # the two US flows half a second apart share a time bin
        self.assertIn([0, 'US', 'LAN', 2, 300], data['buckets'])
        self.assertIn([traffic_map.BINS // 2, 'FR', 'LAN', 1, 150], data['buckets'])
        self.assertIn([traffic_map.BINS - 1, 'LAN', 'DE', 1, 1000], data['buckets'])
        self.assertEqual(data['totals'], {'US': [2, 300], 'LAN': [4, 1450], 'FR': [1, 150], 'DE': [1, 1000]})
        self.assertEqual(data['alertCount'], 2)
        self.assertEqual(data['alerts'], [
            [0.0, 'US', 'LAN', 3, 'ET INFO lookup', '8.8.8.8', '10.0.0.5'],
            [601.0, 'FR', 'LAN', 1, 'ET EXPLOIT something', '210.1.1.1', '10.0.0.5'],
        ])

    def test_a_flow_without_a_start_uses_its_timestamp(self):
        flow = _flow('8.8.8.8', '10.0.0.5', None)
        del flow['flow']['start']
        data = traffic_map.get_traffic_map_data(self._db([flow, EVENTS[2]]))
        self.assertEqual(data['flows'], 2)
        # the FR flow starts at 00:10; the other, with no start, is placed at its 01:00 timestamp
        self.assertEqual(data['start'], 1767226200.0)
        self.assertAlmostEqual(data['span'], 3000.0, places=3)

    def test_country_search(self):
        path = self._db(EVENTS)
        data = traffic_map.get_traffic_map_data(path, ['country:FR'])
        self.assertEqual(data['flows'], 1)
        self.assertEqual([a[1] for a in data['alerts']], ['FR'])
        data = traffic_map.get_traffic_map_data(path, ['country:lan'])
        self.assertEqual(data['flows'], 4)
        data = traffic_map.get_traffic_map_data(path, ['country:US', 'lookup'])
        self.assertEqual((data['flows'], data['alertCount']), (0, 1))

    def test_most_severe_alerts_kept(self):
        events = [_alert('8.8.8.8', '10.0.0.5', f'2026-01-01T00:00:{i:02d}.000000+0000', 1 if i in (7, 9) else 3, f'sig {i}')
                  for i in range(10)]
        with unittest.mock.patch.object(traffic_map, 'MAX_ALERTS', 3):
            data = traffic_map.get_traffic_map_data(self._db(events))
        self.assertEqual(data['alertCount'], 10)
        self.assertEqual([a[4] for a in data['alerts']], ['sig 0', 'sig 7', 'sig 9'])

    def test_a_record_type_takes_the_flows_place(self):
        data = traffic_map.get_traffic_map_data(self._db(EVENTS), event_type='dns')
        self.assertEqual((data['type'], data['hasBytes'], data['flows']), ('dns', False, 1))
        # placed at its timestamp (00:05, of 00:00 to the last alert at
        # 00:10:01), with no bytes; the alerts stay over it
        self.assertEqual(data['buckets'], [[599, 'LAN', 'US', 1, 0]])
        self.assertEqual(data['alertCount'], 2)
        self.assertEqual(data['totals'], {'LAN': [1, 0], 'US': [1, 0]})

    def test_the_alert_type_is_its_alerts_alone(self):
        data = traffic_map.get_traffic_map_data(self._db(EVENTS), event_type='alert')
        # the alerts are its records too, so the countries and the Top list are theirs
        self.assertEqual((data['type'], data['hasBytes'], data['flows'], data['alertCount']), ('alert', False, 2, 2))
        self.assertEqual(data['totals'], {'US': [1, 0], 'FR': [1, 0], 'LAN': [2, 0]})

    def test_the_flow_type_is_the_whole_map(self):
        path = self._db(EVENTS)
        whole = traffic_map.get_traffic_map_data(path)
        self.assertEqual(traffic_map.get_traffic_map_data(path, event_type='flow'), whole)
        self.assertEqual((whole['type'], whole['hasBytes']), (None, True))

    def test_a_connection_type_keeps_its_bytes(self):
        conn = _flow('8.8.8.8', '10.0.0.5', '2026-01-01T00:00:00.000000+0000', toserver=7, toclient=3)
        conn['event_type'] = db.CONNECTION_TYPE_PREFIX + 'openvpn'
        data = traffic_map.get_traffic_map_data(self._db([conn, EVENTS[0]]), event_type=conn['event_type'])
        self.assertEqual((data['flows'], data['hasBytes']), (1, True))
        self.assertEqual(data['buckets'], [[0, 'US', 'LAN', 1, 10]])

    def test_findings_are_the_records_its_rules_match(self):
        def ipmi(src, ts, weaknesses):
            return {'event_type': 'ipmi', 'timestamp': ts, 'src_ip': src, 'dest_ip': '10.0.0.5',
                    'dest_port': 623, 'proto': 'UDP', 'ipmi': {'weaknesses': weaknesses}}
        events = EVENTS + [
            # matches two rules (cipher zero, anonymous): placed once
            ipmi('8.8.8.8', '2026-01-01T00:01:00.000000+0000', ['cipher zero accepted', 'anonymous login']),
            ipmi('210.1.1.1', '2026-01-01T00:02:00.000000+0000', ['cleartext password']),
            ipmi('50.1.1.1', '2026-01-01T00:03:00.000000+0000', []),   # matches none
        ]
        path = self._db(events)
        data = traffic_map.get_traffic_map_data(path, event_type='findings')
        self.assertEqual((data['type'], data['hasBytes'], data['flows'], data['alertCount']), ('findings', False, 2, 2))
        self.assertEqual(data['totals'], {'US': [1, 0], 'FR': [1, 0], 'LAN': [2, 0]})
        # and they're searched like any other records
        data = traffic_map.get_traffic_map_data(path, ['country:FR'], 'findings')
        self.assertEqual(data['flows'], 1)

    def test_all_events_is_every_event_but_the_alerts(self):
        decoder = _alert('8.8.8.8', '10.0.0.5', '2026-01-01T00:00:00.000000+0000', 3, 'SURICATA STREAM')
        decoder['event_type'] = 'protocol_decode'
        decoder['flow'] = {'bytes_toserver': 999, 'bytes_toclient': 999}
        conn = _flow('8.8.8.8', '10.0.0.5', '2026-01-01T00:00:00.000000+0000')
        conn['event_type'] = db.CONNECTION_TYPE_PREFIX + 'openvpn'
        path = self._db(EVENTS + [decoder, conn])
        data = traffic_map.get_traffic_map_data(path, event_type='all')
        # 4 flows, the DNS query and the decoder alert; not the 2 alerts,
        # which fly over it anyway, nor tshark's connection row, which
        # All Events leaves out too
        self.assertEqual((data['type'], data['hasBytes'], data['flows'], data['alertCount']), ('all', True, 6, 2))
        # the bytes are the flows' alone - not the decoder alert's copy of its flow's
        whole = traffic_map.get_traffic_map_data(path)
        self.assertEqual(sum(b[4] for b in data['buckets']), sum(b[4] for b in whole['buckets']))

    def test_a_record_without_addresses_is_left_off(self):
        stats = {'event_type': 'stats', 'timestamp': '2026-01-01T00:00:00.000000+0000', 'stats': {}}
        data = traffic_map.get_traffic_map_data(self._db([stats]), event_type='stats')
        self.assertEqual((data['flows'], data['type']), (0, 'stats'))

    def test_no_flows_or_alerts(self):
        data = traffic_map.get_traffic_map_data(self._db([EVENTS[-1]]))
        self.assertEqual(data['flows'], 0)
        self.assertEqual(data['buckets'], [])
        self.assertIsNone(data['start'])
        self.assertEqual(traffic_map.empty_traffic_map()['bins'], traffic_map.BINS)


class TestCountrySearchTerms(_GeoCase):
    def test_terms_split(self):
        terms = db._build_search_terms(['zmap', 'country:fr', 'Country:LAN', 'country:??', 'country:FR', 'country:xyz', ' '])
        self.assertEqual(list(terms), ['zmap', 'country:xyz'])
        self.assertEqual(terms.countries, ['FR', 'LAN', '??'])
        self.assertEqual(db._build_search_terms('country:de').countries, ['DE'])
        self.assertEqual(db._build_search_terms(None).countries, [])

    def test_country_term(self):
        self.assertEqual(db.country_term(' country:gb '), 'GB')
        self.assertIsNone(db.country_term('country: GB'))
        self.assertIsNone(db.country_term('xcountry:GB'))

    def test_every_view_filters_by_country(self):
        path = self._db(EVENTS)
        self.assertEqual(db.get_event_count_sqlite(path, 'flow', ['country:US']), 2)
        self.assertEqual(db.get_event_count_sqlite(path, None, ['country:US']), 4)   # 2 flows, an alert, the DNS query
        self.assertEqual(db.get_event_types_sqlite(path, ['country:FR']), {'flow': 1, 'alert': 1})
        # two countries: traffic between them
        self.assertEqual(db.get_event_count_sqlite(path, 'flow', ['country:US', 'country:LAN']), 2)
        self.assertEqual(db.get_event_count_sqlite(path, 'flow', ['country:US', 'country:FR']), 0)
        # with a text term, through the full-text index
        self.assertEqual(db.get_event_count_sqlite(path, None, ['country:US', 'example.com']), 1)
        rows = db.query_events_sqlite(path, 'flow', q=['country:DE'])
        self.assertEqual([r['dest_ip'] for r in rows], ['50.1.1.1'])
        sankey = db.get_sankey_data_sqlite(path, 'flow', ['country:FR'])
        self.assertEqual({n['name'] for n in sankey['nodes']}, {'210.1.1.1', '10.0.0.5', '443'})


if __name__ == '__main__':
    unittest.main()
