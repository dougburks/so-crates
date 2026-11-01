#!/usr/bin/env python3
import gzip
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import geo_lookup
from tests.geo_fixtures import RANGES, build_geoip_dir, load_build_geoip, write_csv


class TestCountry(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, True)
        geo_lookup.clear_cache()
        self.addCleanup(geo_lookup.clear_cache)
        self.dir = build_geoip_dir(os.path.join(self.tmpdir, 'geoip'))

    def cc(self, ip):
        return geo_lookup.country(ip, self.dir)

    def test_ipv4_ranges(self):
        self.assertEqual(self.cc('8.8.8.8'), 'US')
        self.assertEqual(self.cc('8.8.8.255'), 'US')   # a range's last address
        self.assertEqual(self.cc('8.8.9.0'), 'DE')     # the next range's first
        self.assertEqual(self.cc('210.1.2.3'), 'FR')
        self.assertEqual(self.cc('223.255.255.254'), 'FR')

    def test_ipv6_ranges(self):
        self.assertEqual(self.cc('2a00:1450::1'), 'JP')
        self.assertEqual(self.cc('2a01::'), 'BR')
        self.assertEqual(self.cc('2a02:dead:beef::1'), 'BR')

    def test_ipv4_mapped_ipv6_is_its_ipv4_address(self):
        self.assertEqual(self.cc('::ffff:8.8.8.8'), 'US')

    def test_zz_is_unknown(self):
        self.assertEqual(self.cc('150.1.1.1'), geo_lookup.UNKNOWN)

    def test_addresses_that_dont_route_are_local(self):
        for ip in ('10.1.2.3', '172.16.0.1', '192.168.1.1', '127.0.0.1', '169.254.1.1', '100.64.1.1',
                   '224.0.0.251', '239.255.255.250', '0.0.0.0', 'fe80::1', 'fd00::1', '::1', 'ff02::fb'):
            with self.subTest(ip=ip):
                self.assertEqual(self.cc(ip), geo_lookup.LOCAL)

    def test_reserved_space_has_no_country(self):
        self.assertEqual(self.cc('240.0.0.1'), geo_lookup.UNKNOWN)

    def test_not_an_address(self):
        for ip in ('', None, 'garbage', '1.2.3', '?'):
            with self.subTest(ip=ip):
                self.assertEqual(self.cc(ip), geo_lookup.UNKNOWN)

    def test_info(self):
        self.assertTrue(geo_lookup.available(self.dir))
        self.assertEqual(geo_lookup.info(self.dir), {'source': 'DB-IP IP to Country Lite', 'date': '2026-11'})

    def test_without_data_public_addresses_are_unknown(self):
        missing = os.path.join(self.tmpdir, 'none')
        self.assertFalse(geo_lookup.available(missing))
        self.assertIsNone(geo_lookup.info(missing))
        self.assertEqual(geo_lookup.country('8.8.8.8', missing), geo_lookup.UNKNOWN)
        self.assertEqual(geo_lookup.country('10.0.0.1', missing), geo_lookup.LOCAL)

    def test_corrupt_or_truncated_file_is_ignored(self):
        bad = os.path.join(self.tmpdir, 'bad')
        os.makedirs(bad)
        with open(os.path.join(self.dir, 'country.bin.gz'), 'rb') as f:
            whole = gzip.decompress(f.read())
        for name, content in (('not gzip', None), ('short', whole[:-5]), ('no magic', b'x' + whole)):
            with self.subTest(name=name):
                geo_lookup.clear_cache()
                path = os.path.join(bad, 'country.bin.gz')
                if content is None:
                    with open(path, 'wb') as f:
                        f.write(b'not a gzip file')
                else:
                    with gzip.open(path, 'wb') as f:
                        f.write(content)
                self.assertFalse(geo_lookup.available(bad))
                self.assertEqual(geo_lookup.country('8.8.8.8', bad), geo_lookup.UNKNOWN)


class TestBuildGeoip(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, True)
        self.build = load_build_geoip().build

    def _build(self, ranges, **kw):
        src = write_csv(os.path.join(self.tmpdir, 'in.csv.gz'), ranges)
        return self.build(src, os.path.join(self.tmpdir, 'out.bin.gz'), '2026-11', **kw)

    def test_header(self):
        h = self._build(RANGES, min_rows=1)
        self.assertEqual((h['v4'], h['v6']), (4, 2))
        self.assertEqual(h['codes'], ['US', 'DE', 'ZZ', 'FR', 'JP', 'BR'])

    def test_refuses_a_gap(self):
        ranges = [r for r in RANGES if r[2] != 'DE']
        with self.assertRaisesRegex(ValueError, 'not contiguous'):
            self._build(ranges, min_rows=1)

    def test_refuses_ranges_that_stop_early(self):
        with self.assertRaisesRegex(ValueError, 'stop before the end'):
            self._build(RANGES[:-1], min_rows=1)

    def test_refuses_a_bad_country_code(self):
        ranges = [(a, b, 'X1' if c == 'DE' else c) for a, b, c in RANGES]
        with self.assertRaisesRegex(ValueError, 'bad country code'):
            self._build(ranges, min_rows=1)

    def test_refuses_a_truncated_download(self):
        with self.assertRaisesRegex(ValueError, 'truncated'):
            self._build(RANGES)


if __name__ == '__main__':
    unittest.main()
