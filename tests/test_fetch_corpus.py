#!/usr/bin/env python3
"""scripts/fetch_corpus.py, without the network: its manifest, the post
each malware-traffic-analysis.net capture comes from, what it takes out
of a GitHub archive, and how it checks a folder against the manifest."""
import io
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scripts'))

import fetch_corpus  # noqa: E402


class _Fetch:
    def __init__(self, data):
        self.data = data

    def get(self, url, max_bytes=None):
        return self.data


class TestFetchCorpus(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_the_manifest_covers_only_folders_it_can_fetch(self):
        manifest = fetch_corpus._manifest()
        self.assertGreater(len(manifest), 500)
        self.assertEqual({p.split('/', 1)[0] for p in manifest}, set(fetch_corpus.FOLDERS))
        self.assertTrue(all(len(d) == 64 for d in manifest.values()))

    def test_every_malware_traffic_capture_has_its_post(self):
        problems = []
        for folder in ('mta', 'mta_scans', 'mta_ex'):
            posts = list(fetch_corpus.mta_posts(folder, report=problems.append))
            self.assertTrue(posts, folder)
            self.assertTrue(all(len(post) == 10 for _name, post in posts))
        self.assertEqual(problems, [])
        self.assertIn(('2021-07-traffic-analysis-exercise.pcap', '2021/07/14'), list(fetch_corpus.mta_posts('mta_ex')))

    def test_an_archive_gives_only_its_captures_by_name(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as tar:
            for name, data in (('repo-master/pcaps/BACnet/a.pcap', b'\xd4\xc3\xb2\xa1one'),
                               ('repo-master/pcaps/BACnet/../../../../escape.pcap', b'\xd4\xc3\xb2\xa1two'),
                               ('repo-master/pcaps/BACnet/notes.txt', b'text'),
                               ('repo-master/pcaps/Other/b.pcap', b'\xd4\xc3\xb2\xa1three')):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        source = ('https://example.invalid/archive.tar.gz', 'repo-master/pcaps', ('BACnet',))
        fetch_corpus.github_archive(_Fetch(buffer.getvalue()), self.tmp, 'ics_x', source)
        written = sorted(os.path.relpath(os.path.join(r, f), self.tmp) for r, _d, fs in os.walk(self.tmp) for f in fs)
        self.assertEqual(written, ['ics_x/BACnet/a.pcap', 'ics_x/BACnet/escape.pcap'],
                         'a capture named with ../ lands in its folder by name; text and other folders are left out')

    def test_wstest_takes_the_listed_test_captures_and_names_wiki_uploads_by_folder(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as tar:
            for name in ('wireshark-master-test-captures/test/captures/arp.pcap',
                         'wireshark-master-test-captures/test/captures/new_coverage.pcap.gz'):
                info = tarfile.TarInfo(name)
                info.size = 8
                tar.addfile(info, io.BytesIO(b'\xd4\xc3\xb2\xa1data'))
        fetch = mock.Mock()
        fetch.get.side_effect = lambda url, max_bytes=None: (
            buffer.getvalue() if url == fetch_corpus.WS_TEST_CAPTURES else b'\x0a\x0d\x0d\x0aupload')
        manifest = {'wstest/arp.pcap': '0' * 64, 'wstest/SampleCaptures_dhcp.pcap': '0' * 64,
                    'wstest/049a1e6e7be7eab6cfcf5c8fbe54dde3_ssh.pcapng': '0' * 64}
        urls = ['https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dhcp.pcap',
                'https://wiki.wireshark.org/uploads/049a1e6e7be7eab6cfcf5c8fbe54dde3/ssh.pcapng',
                'https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/arp.pcap']
        with mock.patch.object(fetch_corpus, '_manifest', return_value=manifest), \
                mock.patch.object(fetch_corpus, 'ws_urls', return_value=urls):
            fetch_corpus.wstest(fetch, self.tmp)
        self.assertEqual(sorted(os.listdir(os.path.join(self.tmp, 'wstest'))),
                         ['049a1e6e7be7eab6cfcf5c8fbe54dde3_ssh.pcapng', 'SampleCaptures_dhcp.pcap', 'arp.pcap'],
                         'a test capture or wiki upload the corpus lacks is left out')

    def test_check_reports_missing_changed_and_extra(self):
        manifest = os.path.join(self.tmp, 'manifest.sha256')
        with open(manifest, 'w') as f:
            f.write('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  ics/same.pcap\n'
                    '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  ics/edited.pcap\n'
                    '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  ics/gone.pcap\n')
        corpus = os.path.join(self.tmp, 'corpus')
        for name, data in (('same.pcap', b'hello'), ('edited.pcap', b'hello!'), ('new.pcap', b'x')):
            fetch_corpus.write(os.path.join(corpus, 'ics'), name, data)
        with mock.patch.object(fetch_corpus, 'MANIFEST', manifest):
            self.assertEqual(fetch_corpus.check(corpus, ['ics']),
                             (['ics/gone.pcap'], ['ics/edited.pcap'], ['ics/new.pcap']))

    def test_only_captures_are_kept(self):
        self.assertTrue(fetch_corpus.is_capture(b'\x0a\x0d\x0d\x0a....'))
        self.assertTrue(fetch_corpus.is_capture(b'\x1f\x8b....'))
        self.assertFalse(fetch_corpus.is_capture(b'<!DOCTYPE html>'))
        messages = []
        fetch_corpus.fetch_urls(_Fetch(b'<html>rate limited</html>'), os.path.join(self.tmp, 'ws'),
                                [('x.pcap', 'https://example.invalid/x.pcap')], report=messages.append)
        self.assertEqual((messages, os.path.exists(os.path.join(self.tmp, 'ws', 'x.pcap'))),
                         (['  skipped x.pcap: not a capture'], False))


if __name__ == '__main__':
    unittest.main()
