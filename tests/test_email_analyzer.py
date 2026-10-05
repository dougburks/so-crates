"""Tests for email_analyzer.py - parsing .eml messages into events, and
storing/scanning their attachments. Messages are built by
tests/eml_fixtures.py; YARA is replaced by a fake scan function."""

import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from email.message import EmailMessage
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import config
import email_analyzer
from suricata_analyzer import find_extracted_file
from tests import eml_fixtures


def _by_type(events, event_type):
    return [e for e in events if e['event_type'] == event_type]


class TestParseMessage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events, cls.attachments = email_analyzer.parse_message(eml_fixtures.phishing_message())
        cls.emails = _by_type(cls.events, 'email')
        cls.top = cls.emails[0]['email']
        cls.links = [e['link'] for e in _by_type(cls.events, 'link')]

    def test_events_have_no_network_fields(self):
        for e in self.events:
            self.assertEqual((e['src_ip'], e['src_port'], e['dest_ip'], e['dest_port'], e['proto']), ('', 0, '', 0, ''))

    def test_headers(self):
        self.assertEqual(self.top['from'], '"Bank, Security Team" <security@bank.example>')
        self.assertEqual(self.top['to'], ['victim@example.com', 'Other Person <other@example.com>'])
        self.assertEqual(self.top['subject'], 'Action required: verify your account', 'encoded-word decoded')
        self.assertEqual(self.top['message_id'], '<abc123@badhost.example>')
        self.assertEqual(self.top['mailer'], 'TotallyLegitMailer 1.0')
        self.assertEqual(self.top['return_path'], 'bounce@badhost.example')

    def test_timestamp_comes_from_date_header(self):
        self.assertEqual(self.emails[0]['timestamp'], '2026-02-03T10:00:00+00:00')
        # Every event of the upload carries it - the forward's too - so
        # they sort together.
        self.assertTrue(all(e['timestamp'] == '2026-02-03T10:00:00+00:00' for e in self.events))

    def test_auth_results(self):
        self.assertEqual((self.top['spf'], self.top['dkim'], self.top['dmarc']), ('fail', 'none', 'fail'))

    def test_received_chain_oldest_first_and_originating_ip(self):
        hops = self.top['received']
        self.assertEqual([h.get('ip') for h in hops], ['1.2.3.4', '10.0.0.5'])
        self.assertEqual(hops[0]['from'], 'sender.badhost.example')
        self.assertEqual(hops[0]['by'], 'mail.example.com')
        self.assertEqual(self.top['originating_ip'], '1.2.3.4', 'first public hop, not the private one')

    def test_warnings(self):
        warnings = ' | '.join(self.top['warnings'])
        self.assertIn('Reply-To domain (collector.example) differs from From (bank.example)', warnings)
        self.assertIn('Return-Path domain (badhost.example)', warnings)
        self.assertIn('SPF fail', warnings)
        self.assertIn('DMARC fail', warnings)
        self.assertNotIn('DKIM', warnings, "'none' is not a failure")
        self.assertIn('1 link(s)', warnings)
        self.assertIn('executable extension: invoice.com', warnings)

    def test_links(self):
        urls = [(l['url'], l['text']) for l in self.links]
        self.assertIn(('https://bank.example.verify-login.example/start', 'https://www.bank.example/login'), urls)
        # The anchor's visible URL text is its label, not a second link;
        # the plain-text copy of the same href isn't repeated either.
        self.assertNotIn('https://www.bank.example/login', [u for u, _ in urls])
        self.assertEqual([u for u, _ in urls].count('https://bank.example.verify-login.example/start'), 1)
        self.assertNotIn('https://not-a-link.example/', [u for u, _ in urls], 'script content is not a link')

    def test_link_mismatch(self):
        by_url = {l['url']: l for l in self.links}
        bad = by_url['https://bank.example.verify-login.example/start']
        self.assertTrue(bad['mismatch'])
        self.assertEqual(bad['text_domain'], 'www.bank.example')
        self.assertEqual(bad['domain'], 'bank.example.verify-login.example')
        self.assertFalse(by_url['https://help.bank.example/faq']['mismatch'], 'plain words claim no domain')
        self.assertFalse(by_url['https://cdn.example/invoice.pdf']['mismatch'], 'a filename is not a domain')

    def test_forwarded_message_is_its_own_email(self):
        self.assertEqual(len(self.emails), 2)
        fwd = self.emails[1]['email']
        self.assertEqual(fwd['subject'], 'FW: earlier notice')
        self.assertEqual(fwd['depth'], 1)
        # The upload's time, so it sorts after the message it was attached
        # to; its own date is kept.
        self.assertEqual(self.emails[1]['timestamp'], '2026-02-03T10:00:00+00:00')
        self.assertEqual(fwd['date'], 'Mon, 02 Feb 2026 09:00:00 +0000')
        self.assertEqual(fwd['attachments'], ['notes.txt'])
        self.assertEqual(self.top['attachments'], ['invoice.com'], "the forward's attachment is not the outer message's")
        self.assertEqual(fwd['link_count'], 1)

    def test_attachments_are_decoded(self):
        self.assertEqual([(n, d) for n, d, _t in self.attachments],
                         [('invoice.com', eml_fixtures.EICAR), ('notes.txt', b'just some notes\n')])

    def test_body_prefers_plain_text(self):
        self.assertTrue(self.top['body'].startswith('Dear customer,'))
        self.assertNotIn('<p>', self.top['body'])
        self.assertFalse(self.top['body_truncated'])


class TestParseEdgeCases(unittest.TestCase):
    def test_plain_message_has_no_warnings(self):
        events, attachments = email_analyzer.parse_message(eml_fixtures.plain_message())
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['email']['warnings'], [])
        self.assertEqual(events[0]['timestamp'], '2026-02-04T13:30:00+00:00', 'converted to UTC')
        self.assertEqual(attachments, [])

    def test_html_only_body_becomes_text(self):
        msg = EmailMessage()
        msg['From'] = 'a@example.com'
        msg['Subject'] = 'html'
        msg.set_content('<p>Hello <b>there</b></p><style>p{}</style>', subtype='html')
        events, _ = email_analyzer.parse_message(msg.as_bytes())
        self.assertEqual(events[0]['email']['body'], 'Hello there')

    def test_missing_or_bad_date_falls_back(self):
        events, _ = email_analyzer.parse_message(b'From: a@example.com\nSubject: x\nDate: not a date\n\nbody\n', now='NOW')
        self.assertEqual(events[0]['timestamp'], 'NOW')

    def test_unknown_charset_does_not_raise(self):
        raw = (b'From: a@example.com\nSubject: x\nContent-Type: text/plain; charset="x-no-such-charset"\n\n'
               b'caf\xe9 https://example.com/a\n')
        events, _ = email_analyzer.parse_message(raw)
        self.assertIn('caf', events[0]['email']['body'])
        self.assertEqual([e['link']['url'] for e in events if e['event_type'] == 'link'], ['https://example.com/a'])

    def test_garbage_does_not_raise(self):
        events, _ = email_analyzer.parse_message(b'\x00\xff\x00 not an email at all')
        self.assertEqual(_by_type(events, 'email')[0]['email']['from'], '')

    def test_macro_enabled_attachment_warning(self):
        msg = EmailMessage()
        msg['From'] = 'a@example.com'
        msg.set_content('see attached')
        msg.add_attachment(b'PK\x03\x04', maintype='application', subtype='octet-stream', filename='Form.XLSM')
        events, _ = email_analyzer.parse_message(msg.as_bytes())
        self.assertIn('Attachment is a macro-enabled Office document: Form.XLSM', events[0]['email']['warnings'])

    def test_url_trailing_punctuation_trimmed(self):
        events, _ = email_analyzer.parse_message(b'From: a@example.com\n\nSee (https://example.com/x).\n')
        self.assertEqual(events[1]['link']['url'], 'https://example.com/x')

    def test_link_count_is_capped(self):
        body = ' '.join(f'https://example.com/{i}' for i in range(20)).encode()
        with mock.patch.object(config, 'MAX_EMAIL_LINKS', 5):
            events, _ = email_analyzer.parse_message(b'From: a@example.com\n\n' + body)
        self.assertEqual(len(_by_type(events, 'link')), 5)

    def test_attachment_count_is_capped(self):
        msg = EmailMessage()
        msg['From'] = 'a@example.com'
        msg.set_content('x')
        for i in range(5):
            msg.add_attachment(b'data%d' % i, maintype='application', subtype='octet-stream', filename=f'f{i}.bin')
        with mock.patch.object(config, 'MAX_EMAIL_ATTACHMENTS', 2):
            _, attachments = email_analyzer.parse_message(msg.as_bytes())
        self.assertEqual(len(attachments), 2)

    def test_forward_depth_is_capped(self):
        inner = EmailMessage()
        inner['Subject'] = 'level 0'
        inner.set_content('x')
        for level in range(1, 4):
            outer = EmailMessage()
            outer['Subject'] = f'level {level}'
            outer.set_content('x')
            outer.add_attachment(inner)
            inner = outer
        with mock.patch.object(config, 'MAX_EMAIL_DEPTH', 1):
            events, _ = email_analyzer.parse_message(inner.as_bytes())
        self.assertEqual([e['email']['subject'] for e in _by_type(events, 'email')], ['level 3', 'level 2'])

    def test_nested_forwards_are_parsed_once_each(self):
        inner = EmailMessage()
        inner['Subject'] = 'inner'
        inner.set_content('x')
        middle = EmailMessage()
        middle['Subject'] = 'middle'
        middle.set_content('x')
        middle.add_attachment(inner)
        outer = EmailMessage()
        outer['Subject'] = 'outer'
        outer.set_content('x')
        outer.add_attachment(middle)
        events, _ = email_analyzer.parse_message(outer.as_bytes())
        self.assertEqual([e['email']['subject'] for e in _by_type(events, 'email')], ['outer', 'middle', 'inner'])


class TestHostileInput(unittest.TestCase):
    """REGRESSIONS (4.4.0 review): phishing mail is hostile input - each of
    these used to fail the whole analysis, run for minutes, or hide an
    attachment without a word."""

    def _parse(self, raw):
        events, attachments = email_analyzer.parse_message(raw, now='NOW')
        return events, attachments, _by_type(events, 'email')[0]['email']

    def test_malformed_address_headers_are_read_raw(self):
        for header in (b'From', b'To', b'Cc', b'Reply-To'):
            with self.subTest(header=header):
                _, _, top = self._parse(header + b': "\r\nSubject: x\r\n\r\nbody\r\n')
                self.assertEqual(top['subject'], 'x')

    def test_out_of_range_date_falls_back(self):
        events, _, _ = self._parse(b'From: a@example.com\r\nDate: Fri, 31 Dec 9999 23:59:59 -2359\r\n\r\nx\r\n')
        self.assertEqual(events[0]['timestamp'], 'NOW')

    def _forwards(self, count):
        outer = EmailMessage()
        outer['Subject'] = 'outer'
        outer.set_content('x')
        for i in range(count):
            fwd = EmailMessage()
            fwd['Subject'] = f'fwd {i}'
            fwd.set_content('x')
            outer.add_attachment(fwd)
        return outer.as_bytes()

    def test_many_forwards_are_capped_quickly_and_reported(self):
        import time
        raw = self._forwards(400)
        start = time.monotonic()
        events, _, top = self._parse(raw)
        self.assertLess(time.monotonic() - start, 5, 'one pass over the parts, not one per forward')
        self.assertEqual(len(_by_type(events, 'email')), 1 + config.MAX_EMAIL_MESSAGES)
        self.assertIn(f'{400 - config.MAX_EMAIL_MESSAGES} forwarded message(s)', ' '.join(top['warnings']))

    def test_attachments_beyond_the_limit_are_reported(self):
        msg = EmailMessage()
        msg['From'] = 'a@example.com'
        msg.set_content('x')
        for i in range(5):
            msg.add_attachment(b'data%d' % i, maintype='application', subtype='octet-stream', filename=f'f{i}.bin')
        with mock.patch.object(config, 'MAX_EMAIL_ATTACHMENTS', 2):
            _, attachments, top = self._parse(msg.as_bytes())
        self.assertEqual(len(attachments), 2)
        self.assertIn('Beyond the analysis limits, not analyzed: 3 attachment(s)', top['warnings'])

    def test_forwards_beyond_the_depth_limit_are_reported(self):
        inner = EmailMessage()
        inner['Subject'] = 'level 0'
        inner.set_content('x')
        for level in range(1, 4):
            outer = EmailMessage()
            outer['Subject'] = f'level {level}'
            outer.set_content('x')
            outer.add_attachment(inner)
            inner = outer
        with mock.patch.object(config, 'MAX_EMAIL_DEPTH', 1):
            _, _, top = self._parse(inner.as_bytes())
        self.assertIn('1 forwarded message(s)', ' '.join(top['warnings']))

    def test_unparsable_structure_falls_back_to_headers(self):
        """Thousands of nested multiparts make the stdlib parser recurse
        past Python's limit."""
        depth = 3000
        parts = [b'From: a@example.com\r\nSubject: deep\r\nContent-Type: multipart/mixed; boundary="b0"\r\n\r\n']
        for i in range(1, depth):
            parts.append(b'--b%d\r\nContent-Type: multipart/mixed; boundary="b%d"\r\n\r\n' % (i - 1, i))
        events, attachments, top = self._parse(b''.join(parts))
        self.assertEqual(top['subject'], 'deep')
        self.assertIn("The message's structure could not be parsed - only its headers were analyzed", top['warnings'])
        self.assertEqual(attachments, [])

    def test_reply_to_subdomain_of_from_is_not_a_warning(self):
        _, _, top = self._parse(b'From: x@example.com\r\nReply-To: support@mail.example.com\r\n\r\nx\r\n')
        self.assertEqual(top['warnings'], [])

    def test_failing_scan_leaves_the_file_hashed(self):
        tmpdir = tempfile.mkdtemp()
        try:
            path = os.path.join(tmpdir, 'm.eml')
            with open(path, 'wb') as f:
                f.write(eml_fixtures.phishing_message())
            def broken_scan(p, rules):
                raise RuntimeError('yara crashed')
            events = email_analyzer.analyze_message(tmpdir, path, 'rules', broken_scan)
            infos = _by_type(events, 'fileinfo')
            self.assertEqual(len(infos), 3)
            self.assertTrue(all(i['fileinfo']['sha256'] for i in infos))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestTextDomain(unittest.TestCase):
    def test_claims(self):
        cases = {
            'https://www.bank.example/login': 'www.bank.example',
            'www.bank.example': 'www.bank.example',
            'paypal.com': 'paypal.com',
            'Click here': '',
            'invoice.pdf': '',
            'report.docx': '',
            'v1.2': '',
            '': '',
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(email_analyzer._text_domain(text), expected)

    def test_same_site(self):
        self.assertTrue(email_analyzer._same_site('www.example.com', 'example.com'))
        self.assertTrue(email_analyzer._same_site('login.example.com', 'example.com'))
        self.assertFalse(email_analyzer._same_site('example.com.evil.example', 'example.com'))
        self.assertFalse(email_analyzer._same_site('', 'example.com'))


class TestAnalyzeMessage(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.eml = os.path.join(self.tmpdir, 'phish.eml')
        with open(self.eml, 'wb') as f:
            f.write(eml_fixtures.phishing_message())

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @staticmethod
    def _fake_scan(path, rules_file):
        with open(path, 'rb') as f:
            data = f.read()
        matches = [{'rule_name': 'EICAR_Test', 'tags': ['test'], 'meta': {'author': 'x'}}] \
            if data == eml_fixtures.EICAR else []
        return (matches, hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest(),
                hashlib.sha1(data).hexdigest(), {'entropy': 1.0})

    def test_attachments_and_message_stored_and_scanned(self):
        events = email_analyzer.analyze_message(self.tmpdir, self.eml, 'rules.yar', self._fake_scan)
        infos = {e['fileinfo']['filename']: e['fileinfo'] for e in _by_type(events, 'fileinfo')}
        self.assertEqual(set(infos), {'phish.eml', 'invoice.com', 'notes.txt'})
        self.assertEqual(infos['phish.eml']['source'], 'message')
        self.assertEqual(infos['invoice.com']['source'], 'attachment')
        eicar_sha = hashlib.sha256(eml_fixtures.EICAR).hexdigest()
        self.assertEqual(infos['invoice.com']['sha256'], eicar_sha)
        self.assertTrue(all(i['stored'] for i in infos.values()))
        # Stored where Send to CyberChef's /api/extracted-file looks.
        path = find_extracted_file(self.tmpdir, eicar_sha)
        with open(path, 'rb') as f:
            self.assertEqual(f.read(), eml_fixtures.EICAR)
        self.assertEqual(infos['invoice.com']['yara'], [{'rule_name': 'EICAR_Test', 'tags': ['test']}])
        alerts = [e['filealerts'] for e in _by_type(events, 'filealerts')]
        self.assertEqual(len(alerts), 1)
        self.assertEqual((alerts[0]['rule_name'], alerts[0]['filename'], alerts[0]['sha256']),
                         ('EICAR_Test', 'invoice.com', eicar_sha))

    def test_without_yara_files_are_still_stored_and_hashed(self):
        events = email_analyzer.analyze_message(self.tmpdir, self.eml, None, None)
        infos = {e['fileinfo']['filename']: e['fileinfo'] for e in _by_type(events, 'fileinfo')}
        self.assertEqual(infos['invoice.com']['sha256'], hashlib.sha256(eml_fixtures.EICAR).hexdigest())
        self.assertEqual(infos['invoice.com']['yara'], [])
        self.assertEqual(_by_type(events, 'filealerts'), [])

    def test_remove_filestore(self):
        email_analyzer.analyze_message(self.tmpdir, self.eml, None, None)
        email_analyzer.remove_filestore(self.tmpdir)
        self.assertFalse(os.path.exists(os.path.join(self.tmpdir, 'filestore')))



class TestBuiltInEmailSample(unittest.TestCase):
    """samples.build_email_sample - the Welcome screen's offline Sample
    email file - and the Sample binary file beside it."""

    def test_log_sample(self):
        """Sysmon JSON lines, deterministic, detected as a log by name and
        content, with only reserved names. (Which Sigma rules fire needs
        Zircolite and its ruleset, so that's checked by hand - see
        build_log_sample.)"""
        import ipaddress
        import json
        import re
        import samples
        import validators
        filename, build = samples.SAMPLES['log']
        data = build()
        self.assertEqual(data, build())
        events = [json.loads(line) for line in data.decode().splitlines()]
        self.assertEqual({e['EventID'] for e in events}, {1, 3, 13})
        self.assertTrue(all(e['Channel'] == 'Microsoft-Windows-Sysmon/Operational' for e in events))
        self.assertTrue(validators.is_log_file(data[:4096]))
        self.assertTrue(validators.is_log_file_by_extension(filename))
        text = data.decode()
        # Every URL goes to a documentation-range IP or a .example host,
        # and the workstation is a .example name.
        url_hosts = re.findall(r'https?://([^/\s"]+)', text)
        self.assertTrue(url_hosts)
        for host in url_hosts:
            self.assertTrue(host.endswith('.example') or ipaddress.ip_address(host) in ipaddress.ip_network('203.0.113.0/24'), host)
        self.assertEqual({e['Computer'] for e in events}, {'FIN-WS-0412.corp.example'})
        documentation = ipaddress.ip_network('203.0.113.0/24')
        self.assertIn('203.0.113.66', re.findall(r'\b(\d+\.\d+\.\d+\.\d+)\b', text))
        for ip in re.findall(r'\b(\d+\.\d+\.\d+\.\d+)\b', text):
            addr = ipaddress.ip_address(ip)
            self.assertTrue(addr.is_private or addr in documentation, ip)

    def test_samples_carry_values_for_cyberchef(self):
        """The email's phishing link carries the recipient's address in
        base64, and the log's PowerShell runs a base64 stager - plain ASCII
        base64, so CyberChef's Magic decodes each in one step (checked by
        hand in the bundled CyberChef) - and the stager is the download the
        log's next event and the pcap show."""
        import base64
        import json
        import re
        import samples
        events, _ = email_analyzer.parse_message(samples.build_email_sample())
        bad = [e['link'] for e in _by_type(events, 'link') if e['link']['mismatch']][0]
        token = bad['url'].split('?u=', 1)[1]
        self.assertEqual(base64.b64decode(token).decode(), 'jordan.lee@corp.example')
        log = [json.loads(line) for line in samples.build_log_sample().decode().splitlines()]
        stager = re.search(r"FromBase64String\('([^']+)'\)", log[1]['CommandLine']).group(1)
        decoded = base64.b64decode(stager).decode('ascii')
        self.assertIn('http://203.0.113.66/update.bin', decoded)
        self.assertEqual(log[2]['ParentCommandLine'], log[1]['CommandLine'])
        self.assertIn(b'GET /update.bin', samples.build_pcap_sample())

    def test_pcap_sample(self):
        """A valid pcap, deterministic, between the workstation and the
        documentation-range C2 only, carrying the AgentTesla-style FTP
        upload and the executable download Suricata's rules fire on.
        (Which ET rules fire needs Suricata and its ruleset, so that's
        checked by hand - see build_pcap_sample.)"""
        import ipaddress
        import socket
        import struct
        import samples
        import validators
        filename, build = samples.SAMPLES['pcap']
        data = build()
        self.assertEqual(data, build())
        self.assertTrue(filename.endswith('.pcap'))
        self.assertTrue(validators.is_pcap_file(data[:4]))
        ips, offset = set(), 24
        while offset < len(data):
            _sec, _usec, caplen, _len = struct.unpack('<IIII', data[offset:offset + 16])
            frame = data[offset + 16:offset + 16 + caplen]
            ip_header = frame[14:34]  # after the Ethernet header
            ips.add(socket.inet_ntoa(ip_header[12:16]))
            ips.add(socket.inet_ntoa(ip_header[16:20]))
            offset += 16 + caplen
        self.assertEqual(offset, len(data), 'records end exactly at the end of the file')
        self.assertEqual(ips, {'10.20.4.12', '203.0.113.66'})
        self.assertIn(ipaddress.ip_address('203.0.113.66'), ipaddress.ip_network('203.0.113.0/24'))
        self.assertIn(b'STOR PW_jordan.lee-FIN-WS-0412_2026_', data)
        self.assertIn(b'User-Agent: Microsoft-CryptoAPI/10.0', data)
        self.assertIn(b'MZ', data)

    def test_binary_sample_is_the_pcap_samples_payload(self):
        """update.exe, byte-for-byte the payload the pcap sample downloads -
        so its hashes match the pcap analysis's extracted file."""
        import samples
        filename, build = samples.SAMPLES['binary']
        self.assertEqual(filename, 'update.exe')
        data = build()
        self.assertTrue(data.startswith(b'MZ'))
        self.assertIn(email_analyzer_eicar(), data)
        # The whole HTTP response fits in one TCP segment, so the payload
        # appears in the pcap contiguously.
        self.assertIn(b'Content-Length: %d\r\nConnection: close\r\n\r\n' % len(data) + data,
                      samples.build_pcap_sample())

    def test_deterministic(self):
        import samples
        self.assertEqual(samples.build_email_sample(), samples.build_email_sample(),
                         'same bytes every time, so loading it twice reopens one analysis')

    def test_exercises_every_warning(self):
        import samples
        events, attachments = email_analyzer.parse_message(samples.build_email_sample())
        top = _by_type(events, 'email')[0]['email']
        warnings = ' | '.join(top['warnings'])
        for expected in ('Reply-To domain', 'Return-Path domain', 'SPF fail', 'DMARC fail',
                         'text names a different domain', 'macro-enabled Office document'):
            self.assertIn(expected, warnings)
        self.assertEqual(top['originating_ip'], '203.0.113.66')
        self.assertTrue(any(e['link']['mismatch'] for e in _by_type(events, 'link')))
        self.assertEqual(len(_by_type(events, 'email')), 2, 'includes a forwarded message')
        name, data, _ts = attachments[0]
        self.assertEqual(name, 'Payroll_Adjustment_Form.docm')
        self.assertTrue(data.startswith(b'PK'), 'an Office Open XML zip')
        self.assertIn(email_analyzer_eicar(), data, 'stored uncompressed, so YARA sees it')

    def test_source_never_holds_the_whole_eicar_string(self):
        """No file in the image may contain the full signature - see the
        samples.py docstring."""
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'samples.py')
        with open(path, 'rb') as f:
            self.assertNotIn(email_analyzer_eicar(), f.read())

    def test_only_reserved_names(self):
        """Every hostname - addresses, Received hops, links - is under the
        reserved .example TLD, and every IP is in a documentation or
        private range, so the sample points at no real organization.
        Checked on the parsed message: the raw one is quoted-printable,
        which wraps long lines mid-URL."""
        import ipaddress
        import samples
        from email.utils import getaddresses
        events, _ = email_analyzer.parse_message(samples.build_email_sample())
        hosts, ips = set(), set()
        for e in _by_type(events, 'email'):
            m = e['email']
            for _name, addr in getaddresses([m['from'], m['return_path']] + m['to'] + m['reply_to']):
                if '@' in addr:
                    hosts.add(addr.rsplit('@', 1)[1])
            for hop in m['received']:
                hosts.update(h.rstrip(';') for h in (hop.get('from'), hop.get('by')) if h)
                ips.add(hop['ip'])
        hosts.update(e['link']['domain'] for e in _by_type(events, 'link'))
        self.assertGreater(len(hosts), 5)
        for host in hosts:
            self.assertTrue(host.endswith('.example'), host)
        documentation = [ipaddress.ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24')]
        for ip in ips:
            addr = ipaddress.ip_address(ip)
            self.assertTrue(addr.is_private or any(addr in n for n in documentation), ip)

def email_analyzer_eicar():
    return eml_fixtures.EICAR

if __name__ == '__main__':
    unittest.main()
