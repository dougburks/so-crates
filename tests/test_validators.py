#!/usr/bin/env python3
import unittest
import unittest.mock
import socket
import sys
import os
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import validators


class TestOfficeFileByExtension(unittest.TestCase):
    """Test is_office_file_by_extension for all Office document extensions."""

    def _assert_office(self, filename):
        self.assertTrue(validators.is_office_file_by_extension(filename),
                        f"'{filename}' should be recognized as an Office file")

    def _assert_not_office(self, filename):
        self.assertFalse(validators.is_office_file_by_extension(filename),
                         f"'{filename}' should NOT be recognized as an Office file")

    # Positive cases: exact match
    def test_doc(self):
        self._assert_office('report.doc')

    def test_docx(self):
        self._assert_office('report.docx')

    def test_xls(self):
        self._assert_office('budget.xls')

    def test_xlsx(self):
        self._assert_office('budget.xlsx')

    def test_ppt(self):
        self._assert_office('slides.ppt')

    def test_pptx(self):
        self._assert_office('slides.pptx')

    def test_docm(self):
        self._assert_office('macro.docm')

    def test_xlsm(self):
        self._assert_office('macro.xlsm')

    def test_pptm(self):
        self._assert_office('macro.pptm')

    def test_odt(self):
        self._assert_office('open.odt')

    def test_ods(self):
        self._assert_office('open.ods')

    def test_odp(self):
        self._assert_office('open.odp')

    # Case sensitivity variants
    def test_docx_uppercase(self):
        self._assert_office('report.DOCX')

    def test_docx_mixed_case(self):
        self._assert_office('report.Docx')

    def test_xls_uppercase(self):
        self._assert_office('budget.XLS')

    def test_ppt_uppercase(self):
        self._assert_office('slides.PPT')

    def test_docm_uppercase(self):
        self._assert_office('macro.DOCM')

    def test_odt_uppercase(self):
        self._assert_office('open.ODT')

    # Path variants
    def test_path_to_docx(self):
        self._assert_office('path/to/report.docx')

    def test_absolute_path_xls(self):
        self._assert_office('/absolute/path/budget.xls')

    # Negative cases
    def test_exe_not_office(self):
        self._assert_not_office('program.exe')

    def test_pdf_not_office(self):
        self._assert_not_office('document.pdf')

    def test_txt_not_office(self):
        self._assert_not_office('notes.txt')

    def test_json_not_office(self):
        self._assert_not_office('data.json')

    def test_evtx_not_office(self):
        self._assert_not_office('logs.evtx')

    def test_no_extension_not_office(self):
        self._assert_not_office('no_extension')

    def test_trailing_dot_not_office(self):
        self._assert_not_office('almost.docx.')

    def test_substring_match_not_office(self):
        """Ensure .docx inside a larger extension isn't falsely matched."""
        self._assert_not_office('file.docx.exe')


class TestIsLogFile(unittest.TestCase):
    """Test is_log_file magic-byte and content detection."""

    def _assert_log(self, data, description):
        self.assertTrue(validators.is_log_file(data),
                        f"{description} should be detected as a log file")

    def _assert_not_log(self, data, description):
        self.assertFalse(validators.is_log_file(data),
                         f"{description} should NOT be detected as a log file")

    # Boundary / short data
    def test_empty_bytes(self):
        self._assert_not_log(b'', 'empty bytes')

    def test_too_short(self):
        self._assert_not_log(b'abc', '3-byte data')

    def test_exactly_three_bytes(self):
        self._assert_not_log(b'{\n}', '3-byte JSON-like data')

    # Positive: EVTX magic
    def test_evtx_magic(self):
        self._assert_log(b'ElfFile\x00', 'EVTX magic bytes')

    def test_evtx_with_content(self):
        self._assert_log(b'ElfFile\x00' + b'\x00' * 100, 'EVTX with padding')

    # Positive: JSON
    def test_json_object(self):
        self._assert_log(b'{"EventID": 1}', 'JSON object')

    def test_json_array(self):
        self._assert_log(b'[1, 2, 3]', 'JSON array')

    def test_jsonl_multiple_lines(self):
        self._assert_log(b'{"ts":"2024-01-01"}\n{"ts":"2024-01-02"}', 'JSONL')

    def test_minimal_json(self):
        self._assert_log(b'{"a":1}', 'minimal JSON object')

    def test_minimal_json_array(self):
        self._assert_log(b'[1,2]', 'minimal JSON array')

    # Positive: XML
    def test_xml_with_prolog(self):
        self._assert_log(b'<?xml version="1.0"?><root/>', 'XML with prolog')

    def test_xml_without_prolog(self):
        self._assert_log(b'<Event><ID>1</ID></Event>', 'XML without prolog')

    def test_xml_evtx_style(self):
        self._assert_log(b'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID></System></Event>', 'EVTX-style XML')

    # Positive: CSV
    def test_csv_with_header(self):
        self._assert_log(b'timestamp,message\n2024-01-01,hello', 'CSV with header')

    def test_minimal_csv(self):
        self._assert_log(b'a,b\n1,2', 'minimal CSV')

    # Negative: OLE Compound File
    def test_ole_compound_file(self):
        self._assert_not_log(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + b'\x00' * 100,
                             'OLE Compound File (legacy Office)')

    # Negative: ZIP / Office Open XML
    def test_zip_pk(self):
        self._assert_not_log(b'PK\x03\x04' + b'\x00' * 100, 'ZIP archive')

    def test_office_open_xml(self):
        self._assert_not_log(b'PK\x03\x04' + b'\x00' * 20 + b'[Content_Types].xml',
                             'Office Open XML (DOCX/XLSX/PPTX)')

    # Negative: PDF
    def test_pdf(self):
        self._assert_not_log(b'%PDF-1.4\n1 0 obj', 'PDF file')

    # Negative: ELF
    def test_elf(self):
        self._assert_not_log(b'\x7fELF\x01\x01\x01', 'ELF binary')

    # Negative: PE / Windows executable
    def test_pe_mz(self):
        self._assert_not_log(b'MZ' + b'\x00' * 62, 'PE executable (MZ)')

    # Negative: Image formats
    def test_png(self):
        self._assert_not_log(b'\x89PNG\r\n\x1a\n' + b'\x00' * 10, 'PNG image')

    def test_jpeg(self):
        self._assert_not_log(b'\xff\xd8\xff\xe0\x00\x10JFIF', 'JPEG image')

    def test_gif87a(self):
        self._assert_not_log(b'GIF87a\x01\x00\x01\x00', 'GIF87a image')

    def test_gif89a(self):
        self._assert_not_log(b'GIF89a\x01\x00\x01\x00', 'GIF89a image')

    def test_bmp(self):
        self._assert_not_log(b'BM\x36\x00\x00\x00', 'BMP image')

    # Negative: Text rejections
    def test_html_doctype(self):
        self._assert_not_log(b'<!DOCTYPE html><html></html>', 'HTML doctype')

    def test_html_tag(self):
        self._assert_not_log(b'<html lang="en"><head></head></html>', 'HTML tag')

    def test_office_open_xml_disguised(self):
        xml = b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        xml += b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        self._assert_not_log(xml, 'Office Open XML disguised as generic XML')

    def test_plain_text_no_commas(self):
        self._assert_not_log(b'hello world\n', 'plain text without commas')

    def test_mostly_binary_with_commas(self):
        self._assert_not_log(b'\x00\x01,\x03\n', 'mostly binary with comma')

    def test_generic_binary(self):
        self._assert_not_log(b'\x00\x01\x02\x03', 'generic binary')

    def test_binary_all_zeros(self):
        self._assert_not_log(b'\x00' * 100, 'all-zero binary')


class TestIsLogFileByExtension(unittest.TestCase):
    """Test is_log_file_by_extension for all known log extensions."""

    def _assert_log_ext(self, filename):
        self.assertTrue(validators.is_log_file_by_extension(filename),
                        f"'{filename}' should be recognized as a log file extension")

    def _assert_not_log_ext(self, filename):
        self.assertFalse(validators.is_log_file_by_extension(filename),
                         f"'{filename}' should NOT be recognized as a log file extension")

    # Positive: exact match for all LOG_EXTENSIONS
    def test_evtx(self):
        self._assert_log_ext('logs.evtx')

    def test_json(self):
        self._assert_log_ext('data.json')

    def test_jsonl(self):
        self._assert_log_ext('lines.jsonl')

    def test_csv(self):
        self._assert_log_ext('events.csv')

    def test_xml(self):
        self._assert_log_ext('config.xml')

    def test_log(self):
        self._assert_log_ext('syslog.log')

    # Case sensitivity variants
    def test_json_uppercase(self):
        self._assert_log_ext('data.JSON')

    def test_json_mixed_case(self):
        self._assert_log_ext('data.Json')

    def test_evtx_uppercase(self):
        self._assert_log_ext('logs.EVTX')

    def test_csv_uppercase(self):
        self._assert_log_ext('events.CSV')

    def test_xml_uppercase(self):
        self._assert_log_ext('config.XML')

    def test_log_uppercase(self):
        self._assert_log_ext('syslog.LOG')

    def test_jsonl_uppercase(self):
        self._assert_log_ext('lines.JSONL')

    # Path variants
    def test_path_to_json(self):
        self._assert_log_ext('path/to/data.json')

    def test_absolute_path_evtx(self):
        self._assert_log_ext('/absolute/path/logs.evtx')

    # Negative cases
    def test_exe_not_log(self):
        self._assert_not_log_ext('program.exe')

    def test_pdf_not_log(self):
        self._assert_not_log_ext('document.pdf')

    def test_txt_not_log(self):
        self._assert_not_log_ext('notes.txt')

    def test_docx_not_log(self):
        self._assert_not_log_ext('report.docx')

    def test_zip_not_log(self):
        self._assert_not_log_ext('archive.zip')

    def test_pcap_not_log(self):
        self._assert_not_log_ext('capture.pcap')

    def test_no_extension_not_log(self):
        self._assert_not_log_ext('no_extension')

    def test_trailing_dot_not_log(self):
        self._assert_not_log_ext('almost.json.')

    def test_substring_match_not_log(self):
        """Ensure .json inside a larger extension isn't falsely matched."""
        self._assert_not_log_ext('file.json.exe')


class TestResolveSafeIps(unittest.TestCase):
    """Tests for resolve_safe_ips, which callers must use to pin a connection
    to a validated IP instead of letting the HTTP client re-resolve the
    hostname (closing the DNS-rebinding TOCTOU window)."""

    def _fake_addrinfo(self, ip):
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, '', (ip, 0))]

    def test_returns_ip_for_public_host(self):
        with unittest.mock.patch('socket.getaddrinfo', return_value=self._fake_addrinfo('93.184.216.34')):
            self.assertEqual(validators.resolve_safe_ips('example.com')[0], '93.184.216.34')

    def test_rejects_private_10x(self):
        with unittest.mock.patch('socket.getaddrinfo', return_value=self._fake_addrinfo('10.0.0.5')):
            with self.assertRaises(ValueError):
                validators.resolve_safe_ips('internal.example.com')

    def test_rejects_loopback(self):
        with unittest.mock.patch('socket.getaddrinfo', return_value=self._fake_addrinfo('127.0.0.1')):
            with self.assertRaises(ValueError):
                validators.resolve_safe_ips('sneaky.example.com')

    def test_rejects_link_local_metadata_ip(self):
        with unittest.mock.patch('socket.getaddrinfo', return_value=self._fake_addrinfo('169.254.169.254')):
            with self.assertRaises(ValueError):
                validators.resolve_safe_ips('metadata.example.com')

    def test_raises_on_dns_failure(self):
        with unittest.mock.patch('socket.getaddrinfo', side_effect=socket.gaierror):
            with self.assertRaises(ValueError):
                validators.resolve_safe_ips('doesnotexist.invalid')

    def test_raises_on_dns_timeout(self):
        with unittest.mock.patch('socket.getaddrinfo', side_effect=socket.timeout):
            with self.assertRaises(ValueError):
                validators.resolve_safe_ips('slow.example.com')

    def test_hanging_resolver_does_not_block_past_the_timeout(self):
        """REGRESSION: socket.setdefaulttimeout() has no effect on
        getaddrinfo() (it's a thin wrapper around the C resolver call, never
        constructs a Python socket) - a slow/non-responding DNS server used
        to be able to hang this call indefinitely instead of the intended
        5s. Must actually stop waiting once the timeout elapses, even if
        the underlying resolver call never returns at all."""
        import time as time_mod

        def _hang(*args, **kwargs):
            time_mod.sleep(60)

        with unittest.mock.patch('socket.getaddrinfo', side_effect=_hang), \
                unittest.mock.patch('validators.DNS_RESOLUTION_TIMEOUT', 0.05):
            start = time_mod.monotonic()
            with self.assertRaises(ValueError):
                validators.resolve_safe_ips('never-responds.example.com')
            elapsed = time_mod.monotonic() - start
        self.assertLess(elapsed, 5, 'must stop waiting at the timeout, not hang for the full 60s resolver call')

    def test_returned_ip_is_what_validate_url_safety_checked(self):
        """resolve_safe_ips must apply the same blocklist as validate_url_safety
        so the IPs it returns for pinning are exactly what was already vetted."""
        with unittest.mock.patch('socket.getaddrinfo', return_value=self._fake_addrinfo('192.168.1.1')):
            with self.assertRaises(ValueError) as ctx:
                validators.resolve_safe_ips('router.local')
            self.assertIn('private', str(ctx.exception).lower())

    def test_resolve_safe_ips_returns_all_addresses_preserving_order(self):
        """REGRESSION: resolve_safe_ips must return every resolved address in
        the resolver's own order, not alphabetically sorted. A plain sort
        puts an IPv6 address before an IPv4 one (since '2' < '8' as
        strings) regardless of which is actually reachable -- exactly the
        bug that broke fetching secure.eicar.org (IPv6-first, no IPv6 route
        in the deployment environment)."""
        addrinfo = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2a00:1828:3000::1:73ad:2', 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('89.238.73.97', 0)),
        ]
        with unittest.mock.patch('socket.getaddrinfo', return_value=addrinfo):
            ips = validators.resolve_safe_ips('secure.eicar.org')
        self.assertEqual(ips, ['2a00:1828:3000::1:73ad:2', '89.238.73.97'],
                          'must preserve resolver order, not sort alphabetically')

    def test_resolve_safe_ips_dedupes_repeated_addresses(self):
        addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0)),
            (socket.AF_INET, socket.SOCK_DGRAM, 17, '', ('93.184.216.34', 0)),
        ]
        with unittest.mock.patch('socket.getaddrinfo', return_value=addrinfo):
            ips = validators.resolve_safe_ips('example.com')
        self.assertEqual(ips, ['93.184.216.34'])

    def test_rejects_hostname_if_any_resolved_ip_is_blocked(self):
        """A hostname that resolves to a mix of public and private/internal
        addresses must be rejected entirely (fail closed), even though one
        of the addresses would have been fine on its own."""
        addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.5', 0)),
        ]
        with unittest.mock.patch('socket.getaddrinfo', return_value=addrinfo):
            with self.assertRaises(ValueError):
                validators.resolve_safe_ips('mixed.example.com')

    def test_rejects_ipv4_mapped_loopback(self):
        """::ffff:127.0.0.1 must be blocked like 127.0.0.1."""
        with unittest.mock.patch('socket.getaddrinfo', return_value=self._fake_addrinfo('::ffff:127.0.0.1')):
            with self.assertRaises(ValueError):
                validators.resolve_safe_ips('v6mapped.example.com')

    def test_rejects_ipv4_mapped_private(self):
        """::ffff:10.0.0.1 must be blocked like 10.0.0.1."""
        with unittest.mock.patch('socket.getaddrinfo', return_value=self._fake_addrinfo('::ffff:10.0.0.1')):
            with self.assertRaises(ValueError):
                validators.resolve_safe_ips('v6mapped-private.example.com')

    def test_rejects_ipv4_compatible_loopback(self):
        """::127.0.0.1 (IPv4-compatible) must be blocked."""
        with unittest.mock.patch('socket.getaddrinfo', return_value=self._fake_addrinfo('::127.0.0.1')):
            with self.assertRaises(ValueError):
                validators.resolve_safe_ips('v6compat.example.com')


class TestIsFileStale(unittest.TestCase):
    def test_fresh_file_is_not_stale(self):
        with tempfile.NamedTemporaryFile() as f:
            self.assertFalse(validators.is_file_stale(f.name, max_age_hours=24))

    def test_old_file_is_stale(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            old_time = time.time() - (25 * 3600)
            os.utime(path, (old_time, old_time))
            self.assertTrue(validators.is_file_stale(path, max_age_hours=24))
        finally:
            os.unlink(path)

    def test_missing_file_is_not_stale(self):
        """Callers already handle 'doesn't exist' as its own case (e.g. fall
        through to the baked-in-rules/download path) - is_file_stale must
        not also treat a missing file as stale and trigger double-handling."""
        self.assertFalse(validators.is_file_stale('/nonexistent/path/rules.yar', max_age_hours=24))

    def test_boundary_just_under_threshold_is_not_stale(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            recent_time = time.time() - (23 * 3600)
            os.utime(path, (recent_time, recent_time))
            self.assertFalse(validators.is_file_stale(path, max_age_hours=24))
        finally:
            os.unlink(path)


class TestIsEpochStale(unittest.TestCase):
    """is_file_stale() is a thin path-to-mtime wrapper around this - a
    caller that has already derived an mtime another way (e.g.
    get_suricata_rules_info()'s min mtime across several active rule
    files) uses this directly instead of re-deriving the same comparison
    by hand."""

    def test_fresh_epoch_is_not_stale(self):
        self.assertFalse(validators.is_epoch_stale(time.time(), max_age_hours=24))

    def test_old_epoch_is_stale(self):
        self.assertTrue(validators.is_epoch_stale(time.time() - (25 * 3600), max_age_hours=24))

    def test_boundary_just_under_threshold_is_not_stale(self):
        self.assertFalse(validators.is_epoch_stale(time.time() - (23 * 3600), max_age_hours=24))


class TestIPBlockingProperties(unittest.TestCase):
    """_ip_is_blocked: property-based SSRF address classes (incl. the
    0.0.0.0 -> localhost connect() behavior on Linux)."""

    def _blocked(self, addr):
        import ipaddress
        return validators._ip_is_blocked(ipaddress.ip_address(addr))

    def test_unspecified_ipv4_blocked(self):
        self.assertTrue(self._blocked('0.0.0.0'))

    def test_this_network_blocked(self):
        self.assertTrue(self._blocked('0.1.2.3'))

    def test_unspecified_ipv6_blocked(self):
        self.assertTrue(self._blocked('::'))

    def test_link_local_ipv6_blocked(self):
        self.assertTrue(self._blocked('fe80::1'))

    def test_multicast_blocked(self):
        self.assertTrue(self._blocked('224.0.0.1'))

    def test_loopback_blocked(self):
        self.assertTrue(self._blocked('127.0.0.1'))

    def test_private_blocked(self):
        self.assertTrue(self._blocked('10.1.2.3'))

    def test_public_not_blocked(self):
        self.assertFalse(self._blocked('8.8.8.8'))
        self.assertFalse(self._blocked('2001:4860:4860::8888'))


class TestReservedArtifactFilenames(unittest.TestCase):
    """Analyzer output artifacts must be rejected as upload names - a
    collision would overwrite results mid-scan or be deleted by reanalyze."""

    def test_artifact_names_rejected(self):
        for name in ('yara_matches.json', 'sigma_matches.json', 'zircolite.log',
                     '.zircolite_events.db', 'file_metadata.json', 'notes.txt'):
            with self.assertRaises(ValueError, msg=name):
                validators.sanitize_filename(name)

    def test_similar_names_still_allowed(self):
        self.assertEqual(validators.sanitize_filename('my_yara_matches.json'),
                         'my_yara_matches.json')


if __name__ == '__main__':
    unittest.main(verbosity=2)
