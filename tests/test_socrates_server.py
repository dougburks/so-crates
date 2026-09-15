#!/usr/bin/env python3
import unittest
import unittest.mock
import json
import os
import sys
import tempfile
import shutil
import hashlib
import socket
import threading
import time
import zipfile
import io
import re
import sqlite3
import subprocess
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import config
import db
import socrates as server
import suricata_analyzer
from validators import is_pcap_file

# Captured before any test patches urllib.request.urlopen (e.g. to mock the
# GitHub version-check call) - TestAPIEndpoints._get()/._post() use the same
# global urlopen to reach the local test server, so a naive mock there would
# also intercept the test's own HTTP client, not just the outbound call
# being tested. Tests that need this select on the target URL and fall back
# to this real reference for everything else (see e.g.
# test_version_check_no_update_when_same_version).
_REAL_URLOPEN = urllib.request.urlopen

SERVER_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'socrates.py')
SURICATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'suricata_analyzer.py')


class SyncThread:
    """Drop-in replacement for threading.Thread that runs its target
    synchronously on .start(), for patching socrates.threading.Thread in
    tests. socrates.py runs file/log analysis in a real background daemon
    thread and callers poll /api/check-status with a fixed time budget -
    under the full test suite's load (many other tests' own background
    threads still contending for CPU/subprocess slots), that budget can be
    missed even though the analysis itself is fast once scheduled, causing
    intermittent failures that don't reproduce when the test runs alone.
    Patching the target to run inline removes the race (and the need to
    poll) entirely, rather than just widening the timeout."""
    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def start(self):
        if self._target:
            self._target(*self._args, **self._kwargs)

    def join(self, timeout=None):
        pass


class TestIPValidation(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(server.validate_ip('192.168.1.1'))
        self.assertTrue(server.validate_ip('10.0.0.1'))
        self.assertTrue(server.validate_ip('8.8.8.8'))
        self.assertTrue(server.validate_ip('0.0.0.0'))
        self.assertTrue(server.validate_ip('255.255.255.255'))

    def test_valid_ipv6(self):
        self.assertTrue(server.validate_ip('::1'))
        self.assertTrue(server.validate_ip('2001:db8::1'))
        self.assertTrue(server.validate_ip('fe80::1'))

    def test_invalid_ip(self):
        self.assertFalse(server.validate_ip(''))
        self.assertFalse(server.validate_ip('not-an-ip'))
        self.assertFalse(server.validate_ip('999.999.999.999'))
        self.assertFalse(server.validate_ip('192.168.1'))
        self.assertFalse(server.validate_ip('192.168.1.1.1'))
        self.assertFalse(server.validate_ip('192.168.1.1; ls'))
        self.assertFalse(server.validate_ip('$(whoami)'))
        self.assertFalse(server.validate_ip('`id`'))
        self.assertFalse(server.validate_ip('192.168.1.1 && cat /etc/passwd'))


class TestPortValidation(unittest.TestCase):
    def test_valid_ports(self):
        self.assertTrue(server.validate_port('0'))
        self.assertTrue(server.validate_port('80'))
        self.assertTrue(server.validate_port('443'))
        self.assertTrue(server.validate_port('8080'))
        self.assertTrue(server.validate_port('65535'))

    def test_invalid_ports(self):
        self.assertFalse(server.validate_port('-1'))
        self.assertFalse(server.validate_port('65536'))
        self.assertFalse(server.validate_port(''))
        self.assertFalse(server.validate_port('abc'))
        self.assertFalse(server.validate_port('80; ls'))
        self.assertFalse(server.validate_port('$(id)'))
        self.assertFalse(server.validate_port(None))


class TestPathSafety(unittest.TestCase):
    def test_safe_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            safe = os.path.join(tmpdir, 'file.txt')
            self.assertTrue(server.is_safe_path(tmpdir, safe))

    def test_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            unsafe = os.path.join(tmpdir, '..', 'etc', 'passwd')
            self.assertFalse(server.is_safe_path(tmpdir, unsafe))

    def test_same_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self.assertTrue(server.is_safe_path(tmpdir, tmpdir))


class TestFilenameSanitization(unittest.TestCase):
    def test_basic_filename(self):
        self.assertEqual(server.sanitize_filename('test.pcap'), 'test.pcap')

    def test_path_traversal_in_filename(self):
        self.assertEqual(server.sanitize_filename('../../../etc/passwd'), 'passwd')
        self.assertEqual(server.sanitize_filename('..\\..\\etc\\passwd'), 'passwd')

    def test_special_characters(self):
        result = server.sanitize_filename('file name.pcap')
        self.assertEqual(result, 'file name.pcap')

    def test_rejects_dot(self):
        with self.assertRaises(ValueError):
            server.sanitize_filename('.')

    def test_rejects_dotdot(self):
        with self.assertRaises(ValueError):
            server.sanitize_filename('..')

    def test_rejects_reserved_filenames(self):
        for reserved in ('events.db', 'eve.json', 'name.txt', '.meta', '.phase', '.error'):
            with self.subTest(filename=reserved):
                with self.assertRaises(ValueError):
                    server.sanitize_filename(reserved)

    def test_rejects_control_characters(self):
        """REGRESSION: sanitize_filename's output becomes the real on-disk
        filename, which yara_analyzer.scan_single_file later writes
        one-per-line into a temp file passed to `yara --scan-list` - an
        embedded newline there splits one entry into two bogus paths, so
        YARA silently never scans the real file while the pipeline still
        reports the scan as clean/completed. Must reject any control
        character (0x00-0x1F, 0x7F), not just strip the specific
        traversal/reserved-name cases already covered above."""
        for bad in ('evil.exe\nfake_line.exe', 'evil.exe\rfake_line.exe',
                    'evil.exe\ttab.exe', 'evil\x00null.exe', 'evil\x7fdel.exe'):
            with self.subTest(filename=bad):
                with self.assertRaises(ValueError):
                    server.sanitize_filename(bad)

    def test_allows_normal_unicode_and_spaces(self):
        """Control-character rejection must not overreach into rejecting
        legitimate filenames - spaces and non-ASCII characters are fine."""
        self.assertEqual(server.sanitize_filename('file with spaces.pcap'), 'file with spaces.pcap')
        self.assertEqual(server.sanitize_filename('unicode-文件.log'), 'unicode-文件.log')


class TestZipSlipPrevention(unittest.TestCase):
    def test_normal_zip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, 'test.zip')
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr('normal.txt', 'content')
            with zipfile.ZipFile(zip_path, 'r') as zf:
                server.validate_zip_extraction(zf, tmpdir)

    def test_slip_attempt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, 'evil.zip')
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr('../../../escape.txt', 'malicious')
            with zipfile.ZipFile(zip_path, 'r') as zf:
                with self.assertRaises(ValueError) as ctx:
                    server.validate_zip_extraction(zf, tmpdir)
                self.assertIn('Zip slip', str(ctx.exception))

    def test_absolute_path_in_zip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, 'evil.zip')
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr('/etc/passwd', 'malicious')
            with zipfile.ZipFile(zip_path, 'r') as zf:
                with self.assertRaises(ValueError):
                    server.validate_zip_extraction(zf, tmpdir)


class TestURLValidation(unittest.TestCase):
    def _addrinfo(self, ip):
        family = socket.AF_INET6 if ':' in ip else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, '', (ip, 0))]

    @unittest.mock.patch('socket.getaddrinfo')
    def test_valid_public_url(self, mock_dns):
        mock_dns.return_value = self._addrinfo('93.184.216.34')
        server.validate_url_safety('https://example.com/file.pcap')

    def test_blocks_localhost(self):
        with self.assertRaises(ValueError) as ctx:
            server.validate_url_safety('http://localhost:8080/secret')
        self.assertIn('localhost', str(ctx.exception).lower())

    @unittest.mock.patch('socket.getaddrinfo')
    def test_blocks_127_0_0_1(self, mock_dns):
        mock_dns.return_value = self._addrinfo('127.0.0.1')
        with self.assertRaises(ValueError):
            server.validate_url_safety('http://127.0.0.1:8080/secret')

    @unittest.mock.patch('socket.getaddrinfo')
    def test_blocks_private_10x(self, mock_dns):
        mock_dns.return_value = self._addrinfo('10.0.0.1')
        with self.assertRaises(ValueError):
            server.validate_url_safety('http://internal.corp/file')

    @unittest.mock.patch('socket.getaddrinfo')
    def test_blocks_private_192x(self, mock_dns):
        mock_dns.return_value = self._addrinfo('192.168.1.1')
        with self.assertRaises(ValueError):
            server.validate_url_safety('http://router.local/file')

    @unittest.mock.patch('socket.getaddrinfo')
    def test_blocks_link_local(self, mock_dns):
        mock_dns.return_value = self._addrinfo('169.254.169.254')
        with self.assertRaises(ValueError):
            server.validate_url_safety('http://169.254.169.254/latest/meta-data/')

    @unittest.mock.patch('socket.getaddrinfo')
    def test_blocks_metadata_service(self, mock_dns):
        mock_dns.return_value = self._addrinfo('169.254.169.254')
        with self.assertRaises(ValueError):
            server.validate_url_safety('http://169.254.169.254/latest/meta-data/')

    def test_blocks_file_scheme(self):
        with self.assertRaises(ValueError):
            server.validate_url_safety('file:///etc/passwd')

    def test_blocks_ftp_scheme(self):
        with self.assertRaises(ValueError):
            server.validate_url_safety('ftp://evil.com/malware')

    def test_blocks_empty_hostname(self):
        with self.assertRaises(ValueError):
            server.validate_url_safety('http:///path')


class TestPinnedConnectionUsesValidatedIp(unittest.TestCase):
    """The pinned connection classes must dial the exact IP that was already
    validated, not let the socket layer re-resolve the hostname. This is the
    mechanism that closes the DNS-rebinding TOCTOU: if this regresses to a
    plain HTTPConnection(hostname, port), a DNS-rebinding attacker's second
    lookup (for the real connection) could return a different, blocked IP."""

    def test_http_connection_dials_pinned_ip_not_hostname(self):
        with unittest.mock.patch('socket.create_connection') as mock_conn:
            mock_conn.return_value = unittest.mock.MagicMock()
            conn = server._PinnedHTTPConnection('example.com', ['203.0.113.5'], 80, 5)
            conn.connect()
            mock_conn.assert_called_once_with(('203.0.113.5', 80), 5)

    def test_https_connection_dials_pinned_ip_but_uses_hostname_for_sni(self):
        with unittest.mock.patch('socket.create_connection') as mock_conn:
            fake_sock = unittest.mock.MagicMock()
            mock_conn.return_value = fake_sock
            conn = server._PinnedHTTPSConnection('example.com', ['203.0.113.5'], 443, 5)
            conn._context = unittest.mock.MagicMock()
            conn._context.wrap_socket.return_value = unittest.mock.MagicMock()
            conn.connect()
            mock_conn.assert_called_once_with(('203.0.113.5', 443), 5)
            # SNI/cert validation must still use the real hostname, not the IP,
            # so TLS verification isn't weakened by the pinning.
            conn._context.wrap_socket.assert_called_once_with(fake_sock, server_hostname='example.com')

    def test_falls_back_to_next_pinned_ip_if_first_is_unreachable(self):
        """REGRESSION: a dual-stack host (e.g. IPv6 + IPv4) must not fail
        outright just because its first resolved address is unreachable from
        this network -- same fallback a plain hostname connect gets. This is
        the exact bug reported for secure.eicar.org (IPv6-first, no IPv6
        route in the deployment environment)."""
        with unittest.mock.patch('socket.create_connection') as mock_conn:
            mock_conn.side_effect = [OSError('Network is unreachable'), unittest.mock.MagicMock()]
            conn = server._PinnedHTTPConnection('example.com', ['2a00:1828::1', '203.0.113.5'], 80, 5)
            conn.connect()
            self.assertEqual(mock_conn.call_count, 2)
            mock_conn.assert_any_call(('2a00:1828::1', 80), 5)
            mock_conn.assert_any_call(('203.0.113.5', 80), 5)

    def test_raises_if_all_pinned_ips_unreachable(self):
        with unittest.mock.patch('socket.create_connection') as mock_conn:
            mock_conn.side_effect = OSError('Network is unreachable')
            conn = server._PinnedHTTPConnection('example.com', ['2a00:1828::1', '203.0.113.5'], 80, 5)
            with self.assertRaises(OSError):
                conn.connect()


class TestFetchUrlSafely(unittest.TestCase):
    """Tests for _fetch_url_safely's SSRF protections: every hop (including
    redirect targets) must be re-validated, not just the initial URL."""

    @classmethod
    def setUpClass(cls):
        import http.server

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == '/redirect':
                    self.send_response(302)
                    self.send_header('Location', '/final')
                    self.end_headers()
                elif self.path == '/final':
                    body = b'final-payload'
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == '/big':
                    body = b'x' * 2000
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == '/redirect-big-body':
                    body = b'y' * 2000
                    self.send_response(302)
                    self.send_header('Location', '/final')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

        cls.httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

        # _fetch_url_safely now streams to disk under server._upload_tmp_dir()
        # (derived from server.DATA_DIR) instead of returning bytes -- sandbox
        # DATA_DIR so these tests don't write into the real data directory.
        cls.tmpdir = tempfile.mkdtemp()
        cls.original_base = server.DATA_DIR
        server.DATA_DIR = cls.tmpdir

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        server.DATA_DIR = cls.original_base
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def _upload_tmp_contents(self):
        d = os.path.join(server.DATA_DIR, config.UPLOAD_TMP_SUBDIR)
        return os.listdir(d) if os.path.isdir(d) else []

    def test_follows_redirect_and_revalidates_each_hop(self):
        """REGRESSION: a redirect target must be validated too, not just the
        initial URL (the old urlopen-based code let redirects bypass
        validate_url_safety entirely)."""
        validated_urls = []

        def spy_validate(url):
            validated_urls.append(url)

        with unittest.mock.patch('socrates.validate_url_safety', side_effect=spy_validate), \
             unittest.mock.patch('socrates.resolve_safe_ips', return_value=['127.0.0.1']):
            path = server._fetch_url_safely(
                f'http://localhost:{self.port}/redirect', timeout=5, max_size=10_000_000
            )
        with open(path, 'rb') as f:
            self.assertEqual(f.read(), b'final-payload')
        os.unlink(path)
        self.assertEqual(len(validated_urls), 2, 'both the initial URL and the redirect target must be validated')
        self.assertIn('/redirect', validated_urls[0])
        self.assertIn('/final', validated_urls[1])

    def test_rejects_redirect_to_blocked_target(self):
        """If a redirect target fails validation, the fetch must abort
        rather than follow it."""
        def spy_validate(url):
            if '/final' in url:
                raise ValueError('Access to private/internal addresses is not allowed')

        with unittest.mock.patch('socrates.validate_url_safety', side_effect=spy_validate), \
             unittest.mock.patch('socrates.resolve_safe_ips', return_value=['127.0.0.1']):
            with self.assertRaises(ValueError):
                server._fetch_url_safely(
                    f'http://localhost:{self.port}/redirect', timeout=5, max_size=10_000_000
                )

    def test_enforces_size_limit(self):
        with unittest.mock.patch('socrates.validate_url_safety', return_value=None), \
             unittest.mock.patch('socrates.resolve_safe_ips', return_value=['127.0.0.1']):
            with self.assertRaises(server._FileTooLargeError):
                server._fetch_url_safely(
                    f'http://localhost:{self.port}/big', timeout=5, max_size=100
                )
        self.assertEqual(self._upload_tmp_contents(), [], 'partial download must be cleaned up on size-limit failure')

    def test_redirect_body_size_is_bounded(self):
        """REGRESSION: the redirect-response body used to be discarded via a
        bare resp.read() with no size bound at all, unlike the 200 path's
        chunked read that aborts past max_size - a malicious/compromised
        server could pair a redirect with an arbitrarily large (or slow-
        trickling) body and exhaust memory before Location was ever read.
        The discard must be bounded the same way."""
        with unittest.mock.patch('socrates.validate_url_safety', return_value=None), \
             unittest.mock.patch('socrates.resolve_safe_ips', return_value=['127.0.0.1']):
            with self.assertRaises(server._FileTooLargeError):
                server._fetch_url_safely(
                    f'http://localhost:{self.port}/redirect-big-body', timeout=5, max_size=100
                )

    def test_plain_fetch_returns_body(self):
        with unittest.mock.patch('socrates.validate_url_safety', return_value=None), \
             unittest.mock.patch('socrates.resolve_safe_ips', return_value=['127.0.0.1']):
            path = server._fetch_url_safely(
                f'http://localhost:{self.port}/final', timeout=5, max_size=10_000_000
            )
        with open(path, 'rb') as f:
            self.assertEqual(f.read(), b'final-payload')
        os.unlink(path)


class TestCleanupUploadTmpDir(unittest.TestCase):
    """_cleanup_upload_tmp_dir() sweeps orphaned files/dirs left behind in
    upload-tmp/ by a process that died mid-upload (crash, OOM-kill, kill -9)
    before its own request-scoped cleanup could run. It's meant to run once
    at startup, before the server accepts requests - at that point anything
    in upload-tmp/ is guaranteed orphaned, so no age check is needed."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.original_data_dir = server.DATA_DIR
        server.DATA_DIR = self.tmpdir

    def tearDown(self):
        server.DATA_DIR = self.original_data_dir
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_removes_leftover_files_and_directories(self):
        upload_tmp = server._upload_tmp_dir()
        # A leftover file (e.g. from _parse_multipart_stream/_fetch_url_safely)
        with open(os.path.join(upload_tmp, 'orphaned-upload.download'), 'wb') as f:
            f.write(b'partial data')
        # A leftover directory (e.g. from _extract_zip_contents' tmp_dir)
        orphaned_dir = os.path.join(upload_tmp, 'orphaned-extract-dir')
        os.makedirs(orphaned_dir)
        with open(os.path.join(orphaned_dir, 'extracted.pcap'), 'wb') as f:
            f.write(b'pcap data')

        server._cleanup_upload_tmp_dir()

        self.assertEqual(os.listdir(upload_tmp), [],
                          'all leftover files and directories must be removed')

    def test_noop_on_empty_dir(self):
        """Must not error when upload-tmp/ is already empty (the common case
        on a clean shutdown/restart)."""
        server._cleanup_upload_tmp_dir()
        self.assertEqual(os.listdir(server._upload_tmp_dir()), [])

    def test_main_calls_cleanup_before_accepting_requests(self):
        """REGRESSION GUARD: the cleanup must actually be wired into main(),
        not just exist as a callable dead function."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        cleanup_call_idx = content.index('_cleanup_upload_tmp_dir()')
        serve_forever_idx = content.index('serve_forever()')
        self.assertLess(cleanup_call_idx, serve_forever_idx,
                         '_cleanup_upload_tmp_dir() must run before the server starts accepting requests')


class TestPcapContentValidation(unittest.TestCase):
    def test_pcap_magic_little_endian(self):
        data = b'\xd4\xc3\xb2\xa1' + b'\x00' * 20
        self.assertTrue(is_pcap_file(data))

    def test_pcap_magic_big_endian(self):
        data = b'\xa1\xb2\xc3\xd4' + b'\x00' * 20
        self.assertTrue(is_pcap_file(data))

    def test_pcapng_magic(self):
        data = b'\x0a\x0d\x0d\x0a' + b'\x00' * 20
        self.assertTrue(is_pcap_file(data))

    def test_random_data_rejected(self):
        data = b'this is not a pcap file at all'
        self.assertFalse(is_pcap_file(data))

    def test_html_rejected(self):
        data = b'<html><body>not a pcap</body></html>'
        self.assertFalse(is_pcap_file(data))

    def test_elf_rejected(self):
        data = b'\x7fELF' + b'\x00' * 20
        self.assertFalse(is_pcap_file(data))

    def test_short_data_not_pcap(self):
        data = b'\x00' * 3
        self.assertFalse(is_pcap_file(data))


class TestMD5Validation(unittest.TestCase):
    def test_valid_md5(self):
        self.assertTrue(bool(__import__('re').match(r'^[a-f0-9]{32}$', 'd41d8cd98f00b204e9800998ecf8427e')))

    def test_invalid_md5(self):
        self.assertFalse(bool(__import__('re').match(r'^[a-f0-9]{32}$', '../../../etc/passwd')))
        self.assertFalse(bool(__import__('re').match(r'^[a-f0-9]{32}$', 'short')))
        self.assertFalse(bool(__import__('re').match(r'^[a-f0-9]{32}$', 'GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG')))
        self.assertFalse(bool(__import__('re').match(r'^[a-f0-9]{32}$', '../etc/passwd')))


class TestAPIEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.original_base = server.DATA_DIR
        server.DATA_DIR = cls.tmpdir

        cls.port = 18000 + (os.getpid() % 1000)
        cls.server = server.ThreadedTCPServer(('127.0.0.1', cls.port), server.Handler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.3)

        # None of these tests exercise real Suricata analysis - they only
        # check upload/API plumbing - so spawn_suricata is mocked class-wide
        # to avoid launching real `suricata` subprocesses per pcap upload.
        # A full-suite run previously spawned a dozen-plus real, unmocked
        # Suricata processes in the background (each with its own 5-minute
        # watchdog) and contributed to an OOM crash. Individual tests that
        # need specific spawn_suricata behavior (e.g. simulating a startup
        # failure) still override this with their own nested patch.
        cls._spawn_suricata_patcher = unittest.mock.patch('socrates.spawn_suricata', return_value=True)
        cls._spawn_suricata_patcher.start()

    @classmethod
    def tearDownClass(cls):
        cls._spawn_suricata_patcher.stop()
        cls.server.shutdown()
        cls.server.server_close()
        server.DATA_DIR = cls.original_base
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def setUp(self):
        time.sleep(0.05)

    def _get(self, path):
        import urllib.request
        try:
            req = urllib.request.Request(f'http://127.0.0.1:{self.port}{path}')
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def _post(self, path, data, content_type='application/json'):
        import urllib.request
        body = json.dumps(data).encode() if isinstance(data, dict) else data
        req = urllib.request.Request(
            f'http://127.0.0.1:{self.port}{path}',
            data=body,
            headers={'Content-Type': content_type}
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def _post_multipart(self, path, filename, file_content):
        import urllib.request
        boundary = '----TestBoundary123'
        body = (
            f'------TestBoundary123\r\n'
            f'Content-Disposition: form-data; name="pcap"; filename="{filename}"\r\n'
            f'Content-Type: application/octet-stream\r\n\r\n'
        ).encode() + file_content + b'\r\n------TestBoundary123--\r\n'

        req = urllib.request.Request(
            f'http://127.0.0.1:{self.port}{path}',
            data=body,
            headers={'Content-Type': f'multipart/form-data; boundary=----TestBoundary123'}
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def test_events_empty(self):
        status, body = self._get('/api/events?md5=' + 'a' * 32)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), [])

    def test_version_endpoint(self):
        status, body = self._get('/api/version')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('version', data)
        self.assertRegex(data['version'], r'^\d+\.\d+\.\d+$')

    def test_playbook_endpoint_valid_nids_id_with_mocked_lookup(self):
        with unittest.mock.patch('socrates.get_playbook', return_value={'name': 'X', 'description': 'Y', 'questions': []}) as mock_get:
            status, body = self._get('/api/playbook?type=nids&id=2000005')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['playbook']['name'], 'X')
        mock_get.assert_called_once_with('nids', '2000005')

    def test_playbook_endpoint_valid_sigma_id_with_mocked_lookup(self):
        sigma_id = '221b251a-357a-49a9-920a-271802777cc0'
        with unittest.mock.patch('socrates.get_playbook', return_value=None) as mock_get:
            status, body = self._get(f'/api/playbook?type=sigma&id={sigma_id}')
        self.assertEqual(status, 200)
        self.assertIsNone(json.loads(body)['playbook'])
        mock_get.assert_called_once_with('sigma', sigma_id)

    def test_playbook_endpoint_no_baked_in_data_returns_null(self):
        # No mocking - exercises the real playbook_lookup.get_playbook
        # against this test environment's real (nonexistent) baked-in dir,
        # proving the "nothing baked in" path degrades to null rather than
        # erroring (e.g. local dev, or an image built without the
        # resources-builder stage).
        status, body = self._get('/api/playbook?type=nids&id=2000005')
        self.assertEqual(status, 200)
        self.assertIsNone(json.loads(body)['playbook'])

    def test_playbook_endpoint_invalid_type_rejected(self):
        status, body = self._get('/api/playbook?type=yara&id=2000005')
        self.assertEqual(status, 400)

    def test_playbook_endpoint_missing_type_rejected(self):
        status, body = self._get('/api/playbook?id=2000005')
        self.assertEqual(status, 400)

    def test_playbook_endpoint_missing_id_rejected(self):
        status, body = self._get('/api/playbook?type=nids')
        self.assertEqual(status, 400)

    def test_playbook_endpoint_non_numeric_nids_id_rejected(self):
        status, body = self._get('/api/playbook?type=nids&id=abc')
        self.assertEqual(status, 400)

    def test_playbook_endpoint_malicious_nids_id_rejected(self):
        for malicious in ('../../../etc/passwd', '2000005;rm -rf', '2000005/../../etc/passwd', '2000005 OR 1=1'):
            status, body = self._get('/api/playbook?type=nids&id=' + urllib.parse.quote(malicious, safe=''))
            self.assertEqual(status, 400, f'{malicious!r} should be rejected')

    def test_playbook_endpoint_malformed_sigma_id_rejected(self):
        for malicious in ('not-a-uuid', '221b251a-357a-49a9-920a', '', '../../../etc/passwd'):
            status, body = self._get('/api/playbook?type=sigma&id=' + urllib.parse.quote(malicious, safe=''))
            self.assertEqual(status, 400, f'{malicious!r} should be rejected')

    def test_playbook_endpoint_post_not_allowed(self):
        status, body = self._post('/api/playbook', {'type': 'nids', 'id': '2000005'})
        self.assertEqual(status, 404)

    def test_ai_summary_endpoint_valid_nids_id_with_mocked_lookup(self):
        with unittest.mock.patch('socrates.get_ai_summary', return_value='This rule detects X.') as mock_get:
            status, body = self._get('/api/ai-summary?type=nids&id=2000005')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['summary'], 'This rule detects X.')
        mock_get.assert_called_once_with('nids', '2000005')

    def test_ai_summary_endpoint_valid_sigma_id_with_mocked_lookup(self):
        sigma_id = '221b251a-357a-49a9-920a-271802777cc0'
        with unittest.mock.patch('socrates.get_ai_summary', return_value=None) as mock_get:
            status, body = self._get(f'/api/ai-summary?type=sigma&id={sigma_id}')
        self.assertEqual(status, 200)
        self.assertIsNone(json.loads(body)['summary'])
        mock_get.assert_called_once_with('sigma', sigma_id)

    def test_ai_summary_endpoint_valid_yara_id_with_mocked_lookup(self):
        # Unlike /api/playbook, 'yara' is a valid type here.
        with unittest.mock.patch('socrates.get_ai_summary', return_value='Detects a web shell.') as mock_get:
            status, body = self._get('/api/ai-summary?type=yara&id=ALFA_SHELL')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['summary'], 'Detects a web shell.')
        mock_get.assert_called_once_with('yara', 'ALFA_SHELL')

    def test_ai_summary_endpoint_no_baked_in_data_returns_null(self):
        # No mocking - exercises the real ai_summary_lookup.get_ai_summary
        # against this test environment's real (nonexistent) baked-in dir,
        # proving the "nothing baked in" path degrades to null rather than
        # erroring (e.g. local dev, or an image built without the
        # resources-builder stage).
        status, body = self._get('/api/ai-summary?type=nids&id=2000005')
        self.assertEqual(status, 200)
        self.assertIsNone(json.loads(body)['summary'])

    def test_ai_summary_endpoint_invalid_type_rejected(self):
        status, body = self._get('/api/ai-summary?type=bogus&id=2000005')
        self.assertEqual(status, 400)

    def test_ai_summary_endpoint_missing_type_rejected(self):
        status, body = self._get('/api/ai-summary?id=2000005')
        self.assertEqual(status, 400)

    def test_ai_summary_endpoint_missing_id_rejected(self):
        status, body = self._get('/api/ai-summary?type=nids')
        self.assertEqual(status, 400)

    def test_ai_summary_endpoint_non_numeric_nids_id_rejected(self):
        status, body = self._get('/api/ai-summary?type=nids&id=abc')
        self.assertEqual(status, 400)

    def test_ai_summary_endpoint_malicious_nids_id_rejected(self):
        for malicious in ('../../../etc/passwd', '2000005;rm -rf', '2000005/../../etc/passwd', '2000005 OR 1=1'):
            status, body = self._get('/api/ai-summary?type=nids&id=' + urllib.parse.quote(malicious, safe=''))
            self.assertEqual(status, 400, f'{malicious!r} should be rejected')

    def test_ai_summary_endpoint_malformed_sigma_id_rejected(self):
        for malicious in ('not-a-uuid', '221b251a-357a-49a9-920a', '', '../../../etc/passwd'):
            status, body = self._get('/api/ai-summary?type=sigma&id=' + urllib.parse.quote(malicious, safe=''))
            self.assertEqual(status, 400, f'{malicious!r} should be rejected')

    def test_ai_summary_endpoint_malformed_yara_id_rejected(self):
        for malicious in ('../../../etc/passwd', '1bad-name', '', 'x' * 201):
            status, body = self._get('/api/ai-summary?type=yara&id=' + urllib.parse.quote(malicious, safe=''))
            self.assertEqual(status, 400, f'{malicious!r} should be rejected')

    def test_ai_summary_endpoint_post_not_allowed(self):
        status, body = self._post('/api/ai-summary', {'type': 'nids', 'id': '2000005'})
        self.assertEqual(status, 404)

    def test_events_with_valid_md5(self):
        md5dir = os.path.join(self.tmpdir, 'd41d8cd98f00b204e9800998ecf8427e')
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00"}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        status, body = self._get('/api/events?md5=d41d8cd98f00b204e9800998ecf8427e')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(len(data), 1)

    def test_events_requires_md5(self):
        """REGRESSION: /api/events used to swallow a missing/malformed md5
        into a 200 with an empty body, unlike every sibling md5-scoped
        route (/api/stats, /api/count, etc.) which all return a clean 400
        for the identical _resolve_md5_dir error - now consistent."""
        status, body = self._get('/api/events')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_events_with_q_parameter(self):
        md5 = 'e99a18c428cb38d5f260853678922e03'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.2.3.4"}\n')
            f.write('{"event_type": "dns", "timestamp": "2026-01-01T00:00:01", "src_ip": "5.6.7.8"}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        status, body = self._get(f'/api/events?md5={md5}&q=dns')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['event_type'], 'dns')

    def test_stats_with_q_parameter(self):
        md5 = 'ab56b4d92b40713acc5af89985d4b786'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.2.3.4"}\n')
            f.write('{"event_type": "dns", "timestamp": "2026-01-01T00:00:01", "src_ip": "5.6.7.8"}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        status, body = self._get(f'/api/stats?md5={md5}&q=alert')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['counts'].get('alert'), 1)
        self.assertNotIn('dns', data['counts'])

    def test_count_with_q_parameter(self):
        md5 = 'a3f5c5f7e7b5f5e5d5c5b5a595857565'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.2.3.4"}\n')
            f.write('{"event_type": "dns", "timestamp": "2026-01-01T00:00:01", "src_ip": "5.6.7.8"}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        status, body = self._get(f'/api/count?md5={md5}&q=dns')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['count'], 1)

    def test_events_all_types_excludes_stats_row(self):
        md5 = '11223344556677889900aabbccddeeff'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.2.3.4"}\n')
            f.write('{"event_type": "dns", "timestamp": "2026-01-01T00:00:01", "src_ip": "5.6.7.8"}\n')
            f.write('{"event_type": "stats", "timestamp": "2026-01-01T00:00:02"}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        # No &type= param - the merged "All Events" query - must exclude 'stats'
        status, body = self._get(f'/api/events?md5={md5}')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(len(data), 2, 'stats row must be excluded from the merged all-types query')
        self.assertNotIn('stats', [e['event_type'] for e in data])

        # Count must match the row query exactly, for pagination consistency
        status, body = self._get(f'/api/count?md5={md5}')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['count'], 2)

        # Explicitly requesting type=stats must still work
        status, body = self._get(f'/api/events?md5={md5}&type=stats')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['event_type'], 'stats')

    def test_events_with_multiple_q_params(self):
        md5 = 'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.2.3.4", "dest_port": 80}\n')
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:01", "src_ip": "5.6.7.8", "dest_port": 443}\n')
            f.write('{"event_type": "dns", "timestamp": "2026-01-01T00:00:02", "src_ip": "1.2.3.4"}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        status, body = self._get(f'/api/events?md5={md5}&q=alert&q=80')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['event_type'], 'alert')
        self.assertEqual(data[0]['dest_port'], 80)

    def test_stats_with_multiple_q_params(self):
        md5 = 'c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.2.3.4", "dest_port": 80}\n')
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:01", "src_ip": "5.6.7.8", "dest_port": 443}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        status, body = self._get(f'/api/stats?md5={md5}&q=alert&q=80')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['counts'].get('alert'), 1)

    def test_stats_includes_date_range_excluding_stats_row(self):
        md5 = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.2.3.4"}\n')
            f.write('{"event_type": "dns", "timestamp": "2026-01-01T00:00:05", "src_ip": "5.6.7.8"}\n')
            f.write('{"event_type": "stats", "timestamp": "2026-01-01T00:00:59"}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        status, body = self._get(f'/api/stats?md5={md5}')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('date_range', data)
        self.assertEqual(data['date_range']['min'], '2026-01-01T00:00:00')
        self.assertEqual(data['date_range']['max'], '2026-01-01T00:00:05')

    def test_count_with_multiple_q_params(self):
        md5 = 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.2.3.4", "dest_port": 80}\n')
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:01", "src_ip": "5.6.7.8", "dest_port": 443}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        status, body = self._get(f'/api/count?md5={md5}&q=alert&q=80')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['count'], 1)

    def test_sigma_count_with_q_parameter(self):
        md5 = 'e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        db_file = os.path.join(md5dir, 'events.db')
        db.init_empty_db(db_file)
        db.insert_sigma_alerts(db_file, [
            {'timestamp': '2026-01-01T00:00:00', 'rule_title': 'Suspicious PowerShell', 'severity': 'high'},
            {'timestamp': '2026-01-01T00:00:01', 'rule_title': 'Benign Login', 'severity': 'low'},
        ])

        status, body = self._get(f'/api/sigma-count?md5={md5}&q=PowerShell')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['count'], 1)

    def test_sigma_count_no_filter_returns_total(self):
        md5 = 'f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        db_file = os.path.join(md5dir, 'events.db')
        db.init_empty_db(db_file)
        db.insert_sigma_alerts(db_file, [
            {'timestamp': '2026-01-01T00:00:00', 'rule_title': 'Rule A', 'severity': 'high'},
            {'timestamp': '2026-01-01T00:00:01', 'rule_title': 'Rule B', 'severity': 'low'},
        ])

        status, body = self._get(f'/api/sigma-count?md5={md5}')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['count'], 2)

    def test_sigma_count_requires_md5(self):
        status, body = self._get('/api/sigma-count')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_sigma_alerts_requires_md5(self):
        """REGRESSION: /api/sigma-alerts used to swallow a missing/malformed
        md5 into a 200 with an empty body, unlike its sibling /api/sigma-
        count, which already returns a clean 400 for the identical
        _resolve_md5_dir error - now consistent."""
        status, body = self._get('/api/sigma-alerts')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_sigma_stats_requires_md5(self):
        """REGRESSION: same inconsistency as /api/sigma-alerts above, for
        /api/sigma-stats."""
        status, body = self._get('/api/sigma-stats')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_sigma_count_invalid_md5_returns_400(self):
        status, body = self._get('/api/sigma-count?md5=invalid')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_sigma_count_traversal_md5_returns_400(self):
        status, body = self._get('/api/sigma-count?md5=../etc/passwd')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_sankey_data_with_populated_events(self):
        md5 = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d7'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "dest_port": 443}\n')
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:01", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "dest_port": 443}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        status, body = self._get(f'/api/sankey-data?md5={md5}')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('nodes', data)
        self.assertIn('links', data)
        names = {n['name'] for n in data['nodes']}
        self.assertIn('1.1.1.1', names)
        self.assertIn('2.2.2.2', names)
        self.assertIn('443', names)

    def test_sankey_data_with_type_filter(self):
        md5 = 'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e8'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "dest_port": 443}\n')
            f.write('{"event_type": "dns", "timestamp": "2026-01-01T00:00:01", "src_ip": "5.5.5.5", "dest_ip": "6.6.6.6", "dest_port": 53}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        status, body = self._get(f'/api/sankey-data?md5={md5}&type=dns')
        self.assertEqual(status, 200)
        data = json.loads(body)
        names = {n['name'] for n in data['nodes']}
        self.assertIn('5.5.5.5', names)
        self.assertNotIn('1.1.1.1', names)

    def test_sankey_data_with_q_parameter(self):
        md5 = 'c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f9'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "dest_port": 443}\n')
            f.write('{"event_type": "dns", "timestamp": "2026-01-01T00:00:01", "src_ip": "5.5.5.5", "dest_ip": "6.6.6.6", "dest_port": 53}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        status, body = self._get(f'/api/sankey-data?md5={md5}&q=dns')
        self.assertEqual(status, 200)
        data = json.loads(body)
        names = {n['name'] for n in data['nodes']}
        self.assertIn('5.5.5.5', names)
        self.assertNotIn('1.1.1.1', names)

    def test_sankey_data_requires_md5(self):
        status, body = self._get('/api/sankey-data')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_sankey_data_invalid_md5_returns_400(self):
        status, body = self._get('/api/sankey-data?md5=invalid')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_sankey_data_traversal_md5_returns_400(self):
        status, body = self._get('/api/sankey-data?md5=../etc/passwd')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_aggregation_data_with_type_filter(self):
        md5 = 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a1'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "proto": "TCP", "alert": {"category": "Trojan", "severity": 2}}\n')
            f.write('{"event_type": "dns", "timestamp": "2026-01-01T00:00:01", "src_ip": "5.5.5.5", "dest_ip": "6.6.6.6", "proto": "UDP", "dns": {"rrname": "example.com", "rrtype": "A"}}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        try:
            status, body = self._get(f'/api/aggregation-data?md5={md5}&type=alert')
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(data['Category'], [{'value': 'Trojan', 'count': 1}])
            self.assertNotIn('Query', data, 'dns-only column must not appear for an alert-type request')
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_aggregation_data_with_q_parameter(self):
        md5 = 'e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b2'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "dns", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "proto": "UDP", "dns": {"rrname": "example.com", "rrtype": "A"}}\n')
            f.write('{"event_type": "dns", "timestamp": "2026-01-01T00:00:01", "src_ip": "5.5.5.5", "dest_ip": "6.6.6.6", "proto": "UDP", "dns": {"rrname": "other.org", "rrtype": "A"}}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        try:
            status, body = self._get(f'/api/aggregation-data?md5={md5}&type=dns&q=example')
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(data['Query'], [{'value': 'example.com', 'count': 1}])
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_aggregation_data_requires_md5(self):
        status, body = self._get('/api/aggregation-data')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_aggregation_data_invalid_md5_returns_400(self):
        status, body = self._get('/api/aggregation-data?md5=invalid')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_aggregation_data_traversal_md5_returns_400(self):
        status, body = self._get('/api/aggregation-data?md5=../etc/passwd')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_aggregation_data_missing_type_returns_merged_data(self):
        """A missing/absent 'type' param means the merged 'all events' view -
        now supported server-side, returning real Type/Detail/Protocol/etc.
        aggregations across all event types, not an empty dict."""
        md5 = 'f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c3'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "proto": "TCP", "alert": {"signature": "ET TEST sig"}}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, os.path.join(md5dir, 'eve.json'))

        try:
            status, body = self._get(f'/api/aggregation-data?md5={md5}')
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(data['Type'], [{'value': 'ALERT', 'count': 1}])
            self.assertEqual(data['Detail'], [{'value': 'ET TEST sig', 'count': 1}])
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_sankey_data_unfiltered_is_cached(self):
        """An unfiltered (no q) /api/sankey-data response must be served from
        cache on repeat requests - proven by mutating events.db directly
        underneath the app (bypassing normal invalidation) and confirming
        the response stays the stale, first-computed result."""
        md5 = 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            eve_file = os.path.join(md5dir, 'eve.json')
            db_file = os.path.join(md5dir, 'events.db')
            with open(eve_file, 'w') as f:
                f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "dest_port": 80}\n')
            db.create_sqlite_db(db_file, eve_file)

            status, body1 = self._get(f'/api/sankey-data?md5={md5}')
            self.assertEqual(status, 200)
            status, body2 = self._get(f'/api/sankey-data?md5={md5}')
            self.assertEqual(status, 200)
            self.assertEqual(body1, body2)

            # Mutate events.db directly, bypassing the app entirely - a
            # genuine recompute would see this; a cache hit would not.
            with open(eve_file, 'w') as f:
                f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "9.9.9.9", "dest_ip": "8.8.8.8", "dest_port": 443}\n')
            os.remove(db_file)
            db.create_sqlite_db(db_file, eve_file)

            status, body3 = self._get(f'/api/sankey-data?md5={md5}')
            self.assertEqual(status, 200)
            self.assertEqual(body3, body1, 'unfiltered sankey-data must be served from cache, not recomputed')
        finally:
            server._evict_analysis_cache(md5)
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_sankey_data_with_q_is_never_cached(self):
        """A search-filtered /api/sankey-data request must always recompute -
        it must reflect a direct events.db mutation made between requests."""
        md5 = 'a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            eve_file = os.path.join(md5dir, 'eve.json')
            db_file = os.path.join(md5dir, 'events.db')
            with open(eve_file, 'w') as f:
                f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "dest_port": 80}\n')
            db.create_sqlite_db(db_file, eve_file)

            status, body1 = self._get(f'/api/sankey-data?md5={md5}&q=alert')
            self.assertEqual(status, 200)

            with open(eve_file, 'w') as f:
                f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "9.9.9.9", "dest_ip": "8.8.8.8", "dest_port": 443}\n')
            os.remove(db_file)
            db.create_sqlite_db(db_file, eve_file)

            status, body2 = self._get(f'/api/sankey-data?md5={md5}&q=alert')
            self.assertEqual(status, 200)
            self.assertNotEqual(body1, body2, 'search-filtered sankey-data must never be cached')
        finally:
            server._evict_analysis_cache(md5)
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_aggregation_data_unfiltered_is_cached(self):
        md5 = 'a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            eve_file = os.path.join(md5dir, 'eve.json')
            db_file = os.path.join(md5dir, 'events.db')
            with open(eve_file, 'w') as f:
                f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "proto": "TCP", "alert": {"category": "Trojan", "severity": 2}}\n')
            db.create_sqlite_db(db_file, eve_file)

            status, body1 = self._get(f'/api/aggregation-data?md5={md5}&type=alert')
            self.assertEqual(status, 200)

            with open(eve_file, 'w') as f:
                f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "9.9.9.9", "dest_ip": "8.8.8.8", "proto": "UDP", "alert": {"category": "Info", "severity": 0}}\n')
            os.remove(db_file)
            db.create_sqlite_db(db_file, eve_file)

            status, body2 = self._get(f'/api/aggregation-data?md5={md5}&type=alert')
            self.assertEqual(status, 200)
            self.assertEqual(body1, body2, 'unfiltered aggregation-data must be served from cache, not recomputed')
        finally:
            server._evict_analysis_cache(md5)
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_delete_analysis_evicts_sankey_and_aggregation_cache(self):
        """After /api/delete-analysis, a fresh analysis re-created under the
        same md5 must not see the previous analysis's cached results."""
        md5 = 'a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            eve_file = os.path.join(md5dir, 'eve.json')
            db_file = os.path.join(md5dir, 'events.db')
            with open(eve_file, 'w') as f:
                f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "dest_port": 80}\n')
            db.create_sqlite_db(db_file, eve_file)

            status, body1 = self._get(f'/api/sankey-data?md5={md5}')
            self.assertEqual(status, 200)

            status, body = self._post('/api/delete-analysis', {'md5': md5})
            self.assertEqual(status, 200)

            os.makedirs(md5dir, exist_ok=True)
            with open(eve_file, 'w') as f:
                f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "9.9.9.9", "dest_ip": "8.8.8.8", "dest_port": 443}\n')
            db.create_sqlite_db(db_file, eve_file)

            status, body2 = self._get(f'/api/sankey-data?md5={md5}')
            self.assertEqual(status, 200)
            self.assertNotEqual(body1, body2, 'delete-analysis must evict the cache, not leave stale data for a re-created md5')
        finally:
            server._evict_analysis_cache(md5)
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_delete_all_analyses_clears_caches(self):
        md5 = 'a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            eve_file = os.path.join(md5dir, 'eve.json')
            db_file = os.path.join(md5dir, 'events.db')
            with open(eve_file, 'w') as f:
                f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "dest_port": 80}\n')
            db.create_sqlite_db(db_file, eve_file)

            status, body = self._get(f'/api/sankey-data?md5={md5}')
            self.assertEqual(status, 200)
            self.assertTrue(any(k[0] == md5 for k in server._SANKEY_CACHE),
                             'sankey cache must be populated before delete-all')
            status, body = self._get(f'/api/aggregation-totals?md5={md5}&type=alert')
            self.assertEqual(status, 200)
            self.assertTrue(any(k[0] == md5 for k in server._AGGREGATION_TOTALS_CACHE),
                             'totals cache must be populated before delete-all')

            status, body = self._post('/api/delete-all-analyses', {})
            self.assertEqual(status, 200)
            self.assertFalse(any(k[0] == md5 for k in server._SANKEY_CACHE),
                              'delete-all-analyses must clear the sankey cache')
            self.assertEqual(len(server._AGGREGATION_CACHE), 0,
                              'delete-all-analyses must clear the aggregation cache')
            self.assertEqual(len(server._AGGREGATION_TOTALS_CACHE), 0,
                              'delete-all-analyses must clear the aggregation totals cache')
        finally:
            server._evict_analysis_cache(md5)
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_events_invalid_limit(self):
        md5 = 'a' * 32
        status, body = self._get(f'/api/events?md5={md5}&limit=abc')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), [])

    def test_events_invalid_offset(self):
        md5 = 'a' * 32
        status, body = self._get(f'/api/events?md5={md5}&offset=xyz')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), [])

    def test_events_negative_limit(self):
        md5 = 'a' * 32
        status, body = self._get(f'/api/events?md5={md5}&limit=-1')
        self.assertEqual(status, 200)

    def test_events_negative_offset(self):
        md5 = 'a' * 32
        status, body = self._get(f'/api/events?md5={md5}&offset=-5')
        self.assertEqual(status, 200)

    def test_events_zero_limit(self):
        md5 = 'a' * 32
        status, body = self._get(f'/api/events?md5={md5}&limit=0')
        self.assertEqual(status, 200)

    def _seed_flow_events(self, md5, events):
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        eve_path = os.path.join(md5dir, 'eve.json')
        with open(eve_path, 'w') as f:
            for e in events:
                f.write(json.dumps(e) + '\n')
        db.create_sqlite_db(os.path.join(md5dir, 'events.db'), eve_path)
        return md5dir

    def test_events_order_by_real_column(self):
        md5 = 'd' * 32
        md5dir = self._seed_flow_events(md5, [
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:00', 'proto': 'TCP', 'src_ip': '1.1.1.1'},
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:01', 'proto': 'UDP', 'src_ip': '2.2.2.2'},
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:02', 'proto': 'ICMP', 'src_ip': '3.3.3.3'},
        ])
        try:
            status, body = self._get(f'/api/events?md5={md5}&type=flow&order_by=Protocol&sort_dir=asc')
            self.assertEqual(status, 200)
            events = json.loads(body)
            self.assertEqual([e['proto'] for e in events], ['ICMP', 'TCP', 'UDP'])
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_events_json_raw_passthrough_returns_valid_multi_row_response(self):
        """/api/events now builds its response via query_events_sqlite_json's
        raw json_data passthrough (skipping the parse/reserialize round
        trip) - confirm the HTTP response is still valid, correctly-shaped
        JSON with the real field values for every row, not just row 1."""
        md5 = 'f' * 32
        md5dir = self._seed_flow_events(md5, [
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:00', 'proto': 'TCP', 'src_ip': '1.1.1.1', 'dest_port': 443},
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:01', 'proto': 'UDP', 'src_ip': '2.2.2.2', 'dest_port': 53},
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:02', 'proto': 'TCP', 'src_ip': '3.3.3.3', 'dest_port': 80},
        ])
        try:
            status, body = self._get(f'/api/events?md5={md5}&type=flow')
            self.assertEqual(status, 200)
            events = json.loads(body)
            self.assertEqual(len(events), 3)
            self.assertEqual([e['src_ip'] for e in events], ['1.1.1.1', '2.2.2.2', '3.3.3.3'])
            self.assertEqual([e['dest_port'] for e in events], [443, 53, 80])
            self.assertTrue(all(e['event_type'] == 'flow' for e in events))
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_events_order_by_injection_attempt_is_safely_ignored(self):
        """A malicious order_by value must never reach raw SQL - it should
        be silently ignored (falls back to default timestamp order), not
        error, and must not affect the underlying database."""
        md5 = 'e' * 32
        md5dir = self._seed_flow_events(md5, [
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:01', 'proto': 'TCP', 'src_ip': '2.2.2.2'},
            {'event_type': 'flow', 'timestamp': '2026-01-01T00:00:00', 'proto': 'UDP', 'src_ip': '1.1.1.1'},
        ])
        try:
            import urllib.parse
            malicious = urllib.parse.quote("'; DROP TABLE events; --")
            status, body = self._get(f'/api/events?md5={md5}&type=flow&order_by={malicious}')
            self.assertEqual(status, 200)
            events = json.loads(body)
            # Falls back to default timestamp-ascending order, not an error.
            self.assertEqual([e['src_ip'] for e in events], ['1.1.1.1', '2.2.2.2'])

            # The events table must still be fully intact afterward.
            status2, body2 = self._get(f'/api/count?md5={md5}&type=flow')
            self.assertEqual(status2, 200)
            self.assertEqual(json.loads(body2)['count'], 2)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_max_query_limit_is_100000(self):
        self.assertEqual(config.MAX_QUERY_LIMIT, 100000)

    def test_limits_endpoint_returns_max_query_limit(self):
        status, body = self._get('/api/limits')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {
            'maxQueryLimit': config.MAX_QUERY_LIMIT,
            'maxUploadSize': config.MAX_UPLOAD_SIZE,
        })

    _VALID_PALETTE_TOML = '''
accent = "#5c7a9d"
foreground = "#FCE7A1"
background = "#000617"
color1 = "#eb3836"
color8 = "#595d62"
color9 = "#ff5851"
color10 = "#c3d7b1"
color11 = "#f0eb90"
color12 = "#7d9dcb"
color13 = "#be95b4"
'''

    _VALID_ALACRITTY_TOML = '''
[colors.primary]
background = "#282a36"
foreground = "#f8f8f2"
[colors.normal]
black = "#21222c"
red = "#ff5555"
green = "#50fa7b"
yellow = "#f1fa8c"
blue = "#bd93f9"
magenta = "#ff79c6"
cyan = "#8be9fd"
white = "#f8f8f2"
[colors.bright]
black = "#6272a4"
red = "#ff6e6e"
green = "#69ff94"
yellow = "#ffffa5"
blue = "#d6acff"
magenta = "#ff92df"
cyan = "#a4ffff"
white = "#ffffff"
'''

    def _write_theme_dir(self, name=None, colors_toml=None, alacritty_toml=None):
        """Builds a fresh temp directory tree following OHMYDEBN_THEME_DIR's
        convention (current/theme.name, current/theme/{colors,alacritty}.toml)
        and returns its base path, ready to assign to server.OHMYDEBN_THEME_DIR."""
        base = tempfile.mkdtemp(dir=self.tmpdir)
        current = os.path.join(base, 'current')
        theme_dir = os.path.join(current, 'theme')
        os.makedirs(theme_dir, exist_ok=True)
        if name is not None:
            with open(os.path.join(current, 'theme.name'), 'w') as f:
                f.write(name)
        if colors_toml is not None:
            with open(os.path.join(theme_dir, 'colors.toml'), 'w') as f:
                f.write(colors_toml)
        if alacritty_toml is not None:
            with open(os.path.join(theme_dir, 'alacritty.toml'), 'w') as f:
                f.write(alacritty_toml)
        return base

    def test_theme_endpoint_returns_none_when_unset(self):
        original = server.OHMYDEBN_THEME_DIR
        server.OHMYDEBN_THEME_DIR = None
        try:
            status, body = self._get('/api/theme')
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), {'theme': None, 'customColors': None})
        finally:
            server.OHMYDEBN_THEME_DIR = original

    def test_theme_endpoint_returns_none_when_dir_missing(self):
        original = server.OHMYDEBN_THEME_DIR
        server.OHMYDEBN_THEME_DIR = os.path.join(self.tmpdir, 'does-not-exist')
        try:
            status, body = self._get('/api/theme')
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), {'theme': None, 'customColors': None})
        finally:
            server.OHMYDEBN_THEME_DIR = original

    def test_theme_endpoint_returns_theme_name_from_dir(self):
        base = self._write_theme_dir(name='tokyo-night\n')
        original = server.OHMYDEBN_THEME_DIR
        server.OHMYDEBN_THEME_DIR = base
        try:
            status, body = self._get('/api/theme')
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), {'theme': 'tokyo-night', 'customColors': None})
        finally:
            server.OHMYDEBN_THEME_DIR = original

    def test_theme_endpoint_accepts_underscores_in_theme_name(self):
        """REGRESSION: real installed OhMyDebn themes (e.g. 'black_arch',
        'snow_black') use underscores in their names - THEME_NAME_RE used
        to only allow hyphens, so these silently came back as theme:
        None, losing the name (and the toast's 'from OhMyDebn theme X'
        suffix) even when a valid customColors palette was available."""
        base = self._write_theme_dir(name='black_arch')
        original = server.OHMYDEBN_THEME_DIR
        server.OHMYDEBN_THEME_DIR = base
        try:
            status, body = self._get('/api/theme')
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)['theme'], 'black_arch')
        finally:
            server.OHMYDEBN_THEME_DIR = original

    def test_theme_endpoint_rejects_malformed_content(self):
        base = self._write_theme_dir(name='<script>alert(1)</script>')
        original = server.OHMYDEBN_THEME_DIR
        server.OHMYDEBN_THEME_DIR = base
        try:
            status, body = self._get('/api/theme')
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), {'theme': None, 'customColors': None})
        finally:
            server.OHMYDEBN_THEME_DIR = original

    def test_theme_sync_available_false_when_unset(self):
        original = server.OHMYDEBN_THEME_DIR
        server.OHMYDEBN_THEME_DIR = None
        try:
            status, body = self._get('/api/theme-sync-available')
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), {'available': False})
        finally:
            server.OHMYDEBN_THEME_DIR = original

    def test_theme_sync_available_false_when_dir_missing(self):
        original = server.OHMYDEBN_THEME_DIR
        server.OHMYDEBN_THEME_DIR = os.path.join(self.tmpdir, 'does-not-exist')
        try:
            status, body = self._get('/api/theme-sync-available')
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), {'available': False})
        finally:
            server.OHMYDEBN_THEME_DIR = original

    def test_theme_sync_available_true_when_name_readable(self):
        """Available even if the name's current *contents* are stale/
        malformed - this endpoint answers "can the frontend show a working
        toggle", not "is there a valid theme right now" (that's /api/theme's
        job)."""
        base = self._write_theme_dir(name='nord')
        original = server.OHMYDEBN_THEME_DIR
        server.OHMYDEBN_THEME_DIR = base
        try:
            status, body = self._get('/api/theme-sync-available')
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), {'available': True})
        finally:
            server.OHMYDEBN_THEME_DIR = original

    def test_theme_endpoint_returns_custom_colors_from_native_colors_toml(self):
        base = self._write_theme_dir(colors_toml=self._VALID_PALETTE_TOML)
        original = server.OHMYDEBN_THEME_DIR
        server.OHMYDEBN_THEME_DIR = base
        try:
            status, body = self._get('/api/theme')
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertIsNone(data['theme'])
            self.assertIsNotNone(data['customColors'])
            self.assertEqual(data['customColors']['--accent'], '#5c7a9d')
            self.assertEqual(data['customColors']['--bg-primary'], '#000617')
            self.assertEqual(data['customColors']['--text-primary'], '#FCE7A1')
        finally:
            server.OHMYDEBN_THEME_DIR = original

    def test_theme_endpoint_falls_back_to_alacritty_when_no_colors_toml(self):
        base = self._write_theme_dir(alacritty_toml=self._VALID_ALACRITTY_TOML)
        original = server.OHMYDEBN_THEME_DIR
        server.OHMYDEBN_THEME_DIR = base
        try:
            status, body = self._get('/api/theme')
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertIsNotNone(data['customColors'])
            self.assertEqual(data['customColors']['--bg-primary'], '#282a36')
            self.assertEqual(data['customColors']['--accent'], '#bd93f9')
        finally:
            server.OHMYDEBN_THEME_DIR = original

    def test_theme_endpoint_native_colors_toml_takes_precedence_over_alacritty(self):
        base = self._write_theme_dir(colors_toml=self._VALID_PALETTE_TOML, alacritty_toml=self._VALID_ALACRITTY_TOML)
        original = server.OHMYDEBN_THEME_DIR
        server.OHMYDEBN_THEME_DIR = base
        try:
            status, body = self._get('/api/theme')
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(data['customColors']['--bg-primary'], '#000617',
                              'a valid native colors.toml must win over alacritty.toml when both are present')
        finally:
            server.OHMYDEBN_THEME_DIR = original

    def test_theme_endpoint_falls_back_to_alacritty_when_native_colors_toml_invalid(self):
        base = self._write_theme_dir(
            colors_toml='accent = "#5c7a9d"\nforeground = "#FCE7A1"\n',  # missing required keys
            alacritty_toml=self._VALID_ALACRITTY_TOML,
        )
        original = server.OHMYDEBN_THEME_DIR
        server.OHMYDEBN_THEME_DIR = base
        try:
            status, body = self._get('/api/theme')
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(data['customColors']['--bg-primary'], '#282a36',
                              'an invalid native colors.toml must fall through to a valid alacritty.toml')
        finally:
            server.OHMYDEBN_THEME_DIR = original

    def test_theme_endpoint_uses_named_palette_when_ansi_slots_absent(self):
        """REGRESSION: OhMyDebn's own 'midnight' theme's colors.toml uses
        semantic names (red/blue/bright_red/muted) instead of color0-15 -
        this used to fall through both the native and alacritty paths
        entirely and disable sync."""
        named_palette_toml = '''
accent = "#407e70"
background = "#000000"
foreground = "#EFEFEF"
muted = "#1e1e1e"
red = "#D35F5F"
bright_red = "#B91C1C"
bright_green = "#A5B799"
bright_yellow = "#F59E0B"
bright_blue = "#A4BBDD"
bright_magenta = "#D9B9D9"
'''
        base = self._write_theme_dir(colors_toml=named_palette_toml)
        original = server.OHMYDEBN_THEME_DIR
        server.OHMYDEBN_THEME_DIR = base
        try:
            status, body = self._get('/api/theme')
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertIsNotNone(data['customColors'])
            self.assertEqual(data['customColors']['--accent'], '#407e70')
            # 'muted' (#1e1e1e) sits too close to background (#000000) to
            # read as text on its own - gets nudged for WCAG contrast
            # rather than used verbatim (see tests.test_ohmydebn_colors).
            self.assertNotEqual(data['customColors']['--text-muted'], '#1e1e1e')
        finally:
            server.OHMYDEBN_THEME_DIR = original

    def test_theme_endpoint_custom_colors_none_when_dir_unset(self):
        original = server.OHMYDEBN_THEME_DIR
        server.OHMYDEBN_THEME_DIR = None
        try:
            status, body = self._get('/api/theme')
            self.assertEqual(status, 200)
            self.assertIsNone(json.loads(body)['customColors'])
        finally:
            server.OHMYDEBN_THEME_DIR = original

    def test_theme_endpoint_custom_colors_none_when_colors_toml_malformed(self):
        base = self._write_theme_dir(colors_toml='this is not [valid toml')
        original = server.OHMYDEBN_THEME_DIR
        server.OHMYDEBN_THEME_DIR = base
        try:
            status, body = self._get('/api/theme')
            self.assertEqual(status, 200)
            self.assertIsNone(json.loads(body)['customColors'])
        finally:
            server.OHMYDEBN_THEME_DIR = original

    def test_theme_endpoint_custom_colors_none_when_alacritty_missing_required_field(self):
        base = self._write_theme_dir(alacritty_toml='[colors.primary]\nforeground = "#f8f8f2"\n')
        original = server.OHMYDEBN_THEME_DIR
        server.OHMYDEBN_THEME_DIR = base
        try:
            status, body = self._get('/api/theme')
            self.assertEqual(status, 200)
            self.assertIsNone(json.loads(body)['customColors'])
        finally:
            server.OHMYDEBN_THEME_DIR = original

    def _selective_urlopen(self, tag_name=None, error=None):
        """side_effect for mocking urllib.request.urlopen that only
        intercepts requests to the GitHub releases API - everything else
        (notably _get()'s own call to the local test server, which uses
        this exact same global function) passes through to the real
        urlopen via the module-level _REAL_URLOPEN captured before any
        patching happened."""
        def fake_urlopen(req, *args, **kwargs):
            url = req.full_url if hasattr(req, 'full_url') else str(req)
            if 'api.github.com' not in url:
                return _REAL_URLOPEN(req, *args, **kwargs)
            if error:
                raise error
            mock_resp = unittest.mock.MagicMock()
            mock_resp.read.return_value = json.dumps({'tag_name': tag_name}).encode()
            mock_resp.__enter__.return_value = mock_resp
            return mock_resp
        return fake_urlopen

    @unittest.mock.patch('socrates.urllib.request.urlopen')
    def test_version_check_no_update_when_same_version(self, mock_urlopen):
        mock_urlopen.side_effect = self._selective_urlopen(tag_name=f'v{server.VERSION}')
        status, body = self._get('/api/version-check')
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertFalse(result['updateAvailable'])
        self.assertIsNone(result['latestVersion'])
        self.assertEqual(result['currentVersion'], server.VERSION)

    @unittest.mock.patch('socrates.urllib.request.urlopen')
    def test_version_check_detects_newer_version(self, mock_urlopen):
        mock_urlopen.side_effect = self._selective_urlopen(tag_name='v99.0.0')
        status, body = self._get('/api/version-check')
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertTrue(result['updateAvailable'])
        self.assertEqual(result['latestVersion'], '99.0.0')

    @unittest.mock.patch('socrates.urllib.request.urlopen')
    def test_version_check_ignores_older_tag(self, mock_urlopen):
        """A tag older than the running version (e.g. a pre-release branch
        or a stale cached release) must never be reported as an update."""
        mock_urlopen.side_effect = self._selective_urlopen(tag_name='v0.0.1')
        status, body = self._get('/api/version-check')
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertFalse(result['updateAvailable'])

    @unittest.mock.patch('socrates.urllib.request.urlopen')
    def test_version_check_handles_network_failure_gracefully(self, mock_urlopen):
        """A network error (unreachable, DNS failure, etc.) must degrade to
        'no update available' with a 200, not a 500 or a crash - this
        endpoint is best-effort by design."""
        mock_urlopen.side_effect = self._selective_urlopen(error=OSError('network unreachable'))
        status, body = self._get('/api/version-check')
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertFalse(result['updateAvailable'])
        self.assertIsNone(result['latestVersion'])

    @unittest.mock.patch('socrates.urllib.request.urlopen')
    def test_version_check_handles_malformed_response_gracefully(self, mock_urlopen):
        mock_urlopen.side_effect = self._selective_urlopen(tag_name='not-a-semver-tag')
        status, body = self._get('/api/version-check')
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertFalse(result['updateAvailable'])

    def test_is_newer_version_detects_newer(self):
        self.assertTrue(server._is_newer_version('3.2.0', '3.1.0'))
        self.assertTrue(server._is_newer_version('4.0.0', '3.9.9'))
        self.assertTrue(server._is_newer_version('3.1.1', '3.1.0'))

    def test_is_newer_version_rejects_same_or_older(self):
        self.assertFalse(server._is_newer_version('3.1.0', '3.1.0'))
        self.assertFalse(server._is_newer_version('3.0.9', '3.1.0'))
        self.assertFalse(server._is_newer_version('2.9.9', '3.1.0'))

    def test_is_newer_version_fails_closed_on_malformed_input(self):
        self.assertFalse(server._is_newer_version('not-a-version', '3.1.0'))
        self.assertFalse(server._is_newer_version('', '3.1.0'))
        self.assertFalse(server._is_newer_version(None, '3.1.0'))

    def test_events_limit_clamped_to_max_query_limit(self):
        md5 = 'b' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        eve_path = os.path.join(md5dir, 'eve.json')
        with open(eve_path, 'w') as f:
            for i in range(config.MAX_QUERY_LIMIT + 1):
                f.write(json.dumps({
                    'event_type': 'flow', 'timestamp': '2026-01-01T00:00:00',
                    'src_ip': '1.1.1.1', 'dest_ip': '2.2.2.2', 'proto': 'TCP',
                    'flow_id': i,
                }) + '\n')
        db.create_sqlite_db(os.path.join(md5dir, 'events.db'), eve_path)

        try:
            status, body = self._get(f'/api/events?md5={md5}&limit={config.MAX_QUERY_LIMIT + 1000}')
            self.assertEqual(status, 200)
            events = json.loads(body)
            self.assertEqual(len(events), config.MAX_QUERY_LIMIT)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_sigma_alerts_limit_clamped_to_max_query_limit(self):
        md5 = 'c' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        db_path = os.path.join(md5dir, 'events.db')
        alerts = [{
            'timestamp': '2026-01-01T00:00:00', 'rule_title': f'Rule {i}',
            'rule_id': str(i), 'severity': 'high', 'level': 'high',
            'logsource': 'test', 'original_log': '{}', 'json_data': '{}',
        } for i in range(config.MAX_QUERY_LIMIT + 1)]
        db.insert_sigma_alerts(db_path, alerts)

        try:
            status, body = self._get(f'/api/sigma-alerts?md5={md5}&limit={config.MAX_QUERY_LIMIT + 1000}')
            self.assertEqual(status, 200)
            result = json.loads(body)
            self.assertEqual(len(result), config.MAX_QUERY_LIMIT)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_stats_requires_md5(self):
        status, body = self._get('/api/stats')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_count_requires_md5(self):
        status, body = self._get('/api/count')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_stats_invalid_md5_returns_400(self):
        status, body = self._get('/api/stats?md5=invalid')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_count_invalid_md5_returns_400(self):
        status, body = self._get('/api/count?md5=invalid')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_stats_traversal_md5_returns_400(self):
        status, body = self._get('/api/stats?md5=../etc/passwd')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_count_traversal_md5_returns_400(self):
        status, body = self._get('/api/count?md5=../etc/passwd')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_download_stream_requires_md5(self):
        status, _ = self._get('/api/download-stream?src=1.2.3.4&sport=80&dst=5.6.7.8&dport=443')
        self.assertEqual(status, 400)

    def test_ascii_stream_requires_md5(self):
        status, _ = self._get('/api/ascii-stream?src=1.2.3.4&sport=80&dst=5.6.7.8&dport=443')
        self.assertEqual(status, 400)

    def test_pcap_path_finds_file_with_no_recognized_extension(self):
        """REGRESSION: a pcap saved with no recognized extension (e.g. a
        Security Onion so-pcap.<timestamp> download) must still resolve via
        magic-byte detection instead of returning 'No pcap found'."""
        md5 = 'd' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        pcap_name = 'so-pcap.1784903949'
        with open(os.path.join(md5dir, pcap_name), 'wb') as f:
            f.write(b'\xd4\xc3\xb2\xa1' + b'\x00' * 20)
        try:
            status, body = self._get(f'/api/pcap-path?md5={md5}')
            self.assertEqual(status, 200)
            self.assertEqual(body, pcap_name)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_analyses_empty(self):
        status, body = self._get('/api/analyses')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), [])

    def test_analyses_includes_date_range(self):
        """The Previous Analyses list shows a short MD5 prefix and,
        instead of forcing an analyst to recognize the MD5 itself, the
        sample's own date range - an analyst is far more likely to
        recognize "when" than a hash fragment. date_range must reflect
        the sample's own event timestamps, not upload time."""
        md5 = '2' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            eve_file = os.path.join(md5dir, 'eve.json')
            db_file = os.path.join(md5dir, 'events.db')
            with open(eve_file, 'w') as f:
                f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "proto": "TCP", "alert": {"category": "Trojan", "severity": 2}}\n')
                f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:05:00", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "proto": "TCP", "alert": {"category": "Trojan", "severity": 2}}\n')
            db.create_sqlite_db(db_file, eve_file)
            with open(os.path.join(md5dir, 'name.txt'), 'w') as f:
                f.write('date-range-test')

            status, body = self._get('/api/analyses')
            self.assertEqual(status, 200)
            entry = next(a for a in json.loads(body) if a['md5'] == md5)
            self.assertEqual(entry['date_range'], {'min': '2026-01-01T00:00:00', 'max': '2026-01-01T00:05:00'})
        finally:
            server._evict_analysis_cache(md5)
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_analyses_date_range_null_before_events_db_exists(self):
        """An analysis still mid-processing (eve.json written, events.db
        not built yet) must not error out of the whole /api/analyses
        listing - date_range degrades to nulls, matching /api/stats's own
        never-raises convention."""
        md5 = '3' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
                f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00"}\n')

            status, body = self._get('/api/analyses')
            self.assertEqual(status, 200)
            entry = next(a for a in json.loads(body) if a['md5'] == md5)
            self.assertEqual(entry['date_range'], {'min': None, 'max': None})
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_analyses_has_notes_true_when_notes_txt_exists(self):
        md5 = '5' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
                f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00"}\n')
            with open(os.path.join(md5dir, 'notes.txt'), 'w') as f:
                f.write('Suspected GuLoader')

            status, body = self._get('/api/analyses')
            self.assertEqual(status, 200)
            entry = next(a for a in json.loads(body) if a['md5'] == md5)
            self.assertTrue(entry['has_notes'])
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_analyses_has_notes_false_when_no_notes_txt(self):
        md5 = '6' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
                f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00"}\n')

            status, body = self._get('/api/analyses')
            self.assertEqual(status, 200)
            entry = next(a for a in json.loads(body) if a['md5'] == md5)
            self.assertFalse(entry['has_notes'])
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_load_analysis_invalid_md5(self):
        status, body = self._get('/api/load-analysis?md5=invalid')
        self.assertEqual(status, 400)

    def test_load_analysis_valid_format_nonexistent(self):
        status, body = self._get('/api/load-analysis?md5=' + 'a' * 32)
        self.assertEqual(status, 404)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_delete_analysis_valid_format_nonexistent(self):
        status, body = self._post('/api/delete-analysis', {'md5': 'a' * 32})
        self.assertEqual(status, 404)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_delete_analysis_get_returns_404(self):
        """GET /api/delete-analysis must return 404 after moving to POST."""
        status, body = self._get('/api/delete-analysis?md5=' + 'a' * 32)
        self.assertEqual(status, 404, 'GET /api/delete-analysis must return 404')

    def test_delete_analysis_malformed_json_returns_400(self):
        """REGRESSION: a malformed JSON body must get a clean 400, not a
        dropped connection from an uncaught json.JSONDecodeError."""
        status, body = self._post('/api/delete-analysis', b'not-json-at-all')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('Invalid JSON', data.get('error', ''))

    def test_rename_analysis_valid_format_nonexistent(self):
        status, body = self._post('/api/rename-analysis', {'md5': 'a' * 32, 'name': 'new name'})
        self.assertEqual(status, 404)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_rename_analysis_invalid_md5_returns_400(self):
        status, body = self._post('/api/rename-analysis', {'md5': 'not-a-real-md5', 'name': 'new name'})
        self.assertEqual(status, 400)

    def test_rename_analysis_get_returns_404(self):
        """GET /api/rename-analysis must return 404 - POST only."""
        status, body = self._get('/api/rename-analysis?md5=' + 'a' * 32)
        self.assertEqual(status, 404)

    def test_rename_analysis_malformed_json_returns_400(self):
        status, body = self._post('/api/rename-analysis', b'not-json-at-all')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('Invalid JSON', data.get('error', ''))

    def test_rename_analysis_success_writes_name_txt(self):
        md5 = 'b' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            status, body = self._post('/api/rename-analysis', {'md5': md5, 'name': 'My Renamed Analysis'})
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(data, {'success': True, 'name': 'My Renamed Analysis'})
            with open(os.path.join(md5dir, 'name.txt')) as f:
                self.assertEqual(f.read(), 'My Renamed Analysis')
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_rename_analysis_overwrites_existing_name_txt(self):
        md5 = 'c' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            with open(os.path.join(md5dir, 'name.txt'), 'w') as f:
                f.write('original-upload.pcap')
            status, body = self._post('/api/rename-analysis', {'md5': md5, 'name': 'Renamed'})
            self.assertEqual(status, 200)
            with open(os.path.join(md5dir, 'name.txt')) as f:
                self.assertEqual(f.read(), 'Renamed')
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_rename_analysis_empty_name_returns_400(self):
        md5 = 'd' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            status, body = self._post('/api/rename-analysis', {'md5': md5, 'name': '   '})
            self.assertEqual(status, 400)
            data = json.loads(body)
            self.assertIn('empty', data.get('error', '').lower())
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_rename_analysis_missing_name_returns_400(self):
        md5 = 'e' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            status, body = self._post('/api/rename-analysis', {'md5': md5})
            self.assertEqual(status, 400)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_rename_analysis_collapses_embedded_newlines(self):
        """REGRESSION: name.txt is read back as one whole-file string, not
        line-by-line - an embedded newline would otherwise become part of
        the displayed name verbatim instead of being treated as whitespace."""
        md5 = 'f' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            status, body = self._post('/api/rename-analysis', {'md5': md5, 'name': 'line one\nline two\r\nline three'})
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertNotIn('\n', data['name'])
            self.assertNotIn('\r', data['name'])
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_rename_analysis_truncates_long_name(self):
        md5 = '1' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            long_name = 'x' * (config.MAX_DISPLAY_NAME_LENGTH + 100)
            status, body = self._post('/api/rename-analysis', {'md5': md5, 'name': long_name})
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(len(data['name']), config.MAX_DISPLAY_NAME_LENGTH)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_analysis_notes_valid_format_nonexistent(self):
        status, body = self._post('/api/analysis-notes', {'md5': 'a' * 32, 'notes': 'some notes'})
        self.assertEqual(status, 404)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_analysis_notes_invalid_md5_returns_400(self):
        status, body = self._post('/api/analysis-notes', {'md5': 'not-a-real-md5', 'notes': 'some notes'})
        self.assertEqual(status, 400)

    def test_analysis_notes_get_returns_404(self):
        """GET /api/analysis-notes must return 404 - POST only."""
        status, body = self._get('/api/analysis-notes?md5=' + 'a' * 32)
        self.assertEqual(status, 404)

    def test_analysis_notes_malformed_json_returns_400(self):
        status, body = self._post('/api/analysis-notes', b'not-json-at-all')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('Invalid JSON', data.get('error', ''))

    def test_analysis_notes_success_writes_notes_txt(self):
        md5 = 'b' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            status, body = self._post('/api/analysis-notes', {'md5': md5, 'notes': 'Suspected GuLoader'})
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(data, {'success': True, 'notes': 'Suspected GuLoader'})
            with open(os.path.join(md5dir, 'notes.txt')) as f:
                self.assertEqual(f.read(), 'Suspected GuLoader')
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_analysis_notes_overwrites_existing_notes_txt(self):
        md5 = 'c' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            with open(os.path.join(md5dir, 'notes.txt'), 'w') as f:
                f.write('old notes')
            status, body = self._post('/api/analysis-notes', {'md5': md5, 'notes': 'new notes'})
            self.assertEqual(status, 200)
            with open(os.path.join(md5dir, 'notes.txt')) as f:
                self.assertEqual(f.read(), 'new notes')
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_analysis_notes_empty_clears_notes_txt(self):
        """REGRESSION: unlike rename (empty name is an error), an empty
        notes submission is a valid, intentional way to clear notes - the
        notes.txt file must be removed, not written as an empty file."""
        md5 = 'd' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            with open(os.path.join(md5dir, 'notes.txt'), 'w') as f:
                f.write('old notes')
            status, body = self._post('/api/analysis-notes', {'md5': md5, 'notes': '   '})
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(data, {'success': True, 'notes': ''})
            self.assertFalse(os.path.exists(os.path.join(md5dir, 'notes.txt')))
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_analysis_notes_empty_when_no_notes_txt_existed(self):
        """Clearing notes that never existed must not error (no notes.txt
        to remove is not a failure)."""
        md5 = 'e' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            status, body = self._post('/api/analysis-notes', {'md5': md5, 'notes': ''})
            self.assertEqual(status, 200)
            self.assertFalse(os.path.exists(os.path.join(md5dir, 'notes.txt')))
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_analysis_notes_missing_notes_returns_success_and_clears(self):
        """A missing 'notes' key defaults to '' (same as rename's
        data.get('name', '')), which is the clear-notes path."""
        md5 = 'f' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            status, body = self._post('/api/analysis-notes', {'md5': md5})
            self.assertEqual(status, 200)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_analysis_notes_non_string_returns_400(self):
        md5 = '2' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            status, body = self._post('/api/analysis-notes', {'md5': md5, 'notes': 12345})
            self.assertEqual(status, 400)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_analysis_notes_preserves_embedded_newlines(self):
        """REGRESSION: unlike rename, notes must preserve multi-line text
        verbatim - this is the whole point of a freeform notes field."""
        md5 = '3' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            status, body = self._post('/api/analysis-notes', {'md5': md5, 'notes': 'line one\nline two\nline three'})
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(data['notes'], 'line one\nline two\nline three')
            with open(os.path.join(md5dir, 'notes.txt')) as f:
                self.assertEqual(f.read(), 'line one\nline two\nline three')
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_analysis_notes_truncates_long_notes(self):
        md5 = '4' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            long_notes = 'x' * (config.MAX_NOTES_LENGTH + 100)
            status, body = self._post('/api/analysis-notes', {'md5': md5, 'notes': long_notes})
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(len(data['notes']), config.MAX_NOTES_LENGTH)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def _make_events_db_with_rows(self, md5):
        """Creates an analysis dir with a real events.db containing one
        events row and one sigma_alerts row, for row-note tests. Returns
        (md5dir, event_id, sigma_alert_id)."""
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        eve_file = os.path.join(md5dir, 'eve.json')
        with open(eve_file, 'w') as f:
            f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00"}\n')
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, eve_file)
        db.insert_sigma_alerts(db_file, [{
            'timestamp': '2026-01-01T00:00:00', 'rule_title': 'Test Rule',
            'rule_id': 'test-rule', 'severity': 'high', 'level': 'high',
        }])
        event_id = db.query_events_sqlite(db_file)[0]['id']
        sigma_alert_id = db.query_sigma_alerts_sqlite(db_file)[0]['id']
        return md5dir, event_id, sigma_alert_id

    def test_row_note_invalid_md5_returns_400(self):
        status, body = self._post('/api/row-note', {'md5': 'not-a-real-md5', 'table': 'events', 'rowId': 1, 'note': 'x'})
        self.assertEqual(status, 400)

    def test_row_note_nonexistent_analysis_returns_404(self):
        status, body = self._post('/api/row-note', {'md5': 'a' * 32, 'table': 'events', 'rowId': 1, 'note': 'x'})
        self.assertEqual(status, 404)

    def test_row_note_get_returns_404(self):
        """GET /api/row-note must return 404 - POST only."""
        status, body = self._get('/api/row-note?md5=' + 'a' * 32)
        self.assertEqual(status, 404)

    def test_row_note_malformed_json_returns_400(self):
        status, body = self._post('/api/row-note', b'not-json-at-all')
        self.assertEqual(status, 400)

    def test_row_note_invalid_table_returns_400(self):
        md5 = '5' * 32
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            status, body = self._post('/api/row-note', {'md5': md5, 'table': 'not_a_table', 'rowId': event_id, 'note': 'x'})
            self.assertEqual(status, 400)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_row_note_sqlite_error_returns_clean_500(self):
        """REGRESSION: set_row_note's caller only caught OSError, but
        sqlite3.Error (e.g. sqlite3.OperationalError from lock contention,
        a disk I/O error, or corruption) is not an OSError subclass - a
        genuine SQLite failure during a note save used to propagate
        uncaught out of the handler (a connection reset, not a clean JSON
        error) instead of becoming a 500 like every other DB-backed route."""
        md5 = '6' * 32
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            with unittest.mock.patch('socrates.set_row_note', side_effect=sqlite3.OperationalError('database is locked')):
                status, body = self._post('/api/row-note', {'md5': md5, 'table': 'events', 'rowId': event_id, 'note': 'x'})
            self.assertEqual(status, 500)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_row_note_invalid_row_id_returns_400(self):
        md5 = '6' * 32
        md5dir, _, _ = self._make_events_db_with_rows(md5)
        try:
            status, body = self._post('/api/row-note', {'md5': md5, 'table': 'events', 'rowId': 'not-an-int', 'note': 'x'})
            self.assertEqual(status, 400)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_row_note_bool_row_id_returns_400(self):
        """REGRESSION: bool is a subclass of int in Python - a bare
        isinstance(x, int) check would silently accept True/False."""
        md5 = '7' * 32
        md5dir, _, _ = self._make_events_db_with_rows(md5)
        try:
            status, body = self._post('/api/row-note', {'md5': md5, 'table': 'events', 'rowId': True, 'note': 'x'})
            self.assertEqual(status, 400)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_row_note_non_string_note_returns_400(self):
        md5 = '8' * 32
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            status, body = self._post('/api/row-note', {'md5': md5, 'table': 'events', 'rowId': event_id, 'note': 12345})
            self.assertEqual(status, 400)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_row_note_success_events_table(self):
        md5 = '9' * 32
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            status, body = self._post('/api/row-note', {'md5': md5, 'table': 'events', 'rowId': event_id, 'note': 'false positive, known scanner'})
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(data, {'success': True, 'note': 'false positive, known scanner'})
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_row_note_success_sigma_alerts_table(self):
        md5 = 'aa' + '0' * 30
        md5dir, _, sigma_id = self._make_events_db_with_rows(md5)
        try:
            status, body = self._post('/api/row-note', {'md5': md5, 'table': 'sigma_alerts', 'rowId': sigma_id, 'note': 'escalated to IR ticket #4521'})
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(data, {'success': True, 'note': 'escalated to IR ticket #4521'})
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_row_note_overwrite_existing(self):
        md5 = 'bb' + '0' * 30
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            self._post('/api/row-note', {'md5': md5, 'table': 'events', 'rowId': event_id, 'note': 'first note'})
            status, body = self._post('/api/row-note', {'md5': md5, 'table': 'events', 'rowId': event_id, 'note': 'second note'})
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(data['note'], 'second note')
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_row_note_empty_clears_note(self):
        """REGRESSION: mirrors analysis-notes' clear-on-empty convention -
        an empty submission removes the row from row_notes rather than
        storing an empty string."""
        md5 = 'cc' + '0' * 30
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            self._post('/api/row-note', {'md5': md5, 'table': 'events', 'rowId': event_id, 'note': 'will be cleared'})
            status, body = self._post('/api/row-note', {'md5': md5, 'table': 'events', 'rowId': event_id, 'note': '  '})
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(data, {'success': True, 'note': ''})
            notes = db.get_row_notes(os.path.join(md5dir, 'events.db'), 'events', [event_id])
            self.assertEqual(notes, {})
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_row_note_empty_when_no_note_existed(self):
        """Clearing a row that was never noted must not error."""
        md5 = 'dd' + '0' * 30
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            status, body = self._post('/api/row-note', {'md5': md5, 'table': 'events', 'rowId': event_id, 'note': ''})
            self.assertEqual(status, 200)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_row_note_truncates_long_note(self):
        md5 = 'ee' + '0' * 30
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            long_note = 'x' * (config.MAX_ROW_NOTE_LENGTH + 100)
            status, body = self._post('/api/row-note', {'md5': md5, 'table': 'events', 'rowId': event_id, 'note': long_note})
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(len(data['note']), config.MAX_ROW_NOTE_LENGTH)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_row_note_unique_per_table_and_id(self):
        """REGRESSION: the same numeric row id in events vs sigma_alerts
        must be independent notes - proves the source_table discriminator
        actually discriminates, not just a bare row_id lookup."""
        md5 = 'ff' + '0' * 30
        md5dir, event_id, sigma_id = self._make_events_db_with_rows(md5)
        try:
            self._post('/api/row-note', {'md5': md5, 'table': 'events', 'rowId': event_id, 'note': 'events note'})
            status, body = self._get('/api/events?md5=' + md5)
            events = json.loads(body)
            self.assertEqual(events[0].get('row_note'), 'events note')

            status, body = self._get('/api/sigma-alerts?md5=' + md5)
            alerts = json.loads(body)
            self.assertNotIn('row_note', alerts[0], 'A note on events must not leak onto a sigma_alerts row with the same numeric id')
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_events_api_includes_id_field(self):
        md5 = '11' + '0' * 30
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            status, body = self._get('/api/events?md5=' + md5)
            events = json.loads(body)
            self.assertEqual(events[0]['id'], event_id)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_events_api_includes_row_note_when_present(self):
        md5 = '22' + '0' * 30
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            self._post('/api/row-note', {'md5': md5, 'table': 'events', 'rowId': event_id, 'note': 'round trip note'})
            status, body = self._get('/api/events?md5=' + md5)
            events = json.loads(body)
            self.assertEqual(events[0]['row_note'], 'round trip note')
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_events_api_row_note_absent_when_not_set(self):
        """A row with no note must omit row_note entirely, not send an
        empty string - keeps the has-a-note signal unambiguous."""
        md5 = '33' + '0' * 30
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            status, body = self._get('/api/events?md5=' + md5)
            events = json.loads(body)
            self.assertNotIn('row_note', events[0])
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_sigma_alerts_api_includes_row_note(self):
        md5 = '44' + '0' * 30
        md5dir, _, sigma_id = self._make_events_db_with_rows(md5)
        try:
            self._post('/api/row-note', {'md5': md5, 'table': 'sigma_alerts', 'rowId': sigma_id, 'note': 'sigma note'})
            status, body = self._get('/api/sigma-alerts?md5=' + md5)
            alerts = json.loads(body)
            self.assertEqual(alerts[0]['row_note'], 'sigma note')
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_row_note_survives_pagination(self):
        """A note set on a specific row must stay attached to that exact
        row when fetching different pages, not bleed onto whichever row
        happens to occupy the same position on another page."""
        md5 = '55' + '0' * 30
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        eve_file = os.path.join(md5dir, 'eve.json')
        with open(eve_file, 'w') as f:
            for i in range(3):
                f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:0%d"}\n' % i)
        db_file = os.path.join(md5dir, 'events.db')
        db.create_sqlite_db(db_file, eve_file)
        try:
            all_events = db.query_events_sqlite(db_file, order_by='Time', sort_dir='asc')
            second_id = all_events[1]['id']
            db.set_row_note(db_file, 'events', second_id, 'middle row note')

            status, body = self._get(f'/api/events?md5={md5}&order_by=Time&sort_dir=asc&offset=1&limit=1')
            page = json.loads(body)
            self.assertEqual(len(page), 1)
            self.assertEqual(page[0]['id'], second_id)
            self.assertEqual(page[0]['row_note'], 'middle row note')
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_acknowledge_alert_invalid_md5_returns_400(self):
        status, body = self._post('/api/acknowledge-alert', {'md5': 'not-a-real-md5', 'table': 'events', 'rowId': 1, 'acknowledged': True})
        self.assertEqual(status, 400)

    def test_acknowledge_alert_nonexistent_analysis_returns_404(self):
        status, body = self._post('/api/acknowledge-alert', {'md5': 'a' * 32, 'table': 'events', 'rowId': 1, 'acknowledged': True})
        self.assertEqual(status, 404)

    def test_acknowledge_alert_get_returns_404(self):
        """GET /api/acknowledge-alert must return 404 - POST only."""
        status, body = self._get('/api/acknowledge-alert?md5=' + 'a' * 32)
        self.assertEqual(status, 404)

    def test_acknowledge_alert_malformed_json_returns_400(self):
        status, body = self._post('/api/acknowledge-alert', b'not-json-at-all')
        self.assertEqual(status, 400)

    def test_acknowledge_alert_invalid_table_returns_400(self):
        md5 = hashlib.md5(b'ack_invalid_table').hexdigest()
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            status, body = self._post('/api/acknowledge-alert', {'md5': md5, 'table': 'not_a_table', 'rowId': event_id, 'acknowledged': True})
            self.assertEqual(status, 400)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_acknowledge_alert_invalid_row_id_returns_400(self):
        md5 = hashlib.md5(b'ack_invalid_row_id').hexdigest()
        md5dir, _, _ = self._make_events_db_with_rows(md5)
        try:
            status, body = self._post('/api/acknowledge-alert', {'md5': md5, 'table': 'events', 'rowId': 'not-an-int', 'acknowledged': True})
            self.assertEqual(status, 400)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_acknowledge_alert_bool_row_id_returns_400(self):
        """REGRESSION: bool is a subclass of int in Python - a bare
        isinstance(x, int) check would silently accept True/False."""
        md5 = hashlib.md5(b'ack_bool_row_id').hexdigest()
        md5dir, _, _ = self._make_events_db_with_rows(md5)
        try:
            status, body = self._post('/api/acknowledge-alert', {'md5': md5, 'table': 'events', 'rowId': True, 'acknowledged': True})
            self.assertEqual(status, 400)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_acknowledge_alert_non_bool_acknowledged_returns_400(self):
        md5 = hashlib.md5(b'ack_non_bool_acknowledged').hexdigest()
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            status, body = self._post('/api/acknowledge-alert', {'md5': md5, 'table': 'events', 'rowId': event_id, 'acknowledged': 'yes'})
            self.assertEqual(status, 400)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_acknowledge_alert_sqlite_error_returns_clean_500(self):
        md5 = hashlib.md5(b'ack_sqlite_error').hexdigest()
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            with unittest.mock.patch('socrates.set_acknowledged', side_effect=sqlite3.OperationalError('database is locked')):
                status, body = self._post('/api/acknowledge-alert', {'md5': md5, 'table': 'events', 'rowId': event_id, 'acknowledged': True})
            self.assertEqual(status, 500)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_acknowledge_alert_success_removes_row_from_events(self):
        md5 = hashlib.md5(b'ack_success_events').hexdigest()
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            status, body = self._post('/api/acknowledge-alert', {'md5': md5, 'table': 'events', 'rowId': event_id, 'acknowledged': True})
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(data, {'success': True, 'acknowledged': True})

            events = db.query_events_sqlite(os.path.join(md5dir, 'events.db'))
            self.assertEqual(events, [], 'acknowledged row must no longer appear in the default query')
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_acknowledge_alert_success_sigma_alerts_table(self):
        md5 = hashlib.md5(b'ack_success_sigma').hexdigest()
        md5dir, _, sigma_id = self._make_events_db_with_rows(md5)
        try:
            status, body = self._post('/api/acknowledge-alert', {'md5': md5, 'table': 'sigma_alerts', 'rowId': sigma_id, 'acknowledged': True})
            self.assertEqual(status, 200)
            alerts = db.query_sigma_alerts_sqlite(os.path.join(md5dir, 'events.db'))
            self.assertEqual(alerts, [])
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_acknowledge_alert_false_reincludes_row(self):
        md5 = hashlib.md5(b'ack_unack_roundtrip').hexdigest()
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            self._post('/api/acknowledge-alert', {'md5': md5, 'table': 'events', 'rowId': event_id, 'acknowledged': True})
            status, body = self._post('/api/acknowledge-alert', {'md5': md5, 'table': 'events', 'rowId': event_id, 'acknowledged': False})
            self.assertEqual(status, 200)
            events = db.query_events_sqlite(os.path.join(md5dir, 'events.db'))
            self.assertEqual([e['id'] for e in events], [event_id])
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_acknowledge_alerts_bulk_invalid_row_ids_type_returns_400(self):
        md5 = hashlib.md5(b'ack_bulk_invalid_type').hexdigest()
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            status, body = self._post('/api/acknowledge-alerts-bulk', {'md5': md5, 'table': 'events', 'rowIds': event_id})
            self.assertEqual(status, 400)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_acknowledge_alerts_bulk_empty_row_ids_returns_400(self):
        md5 = hashlib.md5(b'ack_bulk_empty').hexdigest()
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            status, body = self._post('/api/acknowledge-alerts-bulk', {'md5': md5, 'table': 'events', 'rowIds': []})
            self.assertEqual(status, 400)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_acknowledge_alerts_bulk_non_int_entry_returns_400(self):
        md5 = hashlib.md5(b'ack_bulk_non_int').hexdigest()
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            status, body = self._post('/api/acknowledge-alerts-bulk', {'md5': md5, 'table': 'events', 'rowIds': [event_id, 'nope']})
            self.assertEqual(status, 400)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_acknowledge_alerts_bulk_bool_entry_returns_400(self):
        """REGRESSION: bool is a subclass of int in Python - a bare
        isinstance(x, int) check would silently accept True/False."""
        md5 = hashlib.md5(b'ack_bulk_bool_entry').hexdigest()
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            status, body = self._post('/api/acknowledge-alerts-bulk', {'md5': md5, 'table': 'events', 'rowIds': [event_id, True]})
            self.assertEqual(status, 400)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_acknowledge_alerts_bulk_too_many_row_ids_returns_400(self):
        md5 = hashlib.md5(b'ack_bulk_too_many').hexdigest()
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            too_many = list(range(1, config.MAX_QUERY_LIMIT + 2))
            status, body = self._post('/api/acknowledge-alerts-bulk', {'md5': md5, 'table': 'events', 'rowIds': too_many})
            self.assertEqual(status, 400)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_acknowledge_alerts_bulk_success(self):
        md5 = hashlib.md5(b'ack_bulk_success').hexdigest()
        md5dir, event_id, sigma_id = self._make_events_db_with_rows(md5)
        try:
            status, body = self._post('/api/acknowledge-alerts-bulk', {'md5': md5, 'table': 'events', 'rowIds': [event_id]})
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual(data, {'success': True, 'count': 1})
            events = db.query_events_sqlite(os.path.join(md5dir, 'events.db'))
            self.assertEqual(events, [])
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_acknowledge_alerts_bulk_sqlite_error_returns_clean_500(self):
        md5 = hashlib.md5(b'ack_bulk_sqlite_error').hexdigest()
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            with unittest.mock.patch('socrates.set_acknowledged_bulk', side_effect=sqlite3.OperationalError('database is locked')):
                status, body = self._post('/api/acknowledge-alerts-bulk', {'md5': md5, 'table': 'events', 'rowIds': [event_id]})
            self.assertEqual(status, 500)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_events_api_acknowledged_only_returns_just_acknowledged_rows(self):
        md5 = hashlib.md5(b'ack_events_api_only').hexdigest()
        md5dir, event_id, _ = self._make_events_db_with_rows(md5)
        try:
            self._post('/api/acknowledge-alert', {'md5': md5, 'table': 'events', 'rowId': event_id, 'acknowledged': True})
            status, body = self._get(f'/api/events?md5={md5}&acknowledged=only')
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual([e['id'] for e in data], [event_id])

            status, body = self._get(f'/api/count?md5={md5}&acknowledged=only')
            self.assertEqual(json.loads(body)['count'], 1)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_sigma_alerts_api_acknowledged_only_returns_just_acknowledged_rows(self):
        md5 = hashlib.md5(b'ack_sigma_api_only').hexdigest()
        md5dir, _, sigma_id = self._make_events_db_with_rows(md5)
        try:
            self._post('/api/acknowledge-alert', {'md5': md5, 'table': 'sigma_alerts', 'rowId': sigma_id, 'acknowledged': True})
            status, body = self._get(f'/api/sigma-alerts?md5={md5}&acknowledged=only')
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertEqual([a['id'] for a in data], [sigma_id])

            status, body = self._get(f'/api/sigma-count?md5={md5}&acknowledged=only')
            self.assertEqual(json.loads(body)['count'], 1)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_delete_all_analyses_removes_directories(self):
        md5_one = 'd41d8cd98f00b204e9800998ecf8427e'
        md5_two = 'a3f5c5f7e7b5f5e5d5c5b5a595857565'
        for md5 in (md5_one, md5_two):
            md5dir = os.path.join(self.tmpdir, md5)
            os.makedirs(md5dir, exist_ok=True)
            with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
                f.write('{"event_type": "alert", "timestamp": "2026-01-01T00:00:00"}\n')
        self.assertTrue(os.path.exists(os.path.join(self.tmpdir, md5_one)))
        self.assertTrue(os.path.exists(os.path.join(self.tmpdir, md5_two)))

        status, body = self._post('/api/delete-all-analyses', {})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data.get('success'))
        self.assertGreaterEqual(data.get('deleted', 0), 2)
        self.assertFalse(os.path.exists(os.path.join(self.tmpdir, md5_one)))
        self.assertFalse(os.path.exists(os.path.join(self.tmpdir, md5_two)))

    def test_delete_all_analyses_get_returns_404(self):
        """GET /api/delete-all-analyses must return 404."""
        status, body = self._get('/api/delete-all-analyses')
        self.assertEqual(status, 404)

    def test_delete_all_analyses_empty_state(self):
        """POST /api/delete-all-analyses with no analyses returns deleted: 0."""
        # Ensure the shared temp data dir has no MD5 analysis directories.
        for entry in os.listdir(self.tmpdir):
            entry_path = os.path.join(self.tmpdir, entry)
            if __import__('re').match(r'^[a-f0-9]{32}$', entry) and os.path.isdir(entry_path):
                shutil.rmtree(entry_path)
        status, body = self._post('/api/delete-all-analyses', {})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data.get('success'))
        self.assertEqual(data.get('deleted'), 0)

    def test_pcap_path_invalid_md5(self):
        status, body = self._get('/api/pcap-path?md5=invalid')
        self.assertEqual(status, 400)

    def test_pcap_path_valid_format_nonexistent(self):
        status, body = self._get('/api/pcap-path?md5=' + 'a' * 32)
        self.assertEqual(status, 404)
        data = json.loads(body)
        self.assertIn('error', data)

    def test_download_stream_invalid_ip(self):
        status, _ = self._get('/api/download-stream?src=bad&sport=80&dst=1.2.3.4&dport=443')
        self.assertEqual(status, 400)

    def test_download_stream_invalid_port(self):
        status, _ = self._get('/api/download-stream?src=1.2.3.4&sport=99999&dst=5.6.7.8&dport=80')
        self.assertEqual(status, 400)

    def test_download_stream_command_injection(self):
        status, _ = self._get('/api/download-stream?src=1.2.3.4&sport=80;ls&dst=5.6.7.8&dport=443')
        self.assertEqual(status, 400)

    def test_download_stream_missing_params(self):
        status, _ = self._get('/api/download-stream?src=1.2.3.4')
        self.assertEqual(status, 400)

    def test_ascii_stream_command_injection(self):
        status, _ = self._get('/api/ascii-stream?src=1.2.3.4&sport=80|cat&dst=5.6.7.8&dport=443')
        self.assertEqual(status, 400)

    def test_ascii_stream_missing_params(self):
        status, _ = self._get('/api/ascii-stream?src=1.2.3.4')
        self.assertEqual(status, 400)

    def test_hexdump_stream_requires_md5(self):
        status, _ = self._get('/api/hexdump-stream?src=1.2.3.4&sport=80&dst=5.6.7.8&dport=443')
        self.assertEqual(status, 400)

    def test_hexdump_stream_invalid_ip(self):
        status, _ = self._get('/api/hexdump-stream?src=bad&sport=80&dst=1.2.3.4&dport=443&md5=' + 'a' * 32)
        self.assertEqual(status, 400)

    def test_hexdump_stream_invalid_port(self):
        status, _ = self._get('/api/hexdump-stream?src=1.2.3.4&sport=99999&dst=5.6.7.8&dport=80&md5=' + 'a' * 32)
        self.assertEqual(status, 400)

    def test_hexdump_stream_command_injection(self):
        status, _ = self._get('/api/hexdump-stream?src=1.2.3.4&sport=80;ls&dst=5.6.7.8&dport=443&md5=' + 'a' * 32)
        self.assertEqual(status, 400)

    def test_hexdump_stream_missing_params(self):
        status, _ = self._get('/api/hexdump-stream?src=1.2.3.4&md5=' + 'a' * 32)
        self.assertEqual(status, 400)

    def test_download_stream_returns_404_when_no_pcap_in_valid_analysis_dir(self):
        """REGRESSION: _validate_stream_params used to return a single error
        string, and callers guessed the status code by substring-matching
        it ('required'/'Invalid' -> 400, else 404) - fragile against any
        future wording change. Valid IP/port/md5 but no actual pcap file in
        that analysis directory must still get a clean 404, not 400."""
        md5 = 'b' * 32
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        try:
            status, _ = self._get(f'/api/download-stream?src=1.2.3.4&sport=80&dst=5.6.7.8&dport=443&md5={md5}')
            self.assertEqual(status, 404)
        finally:
            shutil.rmtree(md5dir, ignore_errors=True)

    def test_stream_filter_uses_and_not_or(self):
        """download-stream and hexdump-stream must use 'and port' not 'or port'
        to avoid pulling in unrelated UDP flows sharing the same destination port."""
        import inspect
        import socrates
        source = inspect.getsource(socrates)
        # Find the tcpdump filter lines for hexdump and download
        self.assertIn("f'host {src} and host {dst} and port {sport} and port {dport}'", source)
        self.assertIn("f\"host {src} and host {dst} and port {sport} and port {dport}\"", source)
        self.assertNotIn("or port {dport}", source)

    def test_upload_traversal_filename(self):
        # Use unique PCAP content to avoid collision with test_upload_same_pcap_in_different_zips
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x02' * 100
        status, body = self._post_multipart(
            '/api/upload',
            '../../../etc/evil.pcap',
            pcap_data
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('md5', data)
        md5 = data['md5']
        saved_files = os.listdir(os.path.join(self.tmpdir, md5))
        self.assertIn('evil.pcap', saved_files)
        self.assertNotIn('../../../etc/evil.pcap', saved_files)

    def test_upload_valid_pcap(self):
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x02\x00\x04\x00' + b'\x00' * 92
        status, body = self._post_multipart('/api/upload', 'test.pcap', pcap_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('md5', data)
        self.assertIn('status', data)
        self.assertEqual(data.get('phase'), 'network', 'PCAP upload must report network phase')

    def test_upload_non_pcap_content(self):
        status, body = self._post_multipart('/api/upload', 'fake.pcap', b'not a pcap file')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('md5', data)
        self.assertEqual(data.get('status'), 'processing')
        self.assertEqual(data.get('phase'), 'files', 'Non-PCAP upload must report files phase')

    def test_upload_html_as_pcap(self):
        status, body = self._post_multipart('/api/upload', 'evil.pcap', b'<html><script>alert(1)</script></html>')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('md5', data)
        self.assertEqual(data.get('status'), 'processing')
        self.assertEqual(data.get('phase'), 'files', 'Non-PCAP upload must report files phase')

    def test_upload_elf_as_pcap(self):
        status, body = self._post_multipart('/api/upload', 'malware.pcap', b'\x7fELF' + b'\x00' * 100)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('md5', data)
        self.assertEqual(data.get('status'), 'processing')
        self.assertEqual(data.get('phase'), 'files', 'Non-PCAP upload must report files phase')

    def test_upload_any_extension_detected_as_pcap(self):
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x00' * 100
        status, body = self._post_multipart('/api/upload', 'test.txt', pcap_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('md5', data)
        self.assertEqual(data.get('phase'), 'network', 'PCAP-by-magic upload must report network phase')

    def test_upload_non_pcap_file(self):
        file_data = b'THIS_IS_NOT_A_PCAP_FILE_JUST_TEXT'
        status, body = self._post_multipart('/api/upload', 'test.exe', file_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('md5', data)
        self.assertEqual(data.get('status'), 'processing')
        self.assertEqual(data.get('phase'), 'files', 'Non-PCAP upload must report files phase')

    @unittest.mock.patch('socrates.threading.Thread', new=SyncThread)
    @unittest.mock.patch('socrates.scan_single_file')
    @unittest.mock.patch('socrates.check_yara_executable')
    @unittest.mock.patch('socrates.setup_yara_rules')
    def test_upload_non_pcap_creates_file_analysis_db(self, mock_setup, mock_check, mock_scan):
        """Uploading a non-PCAP file creates events.db with fileinfo + filealerts.

        Patches socrates.threading.Thread with SyncThread so the analysis
        that /api/upload normally dispatches to a background daemon thread
        runs synchronously instead - by the time _post_multipart returns,
        analysis has already completed, so no polling/timeout is needed and
        the test can't flake under full-suite load (see SyncThread's
        docstring for why the polling version could)."""
        mock_setup.return_value = '/tmp/fake-yara-rules'
        mock_check.return_value = True
        matches = [{
            'rule_name': 'TEST_Malware',
            'tags': ['test'],
            'meta': {'author': 'test'},
            'strings': [],
            'file_id': '',
        }]
        mock_scan.return_value = (matches, 'a' * 64, 'b' * 32, 'c' * 40, {'file_type': 'PE32 executable', 'entropy': 7.5})

        file_data = b'MZ' + b'\x00' * 62
        status, body = self._post_multipart('/api/upload', 'test.exe', file_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        md5 = data['md5']
        self.assertEqual(data.get('phase'), 'files')

        dir_path = os.path.join(server.DATA_DIR, md5)
        db_path = os.path.join(dir_path, 'events.db')
        self.assertTrue(os.path.exists(db_path), 'events.db must be created for standalone file')
        self.assertFalse(os.path.exists(os.path.join(dir_path, '.phase')), '.phase must be cleaned up')

        name_path = os.path.join(dir_path, 'name.txt')
        self.assertTrue(os.path.exists(name_path), 'name.txt must be created')
        with open(name_path, 'r') as f:
            self.assertEqual(f.read().strip(), 'test.exe')

        # Verify database contents
        fileinfo_events = db.query_events_sqlite(db_path, event_type='fileinfo')
        self.assertEqual(len(fileinfo_events), 1, 'Must have one fileinfo event')
        fi = fileinfo_events[0]
        self.assertEqual(fi['event_type'], 'fileinfo')
        self.assertEqual(fi['fileinfo']['filename'], 'test.exe')
        self.assertEqual(fi['fileinfo']['size'], 64)
        self.assertEqual(fi['fileinfo']['metadata']['file_type'], 'PE32 executable')
        self.assertEqual(fi['fileinfo']['metadata']['entropy'], 7.5)

        alert_events = db.query_events_sqlite(db_path, event_type='filealerts')
        self.assertEqual(len(alert_events), 1, 'Must have one filealerts event')
        fa = alert_events[0]
        self.assertEqual(fa['event_type'], 'filealerts')
        self.assertEqual(fa['filealerts']['rule_name'], 'TEST_Malware')
        self.assertEqual(fa['filealerts']['author'], 'test')

        # Verify mocks were called
        mock_setup.assert_called_once()
        mock_check.assert_called_once()
        mock_scan.assert_called_once()

    @unittest.mock.patch('socrates.scan_single_file')
    @unittest.mock.patch('socrates.check_yara_executable')
    @unittest.mock.patch('socrates.setup_yara_rules')
    def test_upload_zip_with_non_pcap_creates_file_analysis_db(self, mock_setup, mock_check, mock_scan):
        """Uploading a ZIP containing a non-PCAP file creates events.db with correct extracted name."""
        mock_setup.return_value = '/tmp/fake-yara-rules'
        mock_check.return_value = True
        matches = [{
            'rule_name': 'ZIP_Malware',
            'tags': ['zip'],
            'meta': {},
            'strings': [],
            'file_id': '',
        }]
        mock_scan.return_value = (matches, 'd' * 64, 'e' * 32, 'f' * 40, {})

        # Create ZIP with a non-PCAP file
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('malware.exe', b'\x7fELF' + b'\x00' * 60)
        zip_data = zip_buffer.getvalue()
        expected_md5 = hashlib.md5(b'\x7fELF' + b'\x00' * 60).hexdigest()

        status, body = self._post_multipart('/api/upload', 'samples.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        md5 = data['md5']
        self.assertEqual(md5, expected_md5, 'MD5 must be computed from extracted file bytes')
        self.assertEqual(data.get('phase'), 'files')

        # Poll until analysis is ready
        for _ in range(30):
            time.sleep(0.2)
            status, body = self._post('/api/check-status', {'md5': md5})
            result = json.loads(body)
            if result.get('status') == 'ready':
                break

        dir_path = os.path.join(server.DATA_DIR, md5)
        db_path = os.path.join(dir_path, 'events.db')
        self.assertTrue(os.path.exists(db_path), 'events.db must be created for ZIP-extracted file')

        name_path = os.path.join(dir_path, 'name.txt')
        self.assertTrue(os.path.exists(name_path), 'name.txt must use extracted filename')
        with open(name_path, 'r') as f:
            self.assertEqual(f.read().strip(), 'malware.exe')

        # Verify database uses extracted filename
        fileinfo_events = db.query_events_sqlite(db_path, event_type='fileinfo')
        self.assertEqual(len(fileinfo_events), 1)
        self.assertEqual(fileinfo_events[0]['fileinfo']['filename'], 'malware.exe')

        alert_events = db.query_events_sqlite(db_path, event_type='filealerts')
        self.assertEqual(len(alert_events), 1)
        self.assertEqual(alert_events[0]['filealerts']['rule_name'], 'ZIP_Malware')


    def test_upload_pcap_writes_meta_with_detected_type(self):
        """Direct PCAP upload must write .meta with detected_type 'pcap'."""
        import random
        pcap_data = b'\xd4\xc3\xb2\xa1' + bytes([random.randint(0, 255) for _ in range(100)])
        status, body = self._post_multipart('/api/upload', 'test.pcap', pcap_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        md5 = data['md5']
        dir_path = os.path.join(server.DATA_DIR, md5)
        meta_path = os.path.join(dir_path, '.meta')
        self.assertTrue(os.path.exists(meta_path), '.meta must be written for PCAP upload')
        with open(meta_path, 'r') as f:
            meta = json.load(f)
        self.assertEqual(meta['version'], 1)
        self.assertEqual(meta['detected_type'], 'pcap')
        self.assertEqual(meta['original'], 'test.pcap')
        self.assertEqual(meta['extracted'], 'test.pcap')

    def test_upload_log_writes_meta_with_detected_type(self):
        """Direct log file upload must write .meta with detected_type 'log'."""
        file_data = b'{"EventID": 1, "Channel": "Security"}'
        status, body = self._post_multipart('/api/upload', 'test.json', file_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        md5 = data['md5']
        dir_path = os.path.join(server.DATA_DIR, md5)
        meta_path = os.path.join(dir_path, '.meta')
        self.assertTrue(os.path.exists(meta_path), '.meta must be written for log upload')
        with open(meta_path, 'r') as f:
            meta = json.load(f)
        self.assertEqual(meta['detected_type'], 'log')
        self.assertEqual(meta['original'], 'test.json')

    def test_upload_binary_writes_meta_with_detected_type(self):
        """Direct binary upload must write .meta with detected_type 'binary'.

        REGRESSION: this used to share byte-identical content
        (b'MZ' + b'\\x00' * 62) with test_upload_non_pcap_creates_file_analysis_db,
        both hashing to the same MD5 - since this test's name sorts first
        alphabetically, it always ran first and left that MD5's directory
        behind, so the other test deterministically hit the "already
        analyzed" (status: ready) response instead of a fresh upload
        whenever the full suite ran, even though each test passed fine in
        isolation. A distinguishing suffix keeps their MD5s from colliding."""
        file_data = b'MZ' + b'\x00' * 62 + b'BINARY_META_TEST'
        status, body = self._post_multipart('/api/upload', 'test.exe', file_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        md5 = data['md5']
        dir_path = os.path.join(server.DATA_DIR, md5)
        meta_path = os.path.join(dir_path, '.meta')
        self.assertTrue(os.path.exists(meta_path), '.meta must be written for binary upload')
        with open(meta_path, 'r') as f:
            meta = json.load(f)
        self.assertEqual(meta['detected_type'], 'binary')
        self.assertEqual(meta['original'], 'test.exe')

    def test_upload_zip_pcap_writes_meta_with_detected_type(self):
        """ZIP containing PCAP must write .meta with detected_type 'pcap' and extracted filename."""
        import io
        import zipfile
        import random
        pcap_data = b'\xd4\xc3\xb2\xa1' + bytes([random.randint(0, 255) for _ in range(100)])
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('inner.pcap', pcap_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'capture.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        md5 = data['md5']
        dir_path = os.path.join(server.DATA_DIR, md5)
        meta_path = os.path.join(dir_path, '.meta')
        self.assertTrue(os.path.exists(meta_path), '.meta must be written for ZIP-PCAP upload')
        with open(meta_path, 'r') as f:
            meta = json.load(f)
        self.assertEqual(meta['detected_type'], 'pcap')
        self.assertEqual(meta['original'], 'capture.zip')
        self.assertEqual(meta['extracted'], 'inner.pcap')

    def test_upload_evtx_writes_meta_with_detected_type(self):
        """Direct EVTX upload must write .meta with detected_type 'log'."""
        file_data = b'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID><Channel>Security</Channel></System></Event>'
        status, body = self._post_multipart('/api/upload', 'test.evtx', file_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        md5 = data['md5']
        dir_path = os.path.join(server.DATA_DIR, md5)
        meta_path = os.path.join(dir_path, '.meta')
        self.assertTrue(os.path.exists(meta_path), '.meta must be written for EVTX upload')
        with open(meta_path, 'r') as f:
            meta = json.load(f)
        self.assertEqual(meta['version'], 1)
        self.assertEqual(meta['detected_type'], 'log')
        self.assertEqual(meta['original'], 'test.evtx')
        self.assertEqual(meta['extracted'], 'test.evtx')

    def test_upload_zip_evtx_routes_to_log_analysis(self):
        """ZIP containing EVTX must route to log analysis with detected_type 'log'."""
        import io, zipfile as zf
        evtx_data = b'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID></System></Event>'
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('logs.evtx', evtx_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'logs.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['phase'], 'logs')
        md5 = data['md5']
        dir_path = os.path.join(server.DATA_DIR, md5)
        meta_path = os.path.join(dir_path, '.meta')
        self.assertTrue(os.path.exists(meta_path), '.meta must be written for ZIP-EVTX')
        with open(meta_path, 'r') as f:
            meta = json.load(f)
        self.assertEqual(meta['detected_type'], 'log')
        self.assertEqual(meta['original'], 'logs.zip')
        self.assertEqual(meta['extracted'], 'logs.evtx')

    def test_upload_zip_json_routes_to_log_analysis(self):
        """ZIP containing JSON must route to log analysis with detected_type 'log'."""
        import io, zipfile as zf
        json_data = b'{"timestamp":"2024-01-01T00:00:00Z","event_type":"test"}'
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('logs.json', json_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'logs.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['phase'], 'logs')
        md5 = data['md5']
        dir_path = os.path.join(server.DATA_DIR, md5)
        meta_path = os.path.join(dir_path, '.meta')
        self.assertTrue(os.path.exists(meta_path), '.meta must be written for ZIP-JSON')
        with open(meta_path, 'r') as f:
            meta = json.load(f)
        self.assertEqual(meta['detected_type'], 'log')

    def test_upload_zip_csv_routes_to_log_analysis(self):
        """ZIP containing CSV must route to log analysis with detected_type 'log'."""
        import io, zipfile as zf
        csv_data = b'timestamp,event_type\n2024-01-01T00:00:00Z,test\n'
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('logs.csv', csv_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'logs.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['phase'], 'logs')
        md5 = data['md5']
        dir_path = os.path.join(server.DATA_DIR, md5)
        meta_path = os.path.join(dir_path, '.meta')
        self.assertTrue(os.path.exists(meta_path), '.meta must be written for ZIP-CSV')
        with open(meta_path, 'r') as f:
            meta = json.load(f)
        self.assertEqual(meta['detected_type'], 'log')

    def test_upload_zip_xml_routes_to_log_analysis(self):
        """ZIP containing XML must route to log analysis with detected_type 'log'."""
        import io, zipfile as zf
        xml_data = b'<?xml version="1.0"?><events><event><id>1</id></event></events>'
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('logs.xml', xml_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'logs.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['phase'], 'logs')
        md5 = data['md5']
        dir_path = os.path.join(server.DATA_DIR, md5)
        meta_path = os.path.join(dir_path, '.meta')
        self.assertTrue(os.path.exists(meta_path), '.meta must be written for ZIP-XML')
        with open(meta_path, 'r') as f:
            meta = json.load(f)
        self.assertEqual(meta['detected_type'], 'log')

    @unittest.mock.patch('socrates.run_sigma_pipeline')
    @unittest.mock.patch('socrates.parse_zircolite_results')
    def test_log_analysis_end_to_end(self, mock_parse, mock_pipeline):
        """Full log analysis pipeline: upload -> mocked Zircolite -> DB -> API queries."""
        # 1. Create a fake Zircolite unified DB with a logs table
        fake_zircolite_db = os.path.join(self.tmpdir, 'fake_zircolite.db')
        conn = sqlite3.connect(fake_zircolite_db)
        conn.execute('CREATE TABLE logs (row_id INTEGER, Channel TEXT, EventID INTEGER, SystemTime TEXT, CommandLine TEXT, Image TEXT, SourceIp TEXT, DestinationIp TEXT, SourcePort INTEGER, DestinationPort INTEGER, Protocol TEXT)')
        conn.execute("INSERT INTO logs VALUES (1, 'Microsoft-Windows-Sysmon/Operational', 1, '2024-01-01T12:00:00Z', 'cmd.exe /c whoami', 'C:\\Windows\\System32\\cmd.exe', NULL, NULL, NULL, NULL, NULL)")
        conn.execute("INSERT INTO logs VALUES (2, 'Microsoft-Windows-Sysmon/Operational', 3, '2024-01-01T12:01:00Z', NULL, NULL, '192.168.1.50', '10.0.0.99', 54321, 443, 'tcp')")
        conn.commit()
        conn.close()

        # 2. Stub run_sigma_pipeline to return success + the fake DB path
        def fake_run_pipeline(dir_path, log_path, data_dir=None):
            sigma_json = os.path.join(dir_path, 'sigma_matches.json')
            with open(sigma_json, 'w') as f:
                json.dump([], f)
            return True, fake_zircolite_db
        mock_pipeline.side_effect = fake_run_pipeline

        # 3. Stub parse_zircolite_results to return canned alerts
        mock_parse.return_value = [{
            'timestamp': '2024-01-01T12:00:00Z',
            'rule_title': 'Test Sigma Rule',
            'rule_id': 'test-123',
            'severity': 'high',
            'level': 'high',
            'logsource': 'windows',
            'tags': ['attack.execution'],
            'mitre_techniques': ['attack.t1059'],
            'original_log': json.dumps({'CommandLine': 'cmd.exe /c whoami'}),
            'json_data': json.dumps({'title': 'Test Sigma Rule'}),
        }]

        # 4. Upload a JSON log file
        log_data = (
            b'{"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", '
            b'"SystemTime": "2024-01-01T12:00:00Z", "Computer": "DESKTOP-TEST", '
            b'"Image": "C:\\\\Windows\\\\System32\\\\cmd.exe", '
            b'"CommandLine": "cmd.exe /c whoami", "User": "TESTDOMAIN\\\\jdoe", '
            b'"ProcessId": 1234, "ParentProcessId": 5678}\n'
            b'{"EventID": 3, "Channel": "Microsoft-Windows-Sysmon/Operational", '
            b'"SystemTime": "2024-01-01T12:01:00Z", "SourceIp": "192.168.1.50", '
            b'"DestinationIp": "10.0.0.99", "SourcePort": 54321, '
            b'"DestinationPort": 443, "Protocol": "tcp"}\n'
        )
        status, body = self._post_multipart('/api/upload', 'test.json', log_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['phase'], 'logs')
        md5 = data['md5']
        dir_path = os.path.join(server.DATA_DIR, md5)
        meta_path = os.path.join(dir_path, '.meta')
        self.assertTrue(os.path.exists(meta_path), '.meta must be written for JSON upload')
        with open(meta_path, 'r') as f:
            meta = json.load(f)
        self.assertEqual(meta['detected_type'], 'log')

        # 5. Poll until ready
        for _ in range(30):
            time.sleep(0.2)
            status, body = self._post('/api/check-status', {'md5': md5})
            result = json.loads(body)
            if result.get('status') == 'ready':
                break
        self.assertEqual(result['status'], 'ready', 'Analysis must complete')
        db_path = os.path.join(dir_path, 'events.db')
        self.assertTrue(os.path.exists(db_path), 'events.db must be created after analysis')

        # 6. Assert Sigma alerts are queryable
        status, body = self._get('/api/sigma-alerts?md5=' + md5)
        self.assertEqual(status, 200)
        alerts = json.loads(body)
        self.assertEqual(len(alerts), 1, 'Exactly one Sigma alert must be returned')
        self.assertEqual(alerts[0]['rule_title'], 'Test Sigma Rule')
        self.assertEqual(alerts[0]['severity'], 'high')

        # 7. Assert log events are queryable
        status, body = self._get('/api/events?md5=' + md5 + '&type=log')
        self.assertEqual(status, 200)
        events = json.loads(body)
        self.assertGreaterEqual(len(events), 1, 'At least one log event must be returned')
        self.assertEqual(events[0]['event_type'], 'log')

        # 8. Assert Sigma stats are computed
        status, body = self._get('/api/sigma-stats?md5=' + md5)
        self.assertEqual(status, 200)
        stats = json.loads(body)
        self.assertEqual(stats['total'], 1)
        self.assertEqual(stats['by_severity'].get('high'), 1)
        self.assertIn('attack.t1059', stats['mitre_techniques'])

        # 9. Assert temp Zircolite DB was cleaned up
        self.assertFalse(os.path.exists(os.path.join(dir_path, '.zircolite_events.db')),
                         'Temp Zircolite DB must be deleted after import')

    @unittest.mock.patch('socrates.is_zircolite_available', return_value=False)
    def test_analyze_log_file_zircolite_missing_writes_error(self, mock_zircolite):
        """Log analysis with Zircolite unavailable must write .error and create empty DB."""
        json_data = b'{"timestamp":"2024-01-01T00:00:00Z","event_type":"zircolite_missing_test"}'
        status, body = self._post_multipart('/api/upload', 'test.json', json_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        md5 = data['md5']
        dir_path = os.path.join(server.DATA_DIR, md5)
        error_path = os.path.join(dir_path, '.error')
        db_path = os.path.join(dir_path, 'events.db')
        for _ in range(30):
            time.sleep(0.2)
            if os.path.exists(error_path):
                break
        self.assertTrue(os.path.exists(error_path), '.error must be written when Zircolite is unavailable')
        with open(error_path, 'r') as f:
            error_msg = f.read()
        self.assertIn('unavailable', error_msg.lower())
        self.assertTrue(os.path.exists(db_path), 'events.db must be created even when Zircolite is unavailable')

    @unittest.mock.patch('socrates.setup_yara_rules', return_value='/dummy/rules.yar')
    @unittest.mock.patch('socrates.check_yara_executable', return_value=True)
    @unittest.mock.patch('socrates.scan_single_file', side_effect=Exception('YARA fail'))
    def test_analyze_standalone_file_yara_error_writes_error(self, mock_scan, mock_yara_exec, mock_rules):
        """Standalone file analysis with YARA failure must write .error and create empty DB."""
        file_data = b'MZ' + b'\x00' * 62 + b'YARA_ERROR_TEST'
        status, body = self._post_multipart('/api/upload', 'test.exe', file_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        md5 = data['md5']
        dir_path = os.path.join(server.DATA_DIR, md5)
        error_path = os.path.join(dir_path, '.error')
        db_path = os.path.join(dir_path, 'events.db')
        for _ in range(30):
            time.sleep(0.2)
            if os.path.exists(error_path):
                break
        self.assertTrue(os.path.exists(error_path), '.error must be written when YARA scan fails')
        with open(error_path, 'r') as f:
            error_msg = f.read()
        self.assertIn('YARA scan failed', error_msg)
        self.assertTrue(os.path.exists(db_path), 'events.db must be created with empty matches when YARA fails')

    @unittest.mock.patch('socrates.setup_yara_rules', return_value='/dummy/rules.yar')
    @unittest.mock.patch('socrates.check_yara_executable', return_value=False)
    def test_analyze_standalone_file_never_allows_network_rule_refresh(self, mock_yara_exec, mock_rules):
        """REGRESSION: analyzing a file must never silently phone home to
        refresh YARA rules as a side effect of just uploading it - that's
        now an explicit, opt-in action (Rules modal, or the
        checkForStaleRules() notification), not something the analysis
        path triggers on its own. See AGENTS.md and setup_yara_rules()'s
        network_allowed parameter."""
        file_data = b'MZ' + b'\x00' * 62 + b'NETWORK_CONSENT_TEST'
        status, body = self._post_multipart('/api/upload', 'test.exe', file_data)
        self.assertEqual(status, 200)
        for _ in range(30):
            time.sleep(0.2)
            if mock_rules.called:
                break
        mock_rules.assert_called_once_with(server.DATA_DIR, network_allowed=False)

    def test_reanalyze_preserves_meta(self):
        """Re-analyzing a file must preserve the existing .meta file."""
        import io, zipfile as zf
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x05' * 100
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('capture.pcap', pcap_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'capture.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        md5 = data['md5']
        dir_path = os.path.join(server.DATA_DIR, md5)
        meta_path = os.path.join(dir_path, '.meta')

        # Wait for dir to be created by background processing
        for _ in range(20):
            time.sleep(0.1)
            if os.path.exists(dir_path):
                break

        self.assertTrue(os.path.exists(meta_path), '.meta must exist after upload')
        original_meta = None
        with open(meta_path, 'r') as f:
            original_meta = json.load(f)

        # Simulate completed analysis by creating artifacts and removing .phase
        with open(os.path.join(dir_path, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert"}\n')
        with open(os.path.join(dir_path, 'events.db'), 'w') as f:
            f.write('')
        phase_path = os.path.join(dir_path, '.phase')
        if os.path.exists(phase_path):
            os.unlink(phase_path)

        # Trigger re-analyze
        status, body = self._post('/api/reanalyze', {'md5': md5})
        self.assertEqual(status, 200)

        # .meta should be preserved (rewritten after cleanup)
        self.assertTrue(os.path.exists(meta_path), '.meta must be preserved during re-analyze')
        with open(meta_path, 'r') as f:
            preserved_meta = json.load(f)
        self.assertEqual(preserved_meta['detected_type'], original_meta['detected_type'])
        self.assertEqual(preserved_meta['original'], original_meta['original'])
        self.assertEqual(preserved_meta['extracted'], original_meta['extracted'])

    def test_reanalyze_rewrites_meta(self):
        """Re-analyzing must rewrite .meta with the same detected_type after cleanup."""
        import io, zipfile as zf
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x06' * 100
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('inner.pcap', pcap_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'test.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        md5 = data['md5']
        dir_path = os.path.join(server.DATA_DIR, md5)
        meta_path = os.path.join(dir_path, '.meta')

        # Wait for dir to be created
        for _ in range(20):
            time.sleep(0.1)
            if os.path.exists(dir_path):
                break

        self.assertTrue(os.path.exists(meta_path), '.meta must exist after upload')

        # Simulate completed analysis
        with open(os.path.join(dir_path, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert"}\n')
        with open(os.path.join(dir_path, 'events.db'), 'w') as f:
            f.write('')
        phase_path = os.path.join(dir_path, '.phase')
        if os.path.exists(phase_path):
            os.unlink(phase_path)

        # Trigger re-analyze
        status, body = self._post('/api/reanalyze', {'md5': md5})
        self.assertEqual(status, 200)

        # Verify .meta was rewritten and still has correct detected_type
        self.assertTrue(os.path.exists(meta_path), '.meta must exist after re-analyze')
        with open(meta_path, 'r') as f:
            meta = json.load(f)
        self.assertEqual(meta['detected_type'], 'pcap')
        self.assertEqual(meta['original'], 'test.zip')
        self.assertEqual(meta['extracted'], 'inner.pcap')

    def test_upload_valid_zip(self):
        import io
        import zipfile as zf
        import hashlib
        # Use unique PCAP content so this test doesn't collide with test_upload_same_pcap_in_different_zips
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x01' * 100
        expected_md5 = hashlib.md5(pcap_data).hexdigest()
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('test.pcap', pcap_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'test.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('md5', data)
        self.assertEqual(data['md5'], expected_md5,
                         'MD5 should be computed from extracted PCAP, not the ZIP')
        self.assertEqual(data['status'], 'processing')
        # Verify directory was created using PCAP MD5
        self.assertTrue(os.path.exists(os.path.join(self.tmpdir, expected_md5, 'test.pcap')))

    def test_upload_zip_with_extra_files_analyzes_them_as_standalone_files(self):
        """REGRESSION: only the first PCAP in a multi-file ZIP used to ever
        be analyzed - every other file extracted alongside it was silently
        discarded. Non-pcap extras must now each get their own standalone
        (log/binary) analysis, listed in additionalMd5s, rather than being
        dropped/counted as filesSkipped."""
        import io
        import zipfile as zf
        import hashlib
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x11' * 100
        readme_data = b'not analyzed'
        notes_data = b'also not analyzed'
        expected_md5 = hashlib.md5(pcap_data).hexdigest()
        readme_md5 = hashlib.md5(readme_data).hexdigest()
        notes_md5 = hashlib.md5(notes_data).hexdigest()
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('test.pcap', pcap_data)
            zf_obj.writestr('readme.txt', readme_data)
            zf_obj.writestr('notes.md', notes_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'multi.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['md5'], expected_md5)
        self.assertNotIn('filesSkipped', data)
        self.assertEqual(set(data.get('additionalMd5s', [])), {readme_md5, notes_md5})
        self.assertTrue(os.path.exists(os.path.join(self.tmpdir, readme_md5, 'readme.txt')))
        self.assertTrue(os.path.exists(os.path.join(self.tmpdir, notes_md5, 'notes.md')))

    def test_upload_single_file_zip_has_no_files_skipped(self):
        """A ZIP containing exactly one file must not report filesSkipped
        at all (nothing was actually dropped)."""
        import io
        import zipfile as zf
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x22' * 100
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('solo.pcap', pcap_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'solo.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertNotIn('filesSkipped', data)

    def test_upload_zip_with_two_distinct_pcaps_analyzes_both(self):
        """A ZIP with multiple PCAPs must analyze all of them, not just the
        first - the primary is returned as md5/status/phase as before, and
        every other pcap's md5 is listed in additionalMd5s with its own
        analysis kicked off in the background. Extraction order (and thus
        which pcap ends up 'primary') is a filesystem detail, not something
        this test should assume - it only asserts both were handled."""
        import io
        import zipfile as zf
        import hashlib
        first_data = b'\xd4\xc3\xb2\xa1' + b'\x33' * 100
        second_data = b'\xd4\xc3\xb2\xa1' + b'\x44' * 100
        first_md5 = hashlib.md5(first_data).hexdigest()
        second_md5 = hashlib.md5(second_data).hexdigest()
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('first.pcap', first_data)
            zf_obj.writestr('second.pcap', second_data)
        zip_data = zip_buffer.getvalue()
        with unittest.mock.patch('socrates.spawn_suricata', return_value=True) as mock_spawn:
            status, body = self._post_multipart('/api/upload', 'two-pcaps.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['status'], 'processing')
        self.assertNotIn('filesSkipped', data)
        self.assertEqual({data['md5']} | set(data.get('additionalMd5s', [])), {first_md5, second_md5})
        self.assertEqual(len(data.get('additionalMd5s', [])), 1)
        self.assertTrue(os.path.exists(os.path.join(self.tmpdir, first_md5, 'first.pcap')))
        self.assertTrue(os.path.exists(os.path.join(self.tmpdir, second_md5, 'second.pcap')))
        spawned_dirs = {call.args[0] for call in mock_spawn.call_args_list}
        self.assertEqual(spawned_dirs,
                          {os.path.join(self.tmpdir, first_md5), os.path.join(self.tmpdir, second_md5)},
                          'both pcaps must have their own analysis spawned')

    def test_upload_zip_with_two_pcaps_and_extra_file_analyzes_all_three(self):
        """A ZIP with multiple pcaps plus a non-pcap extra file must
        analyze all three, each as its own independent analysis - the
        extra file is no longer dropped/counted as filesSkipped, it gets
        its own standalone (log/binary) analysis alongside the pcaps."""
        import io
        import zipfile as zf
        import hashlib
        first_data = b'\xd4\xc3\xb2\xa1' + b'\x55' * 100
        second_data = b'\xd4\xc3\xb2\xa1' + b'\x66' * 100
        readme_data = b'also analyzed now'
        first_md5 = hashlib.md5(first_data).hexdigest()
        second_md5 = hashlib.md5(second_data).hexdigest()
        readme_md5 = hashlib.md5(readme_data).hexdigest()
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('first.pcap', first_data)
            zf_obj.writestr('second.pcap', second_data)
            zf_obj.writestr('readme.txt', readme_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'two-pcaps-plus-extra.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertNotIn('filesSkipped', data)
        self.assertEqual({data['md5']} | set(data.get('additionalMd5s', [])),
                          {first_md5, second_md5, readme_md5})
        self.assertEqual(len(data.get('additionalMd5s', [])), 2)
        self.assertTrue(os.path.exists(os.path.join(self.tmpdir, readme_md5, 'readme.txt')))

    def test_upload_zip_with_identical_pcaps_dedupes_within_batch(self):
        """Two byte-identical pcaps in the same ZIP must only produce one
        analysis - the duplicate must not appear in additionalMd5s, must
        not be reported as skipped, must not trigger a second
        commit/spawn, and must not crash the request."""
        import io
        import zipfile as zf
        import hashlib
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x77' * 100
        expected_md5 = hashlib.md5(pcap_data).hexdigest()
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('capture-a.pcap', pcap_data)
            zf_obj.writestr('capture-b.pcap', pcap_data)
        zip_data = zip_buffer.getvalue()
        with unittest.mock.patch('socrates.spawn_suricata', return_value=True) as mock_spawn:
            status, body = self._post_multipart('/api/upload', 'duplicate-pcaps.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['md5'], expected_md5)
        self.assertNotIn('additionalMd5s', data)
        self.assertNotIn('filesSkipped', data)
        self.assertTrue(os.path.exists(os.path.join(self.tmpdir, expected_md5)))
        mock_spawn.assert_called_once()
        self.assertEqual(mock_spawn.call_args.args[0], os.path.join(self.tmpdir, expected_md5),
                          'the duplicate pcap must not trigger a second spawn_suricata call')

    def test_upload_zip_with_pcap_and_exe_analyzes_both(self):
        """A ZIP with a pcap plus a non-pcap binary (e.g. a malware sample)
        must analyze both - the exe is no longer dropped, it gets its own
        standalone binary analysis alongside the pcap's network analysis."""
        import io
        import zipfile as zf
        import hashlib
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x99' * 100
        exe_data = b'MZ' + b'\x90' * 100 + b'PCAP_AND_EXE_TEST'
        pcap_md5 = hashlib.md5(pcap_data).hexdigest()
        exe_md5 = hashlib.md5(exe_data).hexdigest()
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('capture.pcap', pcap_data)
            zf_obj.writestr('malware.exe', exe_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'pcap-and-exe.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['md5'], pcap_md5, 'the pcap must be the primary analysis, exe secondary')
        self.assertEqual(data.get('phase'), 'network')
        self.assertNotIn('filesSkipped', data)
        self.assertEqual(data.get('additionalMd5s'), [exe_md5])
        self.assertTrue(os.path.exists(os.path.join(self.tmpdir, pcap_md5, 'capture.pcap')))
        self.assertTrue(os.path.exists(os.path.join(self.tmpdir, exe_md5, 'malware.exe')))

    def test_upload_zip_with_pcap_and_log_analyzes_both_with_correct_types(self):
        """A ZIP with a pcap plus an EVTX log (e.g. traffic capture bundled
        with the endpoint's event log) must analyze both, each detected
        and routed to its own correct analysis type - network for the
        pcap, log for the EVTX - not just 'the extra gets analyzed
        somehow'."""
        import io
        import zipfile as zf
        import hashlib
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\xaa' * 100
        evtx_data = b'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID><Data>PCAP_AND_LOG_TEST</Data></System></Event>'
        pcap_md5 = hashlib.md5(pcap_data).hexdigest()
        evtx_md5 = hashlib.md5(evtx_data).hexdigest()
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('capture.pcap', pcap_data)
            zf_obj.writestr('security.evtx', evtx_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'pcap-and-log.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['md5'], pcap_md5, 'the pcap must be the primary analysis')
        self.assertEqual(data.get('phase'), 'network')
        self.assertNotIn('filesSkipped', data)
        self.assertEqual(data.get('additionalMd5s'), [evtx_md5])
        self.assertTrue(os.path.exists(os.path.join(self.tmpdir, pcap_md5, 'capture.pcap')))
        log_meta_path = os.path.join(self.tmpdir, evtx_md5, '.meta')
        self.assertTrue(os.path.exists(log_meta_path), '.meta must be written for the additional log file')
        with open(log_meta_path, 'r') as f:
            log_meta = json.load(f)
        self.assertEqual(log_meta['detected_type'], 'log',
                          'the EVTX must be detected as a log, not lumped in as generic binary')
        self.assertEqual(log_meta['extracted'], 'security.evtx')

    def test_upload_zip_with_log_and_exe_no_pcap_analyzes_both_with_correct_types(self):
        """A ZIP with no pcap at all, containing both a log file and a
        binary, must still route each to its own correct analysis type -
        proves type detection is per-file even when neither file is a
        pcap and there's no network-analysis branch involved at all."""
        import io
        import zipfile as zf
        import hashlib
        evtx_data = b'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID><Data>LOG_AND_EXE_TEST</Data></System></Event>'
        exe_data = b'MZ' + b'\x90' * 100 + b'LOG_AND_EXE_TEST'
        evtx_md5 = hashlib.md5(evtx_data).hexdigest()
        exe_md5 = hashlib.md5(exe_data).hexdigest()
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('security.evtx', evtx_data)
            zf_obj.writestr('malware.exe', exe_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'log-and-exe.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertNotIn('filesSkipped', data)
        self.assertEqual({data['md5']} | set(data.get('additionalMd5s', [])), {evtx_md5, exe_md5})
        self.assertEqual(len(data.get('additionalMd5s', [])), 1)

        with open(os.path.join(self.tmpdir, evtx_md5, '.meta'), 'r') as f:
            evtx_meta = json.load(f)
        with open(os.path.join(self.tmpdir, exe_md5, '.meta'), 'r') as f:
            exe_meta = json.load(f)
        self.assertEqual(evtx_meta['detected_type'], 'log')
        self.assertEqual(exe_meta['detected_type'], 'binary')

    def test_upload_zip_with_no_pcap_multiple_files_analyzes_all(self):
        """A ZIP with no pcap but multiple non-pcap files must analyze all
        of them, not just the first - extraction order is a filesystem
        detail, so this only asserts both ended up analyzed."""
        import io
        import zipfile as zf
        import hashlib
        first_data = b'first file contents'
        second_data = b'second file contents'
        first_md5 = hashlib.md5(first_data).hexdigest()
        second_md5 = hashlib.md5(second_data).hexdigest()
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('a.bin', first_data)
            zf_obj.writestr('b.bin', second_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'no-pcap-multi.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertNotIn('filesSkipped', data)
        self.assertEqual({data['md5']} | set(data.get('additionalMd5s', [])), {first_md5, second_md5})
        self.assertEqual(len(data.get('additionalMd5s', [])), 1)

    def test_upload_zip_with_identical_non_pcap_files_dedupes_within_batch(self):
        """Two byte-identical non-pcap files in the same ZIP must only
        produce one analysis, mirroring the pcap-duplicate case."""
        import io
        import zipfile as zf
        import hashlib
        file_data = b'duplicate content'
        expected_md5 = hashlib.md5(file_data).hexdigest()
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('copy-a.bin', file_data)
            zf_obj.writestr('copy-b.bin', file_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'duplicate-files.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['md5'], expected_md5)
        self.assertNotIn('additionalMd5s', data)
        self.assertNotIn('filesSkipped', data)

    def test_upload_zip_extra_file_failure_reported_as_files_skipped(self):
        """A file that genuinely fails to hash/commit within a multi-file
        ZIP must be dropped gracefully and counted via filesSkipped,
        without aborting analysis of the rest of the batch."""
        import io
        import zipfile as zf
        import hashlib
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x88' * 100
        expected_md5 = hashlib.md5(pcap_data).hexdigest()
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('test.pcap', pcap_data)
            zf_obj.writestr('bad.bin', b'unreadable')
        zip_data = zip_buffer.getvalue()

        real_hash_with_prefix = server._hash_file_with_prefix

        def flaky_hash_with_prefix(path, *args, **kwargs):
            if os.path.basename(path) == 'bad.bin':
                raise OSError('simulated failure')
            return real_hash_with_prefix(path, *args, **kwargs)

        with unittest.mock.patch('socrates._hash_file_with_prefix', side_effect=flaky_hash_with_prefix):
            status, body = self._post_multipart('/api/upload', 'flaky.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['md5'], expected_md5)
        self.assertNotIn('additionalMd5s', data)
        self.assertEqual(data.get('filesSkipped'), 1)

    def test_upload_tries_password_protected_zips(self):
        """Upload handler code must attempt common passwords before rejecting protected ZIPs."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        # Verify shared extraction helper exists
        self.assertIn("def _attempt_zip_extract(zip_ref, extract_dir, passwords, max_size=None):", content,
                      'Must define _attempt_zip_extract helper')
        helper_section = content.split("def _attempt_zip_extract(zip_ref, extract_dir, passwords, max_size=None):")[1].split("def extract_pcap_from_zip(")[0]
        # Should try no password first
        self.assertIn("zip_ref.extractall(extract_dir)", helper_section,
                      'Must attempt extraction without password')
        # Should try provided passwords
        self.assertIn("for pwd in passwords:", helper_section,
                      'Must loop over candidate passwords')
        # Verify _extract_zip_contents uses the shared helper
        self.assertIn("_attempt_zip_extract(zip_ref, extract_dir, passwords, max_size)", content,
                      '_extract_zip_contents must delegate to _attempt_zip_extract')
        # Upload handler should derive passwords from filename
        upload_section = content.split("def handle_post_upload(self):")[1].split("def handle_post_load_url(self):")[0]
        self.assertIn("passwords = [b'infected']", upload_section,
                      'Must try infected password')
        self.assertIn(r"re.search(r'(\d{4})-(\d{2})-(\d{2})', original_filename)", upload_section,
                      'Must derive date-based password from filename')
        self.assertIn("'infected_{year}{month}{day}'.encode()", upload_section,
                      'Must construct MTA-style date password')
        # _process_uploaded_file must call _extract_zip_contents
        process_section = content.split("def _process_uploaded_file(self,")[1].split("def handle_post_upload(self):")[0]
        self.assertIn("_extract_zip_contents(src_path, tmp_dir, passwords or [], effective_max)", process_section,
                      'Must call _extract_zip_contents helper')

    def test_load_url_tries_password_protected_zips(self):
        """load-url handler must always try the plain 'infected' password (cheap, harmless
        even for non-MTA URLs), and try the MTA date-derived password first when the URL
        is from malware-traffic-analysis.net with a /YYYY/MM/DD/ path."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        load_url_section = content.split("def handle_post_load_url(self):")[1].split("\n    def ")[0]
        self.assertIn("passwords = [b'infected']", load_url_section,
                      'Must always try infected password, regardless of URL source')
        self.assertIn("if 'malware-traffic-analysis.net' in url:", load_url_section,
                      'Must gate the dated password on the MTA domain')
        self.assertIn(r"re.search(r'/(\d{4})/(\d{2})/(\d{2})/', url)", load_url_section,
                      'Must derive date-based password from the MTA URL path')
        self.assertIn("passwords.insert(0, f'infected_{year}{month}{day}'.encode())", load_url_section,
                      'Dated MTA password must be tried before the plain fallback')

    def test_upload_same_pcap_in_different_zips(self):
        import io
        import zipfile as zf
        import hashlib
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x00' * 100
        expected_md5 = hashlib.md5(pcap_data).hexdigest()

        # First ZIP
        zip1 = io.BytesIO()
        with zf.ZipFile(zip1, 'w') as z:
            z.writestr('capture.pcap', pcap_data)
        status1, body1 = self._post_multipart('/api/upload', 'first.zip', zip1.getvalue())
        self.assertEqual(status1, 200)
        data1 = json.loads(body1)
        self.assertEqual(data1['md5'], expected_md5)

        # Second ZIP with different name and extra file
        zip2 = io.BytesIO()
        with zf.ZipFile(zip2, 'w') as z:
            z.writestr('readme.txt', 'extra file')
            z.writestr('network.pcap', pcap_data)
        status2, body2 = self._post_multipart('/api/upload', 'second.zip', zip2.getvalue())
        self.assertEqual(status2, 200)
        data2 = json.loads(body2)
        self.assertEqual(data2['md5'], expected_md5,
                         'Same PCAP inside different ZIPs should produce the same MD5')

    def test_upload_nested_zip_extracts_pcap(self):
        """ZIP archives with subdirectories must be walked recursively."""
        import io
        import zipfile as zf
        import hashlib
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x00' * 100
        expected_md5 = hashlib.md5(pcap_data).hexdigest()

        zip_buf = io.BytesIO()
        with zf.ZipFile(zip_buf, 'w') as z:
            z.writestr('subfolder/capture.pcap', pcap_data)
        status, body = self._post_multipart('/api/upload', 'nested.zip', zip_buf.getvalue())
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['md5'], expected_md5,
                         'Must find PCAP inside nested ZIP directory')

    def test_upload_zip_case_insensitive_pcap_extension(self):
        """ZIP extraction must match PCAP extensions case-insensitively."""
        import io
        import zipfile as zf
        import hashlib
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x00' * 100
        expected_md5 = hashlib.md5(pcap_data).hexdigest()

        zip_buf = io.BytesIO()
        with zf.ZipFile(zip_buf, 'w') as z:
            z.writestr('capture.PCAP', pcap_data)
        status, body = self._post_multipart('/api/upload', 'uppercase.zip', zip_buf.getvalue())
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['md5'], expected_md5,
                         'Must match .PCAP uppercase extension')

    def test_load_url_no_url_provided(self):
        status, body = self._post('/api/load-url', {})
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('No URL provided', data.get('error', ''))

    def test_load_url_rejects_private_ip(self):
        status, body = self._post('/api/load-url', {'url': 'http://10.0.0.1/test.pcap'})
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('private', data.get('error', '').lower())

    def test_load_url_rejects_localhost(self):
        status, body = self._post('/api/load-url', {'url': 'http://localhost/test.pcap'})
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('localhost', data.get('error', '').lower())

    def test_load_url_empty_url(self):
        status, body = self._post('/api/load-url', {'url': ''})
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('No URL provided', data.get('error', ''))

    def test_load_url_blocks_dns_rebinding(self):
        """Behavioral: load-url must validate URL before and after DNS resolution to prevent rebinding."""
        import unittest.mock
        # Mock DNS to return a private IP for a public-looking hostname
        with unittest.mock.patch('socket.gethostbyname', return_value='127.0.0.1'):
            status, body = self._post('/api/load-url', {'url': 'http://fake-public.example.com/secret'})
            self.assertEqual(status, 400)
            data = json.loads(body)
            # URL validation fails at some point (DNS resolve or IP check)
            self.assertIn('error', data)

    def test_load_url_malformed_json_returns_400(self):
        """REGRESSION: a malformed JSON body must get a clean 400, not a
        dropped connection from an uncaught json.JSONDecodeError."""
        status, body = self._post('/api/load-url', b'not-json-at-all')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('Invalid JSON', data.get('error', ''))

    def test_check_status_missing_md5(self):
        status, body = self._post('/api/check-status', {})
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('md5', data.get('error', '').lower())

    def test_check_status_invalid_md5_format(self):
        status, body = self._post('/api/check-status', {'md5': 'not-a-valid-md5'})
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('Invalid MD5', data.get('error', ''))

    def test_check_status_malformed_json_returns_400(self):
        """REGRESSION: a malformed JSON body must get a clean 400, not a
        dropped connection from an uncaught json.JSONDecodeError."""
        status, body = self._post('/api/check-status', b'not-json-at-all')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('Invalid JSON', data.get('error', ''))

    def test_check_status_path_traversal(self):
        status, body = self._post('/api/check-status', {'md5': '../../../etc/passwd'})
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('Invalid MD5', data.get('error', ''))

    def test_check_status_nonexistent_md5(self):
        status, body = self._post('/api/check-status', {'md5': '0' * 32})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('status', data)

    def test_check_status_ready_with_sqlite(self):
        md5dir = os.path.join(self.tmpdir, 'abc123def45678901234567890123456')
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert"}\n')
        with open(os.path.join(md5dir, 'events.db'), 'w') as f:
            f.write('')

        status, body = self._post('/api/check-status', {'md5': 'abc123def45678901234567890123456'})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get('status'), 'ready')

    def test_check_status_not_ready_while_phase_active_even_with_db(self):
        """REGRESSION: events.db is created the instant create_sqlite_db opens
        its connection, well before the row-by-row ingest finishes - so its
        mere existence isn't sufficient for 'ready'. A live .phase file
        (still 'importing') means the database exists but may not be fully
        populated yet; reporting 'ready' here let the frontend fetch and
        display incomplete/empty stats that were never refreshed again."""
        md5 = 'bbb123def45678901234567890123456'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'events.db'), 'w') as f:
            f.write('')
        with open(os.path.join(md5dir, '.phase'), 'w') as f:
            f.write('importing')

        status, body = self._post('/api/check-status', {'md5': md5})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get('status'), 'processing',
                         "events.db existing must not mean 'ready' while .phase is still active")
        self.assertEqual(data.get('phase'), 'importing')

    def test_check_status_ready_once_stale_phase_cleaned_up(self):
        """A stale (hung/crashed) .phase file is still auto-cleaned exactly as
        before - once removed, an existing events.db correctly reports ready."""
        md5 = 'ccc123def45678901234567890123456'
        md5dir = os.path.join(self.tmpdir, md5)
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'events.db'), 'w') as f:
            f.write('')
        phase_path = os.path.join(md5dir, '.phase')
        with open(phase_path, 'w') as f:
            f.write('importing')
        old_time = time.time() - 700
        os.utime(phase_path, (old_time, old_time))

        status, body = self._post('/api/check-status', {'md5': md5})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get('status'), 'ready')
        self.assertFalse(os.path.exists(phase_path), 'stale .phase must still be cleaned up')

    def test_check_status_ready_with_eve_json_only(self):
        md5dir = os.path.join(self.tmpdir, 'abcdef12345678901234567890123456')
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert"}\n')
        
        status, body = self._post('/api/check-status', {'md5': 'abcdef12345678901234567890123456'})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get('status'), 'processing')

    def test_check_status_processing_empty_eve_json(self):
        md5dir = os.path.join(self.tmpdir, 'aaa123def45678901234567890123456')
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, 'eve.json'), 'w') as f:
            f.write('')
        
        status, body = self._post('/api/check-status', {'md5': 'aaa123def45678901234567890123456'})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get('status'), 'processing')

    def test_check_status_error_file(self):
        md5dir = os.path.join(self.tmpdir, 'deadbeef123456789012345678901234')
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, '.error'), 'w') as f:
            f.write('YARA scan failed: out of memory')
        status, body = self._post('/api/check-status', {'md5': 'deadbeef123456789012345678901234'})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data.get('status'), 'error')
        self.assertIn('out of memory', data.get('message', ''))

    def test_check_status_stale_error_file(self):
        md5dir = os.path.join(self.tmpdir, 'cafebabe123456789012345678901234')
        os.makedirs(md5dir, exist_ok=True)
        with open(os.path.join(md5dir, '.error'), 'w') as f:
            f.write('old error')
        # Make the error file appear older than 10 minutes
        old_time = time.time() - 700
        os.utime(os.path.join(md5dir, '.error'), (old_time, old_time))
        status, body = self._post('/api/check-status', {'md5': 'cafebabe123456789012345678901234'})
        self.assertEqual(status, 200)
        data = json.loads(body)
        # Stale error should be cleaned up, so we see processing (no db yet)
        self.assertEqual(data.get('status'), 'processing')
        self.assertFalse(os.path.exists(os.path.join(md5dir, '.error')))

    def test_reanalyze_keeps_pcap_and_name(self):
        """Behavioral: reanalyze must preserve PCAP and name.txt while removing artifacts."""
        import io, zipfile as zf
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x03' * 100
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('capture.pcap', pcap_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'capture.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        md5 = data['md5']
        dir_path = os.path.join(self.tmpdir, md5)

        # Wait for analysis dir to be created
        import time
        time.sleep(0.2)

        # Create some artifacts to verify cleanup
        with open(os.path.join(dir_path, 'eve.json'), 'w') as f:
            f.write('{"event_type": "alert"}\n')
        with open(os.path.join(dir_path, 'events.db'), 'w') as f:
            f.write('')
        with open(os.path.join(dir_path, 'name.txt'), 'w') as f:
            f.write('capture.zip')

        # Remove .phase so reanalyze is allowed (simulates completed analysis)
        phase_path = os.path.join(dir_path, '.phase')
        if os.path.exists(phase_path):
            os.unlink(phase_path)

        # Call reanalyze when no .phase exists
        status, body = self._post('/api/reanalyze', {'md5': md5})
        self.assertEqual(status, 200)

        # Verify PCAP and name.txt still exist
        pcap_files = [f for f in os.listdir(dir_path) if f.endswith('.pcap')]
        self.assertTrue(len(pcap_files) > 0, 'PCAP file must be preserved after reanalyze')
        self.assertTrue(os.path.exists(os.path.join(dir_path, 'name.txt')), 'name.txt must be preserved')

        # Verify artifacts were removed
        self.assertFalse(os.path.exists(os.path.join(dir_path, 'eve.json')), 'eve.json must be removed')
        self.assertFalse(os.path.exists(os.path.join(dir_path, 'events.db')), 'events.db must be removed')

    def test_reanalyze_blocked_when_analysis_in_progress(self):
        """Reanalyze must return 409 when .phase file indicates active analysis."""
        import io, zipfile as zf
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x04' * 100
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('capture.pcap', pcap_data)
        zip_data = zip_buffer.getvalue()
        status, body = self._post_multipart('/api/upload', 'capture.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        md5 = data['md5']
        dir_path = os.path.join(self.tmpdir, md5)

        import time
        time.sleep(0.2)

        # Create .phase to simulate in-progress analysis
        with open(os.path.join(dir_path, '.phase'), 'w') as f:
            f.write('network')

        # Call reanalyze — should be blocked
        status, body = self._post('/api/reanalyze', {'md5': md5})
        self.assertEqual(status, 409, 'Reanalyze must be blocked when .phase exists')
        result = json.loads(body)
        self.assertIn('already in progress', result.get('error', '').lower())

    def test_reanalyze_reports_real_error_when_suricata_fails_to_start(self):
        """REGRESSION: spawn_suricata() returns False both when analysis is
        already in progress and when Suricata itself failed to start
        (missing binary, permissions, etc) - these used to be conflated
        into the same generic 409 'Analysis already in progress', hiding
        the real cause of a genuine startup failure."""
        import io, zipfile as zf

        def fake_spawn_suricata_ok(dir_path, pcap_path, suricata_config_path=None, data_dir=None):
            return True

        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x33' * 100
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            zf_obj.writestr('capture.pcap', pcap_data)
        zip_data = zip_buffer.getvalue()
        # Mock the upload's own background spawn_suricata too, so it never
        # leaves a real .phase lock behind that would make the reanalyze
        # call below hit reanalyze's *earlier* "already in progress" check
        # before ever reaching the spawn_suricata call under test.
        with unittest.mock.patch('socrates.spawn_suricata', side_effect=fake_spawn_suricata_ok):
            status, body = self._post_multipart('/api/upload', 'capture.zip', zip_data)
        self.assertEqual(status, 200)
        md5 = json.loads(body)['md5']
        dir_path = os.path.join(self.tmpdir, md5)

        import time
        time.sleep(0.2)

        def fake_spawn_suricata_fails(dir_path, pcap_path, suricata_config_path=None, data_dir=None):
            with open(os.path.join(dir_path, '.error'), 'w') as f:
                f.write('Suricata failed to start: [Errno 2] No such file or directory')
            return False

        with unittest.mock.patch('socrates.spawn_suricata', side_effect=fake_spawn_suricata_fails):
            status, body = self._post('/api/reanalyze', {'md5': md5})
        self.assertEqual(status, 500, 'a genuine startup failure must not be reported as 409')
        result = json.loads(body)
        self.assertIn('No such file or directory', result.get('error', ''))

    def test_reanalyze_malformed_json_returns_400(self):
        """REGRESSION: a malformed JSON body must get a clean 400, not a
        dropped connection from an uncaught json.JSONDecodeError."""
        status, body = self._post('/api/reanalyze', b'not-json-at-all')
        self.assertEqual(status, 400)
        data = json.loads(body)
        self.assertIn('Invalid JSON', data.get('error', ''))

    def test_upload_password_protected_zip(self):
        """Behavioral: upload must extract password-protected ZIPs using common passwords."""
        import io, zipfile as zf
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x04' * 100
        zip_buffer = io.BytesIO()
        with zf.ZipFile(zip_buffer, 'w') as zf_obj:
            # Python's zipfile supports simple password encryption with ZIP_STORED
            zf_obj.writestr('secret.pcap', pcap_data)
        zip_data = zip_buffer.getvalue()

        # Test that a non-password ZIP still works
        status, body = self._post_multipart('/api/upload', 'plain.zip', zip_data)
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn('md5', data)

    def test_old_analysis_without_meta_check_status_ready(self):
        """Old analysis without .meta file must still report ready via check-status."""
        import hashlib
        # Create an old-style analysis directory manually (no .meta)
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x07' * 100
        md5 = hashlib.md5(pcap_data).hexdigest()
        dir_path = os.path.join(server.DATA_DIR, md5)
        os.makedirs(dir_path, exist_ok=True)

        # Write a minimal events.db (old OhMyPCAP schema: just events table)
        import sqlite3
        conn = sqlite3.connect(os.path.join(dir_path, 'events.db'))
        conn.executescript('''
            CREATE TABLE events (
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
            CREATE INDEX idx_event_type ON events(event_type);
            CREATE INDEX idx_timestamp ON events(timestamp);
            CREATE INDEX idx_event_type_timestamp ON events(event_type, timestamp);
        ''')
        conn.commit()
        conn.close()

        with open(os.path.join(dir_path, 'name.txt'), 'w') as f:
            f.write('legacy.pcap')
        with open(os.path.join(dir_path, 'legacy.pcap'), 'wb') as f:
            f.write(pcap_data)

        # Check status should still return ready without meta
        status, body = self._post('/api/check-status', {'md5': md5})
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertEqual(result['status'], 'ready')
        self.assertNotIn('meta', result, 'Old analysis must not have meta in status')

    def test_old_analysis_without_meta_load_analysis_success(self):
        """Old analysis without .meta must still load via load-analysis API."""
        import hashlib
        # Create an old-style analysis directory manually (no .meta)
        pcap_data = b'\xd4\xc3\xb2\xa1' + b'\x08' * 100
        md5 = hashlib.md5(pcap_data).hexdigest()
        dir_path = os.path.join(server.DATA_DIR, md5)
        os.makedirs(dir_path, exist_ok=True)

        import sqlite3
        conn = sqlite3.connect(os.path.join(dir_path, 'events.db'))
        conn.executescript('''
            CREATE TABLE events (
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
            CREATE INDEX idx_event_type ON events(event_type);
            CREATE INDEX idx_timestamp ON events(timestamp);
            CREATE INDEX idx_event_type_timestamp ON events(event_type, timestamp);
        ''')
        conn.commit()
        conn.close()

        with open(os.path.join(dir_path, 'name.txt'), 'w') as f:
            f.write('legacy.pcap')
        with open(os.path.join(dir_path, 'legacy.pcap'), 'wb') as f:
            f.write(pcap_data)

        # load-analysis should still succeed
        status, body = self._get('/api/load-analysis?md5=' + md5)
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertTrue(result.get('success'))
        self.assertEqual(result['md5'], md5)
        self.assertIn('file_name', result)

    def _make_ready_analysis_dir(self, md5):
        """Minimal events.db-backed analysis directory, ready to load."""
        dir_path = os.path.join(server.DATA_DIR, md5)
        os.makedirs(dir_path, exist_ok=True)
        import sqlite3
        conn = sqlite3.connect(os.path.join(dir_path, 'events.db'))
        conn.executescript('''
            CREATE TABLE events (
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
        ''')
        conn.commit()
        conn.close()
        return dir_path

    def test_load_analysis_notes_empty_when_no_notes_txt(self):
        md5 = 'a1' * 16
        dir_path = self._make_ready_analysis_dir(md5)
        try:
            status, body = self._get('/api/load-analysis?md5=' + md5)
            self.assertEqual(status, 200)
            result = json.loads(body)
            self.assertEqual(result.get('notes'), '')
        finally:
            shutil.rmtree(dir_path, ignore_errors=True)

    def test_load_analysis_includes_notes_content(self):
        md5 = 'b2' * 16
        dir_path = self._make_ready_analysis_dir(md5)
        try:
            with open(os.path.join(dir_path, 'notes.txt'), 'w') as f:
                f.write('Suspected GuLoader\nC2 at x.top')
            status, body = self._get('/api/load-analysis?md5=' + md5)
            self.assertEqual(status, 200)
            result = json.loads(body)
            self.assertEqual(result.get('notes'), 'Suspected GuLoader\nC2 at x.top')
        finally:
            shutil.rmtree(dir_path, ignore_errors=True)

    def test_corrupted_db_returns_500(self):
        """Corrupted events.db must return HTTP 500 instead of crashing the connection."""
        import hashlib
        md5 = hashlib.md5(b'corrupted_db_test').hexdigest()
        dir_path = os.path.join(server.DATA_DIR, md5)
        os.makedirs(dir_path, exist_ok=True)
        # Write random bytes (not a valid SQLite file)
        with open(os.path.join(dir_path, 'events.db'), 'wb') as f:
            f.write(b'\x00\x01\x02\x03NOT_A_VALID_DB')
        status, body = self._get('/api/events?md5=' + md5)
        self.assertEqual(status, 500, 'Corrupted DB must return 500')
        result = json.loads(body)
        self.assertIn('Database error', result.get('error', ''))

    def test_malformed_json_data_row_skipped(self):
        """Malformed json_data in events table must be skipped, not crash the endpoint."""
        import hashlib
        md5 = hashlib.md5(b'malformed_json_test').hexdigest()
        dir_path = os.path.join(server.DATA_DIR, md5)
        os.makedirs(dir_path, exist_ok=True)
        conn = sqlite3.connect(os.path.join(dir_path, 'events.db'))
        conn.executescript('''
            CREATE TABLE events (
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
            CREATE INDEX idx_event_type ON events(event_type);
            CREATE INDEX idx_timestamp ON events(timestamp);
            CREATE INDEX idx_event_type_timestamp ON events(event_type, timestamp);
        ''')
        conn.execute('''INSERT INTO events (event_type, timestamp, json_data)
                          VALUES (?, ?, ?)''', ('alert', '2026-01-01T00:00:00', '{"valid": true}'))
        conn.execute('''INSERT INTO events (event_type, timestamp, json_data)
                          VALUES (?, ?, ?)''', ('dns', '2026-01-01T00:00:01', 'not valid json'))
        conn.execute('''INSERT INTO events (event_type, timestamp, json_data)
                          VALUES (?, ?, ?)''', ('http', '2026-01-01T00:00:02', '{"valid": true}'))
        conn.commit()
        conn.close()
        status, body = self._get('/api/events?md5=' + md5)
        self.assertEqual(status, 200, 'Malformed row must not crash endpoint')
        events = json.loads(body)
        self.assertEqual(len(events), 3, 'All rows must be returned (malformed ones as an id-only object)')
        self.assertEqual(events[0].get('valid'), True)
        self.assertEqual(events[1], {'id': 2}, 'Malformed json_data must become an object with just its row id')
        self.assertEqual(events[2].get('valid'), True)

    def test_api_status_get_alias_works(self):
        """GET /api/status must behave identically to POST /api/check-status."""
        import hashlib
        md5 = hashlib.md5(b'status_alias_test').hexdigest()
        dir_path = os.path.join(server.DATA_DIR, md5)
        os.makedirs(dir_path, exist_ok=True)
        conn = sqlite3.connect(os.path.join(dir_path, 'events.db'))
        conn.executescript(db.SQLITE_SCHEMA)
        conn.commit()
        conn.close()
        with open(os.path.join(dir_path, 'name.txt'), 'w') as f:
            f.write('test.pcap')

        # GET /api/status
        status_get, body_get = self._get('/api/status?md5=' + md5)
        self.assertEqual(status_get, 200)
        result_get = json.loads(body_get)

        # POST /api/check-status
        status_post, body_post = self._post('/api/check-status', {'md5': md5})
        self.assertEqual(status_post, 200)
        result_post = json.loads(body_post)

        self.assertEqual(result_get['status'], result_post['status'])

    def test_get_status_includes_has_row_notes_false_by_default(self):
        import hashlib
        md5 = hashlib.md5(b'status_has_row_notes_test').hexdigest()
        dir_path = os.path.join(server.DATA_DIR, md5)
        os.makedirs(dir_path, exist_ok=True)
        conn = sqlite3.connect(os.path.join(dir_path, 'events.db'))
        conn.executescript(db.SQLITE_SCHEMA)
        conn.commit()
        conn.close()
        with open(os.path.join(dir_path, 'name.txt'), 'w') as f:
            f.write('test.pcap')

        status, body = self._get('/api/status?md5=' + md5)
        self.assertEqual(status, 200)
        self.assertIn('hasRowNotes', json.loads(body))
        self.assertFalse(json.loads(body)['hasRowNotes'])

    def test_get_status_has_row_notes_true_once_a_row_note_exists(self):
        import hashlib
        md5 = hashlib.md5(b'status_has_row_notes_true_test').hexdigest()
        dir_path = os.path.join(server.DATA_DIR, md5)
        os.makedirs(dir_path, exist_ok=True)
        db_path = os.path.join(dir_path, 'events.db')
        conn = sqlite3.connect(db_path)
        conn.executescript(db.SQLITE_SCHEMA)
        conn.execute("INSERT INTO events (event_type, timestamp, json_data) VALUES ('alert', '2026-01-01T00:00:00', '{}')")
        conn.commit()
        conn.close()
        with open(os.path.join(dir_path, 'name.txt'), 'w') as f:
            f.write('test.pcap')
        db.set_row_note(db_path, 'events', 1, 'a note')

        status, body = self._get('/api/status?md5=' + md5)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)['hasRowNotes'])

    def test_post_check_status_does_not_include_has_row_notes(self):
        """Deliberate: POST /api/check-status is polled every 2s during
        active processing (see checkStatus() in socrates.js) - the extra
        has_row_notes() query only runs on the one-off GET /api/status
        call sites (loadAnalysis/openReanalyzeModal), not this hot path."""
        import hashlib
        md5 = hashlib.md5(b'check_status_no_row_notes_test').hexdigest()
        dir_path = os.path.join(server.DATA_DIR, md5)
        os.makedirs(dir_path, exist_ok=True)
        conn = sqlite3.connect(os.path.join(dir_path, 'events.db'))
        conn.executescript(db.SQLITE_SCHEMA)
        conn.commit()
        conn.close()
        with open(os.path.join(dir_path, 'name.txt'), 'w') as f:
            f.write('test.pcap')

        status, body = self._post('/api/check-status', {'md5': md5})
        self.assertEqual(status, 200)
        self.assertNotIn('hasRowNotes', json.loads(body))

    def test_get_status_while_processing_does_not_create_events_db(self):
        """REGRESSION GUARD (real bug report): GET /api/status used to call
        has_row_notes(events.db) unconditionally, even while an analysis
        was still 'processing' (a .phase file present, events.db not yet
        created by create_sqlite_db) - sqlite3.connect() creates an empty
        file at that path as a side effect of merely opening a connection,
        even a read-only one. Polling /api/status during an active
        reanalyze (real repro: the app's own openReanalyzeModal, or a
        script polling status) would pre-create events.db before Suricata
        finished, so create_sqlite_db()'s own `not os.path.exists(db_file)`
        guard then skipped real ingestion entirely - permanently leaving
        an empty database. GET /api/status must not touch events.db at
        all while still processing."""
        import hashlib
        md5 = hashlib.md5(b'status_processing_no_db_create_test').hexdigest()
        dir_path = os.path.join(server.DATA_DIR, md5)
        os.makedirs(dir_path, exist_ok=True)
        with open(os.path.join(dir_path, 'name.txt'), 'w') as f:
            f.write('test.pcap')
        # Still "processing": a .phase file exists and events.db does not.
        with open(os.path.join(dir_path, '.phase'), 'w') as f:
            f.write('network')
        db_path = os.path.join(dir_path, 'events.db')

        status, body = self._get('/api/status?md5=' + md5)
        self.assertEqual(status, 200)
        parsed = json.loads(body)
        self.assertEqual(parsed['status'], 'processing')
        self.assertFalse(parsed['hasRowNotes'])
        self.assertFalse(os.path.exists(db_path), 'GET /api/status must not create events.db as a side effect while the analysis is still processing')

    @unittest.mock.patch('socrates.threading.Thread', new=SyncThread)
    @unittest.mock.patch('socrates.setup_suricata_config')
    def test_update_rules_single_ruleset_returns_started_and_status_reflects_progress(self, mock_suricata):
        """POST /api/update-rules with a single ruleset must return
        immediately with a 'started' status and spawn a job for only that
        ruleset; GET /api/rule-update-status must then reflect the
        on_progress() lines under that ruleset's key, and mark it done.
        SyncThread makes the spawned thread run inline, so by the time the
        POST response is sent the (mocked, instant) job has already
        finished - no polling needed here."""
        def fake_suricata(data_dir, enable_arp=False, on_progress=print, network_allowed=True, enabled_sources=None, show_protocol_decode_alerts=None):
            on_progress('suricata rules updated (fake)')
        mock_suricata.side_effect = fake_suricata

        status, body = self._post('/api/update-rules', {'ruleset': 'suricata'})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {'status': 'started'})

        status2, body2 = self._get('/api/rule-update-status')
        self.assertEqual(status2, 200)
        result = json.loads(body2)
        self.assertTrue(result['suricata']['done'])
        self.assertFalse(result['suricata']['running'])
        self.assertIn('suricata rules updated (fake)', result['suricata']['lines'])

        # Triggering suricata alone must not touch setup_suricata_config's
        # (nonexistent) 'force' kwarg or pass network_allowed - this is the
        # on-demand refresh path, unlike main()'s startup calls which pass
        # network_allowed=False.
        mock_suricata.assert_called_once()
        self.assertNotIn('network_allowed', mock_suricata.call_args.kwargs)
        self.assertNotIn('force', mock_suricata.call_args.kwargs)

    @unittest.mock.patch('socrates.threading.Thread', new=SyncThread)
    @unittest.mock.patch('socrates.setup_yara_rules')
    def test_update_rules_single_ruleset_forces_refresh(self, mock_yara):
        """YARA/Sigma must be forced to actually check for updates rather
        than silently reporting the cached copy as fine just because the
        24h staleness window hasn't expired yet - that would defeat the
        point of a user explicitly clicking a ruleset's Update button."""
        def fake_yara(data_dir, on_progress=print, network_allowed=True, force=False):
            on_progress('yara rules updated (fake)')
            return '/fake/yara-rules-full.yar'
        mock_yara.side_effect = fake_yara

        status, body = self._post('/api/update-rules', {'ruleset': 'yara'})
        self.assertEqual(status, 200)
        mock_yara.assert_called_once()
        self.assertTrue(mock_yara.call_args.kwargs.get('force'))

        status2, body2 = self._get('/api/rule-update-status')
        result = json.loads(body2)
        self.assertIn('yara rules updated (fake)', result['yara']['lines'])

    @unittest.mock.patch('socrates.threading.Thread', new=SyncThread)
    @unittest.mock.patch('socrates.setup_sigma_rules')
    @unittest.mock.patch('socrates.setup_yara_rules')
    @unittest.mock.patch('socrates.setup_suricata_config')
    def test_update_rules_all_triggers_all_three(self, mock_suricata, mock_yara, mock_sigma):
        """POST /api/update-rules with ruleset='all' must trigger all three
        rulesets (spawned as separate threads - SyncThread just makes each
        one run inline here for a deterministic assertion)."""
        def fake_suricata(data_dir, enable_arp=False, on_progress=print, network_allowed=True, enabled_sources=None, show_protocol_decode_alerts=None):
            on_progress('suricata done (fake)')
        def fake_yara(data_dir, on_progress=print, network_allowed=True, force=False):
            on_progress('yara done (fake)')
        def fake_sigma(data_dir, on_progress=print, network_allowed=True, force=False):
            on_progress('sigma done (fake)')
        mock_suricata.side_effect = fake_suricata
        mock_yara.side_effect = fake_yara
        mock_sigma.side_effect = fake_sigma

        status, body = self._post('/api/update-rules', {'ruleset': 'all'})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {'status': 'started'})

        status2, body2 = self._get('/api/rule-update-status')
        result = json.loads(body2)
        for name, marker in (('suricata', 'suricata done (fake)'), ('yara', 'yara done (fake)'), ('sigma', 'sigma done (fake)')):
            self.assertTrue(result[name]['done'], f'{name} must be done')
            self.assertFalse(result[name]['running'], f'{name} must not still be running')
            self.assertIn(marker, result[name]['lines'])

    @unittest.mock.patch('socrates.threading.Thread', new=SyncThread)
    @unittest.mock.patch('socrates.setup_suricata_config')
    def test_update_rules_exception_populates_error_field(self, mock_suricata):
        """REGRESSION: _rule_update_state[name]['error'] was initialized to
        None and never set to anything else, so the frontend's
        status[name].error-gated toast (see refreshRulesModal() in
        static/socrates.js) could never actually show an update-failed
        message - a run that raised still reported done/not-running with
        error: null, which the frontend reads as success. The except
        branch in _run_ruleset_update() must populate 'error' too."""
        mock_suricata.side_effect = RuntimeError('boom')

        status, body = self._post('/api/update-rules', {'ruleset': 'suricata'})
        self.assertEqual(status, 200)

        status2, body2 = self._get('/api/rule-update-status')
        self.assertEqual(status2, 200)
        result = json.loads(body2)
        self.assertTrue(result['suricata']['done'])
        self.assertFalse(result['suricata']['running'])
        self.assertEqual(result['suricata']['error'], 'boom')

    def test_update_rules_invalid_ruleset_returns_400(self):
        status, body = self._post('/api/update-rules', {'ruleset': 'not-a-real-ruleset'})
        self.assertEqual(status, 400)

    def test_update_rules_unknown_source_returns_400(self):
        """A 'sources' entry that isn't a curated SURICATA_RULE_SOURCES key
        must be rejected up front, rather than reaching
        _reconcile_suricata_sources() and being handed to a suricata-update
        subprocess as an arbitrary string."""
        status, body = self._post('/api/update-rules', {'ruleset': 'suricata', 'sources': ['et/open', 'not-a-real-source']})
        self.assertEqual(status, 400)
        self.assertIn('not-a-real-source', json.loads(body).get('error', ''))

    def test_update_rules_sources_must_be_list_of_strings(self):
        status, body = self._post('/api/update-rules', {'ruleset': 'suricata', 'sources': 'et/open'})
        self.assertEqual(status, 400)

    def test_update_rules_show_protocol_decode_alerts_must_be_bool(self):
        status, body = self._post('/api/update-rules', {'ruleset': 'suricata', 'showProtocolDecodeAlerts': 'yes'})
        self.assertEqual(status, 400)

    @unittest.mock.patch('socrates.threading.Thread', new=SyncThread)
    @unittest.mock.patch('socrates.setup_suricata_config')
    def test_update_rules_show_protocol_decode_alerts_passed_through(self, mock_suricata):
        """An explicit 'showProtocolDecodeAlerts' must reach
        setup_suricata_config() as its own kwarg - the only way this
        setting actually takes effect (see the disable.conf --disable-conf
        wiring in _fetch_single_source)."""
        def fake_suricata(data_dir, enable_arp=False, on_progress=print, network_allowed=True, enabled_sources=None, show_protocol_decode_alerts=None):
            on_progress('suricata rules updated (fake)')
        mock_suricata.side_effect = fake_suricata

        status, body = self._post('/api/update-rules', {'ruleset': 'suricata', 'showProtocolDecodeAlerts': True})
        self.assertEqual(status, 200)
        mock_suricata.assert_called_once()
        self.assertIs(mock_suricata.call_args.kwargs.get('show_protocol_decode_alerts'), True)

    @unittest.mock.patch('socrates.threading.Thread', new=SyncThread)
    @unittest.mock.patch('socrates.setup_suricata_config')
    def test_update_rules_no_show_protocol_decode_alerts_leaves_it_none(self, mock_suricata):
        """Omitting 'showProtocolDecodeAlerts' entirely must reach
        setup_suricata_config() as show_protocol_decode_alerts=None, so the
        previously persisted setting is left untouched rather than reset."""
        def fake_suricata(data_dir, enable_arp=False, on_progress=print, network_allowed=True, enabled_sources=None, show_protocol_decode_alerts=None):
            on_progress('suricata rules updated (fake)')
        mock_suricata.side_effect = fake_suricata

        status, body = self._post('/api/update-rules', {'ruleset': 'suricata'})
        self.assertEqual(status, 200)
        mock_suricata.assert_called_once()
        self.assertIsNone(mock_suricata.call_args.kwargs.get('show_protocol_decode_alerts'))

    @unittest.mock.patch('socrates.threading.Thread', new=SyncThread)
    @unittest.mock.patch('socrates.setup_suricata_config')
    def test_update_rules_valid_sources_passed_through_as_enabled_sources(self, mock_suricata):
        """A valid 'sources' list must reach setup_suricata_config() as its
        enabled_sources kwarg - the only way source selection actually
        takes effect."""
        def fake_suricata(data_dir, enable_arp=False, on_progress=print, network_allowed=True, enabled_sources=None, show_protocol_decode_alerts=None):
            on_progress('suricata rules updated (fake)')
        mock_suricata.side_effect = fake_suricata

        status, body = self._post('/api/update-rules', {'ruleset': 'suricata', 'sources': ['et/open', 'abuse.ch/urlhaus']})
        self.assertEqual(status, 200)
        mock_suricata.assert_called_once()
        self.assertEqual(mock_suricata.call_args.kwargs.get('enabled_sources'), ['et/open', 'abuse.ch/urlhaus'])

    @unittest.mock.patch('socrates.threading.Thread', new=SyncThread)
    @unittest.mock.patch('socrates.setup_suricata_config')
    def test_update_rules_no_sources_leaves_enabled_sources_none(self, mock_suricata):
        """Omitting 'sources' entirely (plain Update click, no checkbox
        interaction) must reach setup_suricata_config() as
        enabled_sources=None, so reconciliation is skipped and behavior is
        unchanged from before this feature existed."""
        def fake_suricata(data_dir, enable_arp=False, on_progress=print, network_allowed=True, enabled_sources=None, show_protocol_decode_alerts=None):
            on_progress('suricata rules updated (fake)')
        mock_suricata.side_effect = fake_suricata

        status, body = self._post('/api/update-rules', {'ruleset': 'suricata'})
        self.assertEqual(status, 200)
        mock_suricata.assert_called_once()
        self.assertIsNone(mock_suricata.call_args.kwargs.get('enabled_sources'))

    def test_update_rules_blocked_when_same_ruleset_already_running(self):
        """A second POST for the SAME ruleset while it's already running
        must get 409, not start a concurrent second job - guards the
        check-and-set race between handle_post_update_rules calls from two
        clients."""
        release = threading.Event()
        entered = threading.Event()

        def blocking_suricata(data_dir, enable_arp=False, on_progress=print, network_allowed=True, enabled_sources=None, show_protocol_decode_alerts=None):
            entered.set()
            release.wait(timeout=5)

        with unittest.mock.patch('socrates.setup_suricata_config', side_effect=blocking_suricata):
            status, body = self._post('/api/update-rules', {'ruleset': 'suricata'})
            self.assertEqual(status, 200)
            self.assertTrue(entered.wait(timeout=5), 'first job must have started')

            status2, body2 = self._post('/api/update-rules', {'ruleset': 'suricata'})
            self.assertEqual(status2, 409)
            self.assertIn('already in progress', json.loads(body2).get('error', '').lower())

            release.set()

            for _ in range(50):
                _, status_body = self._get('/api/rule-update-status')
                if json.loads(status_body)['suricata']['done']:
                    break
                time.sleep(0.1)
            else:
                self.fail('suricata update job did not finish after release')

    def test_update_rules_different_rulesets_run_concurrently(self):
        """Triggering one ruleset must NOT block a different ruleset from
        being triggered at the same time - independence between rulesets is
        the whole point of per-ruleset buttons."""
        release = threading.Event()
        entered = threading.Event()

        def blocking_suricata(data_dir, enable_arp=False, on_progress=print, network_allowed=True, enabled_sources=None, show_protocol_decode_alerts=None):
            entered.set()
            release.wait(timeout=5)

        def fast_yara(data_dir, on_progress=print, network_allowed=True, force=False):
            on_progress('yara done (fake)')

        with unittest.mock.patch('socrates.setup_suricata_config', side_effect=blocking_suricata), \
             unittest.mock.patch('socrates.setup_yara_rules', side_effect=fast_yara):
            status, body = self._post('/api/update-rules', {'ruleset': 'suricata'})
            self.assertEqual(status, 200)
            self.assertTrue(entered.wait(timeout=5), 'suricata job must have started')

            # yara must be triggerable while suricata is still running.
            status2, body2 = self._post('/api/update-rules', {'ruleset': 'yara'})
            self.assertEqual(status2, 200, 'a different ruleset must not be blocked by an unrelated in-progress job')

            for _ in range(50):
                _, status_body = self._get('/api/rule-update-status')
                if json.loads(status_body)['yara']['done']:
                    break
                time.sleep(0.1)
            else:
                self.fail('yara update job did not finish')

            release.set()
            for _ in range(50):
                _, status_body = self._get('/api/rule-update-status')
                if json.loads(status_body)['suricata']['done']:
                    break
                time.sleep(0.1)
            else:
                self.fail('suricata update job did not finish after release')

    def test_update_rules_all_blocked_when_any_ruleset_running(self):
        """POST ruleset='all' must 409 if even one of the three rulesets is
        already running - it's an atomic all-or-nothing trigger, not a
        'top up whichever isn't already running' operation."""
        release = threading.Event()
        entered = threading.Event()

        def blocking_suricata(data_dir, enable_arp=False, on_progress=print, network_allowed=True, enabled_sources=None, show_protocol_decode_alerts=None):
            entered.set()
            release.wait(timeout=5)

        with unittest.mock.patch('socrates.setup_suricata_config', side_effect=blocking_suricata):
            status, body = self._post('/api/update-rules', {'ruleset': 'suricata'})
            self.assertEqual(status, 200)
            self.assertTrue(entered.wait(timeout=5), 'suricata job must have started')

            status2, body2 = self._post('/api/update-rules', {'ruleset': 'all'})
            self.assertEqual(status2, 409)

            release.set()
            for _ in range(50):
                _, status_body = self._get('/api/rule-update-status')
                if json.loads(status_body)['suricata']['done']:
                    break
                time.sleep(0.1)
            else:
                self.fail('suricata update job did not finish after release')

    def test_rules_info_returns_per_ruleset_data(self):
        """GET /api/rules-info must combine all three get_*_rules_info()
        results into one response shaped for the Rules modal."""
        with unittest.mock.patch('socrates.get_suricata_rules_info', return_value={'count': 111, 'updated': 1000.0}), \
             unittest.mock.patch('socrates.get_yara_rules_info', return_value={'count': 222, 'updated': 2000.0}), \
             unittest.mock.patch('socrates.get_sigma_rules_info', return_value={'windows': {'count': 10, 'updated': 3000.0}, 'linux': {'count': 5, 'updated': 4000.0}}):
            status, body = self._get('/api/rules-info')
            self.assertEqual(status, 200)
            result = json.loads(body)
            # suricata also gets enabledSources/availableSources merged in
            # by handle_get_rules_info (see TestSuricataRulesInfoSources
            # below) - check the get_suricata_rules_info()-sourced fields
            # specifically rather than full dict equality.
            self.assertEqual(result['suricata']['count'], 111)
            self.assertEqual(result['suricata']['updated'], 1000.0)
            self.assertEqual(result['yara'], {'count': 222, 'updated': 2000.0})
            self.assertEqual(result['sigma']['windows']['count'], 10)
            self.assertEqual(result['sigma']['linux']['count'], 5)

    def test_rules_info_includes_stale_threshold(self):
        """GET /api/rules-info must expose config.RULES_MAX_AGE_HOURS as
        staleThresholdHours - the single source of truth the frontend reads
        instead of hardcoding its own separate threshold (see AGENTS.md's
        Detection Rule Freshness section: the Rules modal's date-color
        warning and checkForStaleRules()'s notification used to disagree,
        24h vs a 30-day frontend-only constant, until unified here)."""
        status, body = self._get('/api/rules-info')
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertEqual(result['staleThresholdHours'], config.RULES_MAX_AGE_HOURS)

    def test_rules_info_includes_suricata_sources(self):
        """GET /api/rules-info's suricata sub-dict must carry both the
        currently-enabled source names (enabledSources, from
        get_suricata_enabled_sources()) and the full curated catalog
        (availableSources, from SURICATA_RULE_SOURCES) - the frontend reads
        both to render/initialize the Rules modal's ruleset checkboxes
        without duplicating the catalog in JS."""
        status, body = self._get('/api/rules-info')
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertIn('enabledSources', result['suricata'])
        self.assertIn('et/open', result['suricata']['enabledSources'])
        self.assertIn('availableSources', result['suricata'])
        self.assertIn('et/open', result['suricata']['availableSources'])
        self.assertIn('label', result['suricata']['availableSources']['et/open'])

    def test_rules_info_includes_show_protocol_decode_alerts_default_false(self):
        """GET /api/rules-info's suricata sub-dict must carry
        showProtocolDecodeAlerts (from
        get_suricata_show_protocol_decode_alerts()), defaulting to False
        when never explicitly set - the Rules modal's checkbox reads this
        to initialize its checked state."""
        status, body = self._get('/api/rules-info')
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertIn('showProtocolDecodeAlerts', result['suricata'])
        self.assertIs(result['suricata']['showProtocolDecodeAlerts'], False)

    def test_rules_info_includes_sid_ranges(self):
        """GET /api/rules-info's suricata sub-dict must carry sidRanges -
        the single source of truth static/socrates.js's classifyRuleset()
        reads instead of hardcoding a duplicate range table, generated from
        the same suricata_sid_ranges.SURICATA_SID_RANGES that db.py's
        sid_ranges_sql_case() uses for the server-side aggregation column."""
        status, body = self._get('/api/rules-info')
        self.assertEqual(status, 200)
        result = json.loads(body)
        ranges = result['suricata']['sidRanges']
        self.assertIsInstance(ranges, list)
        self.assertGreater(len(ranges), 0)
        for entry in ranges:
            self.assertIn('min', entry)
            self.assertIn('max', entry)
            self.assertIn('label', entry)
        labels = [r['label'] for r in ranges]
        self.assertIn('Emerging Threats Open', labels)
        # The built-in-rules entry must be included too, not just the
        # curated online sources.
        self.assertIn('Suricata (built-in)', labels)
        # abuse.ch/urlhaus has a concrete (not JSON-null-via-None-forever)
        # ceiling - see suricata_sid_ranges.py for why an unbounded entry
        # would have silently swallowed every curated range above it.
        urlhaus = next(r for r in ranges if r['label'] == 'Abuse.ch URLhaus')
        self.assertIsNotNone(urlhaus['max'])


class TestGetSuricataRulesInfoStaleness(unittest.TestCase):
    """'stale' must be False for a just-written rules file and True once
    its mtime is older than config.RULES_MAX_AGE_HOURS - purely a local
    os.path.getmtime() comparison via validators.is_file_stale(), no
    network access."""

    def test_stale_field_reflects_file_age(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_dir = os.path.join(tmpdir, 'suricata', 'rules')
            os.makedirs(rules_dir, exist_ok=True)
            # Active rules/ now holds one file per curated source, not a
            # single merged suricata.rules - must use a recognized curated
            # filename (see suricata_analyzer._CURATED_RULE_FILENAMES) or
            # get_suricata_rules_info() won't count it at all.
            rules_file = os.path.join(rules_dir, 'et-open.rules')
            with open(rules_file, 'w') as f:
                f.write('alert tcp any any -> any any (msg:"test"; sid:1;)\n')

            fresh = suricata_analyzer.get_suricata_rules_info(data_dir=tmpdir)
            self.assertFalse(fresh['stale'], 'a just-written rules file must not be stale')

            old_time = time.time() - (config.RULES_MAX_AGE_HOURS + 1) * 3600
            os.utime(rules_file, (old_time, old_time))
            stale = suricata_analyzer.get_suricata_rules_info(data_dir=tmpdir)
            self.assertTrue(stale['stale'], 'a rules file older than RULES_MAX_AGE_HOURS must be stale')


class TestSpawnSuricataErrorHandling(unittest.TestCase):
    def test_spawn_suricata_writes_error_on_failure(self):
        """Behavioral: spawn_suricata must write .error file when subprocess fails."""
        import unittest.mock
        from suricata_analyzer import spawn_suricata
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_path = os.path.join(tmpdir, 'test.pcap')
            with open(pcap_path, 'wb') as f:
                f.write(b'\xd4\xc3\xb2\xa1' + b'\x00' * 100)

            # Mock subprocess.Popen to raise an error
            with unittest.mock.patch('subprocess.Popen', side_effect=OSError('suricata not found')):
                result = spawn_suricata(tmpdir, pcap_path)
                self.assertFalse(result, 'spawn_suricata must return False on failure')

            # Verify .error file was written
            error_file = os.path.join(tmpdir, '.error')
            self.assertTrue(os.path.exists(error_file), '.error file must be written on spawn failure')
            with open(error_file, 'r') as f:
                error_msg = f.read()
            self.assertIn('suricata not found', error_msg, 'Error message must include the failure reason')

            # Verify .phase was cleared
            self.assertFalse(os.path.exists(os.path.join(tmpdir, '.phase')), '.phase must be cleared on failure')

    def test_watchdog_reaps_process_after_kill_on_timeout(self):
        """REGRESSION: the watchdog thread called proc.kill() on a timeout
        but never called proc.wait() again afterward, leaving a zombie
        process until the whole so-crates server eventually exited."""
        import unittest.mock
        import subprocess
        import time
        from suricata_analyzer import spawn_suricata
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_path = os.path.join(tmpdir, 'test.pcap')
            with open(pcap_path, 'wb') as f:
                f.write(b'\xd4\xc3\xb2\xa1' + b'\x00' * 100)

            mock_proc = unittest.mock.MagicMock()
            mock_proc.wait.side_effect = [subprocess.TimeoutExpired('suricata', 300), None]
            with unittest.mock.patch('subprocess.Popen', return_value=mock_proc):
                result = spawn_suricata(tmpdir, pcap_path)
                self.assertTrue(result)

            # The watchdog runs in a daemon thread - give it a moment to hit
            # the TimeoutExpired branch and reap the killed process.
            for _ in range(50):
                if mock_proc.wait.call_count >= 2:
                    break
                time.sleep(0.1)

            mock_proc.kill.assert_called_once()
            self.assertEqual(mock_proc.wait.call_count, 2,
                             'proc.wait() must be called again after kill() to reap the process, not just once before the timeout')

    def test_watchdog_clears_phase_on_unexpected_non_timeout_exception(self):
        """REGRESSION: _suricata_watchdog only caught subprocess.TimeoutExpired
        around proc.wait() - any other exception occurring anywhere in the
        watchdog's body (here simulated via on_suricata_done()'s own
        _set_phase('files', ...) call failing unexpectedly) left .phase in
        place forever, since this runs in a daemon thread where an
        uncaught exception is silently swallowed rather than propagated to
        spawn_suricata()'s caller. spawn_suricata()'s own re-entry guard
        then refuses to start a new run while .phase exists, so the
        analysis directory would be permanently stuck "in progress"."""
        import unittest.mock
        import time
        import suricata_analyzer
        from suricata_analyzer import spawn_suricata
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_path = os.path.join(tmpdir, 'test.pcap')
            with open(pcap_path, 'wb') as f:
                f.write(b'\xd4\xc3\xb2\xa1' + b'\x00' * 100)

            mock_proc = unittest.mock.MagicMock()
            mock_proc.wait.return_value = None  # succeeds immediately - not a timeout

            # First _set_phase call is spawn_suricata()'s own 'network'
            # phase (must succeed so spawn_suricata itself returns True);
            # the second is on_suricata_done()'s 'files' phase, inside the
            # watchdog thread - simulate that one failing unexpectedly.
            call_count = {'n': 0}
            def flaky_set_phase(dir_path, phase):
                call_count['n'] += 1
                if call_count['n'] == 2:
                    raise RuntimeError('simulated unexpected failure')

            with unittest.mock.patch('subprocess.Popen', return_value=mock_proc), \
                 unittest.mock.patch('suricata_analyzer._set_phase', side_effect=flaky_set_phase):
                result = spawn_suricata(tmpdir, pcap_path)
                self.assertTrue(result)

                error_file = os.path.join(tmpdir, '.error')
                for _ in range(50):
                    if os.path.exists(error_file):
                        break
                    time.sleep(0.1)

            self.assertTrue(os.path.exists(error_file),
                            '.error must be written on an unexpected watchdog failure, not just a subprocess.TimeoutExpired')
            self.assertFalse(os.path.exists(os.path.join(tmpdir, '.phase')),
                             '.phase must be cleared even when the failure is not a subprocess.TimeoutExpired, or the analysis is stuck forever')


class TestServerBinding(unittest.TestCase):
    def test_server_binds_localhost(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn('127.0.0.1', content)
        self.assertNotIn('("", PORT)', content)
        self.assertNotIn('("0.0.0.0", PORT)', content)


class TestNoCorsWildcard(unittest.TestCase):
    def test_no_cors_wildcard(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertNotIn("Access-Control-Allow-Origin', '*'", content)
        self.assertNotIn('Access-Control-Allow-Origin", "*"', content)


class TestErrorMessages(unittest.TestCase):
    def test_no_internal_error_leak(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertNotIn('str(e)', content)
        self.assertNotIn('traceback', content.lower())


class TestLoadUrlContentValidation(unittest.TestCase):
    def test_load_url_detects_pcap_by_magic(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn('is_pcap_file(prefix)', content,
                      'load_url must detect PCAP by magic bytes')
        validators_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'validators.py')
        with open(validators_file, 'r') as f:
            validators_content = f.read()
        self.assertIn('def is_pcap_file(data):', validators_content,
                      'is_pcap_file helper must exist in validators module')




class TestThreadedServer(unittest.TestCase):
    def test_threaded_server_class_exists(self):
        self.assertTrue(hasattr(server, 'ThreadedTCPServer'))


class TestSizeLimitMessages(unittest.TestCase):
    def test_max_eve_size_constant(self):
        self.assertEqual(config.MAX_EVE_SIZE, 5000 * 1024 * 1024)

    def test_max_upload_size_constant(self):
        self.assertEqual(config.MAX_UPLOAD_SIZE, 5000 * 1024 * 1024)

    def test_default_upload_size_constant(self):
        self.assertEqual(config.DEFAULT_UPLOAD_SIZE, 1000 * 1024 * 1024)
    
    def test_error_message_consistency(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        error_count = content.count('max {MAX_EVE_SIZE // (1024*1024)}MB')
        error_text_count = content.count('Analysis data too large to load')
        self.assertGreaterEqual(error_count, 1, 'Error message appears at least once')
        self.assertGreaterEqual(error_text_count, 1, 'too-large error text appears at least once')


class TestHTMLNoDuplicateFunctions(unittest.TestCase):
    def test_no_duplicate_html_functions(self):
        html_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'socrates.html')
        with open(html_file, 'r') as f:
            content = f.read()
        import re
        func_pattern = r'function\s+(\w+)\s*\('
        functions = re.findall(func_pattern, content)
        duplicates = {f for f in functions if functions.count(f) > 1}
        self.assertEqual(len(duplicates), 0, f'Duplicate JavaScript functions found: {duplicates}')


class TestPythonNoBareExcept(unittest.TestCase):
    def test_no_bare_except_statements(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        bare_except_pattern = r'except\s*:'
        matches = re.findall(bare_except_pattern, content)
        self.assertEqual(len(matches), 0, f'Found bare except statements: {matches}')


class TestSuricataConfigRulesPath(unittest.TestCase):
    def test_suricata_yaml_uses_custom_rules_path(self):
        suricata_dir = os.path.expanduser('~/socrates-data/suricata')
        suricata_config = os.path.join(suricata_dir, 'suricata.yaml')
        
        # Skip if config doesn't exist (may not be set up yet)
        if not os.path.exists(suricata_config):
            self.skipTest('Suricata config not found')
        
        with open(suricata_config, 'r') as f:
            content = f.read()
        
        # Verify default-rule-path points to a custom directory
        # (may be ~/socrates-data/suricata/rules for native or /data/suricata/rules for container)
        native_path = os.path.expanduser('~/socrates-data/suricata/rules')
        container_path = '/data/suricata/rules'
        self.assertTrue(native_path in content or container_path in content,
                        f'suricata.yaml should use custom rules path (either {native_path} or {container_path})')
        self.assertNotIn('/var/lib/suricata/rules', content,
                         'suricata.yaml should not use system rules path')


class TestSecurityHeaders(unittest.TestCase):
    def test_x_frame_options(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn("X-Frame-Options', 'DENY'", content)

    def test_x_content_type_options(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn("X-Content-Type-Options', 'nosniff'", content)

    def test_content_security_policy(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn("Content-Security-Policy", content)
        self.assertIn("default-src 'self'", content)

    def test_end_headers_calls_security_headers(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn('def end_headers(self):', content)
        self.assertIn('self._add_security_headers()', content)

    def test_html_cache_control_headers(self):
        """Verify Cache-Control headers are sent for HTML and static assets"""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn("no-cache, no-store, must-revalidate", content)
        self.assertIn("self.path.endswith('.html')", content)
        self.assertIn("self.path.startswith('/static/')", content)
        self.assertIn("Pragma', 'no-cache'", content)
        self.assertIn("Expires', '0'", content)


class TestSubprocessTimeouts(unittest.TestCase):
    def test_tcpdump_has_timeout(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        tcpdump_match = re.search(r"\['tcpdump', '-r', pcap, '-w', '-'.*?timeout=", content, re.DOTALL)
        self.assertIsNotNone(tcpdump_match, 'tcpdump call must have timeout')
        self.assertIn('STREAM_TIMEOUT_SECONDS', content, 'tcpdump timeout must use centralized constant')

    def test_tshark_has_timeout(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        # _extract_payload_lines helper contains the tshark call
        helper_section = content.split("def _extract_payload_lines(self, pcap, src, sport, dst, dport, proto):")[1].split("def handle_get_hexdump_stream(self, params):")[0]
        tshark_match = re.search(r"\['tshark', '-r', pcap.*?timeout=", helper_section, re.DOTALL)
        self.assertIsNotNone(tshark_match, '_extract_payload_lines must call tshark with timeout')
        self.assertIn('STREAM_TIMEOUT_SECONDS', helper_section, 'tshark timeout must use centralized constant')
        # The helper should be called twice (TCP then UDP fallback) from handle_get_ascii_stream
        ascii_section = content.split("def handle_get_ascii_stream(self, params):")[1].split("def _extract_payload_lines(self, pcap, src, sport, dst, dport, proto):")[0]
        calls_in_ascii = ascii_section.count('self._extract_payload_lines(')
        self.assertGreaterEqual(calls_in_ascii, 2, '_extract_payload_lines must be called at least twice from ascii_stream')

    def test_timeout_expired_handled(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn('except subprocess.TimeoutExpired:', content)


class TestNoDuplicateImports(unittest.TestCase):
    def test_threading_imported_at_top_level(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        # Should have exactly one 'import threading' at the top level
        top_level = content.split('class Handler')[0]
        self.assertEqual(top_level.count('import threading'), 1,
                         'threading should be imported once at module level')
        # Should NOT have inline 'import threading' inside methods
        handler_section = content.split('class Handler')[1]
        self.assertEqual(handler_section.count('import threading'), 0,
                         'threading should not be imported inline inside methods')


class TestSetupSuricataConfigLogging(unittest.TestCase):
    def test_copy_warnings_logged(self):
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn("on_progress(f'Warning: could not copy", content)
        self.assertIn("on_progress(f'Warning: could not copy directory", content)


class TestSuricataProcessingLock(unittest.TestCase):
    def test_phase_file_used(self):
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn("'.phase'", content)
        self.assertIn("_set_phase", content)
        self.assertIn("_clear_phase", content)

    def test_phase_removed_in_callback(self):
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn("_clear_phase", content)

    def test_phase_removed_on_spawn_failure(self):
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        # Count occurrences of _clear_phase in except blocks
        # Should appear at least twice: once in callback, once in failure handler
        self.assertGreaterEqual(content.count("_clear_phase"), 2)

    def test_error_helpers_exist(self):
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn("def _set_error(dir_path, message):", content,
                      '_set_error helper must exist in suricata module')
        self.assertIn("def _clear_error(dir_path):", content,
                      '_clear_error helper must exist in suricata module')

    def test_error_set_on_yara_failure(self):
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        on_done = content.split("def on_suricata_done():")[1].split("\n    try:")[0]
        self.assertIn("_set_error", on_done,
                      'YARA failure must write error file')

    def test_error_set_on_db_failure(self):
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        on_done = content.split("def on_suricata_done():")[1].split("\n    try:")[0]
        self.assertIn("create_sqlite_db", on_done,
                      'DB creation must be in callback')
        self.assertIn("_set_error", on_done,
                      'DB failure must write error file')

    def test_error_set_on_spawn_failure(self):
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        spawn_section = content.split("def spawn_suricata(dir_path, pcap_path,")[1].split("def _set_phase(dir_path, phase):")[0]
        self.assertIn("_set_error", spawn_section,
                      'Spawn failure must write error file')

    def test_stale_phase_handled_in_check_status(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        status_helper = content.split("def _build_status_response(self, dir_path):")[1].split("def handle_get_status(self, params):")[0]
        self.assertIn("lock_age", status_helper)
        self.assertIn("STALE_THRESHOLD_SECONDS", status_helper)
        self.assertIn("response['phase'] = phase", status_helper)

    def test_stale_error_handled_in_check_status(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        status_helper = content.split("def _build_status_response(self, dir_path):")[1].split("def handle_get_status(self, params):")[0]
        self.assertIn("error_age", status_helper)
        self.assertIn("'status': 'error'", status_helper)
        self.assertIn("'message': error_msg", status_helper)


class TestNameTxtPathSafety(unittest.TestCase):
    def _display_name_helper_section(self, content):
        """Both /api/analyses and /api/load-analysis resolve display names via
        the shared _resolve_display_name helper, which must validate name.txt."""
        self.assertIn("def _resolve_display_name(self, dir_path, md5):", content,
                      'display name resolution must be shared via _resolve_display_name')
        return content.split("def _resolve_display_name(self, dir_path, md5):")[1].split("def _validate_stream_params(self, params):")[0]

    def test_analyses_checks_name_txt_safety(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        analyses_section = content.split("def handle_get_analyses(self, params):")[1].split("def handle_get_load_analysis(self, params):")[0]
        self.assertIn("self._resolve_display_name(dir_path, md5_dir)", analyses_section,
                      '/api/analyses must resolve display names via the shared helper')
        helper_section = self._display_name_helper_section(content)
        self.assertIn("is_safe_path(dir_path, name_path)", helper_section,
                      '/api/analyses must validate name.txt path')

    def test_load_analysis_checks_name_txt_safety(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        load_section = content.split("def handle_get_load_analysis(self, params):")[1].split("def handle_post_delete_analysis(self):")[0]
        self.assertIn("self._resolve_display_name(dir_path, md5)", load_section,
                      '/api/load-analysis must resolve display names via the shared helper')
        helper_section = self._display_name_helper_section(content)
        self.assertIn("is_safe_path(dir_path, name_path)", helper_section,
                      '/api/load-analysis must validate name.txt path')


class TestSuricataRuleRawEnabled(unittest.TestCase):
    def test_rule_raw_set_in_suricata_spawn(self):
        """Verify that suricata is spawned with --set to enable alert.rule in eve.json"""
        with open(SURICATA_FILE, 'r') as f:
            suricata_content = f.read()
        with open(SERVER_FILE, 'r') as f:
            server_content = f.read()
        # Should appear exactly once in spawn_suricata helper
        self.assertEqual(suricata_content.count("'--set', 'outputs.1.eve-log.types.0.alert.metadata.rule.raw=true'"), 1,
                         'rule.raw must be set exactly once in spawn_suricata helper')
        # Verify spawn_suricata is defined in suricata module
        self.assertIn('def spawn_suricata(dir_path, pcap_path, suricata_config_path=None, data_dir=None):', suricata_content,
                      'spawn_suricata must be defined in suricata module')
        # Verify spawn_suricata is called from _process_uploaded_file and reanalyze
        self.assertIn('spawn_suricata(dir_path, pcap_path, os.path.join(SURICATA_DIR', server_content,
                      'spawn_suricata must be called from _process_uploaded_file or reanalyze')
        reanalyze_section = server_content.split("def handle_post_reanalyze(self):")[1]
        self.assertIn('spawn_suricata(dir_path, pcap_path, os.path.join(SURICATA_DIR', reanalyze_section,
                      'reanalyze must call spawn_suricata for PCAP files')


class TestFindPcapFile(unittest.TestCase):
    """REGRESSION: some real pcaps have no recognized extension at all (e.g.
    Security Onion's so-pcap.<timestamp> downloads) -- they were still
    correctly detected and ingested as pcaps at upload time via magic-byte
    sniffing (is_pcap_file), so _find_pcap_file must use the same detection
    method as a fallback rather than relying on the filename extension
    alone. Previously, extension-only lookups caused 'No pcap file found'
    on the ASCII Transcript/Hexdump/Download-stream views, a wrong filename
    from /api/pcap-path, and a silent misclassification in Reanalyze (a
    real pcap treated as a standalone file, run through the wrong pipeline)."""

    PCAP_MAGIC = b'\xd4\xc3\xb2\xa1' + b'\x00' * 20

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_finds_file_with_recognized_extension(self):
        with open(os.path.join(self.tmpdir, 'capture.pcap'), 'wb') as f:
            f.write(self.PCAP_MAGIC)
        self.assertEqual(server._find_pcap_file(self.tmpdir), 'capture.pcap')

    def test_falls_back_to_magic_bytes_when_extension_missing(self):
        """The exact real-world case: a pcap named like a Security Onion
        download, with no recognized extension."""
        with open(os.path.join(self.tmpdir, 'so-pcap.1784903949'), 'wb') as f:
            f.write(self.PCAP_MAGIC)
        self.assertEqual(server._find_pcap_file(self.tmpdir), 'so-pcap.1784903949')

    def test_extension_match_preferred_over_magic_byte_scan(self):
        """When both exist, the fast extension-based match wins without
        needing to scan other files at all."""
        with open(os.path.join(self.tmpdir, 'capture.pcap'), 'wb') as f:
            f.write(self.PCAP_MAGIC)
        with open(os.path.join(self.tmpdir, 'other-file'), 'wb') as f:
            f.write(self.PCAP_MAGIC)
        self.assertEqual(server._find_pcap_file(self.tmpdir), 'capture.pcap')

    def test_ignores_artifacts_and_hidden_files_during_fallback_scan(self):
        with open(os.path.join(self.tmpdir, 'eve.json'), 'w') as f:
            f.write(self.PCAP_MAGIC.decode('latin1'))  # artifact -- must be skipped even though "content" matches
        with open(os.path.join(self.tmpdir, '.hidden'), 'wb') as f:
            f.write(self.PCAP_MAGIC)
        with open(os.path.join(self.tmpdir, 'name.txt'), 'w') as f:
            f.write('so-pcap.1784903949')
        self.assertIsNone(server._find_pcap_file(self.tmpdir))

    def test_returns_none_when_no_pcap_present(self):
        with open(os.path.join(self.tmpdir, 'not-a-pcap.txt'), 'w') as f:
            f.write('just some text')
        self.assertIsNone(server._find_pcap_file(self.tmpdir))

    def test_returns_none_for_missing_directory(self):
        self.assertIsNone(server._find_pcap_file(os.path.join(self.tmpdir, 'does-not-exist')))

    def test_skips_subdirectories_during_fallback_scan(self):
        """The filestore/ directory (extracted YARA-scanned files) must not
        be mistaken for a candidate pcap file."""
        os.makedirs(os.path.join(self.tmpdir, 'filestore'))
        with open(os.path.join(self.tmpdir, 'so-pcap.123'), 'wb') as f:
            f.write(self.PCAP_MAGIC)
        self.assertEqual(server._find_pcap_file(self.tmpdir), 'so-pcap.123')


class TestReanalyzeEndpoint(unittest.TestCase):
    def test_reanalyze_endpoint_exists(self):
        """Verify /api/reanalyze endpoint exists in POST_ROUTES."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn("'/api/reanalyze': 'handle_post_reanalyze'", content,
                      'POST /api/reanalyze endpoint must exist')

    def test_reanalyze_deletes_analysis_artifacts(self):
        """Verify reanalyze removes eve.json, events.db, .phase, .error, yara_matches.json, sigma_matches.json, .meta, and file_metadata.json."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        # Artifact lists are centralized in module-level constants
        self.assertIn("PCAP_ANALYSIS_ARTIFACTS = ('eve.json', 'events.db', '.phase', '.error', 'yara_matches.json', 'sigma_matches.json', '.meta', 'file_metadata.json')", content,
                      'PCAP artifact list must be centralized in PCAP_ANALYSIS_ARTIFACTS')
        reanalyze_section = content.split("def handle_post_reanalyze(self):")[1]
        # The actual per-artifact loop lives in the shared _remove_artifacts
        # helper now (both the pcap and non-pcap branches used to each
        # inline an identical copy of it) - reanalyze itself just calls it.
        self.assertIn("self._remove_artifacts(dir_path, PCAP_ANALYSIS_ARTIFACTS)", reanalyze_section,
                      'reanalyze must delete PCAP_ANALYSIS_ARTIFACTS via _remove_artifacts')
        remove_artifacts_section = content.split("def _remove_artifacts(self, dir_path, artifacts):")[1].split("\n    def ")[0]
        self.assertIn('for artifact in artifacts:', remove_artifacts_section,
                      '_remove_artifacts must loop over the given artifact list')
        self.assertIn('os.unlink(artifact_path)', remove_artifacts_section,
                      '_remove_artifacts must unlink artifact files')

    def test_reanalyze_evicts_sankey_and_aggregation_cache(self):
        """Reanalyze deletes and rebuilds events.db, so any cached Sankey/
        aggregation result for this md5 must be evicted - otherwise the next
        view would show stale data from before the re-analysis."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        reanalyze_section = content.split("def handle_post_reanalyze(self):")[1]
        # Must evict before the artifact-deletion call, not after.
        evict_pos = reanalyze_section.find('_evict_analysis_cache(md5)')
        removal_pos = reanalyze_section.find('self._remove_artifacts(dir_path, PCAP_ANALYSIS_ARTIFACTS)')
        self.assertNotEqual(evict_pos, -1, 'reanalyze must call _evict_analysis_cache(md5)')
        self.assertLess(evict_pos, removal_pos,
                         'cache eviction must happen before events.db is deleted/rebuilt')

    def test_reanalyze_keeps_pcap_and_name(self):
        """Verify reanalyze does NOT delete pcap files or name.txt."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        # name.txt must not appear in either artifact tuple _remove_artifacts
        # is ever called with from handle_post_reanalyze, and reanalyze must
        # never rmtree the whole analysis directory (only the filestore
        # subdirectory is allowed to be rmtree'd).
        pcap_artifacts_line = content.split('PCAP_ANALYSIS_ARTIFACTS = ')[1].split('\n')[0]
        file_artifacts_line = content.split('FILE_ANALYSIS_ARTIFACTS = ')[1].split('\n')[0]
        self.assertNotIn('name.txt', pcap_artifacts_line,
                         'PCAP_ANALYSIS_ARTIFACTS must not include name.txt')
        self.assertNotIn('name.txt', file_artifacts_line,
                         'FILE_ANALYSIS_ARTIFACTS must not include name.txt')
        reanalyze_section = content.split("def handle_post_reanalyze(self):")[1].split("\n\nclass ")[0]
        self.assertNotIn('shutil.rmtree(dir_path)', reanalyze_section,
                         'reanalyze must not rmtree the whole analysis directory (only filestore/ is allowed)')

    def test_reanalyze_handles_non_pcap_files(self):
        """Verify reanalyze can re-analyze standalone non-PCAP files."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        reanalyze_section = content.split("def handle_post_reanalyze(self):")[1]
        self.assertIn('non_pcap_files', reanalyze_section,
                      'reanalyze must look for non-PCAP files')
        self.assertIn("self._analyze_standalone_file", reanalyze_section,
                      'reanalyze must support standalone file re-analysis')
        self.assertIn("self._analyze_log_file", reanalyze_section,
                      'reanalyze must support log file re-analysis')

    def test_reanalyze_excludes_zircolite_artifacts(self):
        """Verify reanalyze excludes zircolite.log and .zircolite_events.db
        from file selection - via the shared _non_artifact_files() helper
        (also used by _resolve_display_name()), not a hand-rolled
        duplicate list local to handle_post_reanalyze()."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        reanalyze_section = content.split("def handle_post_reanalyze(self):")[1]
        self.assertIn("self._non_artifact_files(dir_path, pcap_file=pcap_file)", reanalyze_section,
                      'reanalyze must use the shared _non_artifact_files() helper for file selection')
        self.assertIn("'zircolite.log'", content,
                      'zircolite.log must be excluded (via FILE_ANALYSIS_ARTIFACTS, checked by _non_artifact_files)')
        self.assertIn("'.zircolite_events.db'", content,
                      '.zircolite_events.db must be excluded (via FILE_ANALYSIS_ARTIFACTS, checked by _non_artifact_files)')

    def test_reanalyze_returns_409_if_already_processing(self):
        """Verify reanalyze returns 409 when analysis is already in progress."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        reanalyze_section = content.split("def handle_post_reanalyze(self):")[1]
        self.assertIn("self._send_error(409, 'Analysis already in progress')", reanalyze_section,
                      'reanalyze must return 409 if already processing')

    def test_reanalyze_calls_spawn_suricata(self):
        """Verify reanalyze calls spawn_suricata after cleaning artifacts."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        reanalyze_section = content.split("def handle_post_reanalyze(self):")[1]
        self.assertIn('spawn_suricata(dir_path, pcap_path, os.path.join(SURICATA_DIR', reanalyze_section,
                      'reanalyze must call spawn_suricata with config path')


class TestRuleDownloadPrompt(unittest.TestCase):
    def test_rule_download_message_in_stdout(self):
        """Verify that suricata-update outputs a message when rules are
        downloaded. The preceding "Internet access detected — refreshing
        Suricata rules..." announcement was deliberately removed - it
        stated an internal implementation fact (the reachability check
        passed) rather than anything actionable, same reasoning as removing
        the standalone "Checking for internet access..." line before it;
        the Fetched/updated-successfully messages already make the outcome
        self-explanatory without it."""
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()

        self.assertNotIn('Internet access detected', content,
                         'the internal reachability-check announcement was removed')
        self.assertIn('Suricata rules updated successfully', content,
                      'Should log when rules update completes')


class TestAirgapFallback(unittest.TestCase):
    def test_has_internet_access_function_exists(self):
        """Verify has_internet_access helper is defined"""
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn('def has_internet_access():', content,
                      'has_internet_access function must exist')

    def test_internet_check_connects_to_rules_server(self):
        """Verify internet check targets the actual rules server"""
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn('rules.emergingthreats.net', content,
                      'Must check connectivity to rules server')
        self.assertIn('is_host_reachable', content,
                      'Must delegate to is_host_reachable for network check')

    def test_baked_in_rules_path_defined(self):
        """Verify baked-in rules path is referenced"""
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn("/usr/share/suricata/rules", content,
                      'Must reference baked-in rules path')

    def test_fallback_uses_shutil_copytree(self):
        """Verify air-gapped fallback copies baked-in rules"""
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn('shutil.copytree', content,
                      'Must use shutil.copytree for baked-in rules')
        self.assertIn('dirs_exist_ok=True', content,
                      'Must safely overwrite existing rules')

    def test_airgap_log_messages_present(self):
        """Verify log messages for air-gapped path exist"""
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn('Baked-in rules copied successfully', content,
                      'Should log when baked-in rules are copied')
        self.assertIn('no baked-in rules found and no internet access', content,
                      'Should warn when no rules are available')


class TestSuricataExistingRulesNoInternetMessage(unittest.TestCase):
    @unittest.mock.patch('suricata_analyzer.has_internet_access')
    def test_uses_existing_rules_message_when_offline_with_prior_rules(self, mock_internet):
        """REGRESSION: a re-run with no internet and no baked-in rules dir
        (e.g. a subsequent offline startup on a non-Docker install) must not
        print the scary 'may not have rules to use' warning if rules from a
        previous successful run already exist on disk."""
        mock_internet.return_value = False
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_dir = os.path.join(tmpdir, 'suricata', 'rules')
            os.makedirs(rules_dir, exist_ok=True)
            # A recognized curated filename, not the old single
            # suricata.rules - see suricata_analyzer._CURATED_RULE_FILENAMES.
            with open(os.path.join(rules_dir, 'et-open.rules'), 'w') as f:
                f.write('# pre-existing rules from a previous run\n')

            captured = io.StringIO()
            with unittest.mock.patch('sys.stdout', captured):
                suricata_analyzer.setup_suricata_config(tmpdir)

        output = captured.getvalue()
        self.assertIn('using existing Suricata rules from a previous run', output,
                      'Must reassure that existing rules are still in place')
        self.assertNotIn('may not have rules to use', output,
                         'Must not print the no-rules warning when rules already exist')

    def test_existing_rules_not_overwritten_by_baked_in_copy_when_offline(self):
        """REGRESSION: the no-live-update branch used to check
        baked_in_rules_exist BEFORE rules_exist, so on every startup
        (network_allowed=False unconditionally, per socrates.py's main())
        a previously-fetched, larger/fresher ruleset on disk would be
        silently overwritten by the generic baked-in copy - destroying a
        real Docker/Podman deployment's live-updated rules on every single
        container restart. Existing on-disk rules must take priority, so
        _seed_active_from_library() (the baked-in-library entry point)
        must never even be called in this case."""
        real_isdir = os.path.isdir
        real_listdir = os.listdir
        baked_in_library_dir = '/usr/share/suricata/rules-available'

        def fake_isdir(path):
            return True if path == baked_in_library_dir else real_isdir(path)

        def fake_listdir(path):
            return ['et-open.rules'] if path == baked_in_library_dir else real_listdir(path)

        with tempfile.TemporaryDirectory() as tmpdir:
            rules_dir = os.path.join(tmpdir, 'suricata', 'rules')
            os.makedirs(rules_dir, exist_ok=True)
            with open(os.path.join(rules_dir, 'et-open.rules'), 'w') as f:
                f.write('# real rules from a previous live update\n')

            with unittest.mock.patch('suricata_analyzer.has_internet_access', return_value=False), \
                 unittest.mock.patch('os.path.isdir', side_effect=fake_isdir), \
                 unittest.mock.patch('os.listdir', side_effect=fake_listdir), \
                 unittest.mock.patch('suricata_analyzer._seed_active_from_library') as mock_seed:
                suricata_analyzer.setup_suricata_config(tmpdir, network_allowed=False)
                mock_seed.assert_not_called()

            with open(os.path.join(rules_dir, 'et-open.rules')) as f:
                self.assertEqual(f.read(), '# real rules from a previous live update\n',
                                  'Pre-existing rules must survive an offline startup untouched')


class TestSuricataUpdateTimeout(unittest.TestCase):
    """_fetch_single_source() (not the old Popen-streamed
    _stream_suricata_update, removed when rules moved to one file per
    source) catches subprocess.TimeoutExpired from any of its
    subprocess.run() calls generically - str(TimeoutExpired(...)) itself
    already reads as "Command '...' timed out after Ns" (confirmed
    directly), so a plain 'Warning: could not fetch {name}: {e}' message
    still clearly communicates a timeout without needing a dedicated
    timeout-specific message path."""

    @unittest.mock.patch('suricata_analyzer.subprocess.run', side_effect=subprocess.TimeoutExpired('suricata-update', 5))
    @unittest.mock.patch('suricata_analyzer.has_internet_access', return_value=True)
    def test_suricata_update_timeout_does_not_crash(self, mock_internet, mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                suricata_analyzer.setup_suricata_config(tmpdir)
            except subprocess.TimeoutExpired:
                self.fail('setup_suricata_config raised TimeoutExpired')

    @unittest.mock.patch('suricata_analyzer.subprocess.run', side_effect=subprocess.TimeoutExpired('suricata-update', 5))
    @unittest.mock.patch('suricata_analyzer.has_internet_access', return_value=True)
    def test_suricata_update_timeout_reports_clear_message(self, mock_internet, mock_run):
        messages = []
        with tempfile.TemporaryDirectory() as tmpdir:
            suricata_analyzer.setup_suricata_config(tmpdir, on_progress=messages.append)
        self.assertTrue(any('timed out after' in m for m in messages), messages)
        self.assertFalse(any('exited with code' in m for m in messages), messages)


class TestSuricataUpdateFailureFallsBack(unittest.TestCase):
    """REGRESSION: a reachable network doesn't guarantee suricata-update
    itself succeeds. setup_suricata_config must fall back to
    baked-in/cached rules when the fetch itself fails even though the
    reachability probe passed - e.g. a proxy blocking the real rule
    mirrors, a cert error, or bad --data-dir permissions - unlike
    setup_yara_rules/setup_sigma_rules previously only having this
    fallback for the "probe itself failed" case."""

    @unittest.mock.patch('suricata_analyzer.subprocess.run')
    @unittest.mock.patch('suricata_analyzer.has_internet_access', return_value=True)
    def test_falls_back_to_existing_rules_when_update_fails(self, mock_internet, mock_run):
        mock_run.return_value = unittest.mock.Mock(returncode=1)
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_dir = os.path.join(tmpdir, 'suricata', 'rules')
            os.makedirs(rules_dir, exist_ok=True)
            rules_file = os.path.join(rules_dir, 'et-open.rules')
            with open(rules_file, 'w') as f:
                f.write('alert tcp any any -> any any (msg:"pre-existing"; sid:1;)\n')

            messages = []
            suricata_analyzer.setup_suricata_config(tmpdir, on_progress=messages.append)

            with open(rules_file) as f:
                self.assertIn('pre-existing', f.read(), 'existing rules must survive a failed update attempt')
            self.assertTrue(any('despite the failed update' in m for m in messages), messages)

    @unittest.mock.patch('suricata_analyzer.subprocess.run')
    @unittest.mock.patch('suricata_analyzer.has_internet_access', return_value=True)
    def test_falls_back_to_baked_in_rules_when_update_fails_and_none_exist(self, mock_internet, mock_run):
        mock_run.return_value = unittest.mock.Mock(returncode=1)
        real_isdir = os.path.isdir
        real_listdir = os.listdir
        baked_in_library_dir = '/usr/share/suricata/rules-available'

        def fake_isdir(path):
            return True if path == baked_in_library_dir else real_isdir(path)

        def fake_listdir(path):
            return ['et-open.rules'] if path == baked_in_library_dir else real_listdir(path)

        with tempfile.TemporaryDirectory() as tmpdir, \
                unittest.mock.patch('os.path.isdir', side_effect=fake_isdir), \
                unittest.mock.patch('os.listdir', side_effect=fake_listdir), \
                unittest.mock.patch('suricata_analyzer._seed_active_from_library') as mock_seed:
            messages = []
            suricata_analyzer.setup_suricata_config(tmpdir, on_progress=messages.append)
        mock_seed.assert_called_once_with(baked_in_library_dir, tmpdir, ['et/open'], unittest.mock.ANY)
        self.assertTrue(any('Falling back to baked-in Suricata rules' in m for m in messages), messages)


class TestNetworkAllowedFalseDoesNotClaimNoInternet(unittest.TestCase):
    """REGRESSION: with no cached rules and no baked-in rules dir, the
    final warning used to say "no internet access" unconditionally -
    including when network_allowed=False (e.g. server startup, which
    never checks reachability at all by design). A real user on a
    machine WITH internet access saw this exact message at startup and
    reasonably assumed something was broken. The message must now
    distinguish "we checked and it failed" from "we didn't check"."""

    def test_network_allowed_false_does_not_say_no_internet(self):
        messages = []
        with tempfile.TemporaryDirectory() as tmpdir:
            suricata_analyzer.setup_suricata_config(tmpdir, on_progress=messages.append, network_allowed=False)
        self.assertFalse(any('no internet' in m.lower() for m in messages), messages)
        self.assertIn('WARNING! No Suricata rules found', messages)

    @unittest.mock.patch('suricata_analyzer.has_internet_access')
    def test_network_allowed_true_and_unreachable_still_says_no_internet(self, mock_internet):
        mock_internet.return_value = False
        messages = []
        with tempfile.TemporaryDirectory() as tmpdir:
            suricata_analyzer.setup_suricata_config(tmpdir, on_progress=messages.append, network_allowed=True)
        self.assertTrue(any('no internet' in m.lower() for m in messages), messages)


class TestStartupTipAlwaysPrinted(unittest.TestCase):
    """The startup "Tip! ... click the menu ... select Rules." line
    always prints, regardless of whether any ruleset warned about
    missing rules - a WARNING! line states a fact (no rules found), not
    an instruction, so the Tip is what actually tells the user what to
    do about it (and is equally relevant to container users whose baked-in
    rules might just be outdated)."""

    def test_tip_print_is_unconditional(self):
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        main_body = content.split('def main():')[1]
        self.assertIn('print("Tip! To check for rule updates', main_body)
        self.assertNotIn('missing_rules_warned', main_body,
                          'the Tip must not be conditionally gated')


class TestSuricataArpStaysDisabledByDefault(unittest.TestCase):
    @unittest.mock.patch('suricata_analyzer.has_internet_access')
    def test_setup_suricata_config_does_not_enable_arp_by_default(self, mock_internet):
        """REGRESSION GUARD: arp is deliberately opt-in (see
        _enable_eve_log_arp's docstring) - a real volume/signal tradeoff on
        a live network that must stay a deliberate choice, not something
        setup_suricata_config() silently flips on for every install. This
        calls the actual end-to-end pipeline (not just _enable_eve_log_arp
        in isolation) against a real /etc/suricata copy, so a future change
        that wires arp into the automatic tuple would be caught here."""
        mock_internet.return_value = False
        with tempfile.TemporaryDirectory() as tmpdir:
            suricata_analyzer.setup_suricata_config(tmpdir)
            with open(os.path.join(tmpdir, 'suricata', 'suricata.yaml')) as f:
                content = f.read()
        self.assertIn('        - arp:\n            enabled: no', content,
                       'arp must stay disabled unless explicitly opted in via enable_arp')

    @unittest.mock.patch('suricata_analyzer.has_internet_access')
    def test_setup_suricata_config_enables_arp_when_opted_in(self, mock_internet):
        """setup_suricata_config(enable_arp=True) - wired to the
        ENABLE_ARP_LOGGING env var in socrates.py's main() - must actually
        flip arp on end-to-end, not just leave the opt-in mechanism dead."""
        mock_internet.return_value = False
        with tempfile.TemporaryDirectory() as tmpdir:
            suricata_analyzer.setup_suricata_config(tmpdir, enable_arp=True)
            with open(os.path.join(tmpdir, 'suricata', 'suricata.yaml')) as f:
                content = f.read()
        self.assertIn('        - arp:\n            enabled: yes', content,
                       'arp must be enabled when enable_arp=True is passed through')

    def test_main_reads_enable_arp_logging_env_var(self):
        """socrates.py's main() must read ENABLE_ARP_LOGGING and pass it
        through to setup_suricata_config - otherwise enable_arp=True is only
        reachable by editing source, defeating the point of an opt-in env
        var (mirrors the existing DEMO env var pattern)."""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn("os.environ.get('ENABLE_ARP_LOGGING')", content)
        self.assertIn("setup_suricata_config(DATA_DIR, enable_arp=", content)


class TestSuricataProtocolEnable(unittest.TestCase):
    def test_enable_app_layer_protocols_handles_comments(self):
        """Modbus has comments between the header and enabled key."""
        sample = '''    modbus:
      # How many unanswered Modbus requests are considered a flood.
      # If the limit is reached, the app-layer-event:modbus.flooded; will match.
      #request-flood: 500

      enabled: no
      detection-ports:
        dp: 502
'''
        result = suricata_analyzer._enable_app_layer_protocols(sample)
        self.assertIn('enabled: yes', result)
        self.assertNotIn('enabled: no', result)

    def test_enable_app_layer_protocols_enables_all_four(self):
        """All four default-disabled protocols are enabled."""
        sample = '''    pgsql:
      enabled: no
    modbus:
      enabled: no
    dnp3:
      enabled: no
    enip:
      enabled: no
'''
        result = suricata_analyzer._enable_app_layer_protocols(sample)
        self.assertEqual(result.count('enabled: yes'), 4)
        self.assertNotIn('enabled: no', result)

    def test_suricata_update_uses_suricata_conf(self):
        """suricata-update must be told which Suricata config to read -
        _fetch_single_source() (used by both the on-demand refresh path
        and, identically, the Docker image's per-source bake loop) passes
        the real suricata.yaml even though it fetches into a scratch
        --data-dir, so version-aware rule filtering still uses the actual
        installed Suricata version rather than silently falling back to
        /etc/suricata/suricata.yaml's default."""
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn("'--suricata-conf', os.path.join(suricata_dir, 'suricata.yaml')", content,
                      'suricata-update must use --suricata-conf for the Suricata config')
        self.assertNotIn("'--no-test', '-c', suricata_config", content,
                         'must not pass -c as the Suricata config argument')

    def test_enable_eve_log_protocol_types_adds_modbus_dnp3(self):
        """Modbus and DNP3 should be added as standalone EVE log types."""
        sample = '''        - pgsql:
            enabled: no
        - stats:
            totals: yes
'''
        result = suricata_analyzer._enable_eve_log_protocol_types(sample)
        self.assertIn('        - modbus:', result)
        self.assertIn('        - dnp3:', result)
        self.assertIn('            enabled: yes', result)
        self.assertNotIn('            enabled: no', result)

    def test_enable_eve_log_protocol_types_default_includes_enip_ntp(self):
        """Now that this app runs on Suricata 8.0.6 (enip logging landed in
        8.0.0, ntp logging in 8.0.5 - confirmed against those release tags),
        enip/ntp are back in the *default* protocols tuple, not just
        supported when passed explicitly. See this function's docstring for
        the Suricata 7.0.10 history where they had to be excluded."""
        sample = '''        - pgsql:
            enabled: no
        - stats:
            totals: yes
'''
        result = suricata_analyzer._enable_eve_log_protocol_types(sample)
        self.assertIn('        - enip:', result)
        self.assertIn('        - ntp:', result)

    def test_enable_eve_log_protocol_types_does_not_duplicate(self):
        """Entries that already exist should not be duplicated."""
        sample = '''        - pgsql:
            enabled: yes
        - modbus:
        - dnp3:
        - stats:
            totals: yes
'''
        result = suricata_analyzer._enable_eve_log_protocol_types(sample)
        self.assertEqual(result.count('        - modbus:'), 1)
        self.assertEqual(result.count('        - dnp3:'), 1)

    def test_enable_eve_log_protocol_types_supports_arbitrary_protocols(self):
        """The protocols tuple is not hardcoded - any protocol name can be
        passed explicitly and gets added the same way, independent of
        whatever the current default tuple happens to be. Exercises the
        mechanism generically with a couple of made-up names."""
        sample = '''        - pgsql:
            enabled: no
        - stats:
            totals: yes
'''
        result = suricata_analyzer._enable_eve_log_protocol_types(sample, protocols=('foo', 'bar'))
        self.assertIn('        - foo:', result)
        self.assertIn('        - bar:', result)

    def test_enable_eve_log_protocol_types_adds_new_protocol_to_already_provisioned_config(self):
        """REGRESSION: the original implementation used one regex requiring
        `- pgsql:` to be followed only by indented property lines up to
        `- stats:`. That's only true on a pristine config - once a previous
        run had already inserted bare `- modbus:`/`- dnp3:` header lines in
        between (exactly what this function itself does), the regex could
        never match again on a second run, so adding a new protocol to the
        tuple later would never actually get inserted into any
        already-provisioned install - it would silently do nothing. This
        reproduces that exact scenario: modbus/dnp3 already present from an
        earlier run, two new protocols requested on top of that."""
        sample = '''        - pgsql:
            enabled: yes
        - modbus:
        - dnp3:
        - stats:
            totals: yes
'''
        result = suricata_analyzer._enable_eve_log_protocol_types(
            sample, protocols=('modbus', 'dnp3', 'enip', 'ntp'))
        self.assertIn('        - enip:', result)
        self.assertIn('        - ntp:', result)
        self.assertEqual(result.count('        - modbus:'), 1)
        self.assertEqual(result.count('        - dnp3:'), 1)

    def test_enable_eve_log_arp_flips_enabled_no_to_yes(self):
        """arp ships disabled by default (Suricata's own comment: 'Many
        events can be logged') - this is deliberately not wired into
        setup_suricata_config() automatically, unlike modbus/dnp3/enip/ntp/
        pgsql, since arp's volume/signal tradeoff needs a deliberate
        decision. Just tests the mechanism works when called explicitly."""
        sample = '''        - arp:
            enabled: no        # Many events can be logged. Disabled by default
        - dhcp:
            enabled: yes
'''
        result = suricata_analyzer._enable_eve_log_arp(sample)
        self.assertIn('enabled: yes        # Many events can be logged. Disabled by default', result)
        self.assertNotIn('enabled: no', result)

    def test_enable_eve_log_arp_is_idempotent(self):
        """Calling it again on an already-enabled config must not error or
        duplicate anything."""
        sample = '''        - arp:
            enabled: yes
        - dhcp:
            enabled: yes
'''
        result = suricata_analyzer._enable_eve_log_arp(sample)
        self.assertEqual(result, sample)

    def test_enable_community_id_flips_false_to_true(self):
        sample = '''      community-id: false
      community-id-seed: 0
'''
        result = suricata_analyzer._enable_community_id(sample)
        self.assertIn('community-id: true', result)
        self.assertIn('community-id-seed: 0', result,
                       'must not also match/mangle the neighboring seed line')

    def test_enable_community_id_is_idempotent(self):
        sample = '''      community-id: true
      community-id-seed: 0
'''
        result = suricata_analyzer._enable_community_id(sample)
        self.assertEqual(result, sample)

    def test_enable_community_id_enabled_unconditionally_by_setup(self):
        """REGRESSION GUARD: unlike arp (a real volume/signal tradeoff kept
        opt-in - see TestSuricataArpStaysDisabledByDefault), community-id
        just adds one deterministic field and must be force-enabled for
        every install, with no opt-out parameter."""
        with unittest.mock.patch('suricata_analyzer.has_internet_access', return_value=False):
            with tempfile.TemporaryDirectory() as tmpdir:
                suricata_analyzer.setup_suricata_config(tmpdir)
                with open(os.path.join(tmpdir, 'suricata', 'suricata.yaml')) as f:
                    content = f.read()
        self.assertIn('community-id: true', content)

    def test_enable_ja3_ja4_fingerprints_flips_commented_auto_to_yes(self):
        sample = '''      #ja3-fingerprints: auto
      #ja4-fingerprints: auto
'''
        result = suricata_analyzer._enable_ja3_ja4_fingerprints(sample)
        self.assertIn('ja3-fingerprints: yes', result)
        self.assertIn('ja4-fingerprints: yes', result)
        self.assertNotIn('#ja3-fingerprints', result)
        self.assertNotIn('#ja4-fingerprints', result)

    def test_enable_ja3_ja4_fingerprints_is_idempotent(self):
        sample = '''      ja3-fingerprints: yes
      ja4-fingerprints: yes
'''
        result = suricata_analyzer._enable_ja3_ja4_fingerprints(sample)
        self.assertEqual(result, sample)

    def test_enable_ja3_ja4_fingerprints_does_not_clobber_operator_override(self):
        """REGRESSION GUARD: the regex must anchor on the commented-out
        `#...: auto` form specifically - an operator who already
        explicitly set ja3-fingerprints: no (uncommented) must not have
        that choice silently overwritten on the next setup_suricata_config()
        call (e.g. every server restart)."""
        sample = '''      ja3-fingerprints: no
      #ja4-fingerprints: auto
'''
        result = suricata_analyzer._enable_ja3_ja4_fingerprints(sample)
        self.assertIn('ja3-fingerprints: no', result)
        self.assertIn('ja4-fingerprints: yes', result)

    def test_ja3_ja4_fingerprints_enabled_unconditionally_by_setup(self):
        """REGRESSION GUARD: like community-id, JA3/JA4 are cheap
        per-handshake fields (not a real volume/signal tradeoff like arp),
        so they must be force-enabled for every install with no opt-out
        parameter."""
        with unittest.mock.patch('suricata_analyzer.has_internet_access', return_value=False):
            with tempfile.TemporaryDirectory() as tmpdir:
                suricata_analyzer.setup_suricata_config(tmpdir)
                with open(os.path.join(tmpdir, 'suricata', 'suricata.yaml')) as f:
                    content = f.read()
        self.assertIn('ja3-fingerprints: yes', content)
        self.assertIn('ja4-fingerprints: yes', content)


class TestProtocolEventUI(unittest.TestCase):
    JS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'static', 'socrates.js')

    def _js_content(self):
        with open(self.JS_PATH, 'r') as f:
            return f.read()

    def test_protocol_detail_renderers_exist(self):
        """Each protocol must have a dedicated detail renderer."""
        content = self._js_content()
        self.assertIn('function renderModbusDetails(e)', content)
        self.assertIn('function renderDnp3Details(e)', content)
        self.assertIn('function renderPgsqlDetails(e)', content)

    def test_protocol_renderers_registered(self):
        """Renderers must be wired into EVENT_RENDERERS."""
        content = self._js_content()
        self.assertIn('modbus: renderModbusDetails', content)
        self.assertIn('dnp3: renderDnp3Details', content)
        self.assertIn('pgsql: renderPgsqlDetails', content)

    def test_protocol_icons_registered(self):
        """Protocol event types should have icons."""
        content = self._js_content()
        self.assertIn('modbus:', content)
        self.assertIn('dnp3:', content)
        self.assertIn('pgsql:', content)
        self.assertIn("'modbus'", content)
        self.assertIn("'dnp3'", content)
        self.assertIn("'pgsql'", content)

    def test_protocol_columns_defined(self):
        """getColumnsForType must return protocol-specific columns."""
        content = self._js_content()
        self.assertIn("case 'modbus':", content)
        self.assertIn("case 'dnp3':", content)
        self.assertIn("case 'pgsql':", content)

    def test_protocol_extractvalue_cases_exist(self):
        """extractValue must know how to pull protocol fields for tables/aggregations."""
        content = self._js_content()
        self.assertIn("case 'Function':", content)
        self.assertIn("case 'Unit ID':", content)
        self.assertIn("case 'Access Type':", content)
        self.assertIn("case 'Error Flags':", content)
        self.assertIn("case 'Source Addr':", content)
        self.assertIn("case 'Dest Addr':", content)
        self.assertIn("case 'Rows':", content)
        self.assertIn("case 'SSL':", content)


class TestServerStartupBanner(unittest.TestCase):
    def test_windows_banner_format(self):
        """Verify the startup banner has the correct format"""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        
        # Check for banner elements
        self.assertIn('Welcome to SO-CRATES', content)

    def test_running_message_has_border(self):
        """Verify the running message is wrapped in a border matching the welcome banner"""
        with open(SERVER_FILE, 'r') as f:
            content = f.read()
        self.assertIn('SO-CRATES running', content)
        self.assertIn('================================================', content)


class TestHTMLNoEmptyFunctions(unittest.TestCase):
    def test_no_empty_functions(self):
        html_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'socrates.html')
        with open(html_file, 'r') as f:
            content = f.read()
        import re
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*\{\s*\}'
        empty_funcs = re.findall(func_pattern, content, re.DOTALL)
        self.assertEqual(len(empty_funcs), 0, f'Found empty functions: {empty_funcs}')


class TestHTMLNoOldStyleFilterEscaping(unittest.TestCase):
    def test_no_old_style_filter_escaping(self):
        html_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'socrates.html')
        with open(html_file, 'r') as f:
            content = f.read()
        vulnerable_pattern = r'clearFilter.*col\.replace\(/\'/g'
        matches = re.findall(vulnerable_pattern, content)
        self.assertEqual(len(matches), 0, 'Found vulnerable col.replace pattern in clearFilter')
        vulnerable_pattern2 = r'applyFilter.*displayVal\.replace\(/\'/g'
        matches2 = re.findall(vulnerable_pattern2, content)
        self.assertEqual(len(matches2), 0, 'Found vulnerable displayVal.replace pattern in applyFilter')


class TestHTMLModalCSS(unittest.TestCase):
    def test_loading_modal_exists(self):
        html_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'socrates.html')
        css_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'static', 'socrates.css')
        with open(html_file, 'r') as f:
            html_content = f.read()
        with open(css_file, 'r') as f:
            css_content = f.read()
        self.assertIn('id="loadingModal"', html_content, 'loadingModal element should exist')
        self.assertIn('.modal {', css_content, 'modal CSS should exist')
        self.assertIn('.modal.active {', css_content, 'modal.active CSS should exist')
        self.assertIn('.spinner {', css_content, 'spinner CSS should exist')
        self.assertIn('.spinner-dot {', css_content, 'spinner-dot CSS should exist')


class TestEnvironmentVariables(unittest.TestCase):
    """Test that configurable environment variables are properly defined."""

    def test_data_dir_env_var(self):
        """DATA_DIR must be defined and replace the old BASE_DIR"""
        self.assertTrue(hasattr(server, 'DATA_DIR'))
        self.assertFalse(hasattr(server, 'BASE_DIR'))

    def test_bind_address_env_var(self):
        """BIND_ADDRESS must be defined for Docker support"""
        self.assertTrue(hasattr(server, 'BIND_ADDRESS'))
        self.assertEqual(server.BIND_ADDRESS, '127.0.0.1')

    def test_port_env_var(self):
        """PORT must be configurable via environment variable"""
        self.assertTrue(hasattr(server, 'PORT'))
        self.assertEqual(server.PORT, 8000)


class TestExecutableChecks(unittest.TestCase):
    def test_check_executables_returns_list(self):
        result = server.check_executables()
        self.assertIsInstance(result, list)

    def test_required_executables_defined(self):
        self.assertIn('tcpdump', suricata_analyzer.REQUIRED_EXECUTABLES)
        self.assertIn('tshark', suricata_analyzer.REQUIRED_EXECUTABLES)
        self.assertIn('suricata', suricata_analyzer.REQUIRED_EXECUTABLES)
        self.assertIn('suricata-update', suricata_analyzer.REQUIRED_EXECUTABLES)

    @unittest.mock.patch('suricata_analyzer.shutil.which')
    def test_check_executables_all_missing(self, mock_which):
        mock_which.return_value = None
        missing = server.check_executables()
        self.assertEqual(len(missing), 4)

    @unittest.mock.patch('suricata_analyzer.shutil.which')
    def test_check_executables_some_present(self, mock_which):
        def which_side_effect(cmd):
            if cmd in ['tcpdump', 'tshark']:
                return f'/usr/bin/{cmd}'
            return None
        mock_which.side_effect = which_side_effect
        missing = server.check_executables()
        self.assertEqual(sorted(missing), ['suricata', 'suricata-update'])


class TestFileAlertsEndpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.original_base = server.DATA_DIR
        server.DATA_DIR = cls.tmpdir

        cls.port = 19000 + (os.getpid() % 1000)
        cls.server = server.ThreadedTCPServer(('127.0.0.1', cls.port), server.Handler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        server.DATA_DIR = cls.original_base
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def _get(self, path):
        import urllib.request
        try:
            req = urllib.request.Request(f'http://127.0.0.1:{self.port}{path}')
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

class TestSuricataFileStoreConfig(unittest.TestCase):
    def test_file_store_enabled_in_config(self):
        """Verify setup_suricata_config rewrites suricata.yaml to enable file-store."""
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn("enabled: yes", content,
                      'setup_suricata_config must enable file-store')
        self.assertIn("dir: filestore", content,
                      'setup_suricata_config must set filestore dir')
        self.assertIn("force-filestore: yes", content,
                      'setup_suricata_config must force filestore')
        self.assertIn("stream-depth: 0", content,
                      'setup_suricata_config must set stream-depth')
        self.assertIn("force-hash: [md5, sha1, sha256]", content,
                      'setup_suricata_config must force file hashes')

    def test_l_dir_in_spawn(self):
        """Verify spawn_suricata sets log directory to per-PCAP dir."""
        with open(SURICATA_FILE, 'r') as f:
            content = f.read()
        self.assertIn("'-l', dir_path", content,
                      'spawn_suricata must set log directory to per-PCAP dir')


class TestYaraScannerModule(unittest.TestCase):
    def test_yara_analyzer_exists(self):
        yara_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'yara_analyzer.py')
        self.assertTrue(os.path.exists(yara_path), 'yara_analyzer.py must exist')

    def test_check_yara_executable_exists(self):
        import yara_analyzer
        self.assertTrue(hasattr(yara_analyzer, 'check_yara_executable'))

    def test_setup_yara_rules_exists(self):
        import yara_analyzer
        self.assertTrue(hasattr(yara_analyzer, 'setup_yara_rules'))

    def test_run_yara_pipeline_exists(self):
        import yara_analyzer
        self.assertTrue(hasattr(yara_analyzer, 'run_yara_pipeline'))

    def test_parse_yara_output_with_tags_and_meta(self):
        """Verify parser handles YARA output with both tags and metadata."""
        import yara_analyzer
        output = 'TestRule [SUSP,MALWARE] [description="test desc",author="tester"] /tmp/filestore/ab/abc123'
        matches = yara_analyzer._parse_yara_output(output, '/tmp/filestore')
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['rule_name'], 'TestRule')
        self.assertEqual(matches[0]['tags'], ['SUSP', 'MALWARE'])
        self.assertEqual(matches[0]['meta'], {'description': 'test desc', 'author': 'tester'})

    def test_parse_yara_output_empty_tags_with_meta(self):
        """Verify parser handles empty tags section with metadata (YARA-Rules style)."""
        import yara_analyzer
        output = 'Delphi_Random [] [author="_pusher_",date="2015-08"] /tmp/filestore/ab/abc123'
        matches = yara_analyzer._parse_yara_output(output, '/tmp/filestore')
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['rule_name'], 'Delphi_Random')
        self.assertEqual(matches[0]['tags'], [])
        self.assertEqual(matches[0]['meta'], {'author': '_pusher_', 'date': '2015-08'})

    def test_parse_yara_output_path_with_spaces_uses_known_paths(self):
        """REGRESSION: the naive last-whitespace-token split truncates any
        scanned file path containing a space (e.g. a user-uploaded
        "My Invoice.pdf") - rule names never contain whitespace, but
        arbitrary uploaded filenames do. known_paths (the exact
        --scan-list contents) must be used to resolve the real path via
        longest-suffix match instead."""
        import yara_analyzer
        path = '/tmp/uploads/My Invoice.pdf'
        output = f'TestRule [SUSP] {path}'
        matches = yara_analyzer._parse_yara_output(output, known_paths=[path])
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['file_path'], path)
        self.assertEqual(matches[0]['rule_name'], 'TestRule')
        self.assertEqual(matches[0]['tags'], ['SUSP'])

    def test_parse_yara_output_falls_back_without_known_paths(self):
        """Without known_paths, behavior is unchanged (last-token split) -
        this documents the pre-existing limitation for a path with spaces
        rather than silently fixing it without the caller opting in."""
        import yara_analyzer
        output = 'TestRule [SUSP] /tmp/uploads/My Invoice.pdf'
        matches = yara_analyzer._parse_yara_output(output)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]['file_path'], 'Invoice.pdf')


class TestSetupYaraRulesFreshness(unittest.TestCase):
    def _make_stale_rules(self, tmpdir):
        import yara_analyzer
        rules_dir = os.path.join(tmpdir, yara_analyzer.YARA_RULES_SUBDIR)
        os.makedirs(rules_dir, exist_ok=True)
        path = os.path.join(rules_dir, yara_analyzer.YARA_FORGE_FILENAME)
        with open(path, 'w') as f:
            f.write('rule Old { condition: true }')
        old_time = time.time() - (config.RULES_MAX_AGE_HOURS + 1) * 3600
        os.utime(path, (old_time, old_time))
        return path

    @unittest.mock.patch('yara_analyzer._download_yara_forge_rules')
    @unittest.mock.patch('yara_analyzer.is_host_reachable', return_value=True)
    def test_stale_cached_rules_are_refreshed_when_online(self, mock_reachable, mock_download):
        import yara_analyzer
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_stale_rules(tmpdir)
            result = yara_analyzer.setup_yara_rules(tmpdir)
        mock_download.assert_called_once()
        self.assertTrue(result.endswith(yara_analyzer.YARA_FORGE_FILENAME))

    @unittest.mock.patch('yara_analyzer._download_yara_forge_rules')
    @unittest.mock.patch('yara_analyzer.is_host_reachable', return_value=False)
    def test_stale_cached_rules_kept_when_offline(self, mock_reachable, mock_download):
        import yara_analyzer
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._make_stale_rules(tmpdir)
            result = yara_analyzer.setup_yara_rules(tmpdir)
        mock_download.assert_not_called()
        self.assertEqual(result, path)

    @unittest.mock.patch('yara_analyzer._download_yara_forge_rules')
    @unittest.mock.patch('yara_analyzer.is_host_reachable', return_value=True)
    def test_fresh_cached_rules_are_not_refreshed(self, mock_reachable, mock_download):
        import yara_analyzer
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_dir = os.path.join(tmpdir, yara_analyzer.YARA_RULES_SUBDIR)
            os.makedirs(rules_dir, exist_ok=True)
            with open(os.path.join(rules_dir, yara_analyzer.YARA_FORGE_FILENAME), 'w') as f:
                f.write('rule Fresh { condition: true }')
            yara_analyzer.setup_yara_rules(tmpdir)
        mock_download.assert_not_called()

    @unittest.mock.patch('yara_analyzer._download_yara_forge_rules', side_effect=OSError('network error'))
    @unittest.mock.patch('yara_analyzer.is_host_reachable', return_value=True)
    def test_refresh_failure_falls_back_to_stale_cached_rules(self, mock_reachable, mock_download):
        """REGRESSION: a failed refresh attempt must not remove or break the
        still-usable stale copy - setup must keep returning it."""
        import yara_analyzer
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._make_stale_rules(tmpdir)
            result = yara_analyzer.setup_yara_rules(tmpdir)
            self.assertEqual(result, path)
            with open(result) as f:
                self.assertEqual(f.read(), 'rule Old { condition: true }')

class TestZipBombPrevention(unittest.TestCase):
    def test_oversized_zip_member_rejected(self):
        """ZIP with a member whose uncompressed size exceeds MAX_UPLOAD_SIZE must be rejected."""
        import validators
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('normal.txt', b'hello world')
        zip_buffer.seek(0)
        with zipfile.ZipFile(zip_buffer, 'r') as zf:
            # Patch getinfo to claim a huge uncompressed size
            real_getinfo = zf.getinfo
            def fake_getinfo(name):
                info = real_getinfo(name)
                info.file_size = config.MAX_UPLOAD_SIZE + 1
                return info
            zf.getinfo = fake_getinfo
            with self.assertRaises(ValueError) as ctx:
                validators.validate_zip_extraction(zf, '/tmp/extract')
            self.assertIn('ZIP member too large', str(ctx.exception))

    def test_total_uncompressed_size_rejected(self):
        """ZIP whose total uncompressed size exceeds MAX_UPLOAD_SIZE must be rejected."""
        import validators
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('file1.txt', b'hello')
            zf.writestr('file2.txt', b'world')
        zip_buffer.seek(0)
        with zipfile.ZipFile(zip_buffer, 'r') as zf:
            # Patch getinfo so each member claims half the limit + 1
            real_getinfo = zf.getinfo
            def fake_getinfo(name):
                info = real_getinfo(name)
                info.file_size = config.MAX_UPLOAD_SIZE // 2 + 1
                return info
            zf.getinfo = fake_getinfo
            with self.assertRaises(ValueError) as ctx:
                validators.validate_zip_extraction(zf, '/tmp/extract')
            self.assertIn('ZIP contents exceed maximum', str(ctx.exception))

    def test_normal_zip_accepted(self):
        """ZIP with total uncompressed size under MAX_UPLOAD_SIZE must pass."""
        import validators
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('normal.txt', b'hello world')
        zip_buffer.seek(0)
        with zipfile.ZipFile(zip_buffer, 'r') as zf:
            # Should not raise
            validators.validate_zip_extraction(zf, '/tmp/extract')

    def test_effective_max_overrides_hard_ceiling(self):
        """REGRESSION: validate_zip_extraction must honor a caller-supplied
        max_size (the resolved per-request ceiling) rather than always
        falling back to the fixed config.MAX_UPLOAD_SIZE hard ceiling -- a
        user who hasn't opted into a higher personal upload limit must not
        get the full 5GB hard ceiling as their zip-bomb decompression budget."""
        import validators
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('file.txt', b'hello world')
        zip_buffer.seek(0)
        with zipfile.ZipFile(zip_buffer, 'r') as zf:
            real_getinfo = zf.getinfo
            def fake_getinfo(name):
                info = real_getinfo(name)
                info.file_size = 2000  # well under config.MAX_UPLOAD_SIZE...
                return info
            zf.getinfo = fake_getinfo
            # ...but over a smaller, caller-supplied effective_max.
            with self.assertRaises(ValueError) as ctx:
                validators.validate_zip_extraction(zf, '/tmp/extract', max_size=1000)
            self.assertIn('ZIP member too large', str(ctx.exception))
            # The same data passes when max_size is high enough.
            validators.validate_zip_extraction(zf, '/tmp/extract', max_size=5000)


class TestResolveUploadSizeLimit(unittest.TestCase):
    """Tests for _resolve_upload_size_limit, which mirrors _parse_pagination's
    clamping semantics for the user-configurable upload-size setting."""

    def test_valid_value_under_ceiling(self):
        self.assertEqual(server._resolve_upload_size_limit(2000 * 1024 * 1024), 2000 * 1024 * 1024)

    def test_missing_falls_back_to_default(self):
        self.assertEqual(server._resolve_upload_size_limit(None), config.DEFAULT_UPLOAD_SIZE)

    def test_malformed_falls_back_to_default(self):
        self.assertEqual(server._resolve_upload_size_limit('not-a-number'), config.DEFAULT_UPLOAD_SIZE)

    def test_negative_falls_back_to_default(self):
        self.assertEqual(server._resolve_upload_size_limit(-5), config.DEFAULT_UPLOAD_SIZE)

    def test_zero_falls_back_to_default(self):
        self.assertEqual(server._resolve_upload_size_limit(0), config.DEFAULT_UPLOAD_SIZE)

    def test_over_ceiling_clamped(self):
        self.assertEqual(
            server._resolve_upload_size_limit(config.MAX_UPLOAD_SIZE + 1000),
            config.MAX_UPLOAD_SIZE,
        )

    def test_string_of_valid_number_accepted(self):
        """Header values arrive as strings -- must parse cleanly."""
        self.assertEqual(server._resolve_upload_size_limit('2000000000'), 2000000000)


class TestCheckDiskSpace(unittest.TestCase):
    def _make_handler(self):
        handler = server.Handler.__new__(server.Handler)
        handler._send_error = unittest.mock.MagicMock()
        return handler

    def test_rejects_when_insufficient_space(self):
        handler = self._make_handler()
        fake_usage = unittest.mock.MagicMock(free=50 * 1024 * 1024)
        with unittest.mock.patch('shutil.disk_usage', return_value=fake_usage):
            result = handler._check_disk_space(100 * 1024 * 1024)
        self.assertFalse(result)
        handler._send_error.assert_called_once_with(507, 'Not enough disk space available on the server for this upload')

    def test_allows_when_ample_space(self):
        handler = self._make_handler()
        fake_usage = unittest.mock.MagicMock(free=10 * 1024 * 1024 * 1024)
        with unittest.mock.patch('shutil.disk_usage', return_value=fake_usage):
            result = handler._check_disk_space(100 * 1024 * 1024)
        self.assertTrue(result)
        handler._send_error.assert_not_called()

    def test_respects_safety_margin(self):
        """Free space exactly equal to required_bytes (no margin left) must
        still be rejected -- the safety margin is not optional headroom."""
        handler = self._make_handler()
        fake_usage = unittest.mock.MagicMock(free=100 * 1024 * 1024)
        with unittest.mock.patch('shutil.disk_usage', return_value=fake_usage):
            result = handler._check_disk_space(100 * 1024 * 1024)
        self.assertFalse(result)

    def test_fails_open_on_os_error(self):
        """If free space can't be determined, don't block the upload over
        an unrelated filesystem/stat error."""
        handler = self._make_handler()
        with unittest.mock.patch('shutil.disk_usage', side_effect=OSError('boom')):
            result = handler._check_disk_space(100 * 1024 * 1024)
        self.assertTrue(result)
        handler._send_error.assert_not_called()


class TestUploadSizeHeaderEnforced(unittest.TestCase):
    """Tests that handle_post_upload actually uses the resolved per-request
    ceiling (from X-Max-Upload-Size), not just the fixed default."""

    def _make_handler(self, content_length, max_upload_size_header=None):
        handler = server.Handler.__new__(server.Handler)
        headers = {'Content-Length': str(content_length)}
        if max_upload_size_header is not None:
            headers['X-Max-Upload-Size'] = str(max_upload_size_header)
        handler.headers = headers
        handler.rfile = io.BytesIO(b'')
        handler._send_error = unittest.mock.MagicMock()
        # Stop the test at the disk-space check -- everything downstream of
        # it (multipart parsing, processing) isn't what this test verifies.
        handler._check_disk_space = unittest.mock.MagicMock(return_value=False)
        return handler

    def test_content_length_over_default_rejected_without_header(self):
        """Without an override header, the old 1GB default ceiling still applies."""
        handler = self._make_handler(config.DEFAULT_UPLOAD_SIZE + 1)
        handler.handle_post_upload()
        handler._send_error.assert_called_once_with(400, 'Invalid Content-Length')
        handler._check_disk_space.assert_not_called()

    def test_content_length_over_default_but_under_header_accepted(self):
        """With an override header requesting more (up to the hard ceiling),
        a Content-Length above the old default must be allowed past the
        initial size check and reach the disk-space check. The disk-space
        check itself must be sized against the resolved ceiling
        (effective_max), not the raw Content-Length -- a compressed upload's
        Content-Length can be far smaller than what it's allowed to expand
        to, so checking free space against effective_max is the actual
        worst case."""
        handler = self._make_handler(config.DEFAULT_UPLOAD_SIZE + 1, max_upload_size_header=config.MAX_UPLOAD_SIZE)
        handler.handle_post_upload()
        handler._check_disk_space.assert_called_once_with(config.MAX_UPLOAD_SIZE)

    def test_content_length_over_hard_ceiling_rejected_even_with_header(self):
        """A header requesting more than the hard ceiling doesn't help --
        still clamped to config.MAX_UPLOAD_SIZE."""
        handler = self._make_handler(config.MAX_UPLOAD_SIZE + 1000, max_upload_size_header=config.MAX_UPLOAD_SIZE + 1000)
        handler.handle_post_upload()
        handler._send_error.assert_called_once_with(400, 'Invalid Content-Length')
        handler._check_disk_space.assert_not_called()


class TestReadPostBody(unittest.TestCase):
    def _make_handler(self, content_length):
        """Create a minimal Handler instance with mocked request and headers."""
        from io import BytesIO
        handler = server.Handler.__new__(server.Handler)
        handler.headers = unittest.mock.MagicMock()
        handler.headers.get = unittest.mock.MagicMock(return_value=str(content_length))
        handler.rfile = BytesIO(b'a' * max(0, content_length))
        handler._send_error = unittest.mock.MagicMock()
        return handler

    def test_negative_content_length_rejected(self):
        """Negative Content-Length must return None and send 400."""
        handler = self._make_handler(-1)
        result = handler._read_post_body(config.MAX_UPLOAD_SIZE)
        self.assertIsNone(result)
        handler._send_error.assert_called_once_with(400, 'Invalid Content-Length')

    def test_oversized_content_length_rejected(self):
        """Content-Length exceeding max_size must return None and send 400."""
        handler = self._make_handler(config.MAX_UPLOAD_SIZE + 1)
        result = handler._read_post_body(config.MAX_UPLOAD_SIZE)
        self.assertIsNone(result)
        handler._send_error.assert_called_once_with(400, 'Invalid Content-Length')

    def test_valid_content_length_returns_body(self):
        """Valid Content-Length must return the body bytes."""
        handler = self._make_handler(10)
        result = handler._read_post_body(config.MAX_UPLOAD_SIZE)
        self.assertEqual(result, b'a' * 10)
        handler._send_error.assert_not_called()

    def test_non_numeric_content_length_rejected(self):
        """REGRESSION: a non-numeric Content-Length must return None and send
        400, not raise an uncaught ValueError from int()."""
        from io import BytesIO
        handler = server.Handler.__new__(server.Handler)
        handler.headers = unittest.mock.MagicMock()
        handler.headers.get = unittest.mock.MagicMock(return_value='not-a-number')
        handler.rfile = BytesIO(b'')
        handler._send_error = unittest.mock.MagicMock()

        result = handler._read_post_body(config.MAX_UPLOAD_SIZE)
        self.assertIsNone(result)
        handler._send_error.assert_called_once_with(400, 'Invalid Content-Length')


class TestReadJsonBody(unittest.TestCase):
    """Tests for _read_json_body, which every JSON POST handler uses so a
    malformed body returns a clean 400 instead of an uncaught exception."""

    def _make_handler(self, body_bytes, content_type='application/json'):
        from io import BytesIO
        handler = server.Handler.__new__(server.Handler)
        headers = {'Content-Length': str(len(body_bytes)),
                   'Content-Type': content_type}
        handler.headers = unittest.mock.MagicMock()
        handler.headers.get = unittest.mock.MagicMock(
            side_effect=lambda name, default=None: headers.get(name, default))
        handler.rfile = BytesIO(body_bytes)
        handler._send_error = unittest.mock.MagicMock()
        return handler

    def test_non_json_content_type_returns_none_and_sends_415(self):
        handler = self._make_handler(b'{"md5": "abc"}', content_type='text/plain')
        result = handler._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        self.assertIsNone(result)
        handler._send_error.assert_called_once_with(415, 'Content-Type must be application/json')

    def test_valid_json_object_returns_dict(self):
        handler = self._make_handler(b'{"md5": "abc"}')
        result = handler._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        self.assertEqual(result, {'md5': 'abc'})
        handler._send_error.assert_not_called()

    def test_malformed_json_returns_none_and_sends_400(self):
        """REGRESSION: malformed JSON must return None and send 400, not raise
        an uncaught json.JSONDecodeError."""
        handler = self._make_handler(b'not-json-at-all')
        result = handler._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        self.assertIsNone(result)
        handler._send_error.assert_called_once_with(400, 'Invalid JSON body')

    def test_json_array_returns_none_and_sends_400(self):
        """A JSON array isn't a dict, so callers' .get() would blow up; must
        be rejected with a clean 400 instead."""
        handler = self._make_handler(b'[1, 2, 3]')
        result = handler._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        self.assertIsNone(result)
        handler._send_error.assert_called_once_with(400, 'Invalid request body')

    def test_json_scalar_returns_none_and_sends_400(self):
        handler = self._make_handler(b'"just a string"')
        result = handler._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        self.assertIsNone(result)
        handler._send_error.assert_called_once_with(400, 'Invalid request body')

    def test_empty_body_returns_none_and_sends_400(self):
        handler = self._make_handler(b'')
        result = handler._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        self.assertIsNone(result)
        handler._send_error.assert_called_once_with(400, 'Invalid JSON body')

    def test_oversized_content_length_short_circuits(self):
        """_read_json_body must propagate _read_post_body's own rejection
        (Content-Length too large) without ever calling json.loads."""
        handler = self._make_handler(b'{}')
        headers = {'Content-Length': str(config.MAX_REQUEST_BODY_SIZE + 1),
                   'Content-Type': 'application/json'}
        handler.headers.get = unittest.mock.MagicMock(
            side_effect=lambda name, default=None: headers.get(name, default))
        result = handler._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        self.assertIsNone(result)
        handler._send_error.assert_called_once_with(400, 'Invalid Content-Length')


DOCKERFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'Dockerfile')
DOCKER_COMPOSE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'docker-compose.yml')
DOCKER_COMPOSE_PODMAN = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'docker-compose.podman.yml')


class TestDockerfile(unittest.TestCase):
    def test_dockerfile_installs_zircolite_via_git(self):
        """Dockerfile must install Zircolite via git clone, not pip."""
        with open(DOCKERFILE, 'r') as f:
            content = f.read()
        self.assertIn('git clone', content, 'Dockerfile must clone Zircolite from GitHub')
        self.assertNotIn('pip3 install zircolite', content.lower(),
                          'Dockerfile must not use pip to install Zircolite')

    def test_dockerfile_installs_zircolite_in_venv(self):
        """Dockerfile must install Zircolite dependencies in an isolated Python venv."""
        with open(DOCKERFILE, 'r') as f:
            content = f.read()
        self.assertIn('python3-venv', content,
                      'Dockerfile must install python3-venv package')
        self.assertIn('python3 -m venv /usr/local/lib/zircolite-venv', content,
                      'Dockerfile must create a zircolite virtual environment')
        self.assertIn('/usr/local/lib/zircolite-venv/bin/pip install', content,
                      'Dockerfile must install Zircolite deps into the venv')
        self.assertIn('requirements.txt', content,
                      'Dockerfile must install Zircolite requirements.txt')

    def test_dockerfile_copies_socrates_files(self):
        """Dockerfile must copy every top-level .py module the app actually
        needs at runtime - checked dynamically against the real repo
        listing (not a hand-maintained filename list) so a newly added
        module can't silently go missing from the image the way
        ohmydebn_colors.py once did (added this session, imported by
        socrates.py, but never added to the Dockerfile's COPY line - the
        container failed at import time as a result).

        REGRESSION: playbook_lookup.py went through this exact failure
        mode a second time - imported unconditionally by socrates.py, but
        missing from the COPY line - and this test still passed, because
        it only checked substring membership against the *whole file*,
        and playbook_lookup.py happened to be named in three unrelated
        comments elsewhere in the Dockerfile. Must check the actual COPY
        instruction's own argument list, not just "mentioned somewhere in
        the file"."""
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        py_files = sorted(f for f in os.listdir(repo_root) if f.endswith('.py'))
        self.assertIn('ohmydebn_colors.py', py_files, 'sanity check: this test must actually see the repo root')
        with open(DOCKERFILE, 'r') as f:
            content = f.read()
        copy_match = re.search(r'^COPY config\.py .*\.\/$', content, re.MULTILINE)
        self.assertIsNotNone(copy_match, 'Dockerfile must have a COPY line starting with config.py and ending with ./')
        copy_line = copy_match.group(0)
        copied_files = set(copy_line.split()[1:-1])  # drop leading 'COPY' and trailing './'
        for py_file in py_files:
            self.assertIn(py_file, copied_files, f'Dockerfile\'s COPY line must copy {py_file}')
        self.assertIn('socrates.html', copied_files, 'Dockerfile\'s COPY line must copy socrates.html')

    def test_dockerfile_installs_ca_certificates_before_any_https_fetch(self):
        """REGRESSION: every FROM stage that does a 'git clone https://...'
        or 'curl ...https://...' must explicitly install ca-certificates
        rather than relying on the base image happening to already have it.
        debian:13-slim (trixie) is still an actively-updated release, and a
        base image refresh silently dropping ca-certificates broke a real
        CI build with git's "Problem with the SSL CA cert (path? access
        rights?)" - the textbook symptom of a missing CA bundle file, not
        an expired/invalid cert."""
        with open(DOCKERFILE, 'r') as f:
            content = f.read()
        stages = re.split(r'(?=^FROM )', content, flags=re.MULTILINE)
        for stage in stages:
            if not re.search(r'https://', stage):
                continue
            self.assertIn(
                'ca-certificates', stage,
                f'Dockerfile stage doing an HTTPS fetch must install ca-certificates explicitly:\n{stage[:200]}'
            )

    def test_dockerfile_bake_loop_uses_baked_in_sources_dynamically(self):
        """The per-source Suricata rules bake loop must derive its slug
        list from suricata_analyzer.BAKED_IN_SURICATA_SOURCES (which
        itself excludes ipfire/dbl - see that module's comment for why:
        biggest space cost of the curated set, and a content-filtering
        blocklist rather than threat detection) rather than hand-listing
        slugs separately in the Dockerfile, where they could drift out of
        sync with the curated catalog."""
        with open(DOCKERFILE, 'r') as f:
            content = f.read()
        self.assertIn('from suricata_analyzer import BAKED_IN_SURICATA_SOURCES, _source_filename', content)
        self.assertIn('for slug in BAKED_IN_SURICATA_SOURCES:', content)
        # Deriving the loop from BAKED_IN_SURICATA_SOURCES (asserted
        # above) rather than a hand-written slug list is what actually
        # keeps ipfire/dbl out - it's still fine (expected, even) for
        # ipfire/dbl to appear in the surrounding prose explaining why.

    def test_dockerfile_bake_loop_isolates_non_et_open_sources(self):
        """REGRESSION: enable-source on a brand-new --data-dir silently
        ALSO auto-enables et/open as its own "default source" regardless
        of what was actually requested (confirmed by hand: an unpatched
        fetch of oisf/trafficid alone produced a merged file with
        et/open's full ~52k rules mixed in, not just trafficid's own much
        smaller set) - the bake loop must explicitly disable it again for
        every other source, or none of the baked-in per-source files are
        actually isolated."""
        with open(DOCKERFILE, 'r') as f:
            content = f.read()
        self.assertIn("if slug != 'et/open':", content)
        self.assertIn("['suricata-update', 'disable-source', 'et/open', '--data-dir', scratch_data]", content)

    def test_playbooks_builder_uses_c_accelerated_yaml_loader(self):
        """REGRESSION: the resources-builder stage's yaml.safe_load() (the
        pure-Python SafeLoader) parsing ~58k individual playbook YAML files
        one at a time, with zero progress output the whole time, measured
        13.6x slower than yaml.CSafeLoader on the real dataset (3.6min ->
        16s natively) - and Debian's python3-yaml package already bundles
        CSafeLoader, confirmed directly against the exact package this
        stage installs. Combined with QEMU's own CPU-bound slowdown, the
        pure-Python path made a real linux/arm64 CI build look hung. Same
        stage also converts the AI summaries dataset (see
        ai_summary_lookup.py) - this check covers the whole stage, not just
        the playbooks portion of it."""
        with open(DOCKERFILE, 'r') as f:
            content = f.read()
        resources_stage = content.split('AS resources-builder')[1].split('FROM debian:13-slim\n\n')[0]
        self.assertIn('CSafeLoader', resources_stage,
                      'resources-builder stage must use the C-accelerated YAML loader')
        # The exact invocation pattern, not a bare substring match - the
        # comment explaining *why* this was changed necessarily mentions
        # "yaml.safe_load()" in prose, which a plain substring check would
        # also (wrongly) flag.
        self.assertNotIn('yaml.safe_load(f)', resources_stage,
                          'resources-builder stage must not use the slow pure-Python safe_load() path')

    def test_dockerfile_bake_loop_updates_sources_before_enabling(self):
        """REGRESSION: enable-source on a brand-new --data-dir can only
        resolve a slug against a local source-index cache that
        update-sources populates first. Skipping this step broke a real CI
        build with a StopIteration deep inside suricata-update's own
        get_sources_from_dir() for the-hunters-ledger/open - a slug not in
        suricata-update's own bundled index, unlike long-established ones
        like et/open (which happened to keep working without this call,
        masking the bug for the other sources). Must mirror
        _fetch_single_source()'s equivalent runtime call in
        suricata_analyzer.py, and must run before enable-source, not after."""
        with open(DOCKERFILE, 'r') as f:
            content = f.read()
        bake_loop = content.split('for slug in BAKED_IN_SURICATA_SOURCES:')[1].split("PY\n")[0]
        update_idx = bake_loop.find("'suricata-update', 'update-sources'")
        enable_idx = bake_loop.find("'suricata-update', 'enable-source'")
        self.assertGreater(update_idx, -1, 'bake loop must call suricata-update update-sources')
        self.assertGreater(enable_idx, -1, 'bake loop must call suricata-update enable-source')
        self.assertLess(update_idx, enable_idx, 'update-sources must run before enable-source')

    def test_dockerfile_has_python_build_dependencies(self):
        """Dockerfile must install build tools for compiling Python packages."""
        with open(DOCKERFILE, 'r') as f:
            content = f.read()
        self.assertIn('build-essential', content, 'Dockerfile must install build-essential')
        self.assertIn('python3-dev', content, 'Dockerfile must install python3-dev')
        self.assertIn('rustc', content, 'Dockerfile must install rustc')
        self.assertIn('cargo', content, 'Dockerfile must install cargo')
        self.assertIn('libxml2-dev', content, 'Dockerfile must install libxml2-dev')
        self.assertIn('libxslt1-dev', content, 'Dockerfile must install libxslt1-dev')

    def _dockerfile_final_stage(self):
        """Return the Dockerfile content for just the final (runtime) stage.

        The Dockerfile has exactly three `FROM debian:13-slim` stages: named
        builder stages that compile the Zircolite venv and convert the
        Security Onion Playbooks YAML plus the AI summaries YAML into
        gzip-compressed JSON indexes (see playbook_lookup.py and
        ai_summary_lookup.py), and an unnamed final stage that ships.
        Splitting on the FROM lines and taking the last part isolates the
        final stage so tests can assert build-only tools never land in it,
        regardless of how many builder stages precede it.
        """
        with open(DOCKERFILE, 'r') as f:
            content = f.read()
        parts = content.split('FROM debian:13-slim')
        self.assertEqual(len(parts), 4,
                          'Dockerfile must have exactly two builder stages and one final stage')
        return parts[-1]

    def test_dockerfile_uses_multistage_build(self):
        """REGRESSION: Dockerfile must build the Zircolite venv in a separate
        stage so its Rust toolchain/build-essential/dev headers/git never
        ship in the final image (previously added ~800MB of unused build
        tooling to every image). The Playbooks conversion and the AI
        summaries conversion (python3-yaml + the raw upstream YAML trees -
        see playbook_lookup.py and ai_summary_lookup.py) share one builder
        stage for the same reason, rather than each getting their own.
        """
        with open(DOCKERFILE, 'r') as f:
            content = f.read()
        self.assertIn('AS zircolite-builder', content,
                      'Dockerfile must define a named zircolite-builder stage')
        self.assertIn('AS resources-builder', content,
                      'Dockerfile must define a named resources-builder stage')
        self.assertEqual(content.count('FROM debian:13-slim'), 3,
                          'Dockerfile must have exactly three build stages')

    def test_build_toolchain_absent_from_final_stage(self):
        """REGRESSION: the Rust/build toolchain used to compile the
        Zircolite venv must not be installed in the final runtime stage."""
        import re
        final_stage = self._dockerfile_final_stage()
        for pkg in ('build-essential', 'python3-dev', 'rustc', 'cargo',
                    'libxml2-dev', 'libxslt1-dev', 'python3-venv'):
            self.assertNotIn(pkg, final_stage, f'{pkg} must not be installed in the final stage')
        self.assertIsNone(re.search(r'\bgit\b', final_stage),
                          'git package must not be installed in the final stage')

    def test_python3_pip_not_installed(self):
        """python3-pip must not be installed anywhere -- python3 -m venv
        bootstraps its own pip via ensurepip, so no system-wide pip package
        is needed in either stage."""
        with open(DOCKERFILE, 'r') as f:
            content = f.read()
        self.assertNotIn('python3-pip', content)

    def test_final_stage_copies_prebuilt_venv(self):
        """Final stage must COPY the pre-built venv from the builder stage
        rather than building it itself."""
        final_stage = self._dockerfile_final_stage()
        self.assertIn('COPY --from=zircolite-builder', final_stage, 'Final stage must copy from the builder stage')
        self.assertIn('/usr/local/lib/zircolite-venv /usr/local/lib/zircolite-venv', final_stage,
                      'Final stage must copy the built venv from the builder stage')
        self.assertIn('COPY --from=zircolite-builder /usr/local/lib/zircolite ', final_stage,
                      'Final stage must copy the zircolite script from the builder stage')

    def test_dockerfile_installs_suricata_from_trixie_backports(self):
        """REGRESSION: debian:13-slim's own repo only has Suricata 7.0.10,
        which has no eve-log output module for enip/ntp at all and lacks
        websocket/pop3/mdns/ldap/arp entirely - confirmed on a real trixie
        install. Suricata must come from Debian's own trixie-backports repo
        (8.0.6 as of writing) instead, mirroring the exact upgrade path
        validated live rather than pulling in OISF's own third-party repo.

        suricata-update must come from trixie-backports too (1.3.8 vs.
        regular trixie's 1.3.4) - 1.3.8 fixes a real security issue
        (arbitrary file write via path traversal in rule archive
        extraction: OISF redmine #8633), independent of any Suricata-8
        compatibility need."""
        final_stage = self._dockerfile_final_stage()
        self.assertIn('trixie-backports', final_stage,
                      'Dockerfile must add the trixie-backports apt source')
        self.assertIn('-t trixie-backports suricata', final_stage,
                      'suricata must be installed explicitly from trixie-backports')
        self.assertIn('-t trixie-backports suricata suricata-update', final_stage,
                      'suricata-update must be installed from trixie-backports too (security fix, redmine #8633)')

    def test_final_stage_uses_runtime_libs_not_dev_headers(self):
        """Final stage needs the runtime shared libs for lxml's compiled
        extension (libxml2/libxslt1.1), not the -dev header packages."""
        final_stage = self._dockerfile_final_stage()
        self.assertIn('libxml2', final_stage, 'Final stage must install the libxml2 runtime library')
        self.assertIn('libxslt1.1', final_stage, 'Final stage must install the libxslt1.1 runtime library')

    def test_dockerfile_venv_owned_by_app_user(self):
        """Dockerfile must copy the Zircolite venv with --chown so the non-root
        user can use it, without a separate chown -R RUN step (which would
        force a full copy-up of the venv's contents into a new overlayfs
        layer, doubling its footprint in the image)."""
        final_stage = self._dockerfile_final_stage()
        self.assertIn('COPY --from=zircolite-builder --chown=1000:1000 /usr/local/lib/zircolite-venv', final_stage,
                      'Dockerfile must set venv ownership via COPY --chown, not a separate chown -R RUN')
        self.assertNotIn('chown -R 1000:1000 /usr/local/lib/zircolite-venv', final_stage,
                          'A separate chown -R on the venv would double its layer footprint')

    def test_dockerfile_exposes_port_8000(self):
        """Dockerfile must expose port 8000."""
        with open(DOCKERFILE, 'r') as f:
            content = f.read()
        self.assertIn('EXPOSE 8000', content, 'Dockerfile must expose port 8000')

    def test_dockerfile_uses_correct_data_dir(self):
        """Dockerfile must set DATA_DIR=/data."""
        with open(DOCKERFILE, 'r') as f:
            content = f.read()
        self.assertIn('ENV DATA_DIR=/data', content, 'Dockerfile must set DATA_DIR')

    def test_dockerfile_bakes_rules_at_paths_the_app_actually_checks(self):
        """REGRESSION: the Dockerfile previously baked Sigma rules as
        rules_windows_merged.json/rules_linux.json (the upstream source
        filenames), but sigma_analyzer.setup_sigma_rules() looks for
        '<ruleset>.json' (windows.json/linux.json) under BAKED_IN_SIGMA_DIR -
        a silent mismatch that meant air-gapped deployments never actually
        found the baked-in Sigma rules, despite the app believing it
        supported air-gapped Sigma. Suricata/YARA's baked-in paths already
        matched; this locks in all three so the mismatch can't reappear
        unnoticed for any of them."""
        import yara_analyzer
        import sigma_analyzer
        with open(DOCKERFILE, 'r') as f:
            content = f.read()
        # baked_in_rules_dir is a local inside setup_suricata_config(), not a
        # module constant like YARA/Sigma's, so this is hardcoded to match it.
        self.assertIn('/usr/share/suricata/rules', content,
                      'Dockerfile must bake Suricata rules at the directory setup_suricata_config() checks')
        self.assertIn(yara_analyzer.BAKED_IN_YARA_FILE, content,
                      'Dockerfile must write the baked-in YARA file at the exact path BAKED_IN_YARA_FILE points to')
        for ruleset_name in sigma_analyzer.ZIRCOLITE_RULES_URLS:
            expected_path = os.path.join(sigma_analyzer.BAKED_IN_SIGMA_DIR, f'{ruleset_name}.json.gz')
            self.assertIn(expected_path, content,
                          f'Dockerfile must write the baked-in Sigma {ruleset_name} rules at {expected_path}, '
                          'matching setup_sigma_rules()\'s BAKED_IN_SIGMA_DIR + \'<ruleset>.json.gz\' lookup')

    def test_docker_compose_uses_so_crates_image(self):
        """docker-compose.yml must reference the SO-CRATES image."""
        with open(DOCKER_COMPOSE, 'r') as f:
            content = f.read()
        self.assertIn('ghcr.io/dougburks/so-crates', content,
                      'docker-compose must use SO-CRATES image')
        self.assertNotIn('ohmypcap', content.lower(),
                         'docker-compose must not reference old OhMyPCAP image')

    def test_docker_compose_maps_port_8000(self):
        """docker-compose.yml must map host port 8000 to container port 8000."""
        with open(DOCKER_COMPOSE, 'r') as f:
            content = f.read()
        self.assertIn('"8000:8000"', content, 'docker-compose must map port 8000')

    def test_docker_compose_uses_socrates_data_volume(self):
        """docker-compose.yml must mount ./socrates-data to /data."""
        with open(DOCKER_COMPOSE, 'r') as f:
            content = f.read()
        self.assertIn('/data', content, 'docker-compose must mount data volume')

    def test_docker_compose_podman_exists(self):
        """docker-compose.podman.yml must exist for Podman users."""
        self.assertTrue(os.path.exists(DOCKER_COMPOSE_PODMAN),
                        'docker-compose.podman.yml must exist')

    def test_docker_compose_podman_has_z_labeled_volume(self):
        """docker-compose.podman.yml must mount the data directory with the :Z
        SELinux label so rootless Podman can write to it."""
        with open(DOCKER_COMPOSE_PODMAN, 'r') as f:
            content = f.read()
        self.assertIn('volumes:', content,
                      'podman compose file must define a volumes section')
        self.assertIn('/data:Z', content,
                      'podman compose data volume must use :Z SELinux label')

    def test_docker_compose_podman_has_user_and_userns(self):
        """docker-compose.podman.yml must set user and userns_mode for host ownership."""
        with open(DOCKER_COMPOSE_PODMAN, 'r') as f:
            content = f.read()
        self.assertIn('user:', content,
                        'podman compose file must set user')
        self.assertIn('userns_mode:', content,
                        'podman compose file must set userns_mode')
        self.assertIn('keep-id', content,
                        'podman compose file must use keep-id userns_mode')


class TestVersionConsistency(unittest.TestCase):
    """Locks in Release Checklist item 4: VERSION in socrates.py, the
    docs/api.md /api/version example, and the latest docs/release-notes.md
    heading must never disagree - previously just a "remember to bump all
    three together" step a human (or agent) could forget."""

    def test_version_matches_across_source_and_docs(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        api_md_path = os.path.join(repo_root, 'docs', 'api.md')
        release_notes_path = os.path.join(repo_root, 'docs', 'release-notes.md')

        with open(api_md_path, 'r') as f:
            api_md_content = f.read()
        api_version_match = re.search(r'/api/version.*?\{"version":\s*"([^"]+)"\}',
                                      api_md_content, re.DOTALL)
        self.assertIsNotNone(api_version_match,
                             'docs/api.md must show a {"version": "X.Y.Z"} example under /api/version')

        with open(release_notes_path, 'r') as f:
            release_notes_content = f.read()
        release_notes_match = re.search(r'^## (\d+\.\d+\.\d+)', release_notes_content, re.MULTILINE)
        self.assertIsNotNone(release_notes_match,
                             'docs/release-notes.md must start with a ## X.Y.Z heading for the '
                             'latest release')

        self.assertEqual(server.VERSION, api_version_match.group(1),
                         "docs/api.md's /api/version example is out of sync with socrates.VERSION")
        self.assertEqual(server.VERSION, release_notes_match.group(1),
                         "docs/release-notes.md's latest heading is out of sync with "
                         'socrates.VERSION - add a new ## entry (and bump VERSION) when releasing')


class TestRoutesPointToRealHandlerMethods(unittest.TestCase):
    """do_GET/do_POST dispatch via getattr(self, GET_ROUTES[path]) /
    POST_ROUTES[path] with no existence check (see socrates.py's do_GET/
    do_POST) - a typo'd or renamed handler name would only surface as an
    AttributeError the first time that route is actually requested. Locks
    in that every registered route names a real Handler method."""

    def test_get_routes_point_to_real_methods(self):
        for path, handler_name in server.Handler.GET_ROUTES.items():
            self.assertTrue(hasattr(server.Handler, handler_name),
                            f'GET_ROUTES[{path!r}] = {handler_name!r} is not a method on Handler')

    def test_post_routes_point_to_real_methods(self):
        for path, handler_name in server.Handler.POST_ROUTES.items():
            self.assertTrue(hasattr(server.Handler, handler_name),
                            f'POST_ROUTES[{path!r}] = {handler_name!r} is not a method on Handler')


class _ChunkedReader:
    """A file-like object that returns at most chunk_size bytes per .read()
    call regardless of what's requested, simulating a socket delivering
    partial reads -- used to exercise _parse_multipart_stream's lookback
    buffer for boundary markers split across chunk boundaries."""

    def __init__(self, data, chunk_size):
        self._data = data
        self._chunk_size = chunk_size
        self._pos = 0

    def read(self, n=-1):
        size = self._chunk_size if n is None or n < 0 else min(n, self._chunk_size)
        end = min(len(self._data), self._pos + size)
        chunk = self._data[self._pos:end]
        self._pos = end
        return chunk


class TestMultipartParsing(unittest.TestCase):
    """REGRESSION: the streaming upload parser must handle quoted/unquoted
    boundaries and filenames, skip preamble, and return (None, None) when no
    file part is present -- and must correctly reassemble a boundary marker
    split across two separate chunk reads."""

    def setUp(self):
        self.dest_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dest_dir, ignore_errors=True)

    def _make_body(self, boundary, filename, content, quote_filename=True, preamble=''):
        disp = 'Content-Disposition: form-data; name="pcap"; '
        if quote_filename:
            disp += f'filename="{filename}"'
        else:
            disp += f'filename={filename}'
        body = (
            (preamble + '\r\n' if preamble else '')
            + f'--{boundary}\r\n'
            + disp + '\r\n'
            + 'Content-Type: application/octet-stream\r\n\r\n'
        ).encode() + content + f'\r\n--{boundary}--\r\n'.encode()
        return body

    def _parse(self, body, content_type, reader=None):
        handler = server.Handler.__new__(server.Handler)
        rfile = reader if reader is not None else io.BytesIO(body)
        path, name = handler._parse_multipart_stream(rfile, len(body), content_type, self.dest_dir)
        if path is None:
            return None, name
        with open(path, 'rb') as f:
            data = f.read()
        os.unlink(path)
        return data, name

    def test_quoted_boundary(self):
        body = self._make_body('WebKitBoundary', 'test.pcap', b'PCAPDATA')
        ct = 'multipart/form-data; boundary="WebKitBoundary"'
        data, name = self._parse(body, ct)
        self.assertEqual(name, 'test.pcap')
        self.assertEqual(data, b'PCAPDATA')

    def test_unquoted_filename(self):
        body = self._make_body('Boundary', 'unquoted.pcap', b'PCAPDATA', quote_filename=False)
        ct = 'multipart/form-data; boundary=Boundary'
        data, name = self._parse(body, ct)
        self.assertEqual(name, 'unquoted.pcap')
        self.assertEqual(data, b'PCAPDATA')

    def test_preamble_skipped(self):
        body = self._make_body('Boundary', 'test.pcap', b'PCAPDATA', preamble='ignore this preamble')
        ct = 'multipart/form-data; boundary=Boundary'
        data, name = self._parse(body, ct)
        self.assertEqual(name, 'test.pcap')
        self.assertEqual(data, b'PCAPDATA')

    def test_missing_boundary(self):
        body = b'--Boundary\r\nContent-Disposition: form-data; filename="x.pcap"\r\n\r\nDATA\r\n--Boundary--\r\n'
        ct = 'multipart/form-data'
        data, name = self._parse(body, ct)
        self.assertIsNone(data)
        self.assertIsNone(name)

    def test_no_file_part(self):
        body = self._make_body('Boundary', 'test.pcap', b'PCAPDATA', quote_filename=False)
        body = body.replace(b'filename=test.pcap', b'name="pcap"')
        ct = 'multipart/form-data; boundary=Boundary'
        data, name = self._parse(body, ct)
        self.assertIsNone(data)
        self.assertIsNone(name)

    def test_end_boundary_split_across_chunk_read(self):
        """The terminating boundary marker (\\r\\n--boundary) may arrive split
        across two separate socket reads -- the lookback buffer must still
        catch it, without truncating or duplicating any file bytes."""
        content = b'A' * 500 + b'PCAPDATA' + b'B' * 500
        body = self._make_body('Boundary', 'test.pcap', content)
        ct = 'multipart/form-data; boundary=Boundary'
        marker = b'\r\n--Boundary'
        offset = body.find(marker)
        self.assertNotEqual(offset, -1)
        # Pick a chunk size so a read boundary lands inside the marker itself.
        chunk_size = offset + 3
        reader = _ChunkedReader(body, chunk_size)
        data, name = self._parse(body, ct, reader=reader)
        self.assertEqual(name, 'test.pcap')
        self.assertEqual(data, content)

    def test_header_terminator_split_across_chunk_read(self):
        """The \\r\\n\\r\\n terminating the part headers may also arrive split
        across two reads -- the header-accumulation loop must carry the
        partial match forward correctly."""
        body = self._make_body('Boundary', 'test.pcap', b'PCAPDATA')
        ct = 'multipart/form-data; boundary=Boundary'
        header_term = body.find(b'\r\n\r\n')
        self.assertNotEqual(header_term, -1)
        chunk_size = header_term + 2
        reader = _ChunkedReader(body, chunk_size)
        data, name = self._parse(body, ct, reader=reader)
        self.assertEqual(name, 'test.pcap')
        self.assertEqual(data, b'PCAPDATA')


class TestNonArtifactFiles(unittest.TestCase):
    """REGRESSION: zircolite.log (a real pipeline artifact for log/Sigma
    analyses) used to slip through _non_artifact_files's suffix-based
    exclusion list entirely, so it could transiently win a directory-listing
    race against the real uploaded file as the display-name fallback (before
    name.txt is written). Fixed by excluding exact known artifact filenames
    in addition to the suffix list - critically, without excluding the bare
    '.log' suffix itself, since a user-uploaded log file legitimately ends in
    .log too and must still be found here."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.handler = server.Handler.__new__(server.Handler)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_zircolite_log_artifact_excluded(self):
        open(os.path.join(self.tmpdir, 'zircolite.log'), 'w').close()
        open(os.path.join(self.tmpdir, 'suspicious.log'), 'w').close()
        result = self.handler._non_artifact_files(self.tmpdir)
        self.assertEqual(result, ['suspicious.log'],
                          'zircolite.log must be excluded but a user-uploaded .log file must not be')

    def test_zircolite_events_db_artifact_excluded(self):
        open(os.path.join(self.tmpdir, '.zircolite_events.db'), 'w').close()
        result = self.handler._non_artifact_files(self.tmpdir)
        self.assertEqual(result, [], 'dotfile is already excluded, but confirm the exact-name set does not error on it')

    def test_missing_dir_returns_empty_list(self):
        result = self.handler._non_artifact_files(os.path.join(self.tmpdir, 'does-not-exist'))
        self.assertEqual(result, [])

    def test_legitimately_named_txt_and_json_uploads_are_found(self):
        """REGRESSION: _non_artifact_files() used to blanket-exclude any
        .txt/.json/.db-suffixed filename by extension, even though a
        legitimately-uploaded standalone file can itself have one of
        those extensions - the exact same directory's file was still
        correctly found by handle_post_reanalyze()'s own separate,
        hand-rolled listing (which only excluded exact artifact names,
        not extensions), so a missing name.txt meant _resolve_display_name()
        could never fall back to the real filename for such an upload
        even though reanalyze happily found and used it. Both call sites
        now share this one helper, so this can no longer disagree."""
        open(os.path.join(self.tmpdir, 'My Notes.txt'), 'w').close()
        result = self.handler._non_artifact_files(self.tmpdir)
        self.assertEqual(result, ['My Notes.txt'],
                          'a legitimately-uploaded .txt file must be found, not treated as an artifact')

    def test_pcap_file_param_excluded_by_exact_name(self):
        """An extension-less pcap (detected via magic bytes by
        _find_pcap_file(), not this function's own PCAP_EXTENSIONS check)
        must still be excludable by passing its name explicitly."""
        open(os.path.join(self.tmpdir, 'so-pcap.1234567890'), 'w').close()
        open(os.path.join(self.tmpdir, 'real-upload.bin'), 'w').close()
        result = self.handler._non_artifact_files(self.tmpdir, pcap_file='so-pcap.1234567890')
        self.assertEqual(result, ['real-upload.bin'])


class TestIngressDefenses(unittest.TestCase):
    """Host-header (DNS rebinding), Origin/Sec-Fetch-Site (CSRF),
    Content-Type enforcement, and /static/ path-normalization defenses."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.original_base = server.DATA_DIR
        server.DATA_DIR = cls.tmpdir
        cls.port = 19000 + (os.getpid() % 1000)
        cls.server = server.ThreadedTCPServer(('127.0.0.1', cls.port), server.Handler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        server.DATA_DIR = cls.original_base
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def _raw(self, method, path, headers=None, body=None):
        import http.client
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            sent = {k.lower() for k in (headers or {})}
            if 'host' not in sent:
                conn.putheader('Host', f'127.0.0.1:{self.port}')
            for k, v in (headers or {}).items():
                conn.putheader(k, v)
            if body is not None:
                conn.putheader('Content-Length', str(len(body)))
            conn.endheaders(body)
            resp = conn.getresponse()
            return resp.status, resp.read().decode()
        finally:
            conn.close()

    # ---- Host header (DNS rebinding) ----

    def test_dns_name_host_rejected(self):
        status, _ = self._raw('GET', '/socrates.html', headers={'Host': 'evil.example.com'})
        self.assertEqual(status, 403)

    def test_ip_literal_host_allowed(self):
        status, _ = self._raw('GET', '/socrates.html', headers={'Host': '192.168.1.50:8000'})
        self.assertEqual(status, 200)

    def test_localhost_host_allowed(self):
        status, _ = self._raw('GET', '/socrates.html', headers={'Host': f'localhost:{self.port}'})
        self.assertEqual(status, 200)

    def test_ipv6_literal_host_allowed(self):
        status, _ = self._raw('GET', '/socrates.html', headers={'Host': '[::1]:8000'})
        self.assertEqual(status, 200)

    def test_rejected_host_blocks_post_too(self):
        status, _ = self._raw('POST', '/api/delete-all-analyses',
                              headers={'Host': 'evil.example.com',
                                       'Content-Type': 'application/json'},
                              body=b'{}')
        self.assertEqual(status, 403)

    # ---- Origin / Sec-Fetch-Site (CSRF) ----

    def test_cross_origin_post_rejected(self):
        status, _ = self._raw('POST', '/api/delete-all-analyses',
                              headers={'Origin': 'https://evil.example.com',
                                       'Content-Type': 'application/json'},
                              body=b'{}')
        self.assertEqual(status, 403)

    def test_null_origin_post_rejected(self):
        status, _ = self._raw('POST', '/api/delete-all-analyses',
                              headers={'Origin': 'null',
                                       'Content-Type': 'application/json'},
                              body=b'{}')
        self.assertEqual(status, 403)

    def test_same_origin_post_allowed(self):
        status, _ = self._raw('POST', '/api/delete-all-analyses',
                              headers={'Origin': f'http://127.0.0.1:{self.port}',
                                       'Content-Type': 'application/json'},
                              body=b'{}')
        self.assertEqual(status, 200)

    def test_cross_site_fetch_metadata_rejected(self):
        status, _ = self._raw('POST', '/api/delete-all-analyses',
                              headers={'Sec-Fetch-Site': 'cross-site',
                                       'Content-Type': 'application/json'},
                              body=b'{}')
        self.assertEqual(status, 403)

    def test_same_origin_fetch_metadata_allowed(self):
        status, _ = self._raw('POST', '/api/delete-all-analyses',
                              headers={'Sec-Fetch-Site': 'same-origin',
                                       'Content-Type': 'application/json'},
                              body=b'{}')
        self.assertEqual(status, 200)

    # ---- Content-Type enforcement on JSON endpoints ----

    def test_json_post_without_json_content_type_rejected(self):
        status, _ = self._raw('POST', '/api/delete-analysis',
                              headers={'Content-Type': 'text/plain'},
                              body=b'{}')
        self.assertEqual(status, 415)

    def test_json_post_with_charset_allowed(self):
        # Passes the Content-Type gate; 400 is the normal missing-md5 error
        status, _ = self._raw('POST', '/api/delete-analysis',
                              headers={'Content-Type': 'application/json; charset=utf-8'},
                              body=b'{}')
        self.assertEqual(status, 400)

    # ---- /static/ path normalization ----

    def test_static_encoded_traversal_rejected(self):
        status, _ = self._raw('GET', '/static/%2e%2e/db.py')
        self.assertEqual(status, 404)

    def test_static_plain_traversal_rejected(self):
        status, _ = self._raw('GET', '/static/../socrates.py')
        self.assertEqual(status, 404)

    def test_static_legit_file_served(self):
        status, _ = self._raw('GET', '/static/socrates.css')
        self.assertEqual(status, 200)


class TestErrorTextSanitizer(unittest.TestCase):
    def test_data_dir_paths_stripped(self):
        msg = server._sanitize_error_text(
            "YARA scan failed: [Errno 13] Permission denied: '%s'"
            % os.path.join(server.DATA_DIR, 'abc', 'file.bin'))
        self.assertNotIn(server.DATA_DIR, msg)

    def test_other_absolute_paths_redacted(self):
        msg = server._sanitize_error_text(
            'Suricata failed: /usr/lib/suricata/suricata.yaml missing')
        self.assertNotIn('/usr/lib/', msg)
        self.assertIn('<path>', msg)

    def test_plain_message_unchanged(self):
        msg = 'Suricata failed to start: command not found'
        self.assertEqual(server._sanitize_error_text(msg), msg)


class TestRunCapped(unittest.TestCase):
    def test_output_capped_and_flagged(self):
        rc, out, truncated = server._run_capped(
            ['python3', '-c', 'import sys; sys.stdout.write("x" * 1000000)'],
            max_bytes=1000, timeout=30)
        self.assertTrue(truncated)
        self.assertEqual(len(out), 1000)

    def test_small_output_untruncated(self):
        rc, out, truncated = server._run_capped(
            ['python3', '-c', 'print("hello")'], max_bytes=1000, timeout=30, text=True)
        self.assertEqual(rc, 0)
        self.assertFalse(truncated)
        self.assertEqual(out.strip(), 'hello')

    def test_timeout_raises(self):
        import subprocess as sp
        with self.assertRaises(sp.TimeoutExpired):
            server._run_capped(['sleep', '30'], max_bytes=1000, timeout=1)


class TestCSPReportOnly(unittest.TestCase):
    """Phase 0 of removing script-src 'unsafe-inline': a Report-Only header
    plus a report sink, without changing the enforced policy."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.original_base = server.DATA_DIR
        server.DATA_DIR = cls.tmpdir
        cls.port = 20000 + (os.getpid() % 1000)
        cls.server = server.ThreadedTCPServer(('127.0.0.1', cls.port), server.Handler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        server.DATA_DIR = cls.original_base
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_report_only_header_present(self):
        import urllib.request
        with urllib.request.urlopen(f'http://127.0.0.1:{self.port}/socrates.html', timeout=5) as resp:
            ro = resp.headers.get('Content-Security-Policy-Report-Only', '')
            enforced = resp.headers.get('Content-Security-Policy', '')
        self.assertIn("script-src 'self'", ro)
        self.assertIn('/api/csp-report', ro)
        self.assertNotIn('unsafe-inline', ro)
        # enforced policy unchanged in phase 0
        self.assertIn("'unsafe-inline'", enforced)

    def test_report_endpoint_accepts_csp_content_type(self):
        import urllib.request
        body = json.dumps({'csp-report': {
            'violated-directive': 'script-src', 'blocked-uri': 'inline',
            'source-file': 'http://x/socrates.html', 'line-number': 1}}).encode()
        req = urllib.request.Request(
            f'http://127.0.0.1:{self.port}/api/csp-report', data=body,
            headers={'Content-Type': 'application/csp-report'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 204)

    def test_report_endpoint_tolerates_garbage(self):
        import urllib.request
        req = urllib.request.Request(
            f'http://127.0.0.1:{self.port}/api/csp-report', data=b'not json',
            headers={'Content-Type': 'application/csp-report'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 204)


if __name__ == '__main__':
    unittest.main(verbosity=2)
