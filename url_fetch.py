"""Downloading a user-supplied URL (/api/load-url) without SSRF.

The checks on the URL itself - scheme, blocked address ranges, resolving
to safe IPs - live in validators.py; this module makes the connection
through only those validated IPs, and re-checks every redirect hop.
"""

import http.client
import os
import socket
import ssl
import tempfile
from urllib.parse import urljoin, urlparse

from validators import resolve_safe_ips, validate_url_safety

MAX_URL_REDIRECTS = 5


class FileTooLargeError(Exception):
    """Raised by fetch_url_safely when the downloaded body exceeds max_size."""


def connect_to_pinned_ips(pinned_ips, port, timeout):
    """Try each pre-validated IP in turn, same fallback behavior as a plain
    hostname connect (e.g. skip an unreachable IPv6 address and fall back to
    IPv4), but every candidate comes from the already-validated set -- no
    new DNS lookup happens here, so the pinning/SSRF protection holds."""
    last_err = None
    for ip in pinned_ips:
        try:
            return socket.create_connection((ip, port), timeout)
        except OSError as e:
            last_err = e
    raise last_err or OSError('No addresses to connect to')


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that connects to a pre-validated IP instead of letting
    the socket layer re-resolve the hostname, closing the DNS-rebinding
    TOCTOU window between validate_url_safety() and the real connection."""

    def __init__(self, hostname, pinned_ips, port, timeout):
        super().__init__(hostname, port, timeout=timeout)
        self._pinned_ips = pinned_ips

    def connect(self):
        self.sock = connect_to_pinned_ips(self._pinned_ips, self.port, self.timeout)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname, pinned_ips, port, timeout):
        super().__init__(hostname, port, timeout=timeout, context=ssl.create_default_context())
        self._pinned_ips = pinned_ips

    def connect(self):
        sock = connect_to_pinned_ips(self._pinned_ips, self.port, self.timeout)
        # server_hostname uses the real hostname (self.host) for SNI/cert
        # validation even though we dialed a pinned IP directly.
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def fetch_url_safely(url, timeout, max_size, tmp_dir, chunk_size=64 * 1024):
    """Download a URL while guarding against SSRF.

    Every hop -- including redirect targets -- is validated with
    validate_url_safety() and then connected via the specific IPs that
    validation just checked (see resolve_safe_ips). This prevents both:
      - DNS-rebinding TOCTOU: an attacker's DNS server returning a public IP
        for validation and a private/internal IP for the real connection.
      - Redirect-based bypass: a public URL that 30x-redirects to a blocked
        address after the initial URL already passed validation.

    Returns the path to a temp file (under tmp_dir) containing the
    downloaded body -- streamed directly to disk rather than buffered in
    memory, so peak memory doesn't scale with the response size.
    Raises ValueError on validation/protocol failures, or FileTooLargeError
    if the body exceeds max_size.
    """
    current_url = url
    for _ in range(MAX_URL_REDIRECTS + 1):
        validate_url_safety(current_url)
        parsed = urlparse(current_url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        pinned_ips = resolve_safe_ips(hostname)

        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query

        conn_cls = PinnedHTTPSConnection if parsed.scheme == 'https' else PinnedHTTPConnection
        conn = conn_cls(hostname, pinned_ips, port, timeout)
        try:
            conn.request('GET', path, headers={'User-Agent': 'Mozilla/5.0'})
            resp = conn.getresponse()

            if resp.status in (301, 302, 303, 307, 308):
                location = resp.getheader('Location')
                # Bounded discard, not a bare resp.read() - a malicious or
                # compromised server could otherwise pair a redirect with an
                # unbounded (or slow-trickling) body and exhaust memory
                # before we ever look at Location.
                total = 0
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_size:
                        raise FileTooLargeError('Redirect response body too large')
                if not location:
                    raise ValueError('Redirect response missing Location header')
                current_url = urljoin(current_url, location)
                continue

            if resp.status != 200:
                raise ValueError(f'Server returned HTTP {resp.status}')

            fd, tmp_path = tempfile.mkstemp(dir=tmp_dir, suffix='.download')
            try:
                total = 0
                with os.fdopen(fd, 'wb') as f:
                    while True:
                        chunk = resp.read(chunk_size)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > max_size:
                            raise FileTooLargeError('File too large')
                        f.write(chunk)
                return tmp_path
            except Exception:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                raise
        finally:
            conn.close()

    raise ValueError('Too many redirects')
