#!/usr/bin/env python3
import http.server
import http.client
import socketserver
import concurrent.futures
import json
import os
import ssl
import sqlite3
import subprocess
import hashlib
import ipaddress
import posixpath
from urllib.parse import urlparse, parse_qs, urljoin, unquote
import urllib.request
import urllib.error
import zipfile
import re
import tempfile
import time
import shutil
import sys
import socket
import threading

from db import (
    get_event_count_sqlite, get_event_types_sqlite, query_events_sqlite_json,
    create_file_analysis_db, insert_sigma_alerts, init_empty_db,
    query_sigma_alerts_sqlite, get_sigma_stats_sqlite,
    get_sigma_alert_count_sqlite, get_event_date_range_sqlite,
    get_sankey_data_sqlite, get_aggregation_data_sqlite, get_aggregation_totals_sqlite,
    AGGREGATION_TOP_N, AGGREGATION_JSON_PATHS, REAL_AGGREGATION_COLUMNS,
    set_row_note, has_row_notes,
    set_acknowledged, set_acknowledged_bulk,
)
from validators import (
    validate_ip, validate_port, sanitize_filename, is_safe_path,
    validate_url_safety, resolve_safe_ips, validate_zip_extraction,
    is_log_file, is_log_file_by_extension, is_office_file_by_extension,
    is_pcap_file,
)
from suricata_analyzer import (
    check_executables, setup_suricata_config, spawn_suricata,
    _set_error, _set_phase, _clear_phase, get_suricata_rules_info,
    get_suricata_enabled_sources, get_suricata_show_protocol_decode_alerts,
    SURICATA_RULE_SOURCES, BAKED_IN_SURICATA_SOURCES,
    DEFAULT_SURICATA_SOURCES,
)
from suricata_sid_ranges import (
    SURICATA_SID_RANGES, SURICATA_BUILTIN_SID_RANGE, SURICATA_BUILTIN_LABEL,
)
from yara_analyzer import check_yara_executable, setup_yara_rules, scan_single_file, get_yara_rules_info
from sigma_analyzer import (
    is_zircolite_available, setup_sigma_rules, run_sigma_pipeline,
    parse_zircolite_results, import_zircolite_logs, get_sigma_rules_info,
)
from ohmydebn_colors import (
    derive_theme_colors, derive_theme_colors_from_alacritty, derive_theme_colors_from_named_palette,
)
from playbook_lookup import get_playbook
from ai_summary_lookup import get_ai_summary
import config
import tomllib

VERSION = '4.1.0'
GITHUB_RELEASES_API = 'https://api.github.com/repos/dougburks/so-crates/releases/latest'
PORT = int(os.environ.get('PORT', 8000))
BIND_ADDRESS = os.environ.get('BIND_ADDRESS', '127.0.0.1')
DATA_DIR = os.environ.get('DATA_DIR', os.path.expanduser('~/socrates-data'))
# Base OhMyDebn config directory (e.g. ~/.config/ohmydebn/), kept in sync
# by an external tool (e.g. OhMyDebn's ohmydebn-theme-set). Unset means the
# theme-sync feature is off. The active theme's name and palette are read
# by convention from <OHMYDEBN_THEME_DIR>/current/theme.name and
# <OHMYDEBN_THEME_DIR>/current/theme/{colors,alacritty}.toml.
OHMYDEBN_THEME_DIR = os.environ.get('OHMYDEBN_THEME_DIR')
# Re-export size limits for backward compatibility
MAX_TRANSCRIPT_SIZE = config.MAX_TRANSCRIPT_SIZE
MAX_EVE_SIZE = config.MAX_EVE_SIZE
SURICATA_DIR = os.path.join(DATA_DIR, 'suricata')

PCAP_EXTENSIONS = ('.pcap', '.pcapng', '.cap', '.trace')
MD5_RE = re.compile(r'^[a-f0-9]{32}$')
# Deliberately permissive rather than an enum of known theme names, so the
# client's own THEMES allowlist (static/socrates.js) stays the single source
# of truth; this just bounds what a malformed/oversized file can smuggle
# through as JSON. Underscores included alongside hyphens - confirmed real
# installed OhMyDebn theme names use them (e.g. "black_arch", "snow_black").
THEME_NAME_RE = re.compile(r'^[a-z0-9_-]{1,40}$')

# Pipeline output artifacts removed by /api/reanalyze before re-running analysis
PCAP_ANALYSIS_ARTIFACTS = ('eve.json', 'events.db', '.phase', '.error', 'yara_matches.json', 'sigma_matches.json', '.meta', 'file_metadata.json')
FILE_ANALYSIS_ARTIFACTS = ('events.db', '.error', 'yara_matches.json', 'sigma_matches.json', '.meta', 'zircolite.log', '.zircolite_events.db')

MAX_URL_REDIRECTS = 5

# Cache of the unfiltered (no search query) Sankey/aggregation result per
# (md5, event_type) - the events table is written once by create_sqlite_db
# and never mutated afterward except by delete/reanalyze (both evict below),
# so caching it is safe and turns every repeat tab-view after the first into
# a no-op instead of a multi-hundred-ms SQL recomputation.
_SANKEY_CACHE = {}
_AGGREGATION_CACHE = {}
_AGGREGATION_TOTALS_CACHE = {}
# Single source of truth for "every analysis-result cache": _evict_analysis_cache
# and the delete-all handler must always cover the same set, so a new cache
# added here is automatically evicted/cleared in both places.
_ALL_CACHES = (_SANKEY_CACHE, _AGGREGATION_CACHE, _AGGREGATION_TOTALS_CACHE)
_CACHE_LOCK = threading.Lock()
# Backstop against cache-fill abuse: cache keys include client-supplied
# strings, so even with per-key validation the total entry count is bounded.
_CACHE_MAX_ENTRIES = 2048


def _evict_analysis_cache(md5):
    with _CACHE_LOCK:
        for cache in _ALL_CACHES:
            for key in [k for k in cache if k[0] == md5]:
                del cache[key]


def _sanitize_error_text(text):
    """Redact server filesystem paths from client-facing .error text -
    exception strings routinely embed absolute paths (data dir, tool
    locations) that a browser client has no use for."""
    text = text.replace(DATA_DIR + os.sep, '').replace(DATA_DIR, '')
    return re.sub(r'(?:^|(?<=[\s:\'"(]))/(?:[\w.+-]+/)+[\w.+-]+', '<path>', text)


def _run_capped(cmd, max_bytes, timeout, text=False):
    """Run a command capturing stdout up to max_bytes.

    subprocess.run(capture_output=True) buffers the entire stdout in RAM
    before any size cap can apply - for pcap-derived streams that can be
    gigabytes. Read incrementally instead and kill the process once the cap
    is reached. Returns (returncode, output, truncated); raises
    subprocess.TimeoutExpired on timeout, matching subprocess.run.
    """
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    timed_out = [False]

    def _kill_on_timeout():
        timed_out[0] = True
        proc.kill()

    timer = threading.Timer(timeout, _kill_on_timeout)
    timer.start()
    chunks = []
    total = 0
    truncated = False
    try:
        while True:
            chunk = proc.stdout.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                chunks.append(chunk[:max_bytes - (total - len(chunk))])
                truncated = True
                proc.kill()
                break
            chunks.append(chunk)
        proc.wait()
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    if timed_out[0]:
        raise subprocess.TimeoutExpired(cmd, timeout)
    data = b''.join(chunks)
    if text:
        data = data.decode('utf-8', errors='replace')
    return proc.returncode, data, truncated


def _cache_put(cache, key, value):
    """Insert into an analysis cache; caller must hold _CACHE_LOCK."""
    if len(cache) >= _CACHE_MAX_ENTRIES:
        cache.clear()
    cache[key] = value


def _cacheable_aggregation_key(event_type, column=None):
    """Only cache keys built from recognized event types/columns - arbitrary
    client strings must not become permanent cache entries (memory DoS)."""
    if event_type is not None and event_type not in AGGREGATION_JSON_PATHS:
        return False
    if column is None:
        return True
    if column in REAL_AGGREGATION_COLUMNS:
        return True
    if event_type is None:
        return column in ('Type', 'Detail')
    return column in AGGREGATION_JSON_PATHS[event_type]


# Server-wide rule-update job state, polled by the frontend via
# GET /api/rule-update-status after POST /api/update-rules starts a
# per-ruleset job. Keyed by ruleset name (not per-md5 like the .phase file
# pattern used elsewhere) since each of the three rulesets can be updated
# independently of the others and of any analysis. Each sub-dict is
# replaced (not mutated field-by-field) when its ruleset's run starts, so a
# slow poller from a previous run of that ruleset can never blend its stale
# reference with a new run's lines.
_rule_update_lock = threading.Lock()
_rule_update_state = {
    'suricata': {'running': False, 'lines': [], 'done': True, 'error': None},
    'yara': {'running': False, 'lines': [], 'done': True, 'error': None},
    'sigma': {'running': False, 'lines': [], 'done': True, 'error': None},
}

_RULESET_LABELS = {'suricata': 'Suricata', 'yara': 'YARA', 'sigma': 'Sigma'}


def _run_ruleset_update(name, sources=None, show_protocol_decode_alerts=None):
    def on_progress(message):
        print(message)
        with _rule_update_lock:
            _rule_update_state[name]['lines'].append(message)

    try:
        if name == 'suricata':
            setup_suricata_config(DATA_DIR, enable_arp=bool(os.environ.get('ENABLE_ARP_LOGGING')), on_progress=on_progress, enabled_sources=sources, show_protocol_decode_alerts=show_protocol_decode_alerts)
        elif name == 'yara':
            setup_yara_rules(DATA_DIR, on_progress=on_progress, force=True)
        elif name == 'sigma':
            setup_sigma_rules(DATA_DIR, on_progress=on_progress, force=True)
    except Exception as e:
        on_progress(f'Error updating {_RULESET_LABELS[name]} rules: {e}')
        with _rule_update_lock:
            _rule_update_state[name]['error'] = f'{e}'
    finally:
        with _rule_update_lock:
            _rule_update_state[name]['done'] = True
            _rule_update_state[name]['running'] = False


class _FileTooLargeError(Exception):
    """Raised by _fetch_url_safely when the downloaded body exceeds max_size."""


def _connect_to_pinned_ips(pinned_ips, port, timeout):
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


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that connects to a pre-validated IP instead of letting
    the socket layer re-resolve the hostname, closing the DNS-rebinding
    TOCTOU window between validate_url_safety() and the real connection."""

    def __init__(self, hostname, pinned_ips, port, timeout):
        super().__init__(hostname, port, timeout=timeout)
        self._pinned_ips = pinned_ips

    def connect(self):
        self.sock = _connect_to_pinned_ips(self._pinned_ips, self.port, self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname, pinned_ips, port, timeout):
        super().__init__(hostname, port, timeout=timeout, context=ssl.create_default_context())
        self._pinned_ips = pinned_ips

    def connect(self):
        sock = _connect_to_pinned_ips(self._pinned_ips, self.port, self.timeout)
        # server_hostname uses the real hostname (self.host) for SNI/cert
        # validation even though we dialed a pinned IP directly.
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _fetch_url_safely(url, timeout, max_size, chunk_size=64 * 1024):
    """Download a URL while guarding against SSRF.

    Every hop -- including redirect targets -- is validated with
    validate_url_safety() and then connected via the specific IPs that
    validation just checked (see resolve_safe_ips). This prevents both:
      - DNS-rebinding TOCTOU: an attacker's DNS server returning a public IP
        for validation and a private/internal IP for the real connection.
      - Redirect-based bypass: a public URL that 30x-redirects to a blocked
        address after the initial URL already passed validation.

    Returns the path to a temp file (under _upload_tmp_dir()) containing the
    downloaded body -- streamed directly to disk rather than buffered in
    memory, so peak memory doesn't scale with the response size.
    Raises ValueError on validation/protocol failures, or _FileTooLargeError
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

        conn_cls = _PinnedHTTPSConnection if parsed.scheme == 'https' else _PinnedHTTPConnection
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
                        raise _FileTooLargeError('Redirect response body too large')
                if not location:
                    raise ValueError('Redirect response missing Location header')
                current_url = urljoin(current_url, location)
                continue

            if resp.status != 200:
                raise ValueError(f'Server returned HTTP {resp.status}')

            fd, tmp_path = tempfile.mkstemp(dir=_upload_tmp_dir(), suffix='.download')
            try:
                total = 0
                with os.fdopen(fd, 'wb') as f:
                    while True:
                        chunk = resp.read(chunk_size)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > max_size:
                            raise _FileTooLargeError('File too large')
                        f.write(chunk)
                return tmp_path
            except Exception:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                raise
        finally:
            conn.close()

    raise ValueError('Too many redirects')


def _attempt_zip_extract(zip_ref, extract_dir, passwords, max_size=None):
    """Extract ZIP contents, trying passwords if needed.

    Returns True on success, False if extraction failed.
    Raises ValueError on zip slip or size violations.
    """
    validate_zip_extraction(zip_ref, extract_dir, max_size)
    extracted = False
    try:
        zip_ref.extractall(extract_dir)
        extracted = True
    except (RuntimeError, NotImplementedError):
        # RuntimeError: bad/missing password. NotImplementedError: zipfile's
        # own signal for strong encryption (AES) or an unsupported
        # compression method - both are real, fairly common in
        # malware-sample archives, not just "wrong password".
        pass

    if not extracted and passwords:
        for pwd in passwords:
            try:
                zip_ref.extractall(extract_dir, pwd=pwd)
                extracted = True
                break
            except (RuntimeError, NotImplementedError):
                continue

    return extracted



def _write_meta(dir_path, original, extracted, detected_type):
    """Write analysis metadata for frontend routing."""
    from datetime import datetime
    meta = {
        'version': 1,
        'original': original,
        'extracted': extracted,
        'detected_type': detected_type,
        'extracted_at': datetime.now().isoformat(),
    }
    meta_path = os.path.join(dir_path, '.meta')
    with open(meta_path, 'w') as f:
        json.dump(meta, f)


def _read_meta(dir_path):
    """Read analysis metadata if it exists."""
    meta_path = os.path.join(dir_path, '.meta')
    if os.path.exists(meta_path):
        try:
            with open(meta_path) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            pass
    return None


def _is_newer_version(candidate, current):
    """Compare two 'X.Y.Z' version strings. Returns False (not True/an
    exception) for anything malformed, since a GitHub release tag that
    doesn't parse as expected should never be treated as "newer" - fails
    closed to "no update available" rather than surfacing a bogus badge."""
    try:
        candidate_parts = tuple(int(x) for x in candidate.split('.'))
        current_parts = tuple(int(x) for x in current.split('.'))
    except (ValueError, AttributeError):
        return False
    return candidate_parts > current_parts


def _load_toml(path):
    try:
        with open(path, 'rb') as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return None


def _get_ohmydebn_custom_colors():
    """Reads the active OhMyDebn/Aether theme's raw palette (under
    OHMYDEBN_THEME_DIR) and derives a full SO-CRATES theme from it, for
    themes the client's THEMES registry has no hand-built CSS for. Tries
    the native colors.toml first - both the numbered color0-15 ANSI-slot
    scheme and the semantic-named variant (red/blue/bright_red/muted/...,
    confirmed on a real installed theme) - falling back to alacritty.toml
    (many custom-installed themes only ship the latter) if neither native
    reading produces a usable result. Never raises - any failure (unset,
    unreadable, malformed TOML, missing/invalid palette keys) just means
    no fallback is available."""
    if not OHMYDEBN_THEME_DIR:
        return None
    theme_dir = os.path.join(OHMYDEBN_THEME_DIR, 'current', 'theme')

    colors_toml = _load_toml(os.path.join(theme_dir, 'colors.toml'))
    if colors_toml is not None:
        result = derive_theme_colors(colors_toml)
        if result is not None:
            return result
        result = derive_theme_colors_from_named_palette(colors_toml)
        if result is not None:
            return result

    alacritty_toml = _load_toml(os.path.join(theme_dir, 'alacritty.toml'))
    if alacritty_toml is not None:
        result = derive_theme_colors_from_alacritty(alacritty_toml)
        if result is not None:
            return result

    return None


def _upload_tmp_dir():
    """Scratch dir for in-progress uploads, on the same filesystem as DATA_DIR
    so the final move into DATA_DIR/<md5>/... is an atomic rename rather than
    a cross-device copy. Recomputed from the current DATA_DIR on every call
    (not cached as a module constant) so it stays correct if DATA_DIR is
    reassigned after import, as the test suite does.
    """
    d = os.path.join(DATA_DIR, config.UPLOAD_TMP_SUBDIR)
    os.makedirs(d, exist_ok=True)
    return d


def _cleanup_upload_tmp_dir():
    """Remove any leftover entries from _upload_tmp_dir(). Meant to be called
    once at startup, before the server accepts requests -- at that point,
    anything found here is guaranteed orphaned (no upload can legitimately
    be in progress yet), left behind by a process that died mid-upload
    (crash, OOM-kill, kill -9) before its own request-scoped cleanup in
    _process_uploaded_file/_fetch_url_safely/_parse_multipart_stream could
    run. Those normal completion/exception paths already clean up after
    themselves within a single request's lifetime; this just catches what
    a hard process death leaves behind, which would otherwise accumulate
    forever across restarts.
    """
    tmp_dir = _upload_tmp_dir()
    for entry in os.listdir(tmp_dir):
        path = os.path.join(tmp_dir, entry)
        try:
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                os.unlink(path)
        except OSError:
            pass


def _find_pcap_file(dir_path):
    """Find the analyzed pcap file within an analysis directory.

    Tries the fast extension-based match first, then falls back to
    magic-byte detection (is_pcap_file) over the remaining non-artifact
    entries. The fallback matters because some real pcaps have no
    recognized extension at all (e.g. Security Onion's
    so-pcap.<timestamp> downloads) -- they were still correctly detected
    and ingested as pcaps at upload time via magic bytes (see
    _process_uploaded_file), so lookups here must use the same detection
    method rather than relying on the filename alone.

    Returns the filename (not full path), or None if not found.
    """
    if not os.path.exists(dir_path):
        return None
    entries = os.listdir(dir_path)
    for f in entries:
        if f.lower().endswith(PCAP_EXTENSIONS):
            return f
    for f in entries:
        if f.startswith('.') or f in PCAP_ANALYSIS_ARTIFACTS or f in ('name.txt', 'notes.txt'):
            continue
        full_path = os.path.join(dir_path, f)
        if not os.path.isfile(full_path):
            continue
        try:
            with open(full_path, 'rb') as fh:
                if is_pcap_file(fh.read(4)):
                    return f
        except OSError:
            continue
    return None


def _resolve_upload_size_limit(requested):
    """Resolve the effective per-request upload-size ceiling from a
    client-provided override (X-Max-Upload-Size header for /api/upload, or
    the maxUploadSize JSON field for /api/load-url), clamped to the hard
    server ceiling (config.MAX_UPLOAD_SIZE) -- mirrors _parse_pagination's
    clamping semantics for MAX_QUERY_LIMIT. Falls back to
    config.DEFAULT_UPLOAD_SIZE if the override is missing/malformed/
    non-positive, matching the pre-existing default behavior for any
    caller that doesn't send one.
    """
    try:
        value = int(requested)
    except (TypeError, ValueError):
        return config.DEFAULT_UPLOAD_SIZE
    if value <= 0:
        return config.DEFAULT_UPLOAD_SIZE
    return min(value, config.MAX_UPLOAD_SIZE)


def _hash_file(path):
    """MD5 of a file, streamed in HASH_CHUNK_SIZE chunks (mirrors the hashing
    pattern in yara_analyzer.scan_single_file)."""
    return _hash_file_with_prefix(path)[0]


def _hash_file_with_prefix(path, prefix_len=4096):
    """Like _hash_file, but also returns the first prefix_len bytes in the
    same pass, for callers that also need a magic-byte/content prefix (e.g.
    is_pcap_file, is_log_file) without a second full-file read."""
    h = hashlib.md5()
    prefix = b''
    with open(path, 'rb') as f:
        first = True
        for chunk in iter(lambda: f.read(config.HASH_CHUNK_SIZE), b''):
            h.update(chunk)
            if first:
                prefix = chunk[:prefix_len]
                first = False
    return h.hexdigest(), prefix


def _extract_zip_contents(zip_path, extract_dir, passwords=None, max_size=None):
    """Extract all contents of the zip file at zip_path into extract_dir.

    max_size is the decompression-size ceiling passed through to
    validate_zip_extraction (defaults to config.MAX_UPLOAD_SIZE there);
    callers should pass the resolved per-request effective_max so the
    zip-bomb budget tracks what this particular upload was actually
    allowed, not always the fixed hard ceiling.

    Returns list of extracted file paths.
    Raises ValueError if extraction fails.
    """
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        if not _attempt_zip_extract(zip_ref, extract_dir, passwords, max_size):
            raise ValueError('Password-protected ZIP could not be opened.')

    # Return all extracted files recursively, excluding hidden/metadata files
    files = []
    for root, _dirs, filenames in os.walk(extract_dir):
        for f in filenames:
            if f.startswith('.') or f.startswith('__'):
                continue
            full_path = os.path.join(root, f)
            if os.path.isfile(full_path):
                files.append(full_path)
    return files


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _add_security_headers(self):
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Content-Type-Options', 'nosniff')
        # script-src 'self' with no inline carve-out: all handlers are wired
        # via addEventListener/data-action dispatch and the theme bootstrap
        # is an external file, so injected markup (an escaping regression in
        # an innerHTML sink) renders as inert text instead of executing.
        # report-uri keeps /api/csp-report as a permanent tripwire - any
        # future violation is blocked AND logged server-side.
        # style-src keeps 'unsafe-inline' deliberately: the UI uses inline
        # style= attributes throughout, and CSS injection is a far weaker
        # primitive than script injection.
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'self'; report-uri /api/csp-report;")

    def end_headers(self):
        self._add_security_headers()
        # Prevent browser caching of HTML and static assets so upgrades
        # are reflected immediately without manual cache clearing.
        if self.path.endswith('.html') or self.path.startswith('/static/'):
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
        super().end_headers()

    def _send_error(self, code, message):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'error': message}).encode())

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_raw_json(self, json_str, status=200):
        """Like _send_json, but for a value that's already a JSON string
        (e.g. query_events_sqlite_json's output) - writes it directly
        without a redundant json.dumps() round-trip."""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json_str.encode())

    def _check_disk_space(self, required_bytes):
        """Reject upfront if DATA_DIR's filesystem doesn't have enough free
        space for an upload of required_bytes, leaving DISK_SPACE_SAFETY_MARGIN
        free so a large upload can't run the disk down to exactly zero.

        Returns True if there's enough room. Otherwise sends a 507 response
        and returns False. Fails open (returns True) if free space can't be
        determined, rather than blocking uploads over an unrelated stat error.
        """
        try:
            free = shutil.disk_usage(DATA_DIR).free
        except OSError:
            return True
        if free < required_bytes + config.DISK_SPACE_SAFETY_MARGIN:
            self._send_error(507, 'Not enough disk space available on the server for this upload')
            return False
        return True

    def _parse_content_length(self, max_size):
        """Parse and bounds-check the Content-Length header.

        Returns the validated length, or None and sends a 400 error if the
        header is missing/malformed or outside [0, max_size]. Shared by
        _read_post_body (which also reads the body right after) and
        handle_post_upload (which needs the length up front to stream the
        body through _parse_multipart_stream, rather than buffering it via
        _read_post_body's own read).
        """
        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except ValueError:
            self._send_error(400, 'Invalid Content-Length')
            return None
        if content_length < 0 or content_length > max_size:
            self._send_error(400, 'Invalid Content-Length')
            return None
        return content_length

    def _read_post_body(self, max_size):
        """Validate Content-Length and read POST body safely.

        Returns the raw body bytes, or None and sends an error response
        if validation fails.
        """
        content_length = self._parse_content_length(max_size)
        if content_length is None:
            return None
        return self.rfile.read(content_length)

    def _read_json_body(self, max_size):
        """Read and parse a JSON object POST body safely.

        Returns the parsed dict, or None and sends an error response if
        reading fails, the body isn't valid JSON, or it isn't a JSON object.

        Requires Content-Type: application/json. Browsers allow cross-site
        "simple request" POSTs (no preflight) only for a few content types -
        never application/json - so this check blocks CSRF from web pages
        while costing legitimate clients nothing (the frontend always sends
        it, and curl users add one header).
        """
        ctype = (self.headers.get('Content-Type') or '').split(';', 1)[0].strip().lower()
        if ctype != 'application/json':
            self._send_error(415, 'Content-Type must be application/json')
            return None
        post_data = self._read_post_body(max_size)
        if post_data is None:
            return None
        try:
            data = json.loads(post_data)
        except json.JSONDecodeError:
            self._send_error(400, 'Invalid JSON body')
            return None
        if not isinstance(data, dict):
            self._send_error(400, 'Invalid request body')
            return None
        return data

    def _resolve_md5_dir(self, md5):
        """Validate MD5 format and resolve to a safe data directory path.

        Returns a tuple (dir_path, error_message). On success error_message is
        None; on failure dir_path is None and error_message is a safe,
        non-internal string suitable for client responses.
        """
        if not md5:
            return None, 'MD5 parameter required'
        if not MD5_RE.match(md5):
            return None, 'Invalid MD5'
        dir_path = os.path.join(DATA_DIR, md5)
        if not is_safe_path(DATA_DIR, dir_path):
            return None, 'Invalid path'
        return dir_path, None

    def _resolve_existing_analysis_dir(self, md5):
        """Like _resolve_md5_dir, but also requires the directory to
        actually exist on disk - the "resolve this md5 to an existing
        analysis, or 400/404" shape shared by handle_post_delete_analysis/
        rename_analysis/analysis_notes/row_note/reanalyze.

        Returns (dir_path, error). On success error is None. On failure
        dir_path is None and error is a (status_code, message) tuple - the
        caller should self._send_error(*error) and return.
        """
        dir_path, error = self._resolve_md5_dir(md5)
        if error:
            return None, (400, error)
        if not os.path.exists(dir_path) or not os.path.isdir(dir_path):
            return None, (404, 'Analysis not found')
        return dir_path, None

    def _parse_search_terms(self, params):
        """Extract sanitized full-text search terms from query params."""
        q_raw = params.get('q', [])
        return [x.strip()[:config.MAX_SEARCH_TERM_LENGTH] for x in q_raw if x.strip()] or None

    def _parse_pagination(self, params, default_limit=1000):
        """Extract clamped (offset, limit) from query params, or None on bad input."""
        try:
            offset = int(params.get('offset', ['0'])[0])
            limit = int(params.get('limit', [str(default_limit)])[0])
        except ValueError:
            return None
        return max(0, offset), max(1, min(limit, config.MAX_QUERY_LIMIT))

    def _non_artifact_files(self, dir_path, pcap_file=None):
        """List the real user-uploaded file(s) in an analysis dir, excluding
        PCAPs/ZIPs, dotfiles, and known pipeline-artifact filenames.

        Shared by _resolve_display_name() (display-name fallback) and
        handle_post_reanalyze() (finding the file to re-run analysis on) -
        these two used to have separately hand-rolled, drifted versions of
        this same listing.

        Exact artifact filenames, not a blanket extension exclusion - a
        user-uploaded log file legitimately ends in .log, and a standalone
        (non-log) upload can legitimately end in .txt/.json/.db too, and
        must still be found here. zircolite.log specifically used to slip
        through an earlier, looser check and could transiently win a
        directory listing race against the real uploaded file's name.

        pcap_file, if the caller already knows it (e.g. from
        _find_pcap_file(), which also matches extension-less pcaps via
        magic bytes - not just this function's own PCAP_EXTENSIONS check),
        is excluded by exact name too.
        """
        if not os.path.exists(dir_path):
            return []
        exact_artifacts = set(PCAP_ANALYSIS_ARTIFACTS) | set(FILE_ANALYSIS_ARTIFACTS) | {'name.txt', 'notes.txt'}
        return [f for f in os.listdir(dir_path)
                if f != pcap_file
                and not f.lower().endswith(PCAP_EXTENSIONS + ('.zip',))
                and not f.startswith('.')
                and f not in exact_artifacts]

    def _resolve_display_name(self, dir_path, md5):
        """Resolve the human-readable display name for an analysis directory.

        Priority: name.txt contents, first PCAP filename, first non-artifact
        filename, then the MD5 itself.
        """
        name_path = os.path.join(dir_path, 'name.txt')
        if os.path.exists(name_path) and is_safe_path(dir_path, name_path):
            try:
                with open(name_path, 'r') as f:
                    display_name = f.read().strip()
                if display_name:
                    return display_name
            except OSError:
                pass

        if os.path.exists(dir_path):
            pcap_files = [f for f in os.listdir(dir_path) if f.lower().endswith(PCAP_EXTENSIONS)]
            if pcap_files:
                return pcap_files[0]

        non_pcap_files = self._non_artifact_files(dir_path)
        if non_pcap_files:
            return non_pcap_files[0]

        return md5

    def _validate_stream_params(self, params):
        """Returns (result, error_message, status_code). On success,
        error_message/status_code are both None."""
        src = params.get('src', [''])[0]
        sport = params.get('sport', [''])[0]
        dst = params.get('dst', [''])[0]
        dport = params.get('dport', [''])[0]
        md5 = params.get('md5', [''])[0]

        if not (validate_ip(src) and validate_ip(dst) and validate_port(sport) and validate_port(dport)):
            return None, 'Invalid IP or port', 400
        dir_path, error = self._resolve_md5_dir(md5)
        if error:
            # _resolve_md5_dir's own errors (missing/malformed md5, unsafe
            # path) are always 400 - never guessed from the message text.
            return None, error, 400

        pcap_file = _find_pcap_file(dir_path)
        pcap = os.path.join(dir_path, pcap_file) if pcap_file else None
        if not pcap:
            return None, 'No pcap file found', 404

        return {'pcap': pcap, 'src': src, 'sport': sport, 'dst': dst, 'dport': dport}, None, None

    GET_ROUTES = {
        '/api/events': 'handle_get_events',
        '/api/stats': 'handle_get_stats',
        '/api/count': 'handle_get_count',
        '/api/sankey-data': 'handle_get_sankey_data',
        '/api/aggregation-data': 'handle_get_aggregation_data',
        '/api/aggregation-totals': 'handle_get_aggregation_totals',
        '/api/download-stream': 'handle_get_download_stream',
        '/api/ascii-stream': 'handle_get_ascii_stream',
        '/api/hexdump-stream': 'handle_get_hexdump_stream',
        '/api/analyses': 'handle_get_analyses',
        '/api/load-analysis': 'handle_get_load_analysis',
        '/api/pcap-path': 'handle_get_pcap_path',
        '/api/version': 'handle_get_version',
        '/api/version-check': 'handle_get_version_check',
        '/api/limits': 'handle_get_limits',
        '/api/theme': 'handle_get_theme',
        '/api/theme-sync-available': 'handle_get_theme_sync_available',
        '/api/sigma-alerts': 'handle_get_sigma_alerts',
        '/api/sigma-count': 'handle_get_sigma_count',
        '/api/sigma-stats': 'handle_get_sigma_stats',
        '/api/status': 'handle_get_status',
        '/api/rule-update-status': 'handle_get_rule_update_status',
        '/api/rules-info': 'handle_get_rules_info',
        '/api/playbook': 'handle_get_playbook',
        '/api/ai-summary': 'handle_get_ai_summary',
    }

    POST_ROUTES = {
        '/api/upload': 'handle_post_upload',
        '/api/load-url': 'handle_post_load_url',
        '/api/check-status': 'handle_post_check_status',
        '/api/reanalyze': 'handle_post_reanalyze',
        '/api/delete-analysis': 'handle_post_delete_analysis',
        '/api/rename-analysis': 'handle_post_rename_analysis',
        '/api/analysis-notes': 'handle_post_analysis_notes',
        '/api/row-note': 'handle_post_row_note',
        '/api/acknowledge-alert': 'handle_post_acknowledge_alert',
        '/api/acknowledge-alerts-bulk': 'handle_post_acknowledge_alerts_bulk',
        '/api/delete-all-analyses': 'handle_post_delete_all_analyses',
        '/api/csp-report': 'handle_post_csp_report',
        '/api/update-rules': 'handle_post_update_rules',
    }

    # Hostnames accepted in Host/Origin headers beyond localhost and IP
    # literals; comma-separated env var for reverse-proxy/hostname deployments.
    ALLOWED_HOSTNAMES = frozenset(
        h.strip().lower()
        for h in os.environ.get('ALLOWED_HOSTS', '').split(',') if h.strip()
    )

    def _trusted_host(self, netloc):
        """True when a Host/Origin host is safe for this localhost-first app.

        IP literals are always accepted: DNS rebinding needs a *name* (the
        attacker's domain re-resolving to this server), so a raw IP in Host
        cannot be a rebinding attack, and LAN users legitimately browse to
        the server's IP. Names are limited to localhost (+subdomains) plus
        the ALLOWED_HOSTS env allowlist.
        """
        if not netloc:
            return True  # non-browser clients (curl, scripts) may omit Host
        try:
            host = urlparse('//' + netloc).hostname or ''
        except ValueError:
            return False
        if host == 'localhost' or host.endswith('.localhost'):
            return True
        if host in self.ALLOWED_HOSTNAMES:
            return True
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _reject_cross_origin(self, is_post):
        """DNS-rebinding (Host) and CSRF (Origin/Sec-Fetch-Site) defenses.

        Returns True (and sends a 403) when the request must not proceed.
        Complements _read_json_body's Content-Type check, which blocks the
        cross-site "simple request" POSTs that carry neither header.
        """
        if not self._trusted_host(self.headers.get('Host', '')):
            self._send_error(403, 'Invalid Host header')
            return True
        if not is_post:
            return False
        origin = self.headers.get('Origin')
        if origin:
            if origin.lower() == 'null':
                self._send_error(403, 'Cross-origin request rejected')
                return True
            if not self._trusted_host(urlparse(origin).netloc):
                self._send_error(403, 'Cross-origin request rejected')
                return True
        if (self.headers.get('Sec-Fetch-Site') or '').lower() == 'cross-site':
            self._send_error(403, 'Cross-origin request rejected')
            return True
        return False

    def do_GET(self):
        if self._reject_cross_origin(is_post=False):
            return
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == '/':
            self.send_response(301)
            self.send_header('Location', '/socrates.html')
            self.end_headers()
            return

        if path == '/favicon.ico':
            self.send_response(204)
            self.end_headers()
            return

        handler_name = self.GET_ROUTES.get(path)
        if handler_name:
            getattr(self, handler_name)(params)
        elif path == '/socrates.html' or path.startswith('/static/'):
            # The prefix check above runs on the raw path, but the stdlib
            # handler unquotes and normalizes before serving - so a path like
            # /static/%2e%2e/foo would escape /static/. Re-check the prefix
            # on the same normalized form the file server will actually use.
            normalized = posixpath.normpath(unquote(path))
            if normalized == '/socrates.html' or (
                    normalized.startswith('/static/')
                    and '..' not in normalized.split('/')):
                super().do_GET()
            else:
                self._send_error(404, 'Not found')
        else:
            self._send_error(404, 'Not found')

    def do_POST(self):
        if self._reject_cross_origin(is_post=True):
            return
        handler_name = self.POST_ROUTES.get(self.path)
        if handler_name:
            getattr(self, handler_name)()
        else:
            self._send_error(404, 'Not found')

    # ------------------------------------------------------------------
    # GET handlers
    # ------------------------------------------------------------------

    def handle_get_events(self, params):
        md5 = params.get('md5', [''])[0]
        dir_path, error = self._resolve_md5_dir(md5)
        if error:
            self._send_error(400, error)
            return

        pagination = self._parse_pagination(params)
        if pagination is None:
            self._send_json([])
            return
        offset, limit = pagination

        event_type = params.get('type', [''])[0] or None
        q = self._parse_search_terms(params)
        order_by = params.get('order_by', [''])[0] or None
        sort_dir = params.get('sort_dir', ['asc'])[0]
        # 'only' is the sole recognized value (used by the Acknowledged
        # Alerts tab's own fetches) - anything else, including the param's
        # absence, keeps the default exclude-acknowledged behavior every
        # other tab relies on.
        acknowledged_only = params.get('acknowledged', [''])[0] == 'only'

        db_file = os.path.join(dir_path, 'events.db')
        if os.path.exists(db_file):
            try:
                json_str, _ids = query_events_sqlite_json(db_file, event_type, offset, limit, q, order_by, sort_dir, acknowledged_only)
                self._send_raw_json(json_str)
            except Exception:
                self._send_error(500, 'Database error')
        else:
            self._send_json([])

    def handle_get_stats(self, params):
        md5 = params.get('md5', [''])[0]
        dir_path, error = self._resolve_md5_dir(md5)
        if error:
            self._send_error(400, error)
            return
        db_file = os.path.join(dir_path, 'events.db')
        q = self._parse_search_terms(params)

        counts = {}
        date_range = {'min': None, 'max': None}
        if os.path.exists(db_file):
            try:
                counts = get_event_types_sqlite(db_file, q)
                date_range = get_event_date_range_sqlite(db_file, q)
            except Exception:
                self._send_error(500, 'Database error')
                return
        self._send_json({'counts': counts, 'date_range': date_range})

    def handle_get_count(self, params):
        md5 = params.get('md5', [''])[0]
        dir_path, error = self._resolve_md5_dir(md5)
        if error:
            self._send_error(400, error)
            return
        event_type = params.get('type', [''])[0] or None
        q = self._parse_search_terms(params)
        acknowledged_only = params.get('acknowledged', [''])[0] == 'only'

        db_file = os.path.join(dir_path, 'events.db')

        if os.path.exists(db_file):
            try:
                count = get_event_count_sqlite(db_file, event_type, q, acknowledged_only)
            except Exception:
                self._send_error(500, 'Database error')
                return
        else:
            count = 0
        self._send_json({'count': count})

    def handle_get_sankey_data(self, params):
        md5 = params.get('md5', [''])[0]
        dir_path, error = self._resolve_md5_dir(md5)
        if error:
            self._send_error(400, error)
            return
        event_type = params.get('type', [''])[0] or None
        q = self._parse_search_terms(params)

        db_file = os.path.join(dir_path, 'events.db')

        if not os.path.exists(db_file):
            self._send_json({'nodes': [], 'links': []})
            return
        try:
            if q is None and _cacheable_aggregation_key(event_type):
                cache_key = (md5, event_type)
                with _CACHE_LOCK:
                    cached = _SANKEY_CACHE.get(cache_key)
                if cached is not None:
                    self._send_json(cached)
                    return
                data = get_sankey_data_sqlite(db_file, event_type, q)
                with _CACHE_LOCK:
                    _cache_put(_SANKEY_CACHE, cache_key, data)
            else:
                data = get_sankey_data_sqlite(db_file, event_type, q)
        except Exception:
            self._send_error(500, 'Database error')
            return
        self._send_json(data)

    def handle_get_aggregation_data(self, params):
        md5 = params.get('md5', [''])[0]
        dir_path, error = self._resolve_md5_dir(md5)
        if error:
            self._send_error(400, error)
            return
        event_type = params.get('type', [''])[0] or None
        q = self._parse_search_terms(params)

        # Page number and page size are both client-controllable now - page
        # size via the "Items per page" selector (AGG_PAGE_SIZE_OPTIONS in
        # static/socrates.js; only those exact values are accepted here too,
        # not just numerically clamped, so the two can never silently drift
        # apart), page number for Prev/Next pagination through one column at
        # a time (column omitted/page omitted -> the original bulk "every
        # column, page 1" fetch). Anything non-numeric/not an allowed page
        # size falls back to the original default rather than erroring.
        column = params.get('column', [''])[0] or None
        try:
            page = int(params.get('page', [''])[0])
        except (ValueError, TypeError):
            page = 1
        page = max(1, page)
        try:
            page_size = int(params.get('page_size', [''])[0])
        except (ValueError, TypeError):
            page_size = AGGREGATION_TOP_N
        if page_size not in (10, 25, 50, 100):
            page_size = AGGREGATION_TOP_N
        offset = (page - 1) * page_size

        db_file = os.path.join(dir_path, 'events.db')
        if not os.path.exists(db_file):
            self._send_json({})
            return
        try:
            if q is None and _cacheable_aggregation_key(event_type, column):
                cache_key = (md5, event_type, column, page, page_size)
                with _CACHE_LOCK:
                    cached = _AGGREGATION_CACHE.get(cache_key)
                if cached is not None:
                    self._send_json(cached)
                    return
                data = get_aggregation_data_sqlite(db_file, event_type, q, top_n=page_size, offset=offset, column=column)
                with _CACHE_LOCK:
                    _cache_put(_AGGREGATION_CACHE, cache_key, data)
            else:
                data = get_aggregation_data_sqlite(db_file, event_type, q, top_n=page_size, offset=offset, column=column)
        except Exception:
            self._send_error(500, 'Database error')
            return
        self._send_json(data)

    def handle_get_aggregation_totals(self, params):
        """Distinct-value COUNT per column - a client fetches this once per
        section open/filter change (not on every Prev/Next click) to compute
        page counts for handle_get_aggregation_data's per-page results. See
        get_aggregation_totals_sqlite's own docstring for why this is a
        separate endpoint instead of folding a total into every page."""
        md5 = params.get('md5', [''])[0]
        dir_path, error = self._resolve_md5_dir(md5)
        if error:
            self._send_error(400, error)
            return
        event_type = params.get('type', [''])[0] or None
        q = self._parse_search_terms(params)

        db_file = os.path.join(dir_path, 'events.db')
        if not os.path.exists(db_file):
            self._send_json({})
            return
        try:
            if q is None and _cacheable_aggregation_key(event_type):
                cache_key = (md5, event_type)
                with _CACHE_LOCK:
                    cached = _AGGREGATION_TOTALS_CACHE.get(cache_key)
                if cached is not None:
                    self._send_json(cached)
                    return
                data = get_aggregation_totals_sqlite(db_file, event_type, q)
                with _CACHE_LOCK:
                    _cache_put(_AGGREGATION_TOTALS_CACHE, cache_key, data)
            else:
                data = get_aggregation_totals_sqlite(db_file, event_type, q)
        except Exception:
            self._send_error(500, 'Database error')
            return
        self._send_json(data)

    def handle_get_download_stream(self, params):
        result, error, status_code = self._validate_stream_params(params)
        if error:
            self._send_error(status_code, error)
            return

        pcap = result['pcap']
        src = result['src']
        sport = result['sport']
        dst = result['dst']
        dport = result['dport']

        try:
            returncode, stdout, truncated = _run_capped(
                ['tcpdump', '-r', pcap, '-w', '-', f"host {src} and host {dst} and port {sport} and port {dport}"],
                max_bytes=config.MAX_STREAM_DOWNLOAD_SIZE,
                timeout=config.STREAM_TIMEOUT_SECONDS
            )
            if truncated:
                # A cut-off pcap is a corrupt download - refuse rather than
                # serve a partial file that looks complete.
                self._send_error(413, 'Stream too large to download')
            elif returncode == 0 and len(stdout) > 0:
                filename = f"stream_{src}_{sport}_to_{dst}_{dport}.pcap"
                self.send_response(200)
                self.send_header('Content-Type', 'application/vnd.tcpdump.pcap')
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                self.send_header('Content-Length', str(len(stdout)))
                self.end_headers()
                self.wfile.write(stdout)
            else:
                self._send_error(404, 'No packets found')
        except subprocess.TimeoutExpired:
            self._send_error(500, 'Stream carving timed out')
        except Exception:
            self._send_error(500, 'Internal server error')

    def handle_get_ascii_stream(self, params):
        result, error, status_code = self._validate_stream_params(params)
        if error:
            self._send_error(status_code, error)
            return

        pcap = result['pcap']
        src = result['src']
        sport = result['sport']
        dst = result['dst']
        dport = result['dport']

        try:
            lines = self._extract_payload_lines(pcap, src, sport, dst, dport, 'tcp')
            if not lines:
                lines = self._extract_payload_lines(pcap, src, sport, dst, dport, 'udp')

            truncated = False
            if len(lines) > config.MAX_TRANSCRIPT_LINES:
                lines = lines[:config.MAX_TRANSCRIPT_LINES]
                truncated = True

            # Enforce the character-size bound too: a handful of very long
            # lines can exceed MAX_TRANSCRIPT_SIZE even under the line cap.
            kept = []
            total_chars = 0
            for line in lines:
                total_chars += len(line['text'])
                if total_chars > MAX_TRANSCRIPT_SIZE:
                    truncated = True
                    break
                kept.append(line)
            lines = kept

            self._send_json({'lines': lines, 'truncated': truncated})
        except subprocess.TimeoutExpired:
            self._send_error(500, 'ASCII transcript extraction timed out')
        except Exception:
            self._send_error(500, 'Internal server error')

    def _extract_payload_lines(self, pcap, src, sport, dst, dport, proto):
        # Capped read: the response is trimmed to MAX_TRANSCRIPT_* far below
        # this, so anything past the cap could never be shown anyway.
        _, stdout, _ = _run_capped(
            ['tshark', '-r', pcap, '-Y',
             f'ip.addr == {src} && ip.addr == {dst} && {proto}.port == {sport} && {proto}.port == {dport}',
             '-T', 'fields', '-e', 'ip.src', '-e', f'{proto}.payload'],
            max_bytes=config.MAX_STREAM_TEXT_OUTPUT,
            timeout=config.STREAM_TIMEOUT_SECONDS, text=True
        )
        lines = []
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) < 2:
                continue
            packet_src = parts[0].strip()
            payload_hex = parts[1].replace(':', '') if len(parts) > 1 else ''
            if payload_hex:
                try:
                    payload_bytes = bytes.fromhex(payload_hex)
                    payload_str = payload_bytes.decode('utf-8', errors='replace')
                    cleaned = ''.join(c if c in '\n\r\t' or 32 <= ord(c) < 127 else '.' for c in payload_str)
                    if cleaned.strip():
                        direction = 'src' if packet_src == src else 'dst'
                        lines.append({'text': cleaned, 'direction': direction})
                except (ValueError, UnicodeDecodeError):
                    pass
        return lines

    def handle_get_hexdump_stream(self, params):
        result, error, status_code = self._validate_stream_params(params)
        if error:
            self._send_error(status_code, error)
            return

        pcap = result['pcap']
        src = result['src']
        sport = result['sport']
        dst = result['dst']
        dport = result['dport']

        try:
            _, stdout, raw_truncated = _run_capped(
                ['tcpdump', '-r', pcap, '-X', '-nn',
                 f'host {src} and host {dst} and port {sport} and port {dport}'],
                max_bytes=config.MAX_STREAM_TEXT_OUTPUT,
                timeout=config.STREAM_TIMEOUT_SECONDS, text=True
            )
            packets = []
            current_packet = None
            total_chars = 0
            truncated = raw_truncated

            for line in stdout.split('\n'):
                if not line.strip():
                    if current_packet:
                        packets.append(current_packet)
                        current_packet = None
                    continue

                if line.startswith('\t0x'):
                    if current_packet:
                        current_packet['lines'].append(line.strip())
                        total_chars += len(line)
                else:
                    if current_packet:
                        packets.append(current_packet)
                    current_packet = {'header': line.strip(), 'lines': []}

                if len(packets) >= config.MAX_HEXDUMP_PACKETS or total_chars > MAX_TRANSCRIPT_SIZE:
                    truncated = True
                    break

            if current_packet:
                packets.append(current_packet)

            self._send_json({'packets': packets, 'truncated': truncated})
        except subprocess.TimeoutExpired:
            self._send_error(500, 'Hexdump extraction timed out')
        except Exception:
            self._send_error(500, 'Internal server error')

    def handle_get_analyses(self, params):
        analyses = []
        if os.path.exists(DATA_DIR):
            candidates = []
            for md5_dir in os.listdir(DATA_DIR):
                if not MD5_RE.match(md5_dir):
                    continue
                dir_path = os.path.join(DATA_DIR, md5_dir)
                if not os.path.isdir(dir_path):
                    continue
                eve_path = os.path.join(dir_path, 'eve.json')
                db_path = os.path.join(dir_path, 'events.db')
                if os.path.exists(eve_path):
                    eve_size = os.path.getsize(eve_path)
                    if eve_size > MAX_EVE_SIZE:
                        continue

                if os.path.exists(eve_path) or os.path.exists(db_path):
                    candidates.append((md5_dir, dir_path, db_path if os.path.exists(db_path) else None))

            # Each candidate's date-range query opens its own SQLite
            # connection against an independent events.db - run them
            # concurrently rather than one at a time, same pattern as
            # db.py's Sankey/aggregation queries.
            def _date_range(db_path):
                return get_event_date_range_sqlite(db_path) if db_path else {'min': None, 'max': None}
            if candidates:
                max_workers = min(len(candidates), os.cpu_count() or 4)
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    date_ranges = executor.map(_date_range, (c[2] for c in candidates))
            else:
                date_ranges = []

            for (md5_dir, dir_path, _), date_range in zip(candidates, date_ranges):
                analyses.append({
                    'md5': md5_dir,
                    'name': self._resolve_display_name(dir_path, md5_dir),
                    'date_range': date_range,
                    'has_notes': os.path.isfile(os.path.join(dir_path, 'notes.txt')),
                })

            analyses.sort(key=lambda x: x['name'].lower())

        self._send_json(analyses)

    def handle_get_load_analysis(self, params):
        md5 = params.get('md5', [''])[0]
        dir_path, error = self._resolve_md5_dir(md5)
        if error:
            self._send_error(400, error)
            return

        eve_path = os.path.join(dir_path, 'eve.json')
        db_path = os.path.join(dir_path, 'events.db')

        if os.path.exists(eve_path) or os.path.exists(db_path):
            if os.path.exists(eve_path):
                eve_size = os.path.getsize(eve_path)
                if eve_size > MAX_EVE_SIZE:
                    self._send_error(400, f'Analysis data too large to load ({eve_size // (1024*1024)}MB, max {MAX_EVE_SIZE // (1024*1024)}MB). Try reanalyzing.')
                    return

            notes = ''
            notes_path = os.path.join(dir_path, 'notes.txt')
            if os.path.isfile(notes_path):
                try:
                    with open(notes_path, 'r') as f:
                        notes = f.read()
                except OSError:
                    notes = ''
            self._send_json({'success': True, 'md5': md5, 'file_name': self._resolve_display_name(dir_path, md5), 'notes': notes})
        else:
            self._send_error(404, 'Analysis not found')

    def handle_post_delete_analysis(self):
        data = self._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        if data is None:
            return
        md5 = data.get('md5', '')
        dir_path, error = self._resolve_existing_analysis_dir(md5)
        if error:
            self._send_error(*error)
            return

        shutil.rmtree(dir_path)
        _evict_analysis_cache(md5)
        self._send_json({'success': True})

    def handle_post_rename_analysis(self):
        """Overwrite name.txt with a user-chosen display name.

        This only ever changes what's displayed (header, previous-analyses
        list) - the real originally-uploaded filename stays intact in
        .meta's 'original' field, so nothing is lost by renaming.
        """
        data = self._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        if data is None:
            return
        md5 = data.get('md5', '')
        dir_path, error = self._resolve_existing_analysis_dir(md5)
        if error:
            self._send_error(*error)
            return

        new_name = data.get('name', '')
        if not isinstance(new_name, str):
            self._send_error(400, 'Invalid name')
            return
        # name.txt is read back as one whole-file string, not line-by-line -
        # collapse embedded newlines so they can't become part of the
        # displayed name verbatim.
        new_name = new_name.replace('\r', ' ').replace('\n', ' ').strip()[:config.MAX_DISPLAY_NAME_LENGTH]
        if not new_name:
            self._send_error(400, 'Name cannot be empty')
            return

        name_path = os.path.join(dir_path, 'name.txt')
        try:
            with open(name_path, 'w') as f:
                f.write(new_name)
        except OSError:
            self._send_error(500, 'Could not rename analysis')
            return
        self._send_json({'success': True, 'name': new_name})

    def handle_post_analysis_notes(self):
        """Overwrite (or clear) notes.txt with freeform analyst notes.

        Unlike name.txt, embedded newlines are preserved (multi-line notes
        are the point) and an empty submission is a valid, intentional way
        to clear notes rather than an error.
        """
        data = self._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        if data is None:
            return
        md5 = data.get('md5', '')
        dir_path, error = self._resolve_existing_analysis_dir(md5)
        if error:
            self._send_error(*error)
            return

        notes = data.get('notes', '')
        if not isinstance(notes, str):
            self._send_error(400, 'Invalid notes')
            return
        notes = notes.strip()[:config.MAX_NOTES_LENGTH]

        notes_path = os.path.join(dir_path, 'notes.txt')
        try:
            if notes:
                with open(notes_path, 'w') as f:
                    f.write(notes)
            else:
                try:
                    os.remove(notes_path)
                except FileNotFoundError:
                    pass
        except OSError:
            self._send_error(500, 'Could not save notes')
            return
        self._send_json({'success': True, 'notes': notes})

    def handle_post_row_note(self):
        """Create, overwrite, or (empty submission) clear the note on one
        row of the events or sigma_alerts table - the row-scoped
        counterpart to handle_post_analysis_notes above, same
        clear-on-empty convention.
        """
        data = self._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        if data is None:
            return
        md5 = data.get('md5', '')
        dir_path, error = self._resolve_existing_analysis_dir(md5)
        if error:
            self._send_error(*error)
            return

        table = data.get('table', '')
        if table not in ('events', 'sigma_alerts'):
            self._send_error(400, 'Invalid table')
            return

        row_id = data.get('rowId')
        # bool is a subclass of int in Python, so a bare isinstance(x, int)
        # check would silently accept True/False from a malformed request.
        if not isinstance(row_id, int) or isinstance(row_id, bool):
            self._send_error(400, 'Invalid rowId')
            return

        note = data.get('note', '')
        if not isinstance(note, str):
            self._send_error(400, 'Invalid note')
            return
        note = note.strip()[:config.MAX_ROW_NOTE_LENGTH]

        db_file = os.path.join(dir_path, 'events.db')
        if not os.path.exists(db_file):
            self._send_error(404, 'Analysis not found')
            return
        try:
            set_row_note(db_file, table, row_id, note)
        except (OSError, sqlite3.Error):
            # get_row_notes/has_row_notes (the read-path siblings of
            # set_row_note) both already catch sqlite3.OperationalError and
            # degrade to an empty result - set_row_note itself has no such
            # guard (a write failure can't silently degrade to "success"),
            # so this catch belongs at the caller. sqlite3.Error is not an
            # OSError subclass, so a genuine SQLite failure here (lock
            # contention past the busy_timeout, disk I/O error, corruption)
            # used to propagate uncaught instead of becoming a clean 500.
            self._send_error(500, 'Could not save note')
            return
        self._send_json({'success': True, 'note': note})

    def _validate_ack_table(self, data):
        """Shared table validation for both acknowledge endpoints below -
        same shape as handle_post_row_note's own check. Returns the table
        name on success, or None after already sending an error response."""
        table = data.get('table', '')
        if table not in ('events', 'sigma_alerts'):
            self._send_error(400, 'Invalid table')
            return None
        return table

    def _validate_ack_row_id(self, data):
        """Shared table/rowId validation for the single-row acknowledge
        endpoint below. Returns (table, row_id) on success, or (None, None)
        after already sending an error response."""
        table = self._validate_ack_table(data)
        if table is None:
            return None, None
        row_id = data.get('rowId')
        if not isinstance(row_id, int) or isinstance(row_id, bool):
            self._send_error(400, 'Invalid rowId')
            return None, None
        return table, row_id

    def handle_post_acknowledge_alert(self):
        """Acknowledge or un-acknowledge one alert row - the single-row
        counterpart to handle_post_acknowledge_alerts_bulk below. Removing
        an alert from view (rather than just flagging it) happens entirely
        as a side effect of set_acknowledged() feeding into every read
        query's own WHERE clause (see db.py's _build_where_conditions/
        _sigma_alert_where) - nothing else needs updating here.
        """
        data = self._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        if data is None:
            return
        md5 = data.get('md5', '')
        dir_path, error = self._resolve_existing_analysis_dir(md5)
        if error:
            self._send_error(*error)
            return

        table, row_id = self._validate_ack_row_id(data)
        if table is None:
            return

        acknowledged = data.get('acknowledged', True)
        if not isinstance(acknowledged, bool):
            self._send_error(400, 'Invalid acknowledged')
            return

        db_file = os.path.join(dir_path, 'events.db')
        if not os.path.exists(db_file):
            self._send_error(404, 'Analysis not found')
            return
        try:
            set_acknowledged(db_file, table, row_id, acknowledged)
        except (OSError, sqlite3.Error):
            self._send_error(500, 'Could not update acknowledged state')
            return
        self._send_json({'success': True, 'acknowledged': acknowledged})

    def handle_post_acknowledge_alerts_bulk(self):
        """Acknowledge every id in rowIds in one call - the "all instances
        of this alert" path. The matching row-id set is computed
        client-side (from whatever's already loaded via ensureCappedBatch)
        rather than server-side by signature_id/rule_id, so this is a
        dumb bulk insert, not a filtered query of its own. No bulk
        un-acknowledge counterpart - undoing is always one row at a time,
        from within the Acknowledged Alerts tab.
        """
        data = self._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        if data is None:
            return
        md5 = data.get('md5', '')
        dir_path, error = self._resolve_existing_analysis_dir(md5)
        if error:
            self._send_error(*error)
            return

        table = self._validate_ack_table(data)
        if table is None:
            return

        row_ids = data.get('rowIds')
        # Same bool-is-an-int-subclass guard as the single-row path above,
        # applied to every entry - and a defensive cap (matching the
        # server's own hard query-result ceiling, config.MAX_QUERY_LIMIT)
        # against a malformed/hostile request trying to force an
        # enormous executemany.
        if (not isinstance(row_ids, list) or not row_ids
                or len(row_ids) > config.MAX_QUERY_LIMIT
                or not all(isinstance(r, int) and not isinstance(r, bool) for r in row_ids)):
            self._send_error(400, 'Invalid rowIds')
            return

        db_file = os.path.join(dir_path, 'events.db')
        if not os.path.exists(db_file):
            self._send_error(404, 'Analysis not found')
            return
        try:
            set_acknowledged_bulk(db_file, table, row_ids)
        except (OSError, sqlite3.Error):
            self._send_error(500, 'Could not update acknowledged state')
            return
        self._send_json({'success': True, 'count': len(row_ids)})

    # Dedupe key -> True for CSP violations already logged this run, so a
    # page with one unconverted inline handler doesn't flood the console on
    # every click. Bounded: cleared when it grows past a sane size.
    _CSP_REPORTS_SEEN = {}

    def handle_post_csp_report(self):
        """Sink for Content-Security-Policy violation reports.

        Browsers POST these with Content-Type: application/csp-report, so
        this reads the raw body instead of going through _read_json_body's
        application/json requirement. The enforced policy's report-uri
        points here, so any future inline-script regression is blocked by
        the browser AND logged (deduplicated) server-side. Always 204.
        """
        body = self._read_post_body(65536)
        if body is None:
            return
        try:
            report = json.loads(body).get('csp-report', {})
        except (json.JSONDecodeError, AttributeError):
            report = {}
        if report:
            key = (report.get('violated-directive'),
                   report.get('blocked-uri'),
                   report.get('source-file'),
                   report.get('line-number'))
            if key not in self._CSP_REPORTS_SEEN:
                if len(self._CSP_REPORTS_SEEN) > 512:
                    self._CSP_REPORTS_SEEN.clear()
                self._CSP_REPORTS_SEEN[key] = True
                print(f"CSP report: {report.get('violated-directive')} "
                      f"blocked={report.get('blocked-uri')} "
                      f"at {report.get('source-file')}:{report.get('line-number')}")
        self.send_response(204)
        self.end_headers()

    def handle_post_delete_all_analyses(self):
        deleted = 0
        errors = []
        if os.path.exists(DATA_DIR):
            for md5_dir in os.listdir(DATA_DIR):
                if not MD5_RE.match(md5_dir):
                    continue
                dir_path = os.path.join(DATA_DIR, md5_dir)
                if not os.path.isdir(dir_path):
                    continue
                if not is_safe_path(DATA_DIR, dir_path):
                    errors.append(md5_dir)
                    continue
                try:
                    shutil.rmtree(dir_path)
                    deleted += 1
                except Exception as e:
                    errors.append(f'{md5_dir}: {e}')
        if errors and deleted == 0:
            self._send_error(500, f'Could not delete analyses: {errors[0]}')
            return
        with _CACHE_LOCK:
            for cache in _ALL_CACHES:
                cache.clear()
        self._send_json({'success': True, 'deleted': deleted})

    def handle_post_update_rules(self):
        data = self._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        if data is None:
            return
        ruleset = data.get('ruleset', '')
        if ruleset not in ('suricata', 'yara', 'sigma', 'all'):
            self._send_error(400, "ruleset must be one of 'suricata', 'yara', 'sigma', 'all'")
            return

        sources = data.get('sources')
        if sources is not None:
            if not isinstance(sources, list) or not all(isinstance(s, str) for s in sources):
                self._send_error(400, "sources must be a list of strings")
                return
            unknown = [s for s in sources if s not in SURICATA_RULE_SOURCES]
            if unknown:
                self._send_error(400, f"unknown suricata source(s): {', '.join(unknown)}")
                return

        show_protocol_decode_alerts = data.get('showProtocolDecodeAlerts')
        if show_protocol_decode_alerts is not None and not isinstance(show_protocol_decode_alerts, bool):
            self._send_error(400, "showProtocolDecodeAlerts must be a boolean")
            return

        names = ('suricata', 'yara', 'sigma') if ruleset == 'all' else (ruleset,)
        # Check-and-set every targeted ruleset's 'running' flag under a
        # single lock acquisition - for 'all' this must check+set all three
        # keys atomically together, not one at a time, or two concurrent
        # 'all' requests could interleave and each start a different subset.
        with _rule_update_lock:
            if any(_rule_update_state[n]['running'] for n in names):
                self._send_error(409, 'Rule update already in progress')
                return
            for n in names:
                _rule_update_state[n] = {'running': True, 'lines': [], 'done': False, 'error': None}
        for n in names:
            threading.Thread(
                target=_run_ruleset_update,
                args=(n, sources if n == 'suricata' else None, show_protocol_decode_alerts if n == 'suricata' else None),
                daemon=True).start()
        self._send_json({'status': 'started'})

    def handle_get_rule_update_status(self, params):
        # Copy 'lines' (not just the outer dict) while holding the lock, and
        # send the response after releasing it - holding the lock across
        # the socket write would stall the background job's on_progress()
        # appends if this client is slow to read.
        with _rule_update_lock:
            state = {
                n: {
                    'running': _rule_update_state[n]['running'],
                    'lines': list(_rule_update_state[n]['lines']),
                    'done': _rule_update_state[n]['done'],
                    'error': _rule_update_state[n]['error'],
                }
                for n in _rule_update_state
            }
        self._send_json(state)

    def handle_get_rules_info(self, params):
        suricata_info = get_suricata_rules_info(DATA_DIR)
        suricata_info['enabledSources'] = get_suricata_enabled_sources(DATA_DIR)
        suricata_info['showProtocolDecodeAlerts'] = get_suricata_show_protocol_decode_alerts(DATA_DIR)
        # bakedIn tells the Rules modal whether a not-yet-staged source
        # needs internet the first time it's enabled (see
        # BAKED_IN_SURICATA_SOURCES's own comment for why ipfire/dbl is the
        # only current exception) - computed here rather than stored on
        # SURICATA_RULE_SOURCES itself so there's exactly one place
        # (BAKED_IN_SURICATA_SOURCES) that can ever disagree with the
        # Dockerfile's own bake loop.
        suricata_info['availableSources'] = {
            slug: {**info, 'bakedIn': slug in BAKED_IN_SURICATA_SOURCES}
            for slug, info in SURICATA_RULE_SOURCES.items()
        }
        # Lets "Revert to Default" in the Rules modal read the actual
        # default instead of hardcoding 'et/open' client-side - the same
        # reasoning as bakedIn above: DEFAULT_SURICATA_SOURCES is already
        # the single source of truth (_reconcile_suricata_sources()'s own
        # empty-selection fallback), so the frontend must not keep an
        # independent copy that could silently drift from it.
        suricata_info['defaultSources'] = list(DEFAULT_SURICATA_SOURCES)
        # Single source of truth for classifying an alert's signature_id to
        # the ruleset it came from - static/socrates.js's classifyRuleset()
        # reads this instead of hardcoding a duplicate range table, mirroring
        # db.py's sid_ranges_sql_case() (both generated from
        # suricata_sid_ranges.SURICATA_SID_RANGES).
        suricata_info['sidRanges'] = (
            [{'min': min_sid, 'max': max_sid, 'label': label}
             for min_sid, max_sid, _slug, label in SURICATA_SID_RANGES]
            + [{'min': SURICATA_BUILTIN_SID_RANGE[0], 'max': SURICATA_BUILTIN_SID_RANGE[1],
                'label': SURICATA_BUILTIN_LABEL}]
        )
        self._send_json({
            'suricata': suricata_info,
            'yara': get_yara_rules_info(DATA_DIR),
            'sigma': get_sigma_rules_info(DATA_DIR),
            # Single source of truth for "how old is too old", so the
            # frontend's own staleness indicator (Rules modal's amber date
            # warning) can't independently drift from the 'stale' fields
            # above the way it used to (see config.RULES_MAX_AGE_HOURS).
            'staleThresholdHours': config.RULES_MAX_AGE_HOURS,
        })

    # Strict per-type allowlist for handle_get_playbook's `id` param - rule_id
    # is a dict key into playbook_lookup's in-memory index, not a filesystem
    # path component, so this isn't guarding against path traversal, but it's
    # still unscoped client input and worth rejecting early with a clean 400
    # rather than a silent miss on garbage.
    _PLAYBOOK_ID_PATTERNS = {
        'nids': re.compile(r'^[0-9]{1,10}$'),
        'sigma': re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'),
    }

    def handle_get_playbook(self, params):
        """Security Onion Playbooks - global static reference data baked
        into the image (see playbook_lookup.py), deliberately not scoped
        to an analysis - unlike almost every other route here, this one
        takes no md5."""
        detection_type = params.get('type', [''])[0]
        rule_id = params.get('id', [''])[0]
        pattern = self._PLAYBOOK_ID_PATTERNS.get(detection_type)
        if not pattern or not pattern.match(rule_id):
            self._send_error(400, 'Invalid type or id')
            return
        self._send_json({'playbook': get_playbook(detection_type, rule_id)})

    # Same rationale as _PLAYBOOK_ID_PATTERNS above, kept as a separate dict
    # (not shared) so the two can evolve independently - e.g. 'yara' is valid
    # here but not (yet) for Playbooks. nids/sigma reuse identical shapes;
    # 'yara' rule names are bare identifiers (checked against every baked-in
    # name: max observed length 116, so 200 leaves headroom).
    _AI_SUMMARY_ID_PATTERNS = {
        'nids': re.compile(r'^[0-9]{1,10}$'),
        'sigma': re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'),
        'yara': re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,199}$'),
    }

    def handle_get_ai_summary(self, params):
        """AI-generated per-rule summaries - global static reference data
        baked into the image (see ai_summary_lookup.py), deliberately not
        scoped to an analysis - same shape as handle_get_playbook above."""
        detection_type = params.get('type', [''])[0]
        rule_id = params.get('id', [''])[0]
        pattern = self._AI_SUMMARY_ID_PATTERNS.get(detection_type)
        if not pattern or not pattern.match(rule_id):
            self._send_error(400, 'Invalid type or id')
            return
        self._send_json({'summary': get_ai_summary(detection_type, rule_id)})

    def handle_get_pcap_path(self, params):
        md5 = params.get('md5', [''])[0]
        dir_path, error = self._resolve_md5_dir(md5)
        if error:
            self._send_error(400, error)
            return
        pcap_file = _find_pcap_file(dir_path)
        if pcap_file:
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            # Return only the filename, not the absolute path
            self.wfile.write(pcap_file.encode())
        else:
            self._send_error(404, 'No pcap found')

    def handle_get_version(self, params):
        self._send_json({'version': VERSION})

    def handle_get_version_check(self, params):
        """Hits GitHub's releases API - the frontend never calls this route
        unless the user has explicitly opted in via the Settings checkbox
        (see pollOhmydebnTheme() for the same "check localStorage before
        ever fetching" pattern this mirrors). GITHUB_RELEASES_API is a
        hardcoded constant, not user input, so this doesn't need the
        SSRF-hardened path _fetch_url_safely() exists for - same reasoning
        already applied to the YARA Forge/Sigma rule downloads' hardcoded
        URLs."""
        latest_version = None
        update_available = False
        try:
            req = urllib.request.Request(
                GITHUB_RELEASES_API,
                headers={'User-Agent': 'so-crates', 'Accept': 'application/vnd.github+json'},
            )
            with urllib.request.urlopen(req, timeout=config.URL_DOWNLOAD_TIMEOUT) as resp:
                data = json.loads(resp.read())
            tag = data.get('tag_name', '')
            candidate = tag[1:] if tag.startswith('v') else tag
            if _is_newer_version(candidate, VERSION):
                latest_version = candidate
                update_available = True
        except (OSError, urllib.error.URLError, ValueError, AttributeError):
            pass
        self._send_json({
            'currentVersion': VERSION,
            'latestVersion': latest_version,
            'updateAvailable': update_available,
        })

    def handle_get_limits(self, params):
        self._send_json({'maxQueryLimit': config.MAX_QUERY_LIMIT, 'maxUploadSize': config.MAX_UPLOAD_SIZE})

    def _read_ohmydebn_theme_name(self):
        """Reads the raw contents of <OHMYDEBN_THEME_DIR>/current/theme.name,
        or None if OHMYDEBN_THEME_DIR is unset or the file can't be read.
        Callers apply their own notion of validity on top of this."""
        if not OHMYDEBN_THEME_DIR:
            return None
        try:
            name_path = os.path.join(OHMYDEBN_THEME_DIR, 'current', 'theme.name')
            with open(name_path, 'r') as f:
                return f.read(256).strip()
        except OSError:
            return None

    def handle_get_theme(self, params):
        candidate = self._read_ohmydebn_theme_name()
        theme = candidate if candidate and THEME_NAME_RE.match(candidate) else None
        self._send_json({'theme': theme, 'customColors': _get_ohmydebn_custom_colors()})

    def handle_get_theme_sync_available(self, params):
        """Lets the frontend hide the "Sync theme to OhMyDebn" toggle
        entirely rather than showing a control that can never do anything
        (OHMYDEBN_THEME_DIR unset, or its theme.name unreadable)."""
        self._send_json({'available': self._read_ohmydebn_theme_name() is not None})

    def handle_get_sigma_alerts(self, params):
        md5 = params.get('md5', [''])[0]
        dir_path, error = self._resolve_md5_dir(md5)
        if error:
            self._send_error(400, error)
            return

        pagination = self._parse_pagination(params)
        if pagination is None:
            self._send_json([])
            return
        offset, limit = pagination

        severity = params.get('severity', [''])[0] or None
        q = self._parse_search_terms(params)
        acknowledged_only = params.get('acknowledged', [''])[0] == 'only'

        db_file = os.path.join(dir_path, 'events.db')
        if os.path.exists(db_file):
            try:
                alerts = query_sigma_alerts_sqlite(db_file, offset, limit, q, severity, acknowledged_only)
                self._send_json(alerts)
            except Exception:
                self._send_error(500, 'Database error')
        else:
            self._send_json([])

    def handle_get_sigma_count(self, params):
        md5 = params.get('md5', [''])[0]
        dir_path, error = self._resolve_md5_dir(md5)
        if error:
            self._send_error(400, error)
            return
        q = self._parse_search_terms(params)
        severity = params.get('severity', [''])[0] or None
        acknowledged_only = params.get('acknowledged', [''])[0] == 'only'

        db_file = os.path.join(dir_path, 'events.db')

        if os.path.exists(db_file):
            try:
                count = get_sigma_alert_count_sqlite(db_file, q, severity, acknowledged_only)
            except Exception:
                self._send_error(500, 'Database error')
                return
        else:
            count = 0
        self._send_json({'count': count})

    def handle_get_sigma_stats(self, params):
        md5 = params.get('md5', [''])[0]
        dir_path, error = self._resolve_md5_dir(md5)
        if error:
            self._send_error(400, error)
            return

        db_file = os.path.join(dir_path, 'events.db')
        if os.path.exists(db_file):
            try:
                stats = get_sigma_stats_sqlite(db_file)
                self._send_json(stats)
            except Exception:
                self._send_error(500, 'Database error')
        else:
            self._send_json({})

    def _commit_file_or_return_ready(self, dir_path, md5_hash, dedup_markers, commit_fn):
        """Shared first step of every _process_uploaded_file branch: if any
        dedup_markers file already exists in dir_path, this upload is a
        duplicate of an already-completed analysis - return the 'ready'
        response immediately without touching anything on disk. Otherwise
        create dir_path and call commit_fn() to move the uploaded/extracted
        file into place.

        Returns the 'ready' response dict if deduped (caller should return
        it immediately), or None if the caller should continue processing.
        """
        if any(os.path.exists(os.path.join(dir_path, marker)) for marker in dedup_markers):
            return {'status': 'ready', 'md5': md5_hash}
        os.makedirs(dir_path, exist_ok=True)
        commit_fn()
        return None

    def _commit_and_spawn_pcap_analysis(self, extracted_pcap_path, safe_filename, md5_hash=None):
        """Hash one already-extracted pcap (unless the caller already knows
        its hash - see _process_uploaded_file's within-batch dedup), commit
        it into DATA_DIR/<md5>/ if not already analyzed, and spawn Suricata.
        Used both for a ZIP's primary pcap and every additional pcap found
        alongside it.

        Returns (md5_hash, deduped: bool).
        """
        if md5_hash is None:
            md5_hash = _hash_file(extracted_pcap_path)
        dir_path = os.path.join(DATA_DIR, md5_hash)
        pcap_filename = sanitize_filename(os.path.basename(extracted_pcap_path))
        pcap_path = os.path.join(dir_path, pcap_filename)

        deduped = self._commit_file_or_return_ready(
            dir_path, md5_hash, ('eve.json',),
            lambda: shutil.move(extracted_pcap_path, pcap_path)
        )
        if not deduped:
            with open(os.path.join(dir_path, 'name.txt'), 'w') as f:
                f.write(pcap_filename)
            _write_meta(dir_path, safe_filename, pcap_filename, 'pcap')
            spawn_suricata(dir_path, pcap_path, os.path.join(SURICATA_DIR, 'suricata.yaml'), data_dir=DATA_DIR)
        return md5_hash, bool(deduped)

    def _commit_and_analyze_standalone_file(self, extracted_path, safe_filename, md5_hash, prefix):
        """Commit one already-extracted, already-hashed non-pcap file (see
        _hash_file_with_prefix) into DATA_DIR/<md5>/ if not already
        analyzed, and dispatch it to log or binary/YARA analysis in the
        background. Mirrors _commit_and_spawn_pcap_analysis for the pcap
        case - md5_hash/prefix are always precomputed by the caller so
        within-zip duplicate content can be recognized before ever
        touching disk (see _process_uploaded_file's within-batch dedup).

        Returns (md5_hash, deduped: bool, detected_type: 'log'|'binary').
        """
        dir_path = os.path.join(DATA_DIR, md5_hash)
        dest_filename = sanitize_filename(os.path.basename(extracted_path))
        dest_path = os.path.join(dir_path, dest_filename)

        deduped = self._commit_file_or_return_ready(
            dir_path, md5_hash, ('events.db',),
            lambda: shutil.move(extracted_path, dest_path)
        )
        detected = 'log' if (is_log_file(prefix) or is_log_file_by_extension(dest_path)) else 'binary'
        if not deduped:
            _write_meta(dir_path, safe_filename, dest_filename, detected)
            if detected == 'log':
                self._analyze_log_file(dir_path, dest_path, dest_filename)
            else:
                self._analyze_standalone_file(dir_path, dest_path, dest_filename)
        return md5_hash, bool(deduped), detected

    def _process_uploaded_file(self, src_path, original_filename, passwords=None, effective_max=None):
        """Process uploaded or downloaded file: detect ZIP, extract, find PCAP, compute MD5, dispatch.

        Args:
            src_path: Path to the already-on-disk uploaded/downloaded file
                (e.g. under _upload_tmp_dir()). This function takes ownership
                of it -- it's moved into place on success and unlinked in all
                other cases (dedup-return, zip extraction, failure).
            original_filename: Original filename for password derivation.
            passwords: Optional list of bytes passwords for ZIP extraction.
            effective_max: The resolved per-request upload-size ceiling (see
                _resolve_upload_size_limit), passed through to zip-bomb
                decompression-size checks so it tracks what this particular
                upload was actually allowed rather than always the fixed
                hard ceiling. Defaults to config.MAX_UPLOAD_SIZE if not given.

        Returns:
            dict with 'status' and 'md5' keys.

        Raises:
            ValueError: For extraction or validation failures.
        """
        try:
            safe_filename = sanitize_filename(original_filename)
            with open(src_path, 'rb') as f:
                magic = f.read(2)
            is_zip = magic == b'PK'

            if is_zip and not is_office_file_by_extension(safe_filename):
                tmp_dir = tempfile.mkdtemp(dir=_upload_tmp_dir())
                try:
                    extracted_files = _extract_zip_contents(src_path, tmp_dir, passwords or [], effective_max)
                    # Every extracted file is analyzed, each as its own
                    # independent analysis - pcaps get network analysis
                    # (_commit_and_spawn_pcap_analysis), everything else
                    # gets log/binary analysis
                    # (_commit_and_analyze_standalone_file). 'filesSkipped'
                    # now only ever reflects genuine per-file failures, not
                    # by-design drops.
                    non_hidden_extracted = [f for f in extracted_files if not os.path.basename(f).startswith('.')]
                    pcap_files = [f for f in extracted_files if f.lower().endswith(PCAP_EXTENSIONS)]
                    pcap_file_set = set(pcap_files)
                    non_pcap_files = [f for f in non_hidden_extracted if f not in pcap_file_set]

                    if pcap_files:
                        primary_md5, primary_deduped = self._commit_and_spawn_pcap_analysis(pcap_files[0], safe_filename)
                        primary_phase = 'network'
                        remaining_pcaps = pcap_files[1:]
                        remaining_non_pcaps = non_pcap_files
                    else:
                        if not non_pcap_files:
                            raise ValueError('ZIP archive is empty')
                        first_md5, first_prefix = _hash_file_with_prefix(non_pcap_files[0])
                        primary_md5, primary_deduped, primary_detected = self._commit_and_analyze_standalone_file(
                            non_pcap_files[0], safe_filename, first_md5, first_prefix)
                        primary_phase = 'logs' if primary_detected == 'log' else 'files'
                        remaining_pcaps = []
                        remaining_non_pcaps = non_pcap_files[1:]

                    # A duplicate's own dedup marker (eve.json/events.db)
                    # can't have appeared yet for a byte-identical *later*
                    # file in this same zip while its analysis is still in
                    # flight - track md5s already handled in this batch and
                    # check *before* committing/analyzing (not just before
                    # listing) so such a duplicate is never re-committed or
                    # double-analyzed.
                    seen = {primary_md5}
                    additional_md5s = []
                    failed_count = 0

                    for extra in remaining_pcaps:
                        try:
                            md5_hash = _hash_file(extra)
                        except OSError:
                            failed_count += 1
                            continue
                        if md5_hash in seen:
                            continue
                        try:
                            self._commit_and_spawn_pcap_analysis(extra, safe_filename, md5_hash=md5_hash)
                        except (OSError, ValueError):
                            # ValueError: e.g. a reserved artifact filename
                            # inside the ZIP - skip that member, keep the rest
                            failed_count += 1
                            continue
                        seen.add(md5_hash)
                        additional_md5s.append(md5_hash)

                    for extra in remaining_non_pcaps:
                        try:
                            md5_hash, prefix = _hash_file_with_prefix(extra)
                        except OSError:
                            failed_count += 1
                            continue
                        if md5_hash in seen:
                            continue
                        try:
                            self._commit_and_analyze_standalone_file(extra, safe_filename, md5_hash, prefix)
                        except (OSError, ValueError):
                            failed_count += 1
                            continue
                        seen.add(md5_hash)
                        additional_md5s.append(md5_hash)

                    if primary_deduped:
                        response = {'status': 'ready', 'md5': primary_md5}
                    else:
                        response = {'status': 'processing', 'md5': primary_md5, 'phase': primary_phase}
                    if additional_md5s:
                        response['additionalMd5s'] = additional_md5s
                    if failed_count:
                        response['filesSkipped'] = failed_count
                    return response
                finally:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
            else:
                md5_hash, prefix = _hash_file_with_prefix(src_path)
                dir_path = os.path.join(DATA_DIR, md5_hash)
                dest_filename = safe_filename if safe_filename else 'uploaded'
                dest_path = os.path.join(dir_path, dest_filename)
                name_path = os.path.join(dir_path, 'name.txt')

                deduped = self._commit_file_or_return_ready(
                    dir_path, md5_hash, ('eve.json', 'events.db'),
                    lambda: os.replace(src_path, dest_path)
                )
                if deduped:
                    return deduped
                with open(name_path, 'w') as f:
                    f.write(dest_filename)

                if is_pcap_file(prefix):
                    detected = 'pcap'
                    spawn_suricata(dir_path, dest_path, os.path.join(SURICATA_DIR, 'suricata.yaml'), data_dir=DATA_DIR)
                    phase = 'network'
                elif is_log_file(prefix) or is_log_file_by_extension(dest_path):
                    detected = 'log'
                    self._analyze_log_file(dir_path, dest_path, dest_filename)
                    phase = 'logs'
                else:
                    detected = 'binary'
                    self._analyze_standalone_file(dir_path, dest_path, dest_filename)
                    phase = 'files'
                _write_meta(dir_path, dest_filename, dest_filename, detected)
                return {'status': 'processing', 'md5': md5_hash, 'phase': phase}
        finally:
            if os.path.exists(src_path):
                os.unlink(src_path)

    def _analyze_standalone_file(self, dir_path, file_path, safe_filename):
        """Run standalone YARA analysis on a non-PCAP file in the background."""
        def run_analysis():
            _set_phase(dir_path, 'files')

            try:
                # network_allowed=False: analysis must never silently reach
                # out to refresh rules on its own - that's now an explicit,
                # opt-in action (Rules modal, or the checkForStaleRules()
                # notification). Uses whatever's already cached/baked-in,
                # however old.
                rules_file = setup_yara_rules(DATA_DIR, network_allowed=False)
                db_file = os.path.join(dir_path, 'events.db')
                name_path = os.path.join(dir_path, 'name.txt')

                if rules_file and check_yara_executable():
                    try:
                        matches, sha256, md5, sha1, metadata = scan_single_file(file_path, rules_file)
                        create_file_analysis_db(db_file, file_path, matches, md5, sha1, sha256, metadata=metadata)
                    except Exception as e:
                        _set_error(dir_path, f'YARA scan failed: {e}')
                        create_file_analysis_db(db_file, file_path, [], '', '', '')
                else:
                    create_file_analysis_db(db_file, file_path, [], '', '', '')

                with open(name_path, 'w') as f:
                    f.write(safe_filename)
            except Exception as e:
                _set_error(dir_path, f'Analysis failed: {e}')
            finally:
                _clear_phase(dir_path)

        threading.Thread(target=run_analysis, daemon=True).start()

    def _analyze_log_file(self, dir_path, file_path, safe_filename):
        """Run Zircolite Sigma analysis on a log file in the background."""
        def run_analysis():
            _set_phase(dir_path, 'logs')

            try:
                db_file = os.path.join(dir_path, 'events.db')
                name_path = os.path.join(dir_path, 'name.txt')

                if not is_zircolite_available():
                    _set_error(dir_path, f'Sigma analysis unavailable — Zircolite is not installed. Install with: pip3 install zircolite=={config.ZIRCOLITE_VERSION}')
                    init_empty_db(db_file)
                else:
                    try:
                        success, zircolite_db = run_sigma_pipeline(dir_path, file_path, data_dir=DATA_DIR)
                        if success:
                            # Import all log events from Zircolite's unified DB
                            if zircolite_db and os.path.exists(zircolite_db):
                                import_zircolite_logs(zircolite_db, db_file)
                                try:
                                    os.unlink(zircolite_db)
                                except OSError:
                                    pass
                            # Import sigma alerts
                            sigma_output = os.path.join(dir_path, 'sigma_matches.json')
                            alerts = parse_zircolite_results(sigma_output)
                            insert_sigma_alerts(db_file, alerts)
                        else:
                            # Rules missing or Zircolite failed: create empty DB so UI shows ready
                            init_empty_db(db_file)
                    except Exception as e:
                        _set_error(dir_path, f'Sigma analysis failed: {e}')

                with open(name_path, 'w') as f:
                    f.write(safe_filename)
            except Exception as e:
                _set_error(dir_path, f'Log analysis failed: {e}')
            finally:
                _clear_phase(dir_path)

        threading.Thread(target=run_analysis, daemon=True).start()

    # ------------------------------------------------------------------
    # POST handlers
    # ------------------------------------------------------------------

    def _parse_multipart_stream(self, rfile, content_length, content_type, dest_dir, chunk_size=64 * 1024):
        """Extract the first uploaded file from a streamed multipart/form-data
        body, writing it directly to a temp file under dest_dir instead of
        buffering the whole body in memory.

        Returns (tmp_path, filename) or (None, None) on failure (any partial
        temp file is cleaned up before returning in the failure case).
        """
        boundary_match = re.search(r'boundary=("[^"]+"|[^;\s]+)', content_type, re.IGNORECASE)
        if not boundary_match:
            return None, None

        boundary = boundary_match.group(1).strip().strip('"\'').encode()
        if not boundary:
            return None, None

        delimiter = b'--' + boundary
        end_delim = b'\r\n--' + boundary

        remaining = [content_length]

        def read_chunk():
            if remaining[0] <= 0:
                return b''
            chunk = rfile.read(min(chunk_size, remaining[0]))
            if not chunk:
                remaining[0] = 0
                return b''
            remaining[0] -= len(chunk)
            return chunk

        # Phase 1: accumulate a bounded buffer until we've seen the first
        # boundary line AND the end of the part headers (both are small and
        # near the start, so this never needs more than a small window --
        # capped defensively in case of a malformed/boundary-less body).
        MAX_HEADER_BUF = 64 * 1024
        buf = b''
        header_start = header_end = -1
        while True:
            chunk = read_chunk()
            if chunk:
                buf += chunk
            delim_pos = buf.find(delimiter)
            if delim_pos != -1:
                header_start = delim_pos + len(delimiter)
                if buf[header_start:header_start + 2] == b'\r\n':
                    header_start += 2
                header_end = buf.find(b'\r\n\r\n', header_start)
                if header_end != -1:
                    break
            if not chunk:
                return None, None
            if len(buf) > MAX_HEADER_BUF:
                return None, None

        headers = buf[header_start:header_end].decode('utf-8', errors='replace')
        filename = None
        # Quoted filename (handles escaped quotes per RFC 6266).
        cd_match = re.search(
            r'Content-Disposition:\s*form-data\s*;[^\r\n]*filename="((?:\\.|[^\\"])*)"',
            headers,
            re.IGNORECASE,
        )
        if cd_match:
            filename = cd_match.group(1).replace('\\"', '"').replace('\\\\', '\\')
        else:
            # Unquoted filename.
            unquoted_match = re.search(
                r'Content-Disposition:\s*form-data\s*;[^\r\n]*filename=([^;\r\n]+)',
                headers,
                re.IGNORECASE,
            )
            if unquoted_match:
                filename = unquoted_match.group(1).strip()
        if not filename:
            return None, None

        # Phase 2: stream the rest of the body to a temp file, holding back
        # the last len(end_delim)-1 bytes at all times so an end-delimiter
        # split across two chunk reads is still caught correctly.
        fd, tmp_path = tempfile.mkstemp(dir=dest_dir)
        hold = len(end_delim) - 1
        found = False
        try:
            with os.fdopen(fd, 'wb') as out:
                lookback = b''
                pending = buf[header_end + 4:]
                while True:
                    window = lookback + pending
                    idx = window.find(end_delim)
                    if idx != -1:
                        out.write(window[:idx])
                        found = True
                        break
                    if len(window) > hold:
                        out.write(window[:-hold])
                        lookback = window[-hold:]
                    else:
                        lookback = window
                    pending = read_chunk()
                    if not pending:
                        break
            if not found:
                os.unlink(tmp_path)
                return None, None
            return tmp_path, filename
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    def handle_post_upload(self):
        effective_max = _resolve_upload_size_limit(self.headers.get('X-Max-Upload-Size'))
        content_length = self._parse_content_length(effective_max)
        if content_length is None:
            return
        if not self._check_disk_space(effective_max):
            return

        content_type = self.headers.get('Content-Type', '')
        src_path, original_filename = self._parse_multipart_stream(
            self.rfile, content_length, content_type, _upload_tmp_dir()
        )

        if src_path is None:
            self._send_error(400, 'Invalid file')
            return

        passwords = [b'infected']
        date_match = re.search(r'(\d{4})-(\d{2})-(\d{2})', original_filename)
        if date_match:
            year, month, day = date_match.groups()
            passwords.append(f'infected_{year}{month}{day}'.encode())

        try:
            result = self._process_uploaded_file(src_path, original_filename, passwords, effective_max)
            self._send_json(result)
        except ValueError as exc:
            self._send_error(400, str(exc))
        except Exception:
            self._send_error(500, 'Internal server error')

    def handle_post_load_url(self):
        data = self._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        if data is None:
            return
        url = data.get('url', '')

        if not url:
            self._send_error(400, 'No URL provided')
            return

        effective_max = _resolve_upload_size_limit(data.get('maxUploadSize'))
        if not self._check_disk_space(effective_max):
            return

        try:
            src_path = _fetch_url_safely(url, config.URL_DOWNLOAD_TIMEOUT, effective_max)

            parsed_url = urlparse(url)
            original_filename = os.path.basename(parsed_url.path)
            if not original_filename:
                original_filename = 'downloaded'

            passwords = [b'infected']
            if 'malware-traffic-analysis.net' in url:
                date_match = re.search(r'/(\d{4})/(\d{2})/(\d{2})/', url)
                if date_match:
                    year, month, day = date_match.groups()
                    passwords.insert(0, f'infected_{year}{month}{day}'.encode())

            result = self._process_uploaded_file(src_path, original_filename, passwords, effective_max)
            self._send_json(result)
        except _FileTooLargeError:
            self._send_error(413, 'File too large')
        except ValueError as exc:
            self._send_error(400, str(exc))
        except Exception:
            self._send_error(500, 'Internal server error')

    def _build_status_response(self, dir_path):
        """Shared status-check logic for both GET /api/status and POST /api/check-status."""
        db_file = os.path.join(dir_path, 'events.db')

        # Check for error files first (highest priority)
        error_file = os.path.join(dir_path, '.error')
        if os.path.exists(error_file):
            error_age = time.time() - os.path.getmtime(error_file)
            if error_age > config.STALE_THRESHOLD_SECONDS:
                try:
                    os.unlink(error_file)
                except OSError:
                    pass
            else:
                try:
                    with open(error_file, 'r') as f:
                        error_msg = _sanitize_error_text(f.read().strip())
                except OSError:
                    error_msg = 'Analysis failed'
                return {'status': 'error', 'message': error_msg}

        phase_file = os.path.join(dir_path, '.phase')
        if os.path.exists(phase_file):
            lock_age = time.time() - os.path.getmtime(phase_file)
            if lock_age > config.STALE_THRESHOLD_SECONDS:
                try:
                    os.unlink(phase_file)
                except OSError:
                    pass

        phase = ''
        phase_still_active = os.path.exists(phase_file)
        if phase_still_active:
            try:
                with open(phase_file, 'r') as f:
                    phase = f.read().strip()
            except OSError:
                pass

        meta = _read_meta(dir_path)
        # events.db is created the instant create_sqlite_db opens its
        # connection - well before the row-by-row ingest finishes - so its
        # mere existence isn't sufficient for 'ready'. .phase stays set for
        # exactly that import window (cleared only after ingest completes),
        # so it must also be absent.
        is_ready = os.path.exists(db_file) and not phase_still_active
        response = {'status': 'ready' if is_ready else 'processing'}
        if not is_ready:
            response['phase'] = phase
        if meta:
            response['meta'] = meta
        return response

    def handle_get_status(self, params):
        md5 = params.get('md5', [''])[0]
        dir_path, error = self._resolve_md5_dir(md5)
        if error:
            self._send_error(400, error)
            return
        response = self._build_status_response(dir_path)
        # Only on this one-off GET (loadAnalysis/openReanalyzeModal), not
        # the hot-polled POST /api/check-status - both share
        # _build_status_response, but this extra query has no business
        # running every 2s during active processing. Also skipped
        # whenever the analysis itself isn't ready yet (definitely no
        # notes yet either) - has_row_notes() is now safe to call
        # regardless (see its own comment), but there's still no reason
        # to open a connection at all before there's anything to find.
        if response['status'] == 'ready':
            response['hasRowNotes'] = has_row_notes(os.path.join(dir_path, 'events.db'))
        else:
            response['hasRowNotes'] = False
        self._send_json(response)

    def handle_post_check_status(self):
        data = self._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        if data is None:
            return
        md5 = data.get('md5', '')
        dir_path, error = self._resolve_md5_dir(md5)
        if error:
            self._send_error(400, error)
            return
        self._send_json(self._build_status_response(dir_path))

    def _remove_artifacts(self, dir_path, artifacts):
        """Delete each named artifact file from dir_path if present.
        Best-effort per-file (a stuck/permission-denied file doesn't block
        cleanup of the rest) - shared by handle_post_reanalyze's pcap and
        non-pcap branches, which previously each inlined an identical copy
        of this loop over their own artifact tuple.
        """
        for artifact in artifacts:
            artifact_path = os.path.join(dir_path, artifact)
            if os.path.exists(artifact_path):
                try:
                    os.unlink(artifact_path)
                except OSError:
                    pass

    def _restore_meta(self, meta_path, preserved_meta):
        """Rewrite .meta after a reanalyze cleanup, so the frontend
        retains detected_type across the reanalyze - best-effort, same
        reasoning as _remove_artifacts. Shared by handle_post_reanalyze's
        pcap and non-pcap branches, which previously each inlined an
        identical copy of this block.
        """
        if preserved_meta:
            try:
                with open(meta_path, 'w') as f:
                    json.dump(preserved_meta, f)
            except OSError:
                pass

    def handle_post_reanalyze(self):
        data = self._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        if data is None:
            return
        md5 = data.get('md5', '')
        dir_path, error = self._resolve_existing_analysis_dir(md5)
        if error:
            self._send_error(*error)
            return

        phase_file = os.path.join(dir_path, '.phase')
        if os.path.exists(phase_file):
            self._send_error(409, 'Analysis already in progress')
            return

        _evict_analysis_cache(md5)

        pcap_file = _find_pcap_file(dir_path)
        non_pcap_files = self._non_artifact_files(dir_path, pcap_file=pcap_file)

        # Preserve existing .meta so we can rewrite it after cleanup
        meta_path = os.path.join(dir_path, '.meta')
        preserved_meta = None
        if os.path.exists(meta_path):
            try:
                with open(meta_path, 'r') as f:
                    preserved_meta = json.load(f)
            except (OSError, ValueError):
                preserved_meta = None

        # Determine if this is a PCAP, log file, or standalone file analysis
        if pcap_file:
            pcap_path = os.path.join(dir_path, pcap_file)

            self._remove_artifacts(dir_path, PCAP_ANALYSIS_ARTIFACTS)

            # Clean up extracted files from previous analysis
            filestore_dir = os.path.join(dir_path, 'filestore')
            if os.path.isdir(filestore_dir):
                try:
                    shutil.rmtree(filestore_dir)
                except OSError:
                    pass

            self._restore_meta(meta_path, preserved_meta)

            if spawn_suricata(dir_path, pcap_path, os.path.join(SURICATA_DIR, 'suricata.yaml'), data_dir=DATA_DIR):
                self._send_json({'status': 'processing', 'md5': md5, 'phase': 'network'})
            else:
                # spawn_suricata() returns False for two different reasons -
                # already in progress (no .error written), or a genuine
                # failure to start (Suricata missing/permissions/etc, which
                # does write .error) - check which one actually happened
                # rather than always reporting "already in progress" for a
                # real startup failure.
                error_file = os.path.join(dir_path, '.error')
                if os.path.exists(error_file):
                    try:
                        with open(error_file, 'r') as f:
                            error_msg = _sanitize_error_text(f.read().strip())
                    except OSError:
                        error_msg = 'Suricata failed to start'
                    self._send_error(500, error_msg)
                else:
                    self._send_error(409, 'Analysis already in progress')
        elif non_pcap_files:
            file_path = os.path.join(dir_path, non_pcap_files[0])
            self._remove_artifacts(dir_path, FILE_ANALYSIS_ARTIFACTS)
            self._restore_meta(meta_path, preserved_meta)

            if is_log_file_by_extension(file_path):
                self._analyze_log_file(dir_path, file_path, non_pcap_files[0])
                self._send_json({'status': 'processing', 'md5': md5, 'phase': 'logs'})
            else:
                self._analyze_standalone_file(dir_path, file_path, non_pcap_files[0])
                self._send_json({'status': 'processing', 'md5': md5, 'phase': 'files'})
        else:
            self._send_error(404, 'No analysis file found')


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

def main():
    """Run SO-CRATES server."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(os.path.join(DATA_DIR, config.UPLOAD_TMP_SUBDIR), exist_ok=True)
    _cleanup_upload_tmp_dir()

    # Check for required executables
    missing = check_executables()
    if missing:
        print(f"Error: Missing required executables: {', '.join(missing)}")
        print("Please install them and try again.")
        sys.exit(1)
    
    # Show banner immediately so users know the app is alive
    title = f'Welcome to SO-CRATES {VERSION}!'
    padding = ' ' * (61 - len(title))
    print(f"""
    ================================================================
    | {title}{padding}|
    ================================================================
    """)

    # Local bootstrap only - config files, cached/baked-in rules. No network
    # calls here (network_allowed=False), so the server can never block
    # startup on a slow/unreachable rule source; refreshing rules over the
    # network is now an explicit on-demand action (see _run_ruleset_update()
    # and POST /api/update-rules) triggered from the Rules modal (gear menu)
    # instead.
    setup_suricata_config(DATA_DIR, enable_arp=bool(os.environ.get('ENABLE_ARP_LOGGING')), network_allowed=False)
    setup_yara_rules(DATA_DIR, network_allowed=False)
    setup_sigma_rules(DATA_DIR, network_allowed=False)

    print("Tip! To check for rule updates, click the menu in the upper-right corner and then select Rules.")

    if os.environ.get('DEMO'):
        msg = 'SO-CRATES is now running. Click the link on the left!'
    else:
        # 0.0.0.0 means "listen on all interfaces," not a browsable address -
        # printing it verbatim gives a link that (a) isn't treated as a
        # secure context by browsers, breaking navigator.clipboard, and
        # (b) doesn't even resolve on some systems. localhost is what the
        # container's BIND_ADDRESS=0.0.0.0 is actually meant to be reached
        # through when clicking the link on the machine running docker.
        display_host = 'localhost' if BIND_ADDRESS == '0.0.0.0' else BIND_ADDRESS
        msg = f'SO-CRATES running at http://{display_host}:{PORT}/socrates.html'
    padding = ' ' * (61 - len(msg))
    print(f"""
    ================================================================
    | {msg}{padding}|
    ================================================================
    """)
    
    with ThreadedTCPServer((BIND_ADDRESS, PORT), Handler) as httpd:
        httpd.serve_forever()


if __name__ == '__main__':
    main()
