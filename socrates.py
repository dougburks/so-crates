#!/usr/bin/env python3
import contextlib
import functools
import http.server
import socketserver
import concurrent.futures
import json
import os
import sqlite3
import subprocess
import ipaddress
import posixpath
import signal
from urllib.parse import urlparse, parse_qs, unquote
import urllib.request
import urllib.error
import re
import tempfile
import shutil
import sys
import threading

from db import (
    get_event_count_sqlite, get_event_types_sqlite, query_events_sqlite_json,
    create_email_analysis_db,
    query_sigma_alerts_sqlite, get_sigma_stats_sqlite,
    get_sigma_alert_count_sqlite, get_event_date_range_sqlite,
    get_sankey_data_sqlite, get_aggregation_data_sqlite, get_aggregation_totals_sqlite,
    tshark_types,
    AGGREGATION_TOP_N, AGGREGATION_PAGE_SIZE_OPTIONS,
    set_row_note, has_row_notes,
    set_acknowledged, set_acknowledged_bulk,
)
from validators import (
    validate_ip, validate_port, sanitize_filename, is_safe_path,
    is_log_file, is_log_file_by_extension, is_office_file_by_extension,
    is_email_file, is_email_file_by_extension, is_pcap_file,
)
from url_fetch import FileTooLargeError, fetch_url_safely
from storage import (
    PCAP_EXTENSIONS, PCAP_ANALYSIS_ARTIFACTS, FILE_ANALYSIS_ARTIFACTS,
    upload_tmp_dir, cleanup_upload_tmp_dir, cleanup_stale_tmp, remove_imported_eve_files, resolve_upload_size_limit, extract_zip_contents,
    hash_file, hash_file_with_prefix, is_pcap_path, write_meta, read_meta, find_pcap_file,
    add_analysis_warning, read_analysis_warnings,
    non_artifact_files, resolve_display_name, remove_artifacts, restore_meta, finished_analysis_dirs,
)
from analysis_cache import (
    SANKEY_CACHE, AGGREGATION_CACHE, AGGREGATION_TOTALS_CACHE, ALL_CACHES, CACHE_LOCK,
    cache_put, evict_analysis_cache, cacheable_aggregation_key,
)
from suricata_analyzer import (
    check_executables, setup_suricata_config, spawn_suricata,
    _set_error, _set_phase, _clear_phase, read_error, read_phase, analysis_running,
    get_suricata_rules_info,
    get_suricata_enabled_sources, get_suricata_show_protocol_decode_alerts,
    SURICATA_RULE_SOURCES, BAKED_IN_SURICATA_SOURCES,
    DEFAULT_SURICATA_SOURCES, find_extracted_file,
)
from stream_payload import DIRECTIONS as STREAM_DIRECTIONS, run_follow_raw, transcript_lines, parse_hexdump
from suricata_sid_ranges import (
    SURICATA_SID_RANGES, SURICATA_BUILTIN_SID_RANGES, SURICATA_BUILTIN_LABEL,
)
from yara_analyzer import (
    check_yara_executable, setup_yara_rules, scan_single_file, get_yara_rules_info, analyze_standalone_file,
)
from sigma_analyzer import (
    setup_sigma_rules, get_sigma_rules_info, analyze_log_file,
)
from ohmydebn_colors import (
    derive_theme_colors, derive_theme_colors_from_alacritty, derive_theme_colors_from_named_palette,
)
from email_analyzer import analyze_message, remove_filestore
import shark_analyzer
from findings import query_findings
from playbook_lookup import get_playbook
from samples import SAMPLES
from ai_summary_lookup import get_ai_summary
import config
import cyberchef
import tomllib

VERSION = '5.1.0'
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

# \A...\Z, not ^...$: in Python $ also matches just before a trailing newline,
# so "<md5>\n" would slip through - \Z anchors the absolute end of the string.
MD5_RE = re.compile(r'\A[a-f0-9]{32}\Z')
# Deliberately permissive rather than an enum of known theme names, so the
# client's own THEMES allowlist (static/socrates.js) stays the single source
# of truth; this just bounds what a malformed/oversized file can smuggle
# through as JSON. Underscores included alongside hyphens - confirmed real
# installed OhMyDebn theme names use them (e.g. "black_arch", "snow_black").
THEME_NAME_RE = re.compile(r'^[a-z0-9_-]{1,40}$')

_REANALYZE_LOCK = threading.Lock()


def _sanitize_error_text(text):
    """Redact server filesystem paths from client-facing .error text -
    exception strings routinely embed absolute paths (data dir, tool
    locations) that a browser client has no use for."""
    text = text.replace(DATA_DIR + os.sep, '').replace(DATA_DIR, '')
    return re.sub(r'(?:^|(?<=[\s:\'"(]))/(?:[\w.+-]+/)+[\w.+-]+', '<path>', text)


def _stream_bpf_filter(src, sport, dst, dport):
    """tcpdump filter for one flow. 'and port', not 'or port', so unrelated
    flows sharing a port stay out. The second half matches the same flow
    inside 802.1Q VLAN-tagged frames: BPF's host/port primitives only look
    at untagged offsets, so without it a capture from a tagged SPAN/trunk
    port carves to an empty file (seen for real: a Security Onion capture
    with every packet on VLAN 244). 'vlan' shifts the offsets for what
    follows it, hence the whole expression repeated after it."""
    flow = f'host {src} and host {dst} and port {sport} and port {dport}'
    return f'({flow}) or (vlan and ({flow}))'


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
    # Daemon, like every request thread: a non-daemon timer still pending
    # when the server shuts down would hold the process open for up to
    # the full timeout.
    timer.daemon = True
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
        proc.stdout.close()
    if timed_out[0]:
        raise subprocess.TimeoutExpired(cmd, timeout)
    data = b''.join(chunks)
    if text:
        data = data.decode('utf-8', errors='replace')
    return proc.returncode, data, truncated


# A flow carved for a transcript or payload, in /tmp (_carved_flow) - and
# what a startup sweep removes when a server that died left one there
FLOW_CARVE_PREFIX = 'socrates-flow-'


class _CarveFailed(Exception):
    """tcpdump couldn't read the capture to carve a flow out of it."""


@contextlib.contextmanager
def _carved_flow(pcap, src, sport, dst, dport, max_bytes):
    """One flow, carved out of pcap by tcpdump into a file in /tmp, for
    tshark to read: (its path, whether the carve was cut off at max_bytes).
    Removed on exit. tshark reads a whole
    capture even to follow one flow (~8s on a 1GB pcap, measured), while
    tcpdump's BPF filter carves it out in a fraction of a second - and /tmp
    is the one place AppArmor 5's profile for tshark (Ubuntu 26.04 on) lets
    it read a file at all, in a rootless container too (see
    shark_analyzer's _DENIED_CAPTURE)."""
    rc, carved, truncated = _run_capped(
        ['tcpdump', '-r', pcap, '-w', '-', _stream_bpf_filter(src, sport, dst, dport)],
        max_bytes=max_bytes,
        timeout=config.STREAM_TIMEOUT_SECONDS
    )
    # Nothing written at all, not even a capture header: tcpdump couldn't
    # read the capture - an error, not a flow with no packets. (Killed at
    # max_bytes, or a capture cut off mid-packet, it still wrote some.)
    if rc != 0 and not carved:
        raise _CarveFailed()
    with tempfile.NamedTemporaryFile(prefix=FLOW_CARVE_PREFIX, suffix='.pcap') as tmp:
        tmp.write(carved)
        tmp.flush()
        yield tmp.name, truncated


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
        # Served back by /api/rule-update-status - no absolute paths.
        on_progress(_sanitize_error_text(f'Error updating {_RULESET_LABELS[name]} rules: {e}'))
        with _rule_update_lock:
            _rule_update_state[name]['error'] = _sanitize_error_text(f'{e}')
    finally:
        with _rule_update_lock:
            _rule_update_state[name]['done'] = True
            _rule_update_state[name]['running'] = False


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


# The phase a non-pcap analysis starts in, by detected type - what
# /api/upload and /api/reanalyze report, and what the frontend's loading
# message keys on.
_ANALYSIS_PHASES = {'log': 'logs', 'email': 'email', 'binary': 'files'}


def _detect_file_type(prefix, path):
    """'log', 'email' or 'binary' for a non-pcap file, by extension or
    content (its first bytes, prefix) - the one test every upload path and
    reanalyze share. A known extension decides first, so a .log of
    'Key: value' lines stays a log; by content, email is checked before
    log, since a message's header block isn't a log whatever the log
    checks would make of it."""
    if is_email_file_by_extension(path):
        return _email_or_binary(path)
    if is_log_file_by_extension(path):
        return 'log'
    if is_email_file(prefix):
        return _email_or_binary(path)
    if is_log_file(prefix):
        return 'log'
    return 'binary'


def _email_or_binary(path):
    """Email parsing holds the message and its decoded attachments in
    memory - a message past MAX_EMAIL_SIZE is analyzed as a plain file."""
    try:
        return 'binary' if os.path.getsize(path) > config.MAX_EMAIL_SIZE else 'email'
    except OSError:
        return 'email'


class Handler(http.server.SimpleHTTPRequestHandler):
    # Set by do_GET for a /cyberchef/ request that passed its path checks -
    # switches translate_path() to CYBERCHEF_DIR and _add_security_headers()
    # to CyberChef's own CSP for this one response.
    _serving_cyberchef = False

    def log_message(self, format, *args):
        pass

    def translate_path(self, path):
        if not self._serving_cyberchef:
            return super().translate_path(path)
        # do_GET already rejected any '..' segment in this normalized form.
        normalized = posixpath.normpath(unquote(urlparse(path).path))
        parts = [p for p in normalized.split('/')[2:] if p]
        return os.path.join(cyberchef.CYBERCHEF_DIR, *parts)

    def list_directory(self, path):
        # SimpleHTTPRequestHandler's fallback for a directory with no
        # index.html (e.g. /static/ or /cyberchef/assets/) - never a page
        # this app means to serve.
        self._send_error(404, 'Not found')
        return None

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
        # /cyberchef/ gets its own, looser policy - see cyberchef.py for
        # what each carve-out is for and why it stays off this app's pages.
        if self._serving_cyberchef:
            self.send_header('Content-Security-Policy', cyberchef.get_csp())
        else:
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'self'; report-uri /api/csp-report;")

    def end_headers(self):
        self._add_security_headers()
        # Prevent browser caching of HTML and static assets so upgrades
        # are reflected immediately without manual cache clearing.
        # CyberChef is ~48MB, too big to re-download on every open, but its
        # asset names don't change between versions (assets/main.js), so it
        # can't be cached blindly either: no-cache makes the browser
        # revalidate each time, and the stdlib handler answers with a cheap
        # 304 until an image upgrade changes the files' Last-Modified.
        if self._serving_cyberchef:
            self.send_header('Cache-Control', 'no-cache')
        elif self.path.endswith('.html') or self.path.startswith('/static/'):
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
        # A JSON body can carry any type - a number or list here used to
        # raise out of the handler with no response at all.
        if not isinstance(md5, str) or not MD5_RE.match(md5):
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

        pcap_file = find_pcap_file(dir_path)
        pcap = os.path.join(dir_path, pcap_file) if pcap_file else None
        if not pcap:
            return None, 'No pcap file found', 404

        return {'pcap': pcap, 'src': src, 'sport': sport, 'dst': dst, 'dport': dport}, None, None

    GET_ROUTES = {
        '/api/events': 'handle_get_events',
        '/api/stats': 'handle_get_stats',
        '/api/count': 'handle_get_count',
        '/api/findings': 'handle_get_findings',
        '/api/sankey-data': 'handle_get_sankey_data',
        '/api/aggregation-data': 'handle_get_aggregation_data',
        '/api/aggregation-totals': 'handle_get_aggregation_totals',
        '/api/download-stream': 'handle_get_download_stream',
        '/api/ascii-stream': 'handle_get_ascii_stream',
        '/api/hexdump-stream': 'handle_get_hexdump_stream',
        '/api/raw-stream': 'handle_get_raw_stream',
        '/api/extracted-file': 'handle_get_extracted_file',
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
        '/api/shark-status': 'handle_get_shark_status',
        '/api/shark-settings': 'handle_get_shark_settings',
        '/api/rule-update-status': 'handle_get_rule_update_status',
        '/api/rules-info': 'handle_get_rules_info',
        '/api/playbook': 'handle_get_playbook',
        '/api/ai-summary': 'handle_get_ai_summary',
    }

    POST_ROUTES = {
        '/api/upload': 'handle_post_upload',
        '/api/load-url': 'handle_post_load_url',
        '/api/load-sample': 'handle_post_load_sample',
        '/api/check-status': 'handle_post_check_status',
        '/api/reanalyze': 'handle_post_reanalyze',
        '/api/shark-start': 'handle_post_shark_start',
        '/api/shark-settings': 'handle_post_shark_settings',
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
    # Entries: exact hostnames, '*.suffix' wildcards (matches the suffix
    # itself and any subdomain of it - the shape proxied environments like
    # Killercoda/Codespaces need, where the exact per-session hostname
    # isn't known in advance), or a bare '*' to accept any Host (explicit
    # opt-out of the DNS-rebinding defense for deployments that accept
    # that risk).
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
        the ALLOWED_HOSTS env allowlist (see ALLOWED_HOSTNAMES above for
        the wildcard forms).
        """
        if not netloc:
            return True  # non-browser clients (curl, scripts) may omit Host
        try:
            host = urlparse('//' + netloc).hostname or ''
        except ValueError:
            return False
        if host == 'localhost' or host.endswith('.localhost'):
            return True
        for allowed in self.ALLOWED_HOSTNAMES:
            if allowed == '*':
                return True
            if allowed.startswith('*.'):
                suffix = allowed[2:]
                if host == suffix or host.endswith('.' + suffix):
                    return True
            elif host == allowed:
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
            # Actionable, not a dead end: proxied environments (Killercoda,
            # Codespaces, reverse proxies) legitimately serve SO-CRATES via
            # a hostname this instance has never heard of. The hostname is
            # attacker-influenced text, but it's JSON-encoded by
            # _send_error and never rendered as HTML.
            host = (self.headers.get('Host', '') or '').split(':')[0][:200]
            self._send_error(403,
                f"Invalid Host header ('{host}'). If you are deliberately serving "
                f"SO-CRATES via this hostname (e.g. behind a proxy), restart it with "
                f"the ALLOWED_HOSTS environment variable - for example "
                f"ALLOWED_HOSTS={host or 'my.host.example'} or a wildcard like "
                f"ALLOWED_HOSTS=*.example.com")
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
        elif path == '/cyberchef':
            self.send_response(301)
            self.send_header('Location', '/cyberchef/')
            self.end_headers()
        elif path.startswith('/cyberchef/'):
            # Same normalized-form re-check as /static/ above.
            normalized = posixpath.normpath(unquote(path))
            if ((normalized == '/cyberchef' or normalized.startswith('/cyberchef/'))
                    and '..' not in normalized.split('/')):
                self._serving_cyberchef = True
                super().do_GET()
            else:
                self._send_error(404, 'Not found')
        else:
            self._send_error(404, 'Not found')

    def do_HEAD(self):
        # SimpleHTTPRequestHandler's inherited do_HEAD serves straight from
        # the working directory, skipping every check do_GET makes (Host
        # header, routing, path normalization) - HEAD /socrates.py answered
        # 200 with the file's size. Nothing in this app needs HEAD (browsers
        # never send it here), so refuse it outright rather than duplicate
        # do_GET's routing for a method no client uses. No body: a HEAD
        # response must not have one, so not _send_error.
        self.send_response(405)
        self.send_header('Allow', 'GET, POST')
        self.send_header('Content-Length', '0')
        self.end_headers()

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
                tshark = tshark_types(db_file)
            except Exception:
                self._send_error(500, 'Database error')
                return
        else:
            tshark = []
        # tshark_types: the types tshark added to this analysis (the cards
        # marked as tshark's)
        self._send_json({'counts': counts, 'date_range': date_range, 'tshark_types': tshark})

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

    def handle_get_findings(self, params):
        md5 = params.get('md5', [''])[0]
        dir_path, error = self._resolve_md5_dir(md5)
        if error:
            self._send_error(400, error)
            return
        q = self._parse_search_terms(params)
        counts_only = params.get('counts', [''])[0] == '1'
        # One finding's own records: its rule, detail and addresses
        group = None
        if params.get('rule', [''])[0]:
            port = params.get('dest_port', [''])[0]
            if port and not (port.isascii() and port.isdigit()):
                self._send_error(400, 'Invalid dest_port')
                return
            group = {'rule': params['rule'][0], 'detail': params.get('detail', [''])[0],
                     'dest_ip': params.get('dest_ip', [''])[0],
                     'dest_port': int(port) if port else None}

        db_file = os.path.join(dir_path, 'events.db')
        if not os.path.exists(db_file):
            self._send_json({'rules': [], 'findings': []})
            return
        try:
            result = query_findings(db_file, q, counts_only, group)
        except Exception:
            self._send_error(500, 'Database error')
            return
        self._send_json(result)

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
            if q is None and cacheable_aggregation_key(event_type):
                cache_key = (md5, event_type)
                with CACHE_LOCK:
                    cached = SANKEY_CACHE.get(cache_key)
                if cached is not None:
                    self._send_json(cached)
                    return
                data = get_sankey_data_sqlite(db_file, event_type, q)
                with CACHE_LOCK:
                    cache_put(SANKEY_CACHE, cache_key, data)
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
        if page_size not in AGGREGATION_PAGE_SIZE_OPTIONS:
            page_size = AGGREGATION_TOP_N
        offset = (page - 1) * page_size

        db_file = os.path.join(dir_path, 'events.db')
        if not os.path.exists(db_file):
            self._send_json({})
            return
        try:
            if q is None and cacheable_aggregation_key(event_type, column):
                cache_key = (md5, event_type, column, page, page_size)
                with CACHE_LOCK:
                    cached = AGGREGATION_CACHE.get(cache_key)
                if cached is not None:
                    self._send_json(cached)
                    return
                data = get_aggregation_data_sqlite(db_file, event_type, q, top_n=page_size, offset=offset, column=column)
                with CACHE_LOCK:
                    cache_put(AGGREGATION_CACHE, cache_key, data)
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
            if q is None and cacheable_aggregation_key(event_type):
                cache_key = (md5, event_type)
                with CACHE_LOCK:
                    cached = AGGREGATION_TOTALS_CACHE.get(cache_key)
                if cached is not None:
                    self._send_json(cached)
                    return
                data = get_aggregation_totals_sqlite(db_file, event_type, q)
                with CACHE_LOCK:
                    cache_put(AGGREGATION_TOTALS_CACHE, cache_key, data)
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
                ['tcpdump', '-r', pcap, '-w', '-', _stream_bpf_filter(src, sport, dst, dport)],
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
            # Read from the flow carved out (see _carved_flow) - a carve
            # cut off at its size limit still reads up to the cut, as much
            # of a transcript as there's room to show anyway
            with _carved_flow(pcap, src, sport, dst, dport,
                              config.MAX_TRANSCRIPT_CARVE_SIZE) as (flow_pcap, truncated):
                proto = 'tcp'
                lines = transcript_lines(_run_capped, flow_pcap, src, sport, dst, dport, 'tcp',
                                         config.MAX_STREAM_TEXT_OUTPUT, config.STREAM_TIMEOUT_SECONDS)
                if not lines:
                    proto = 'udp'
                    lines = transcript_lines(_run_capped, flow_pcap, src, sport, dst, dport, 'udp',
                                             config.MAX_STREAM_TEXT_OUTPUT, config.STREAM_TIMEOUT_SECONDS)

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

            # proto lets the transcript join a TCP stream's segments back
            # into one byte stream (a UDP datagram is its own message).
            self._send_json({'lines': lines, 'truncated': truncated, 'proto': proto})
        except subprocess.TimeoutExpired:
            self._send_error(500, 'ASCII transcript extraction timed out')
        except _CarveFailed:
            self._send_error(500, "Couldn't read the capture")
        except Exception:
            self._send_error(500, 'Internal server error')

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
                 _stream_bpf_filter(src, sport, dst, dport)],
                max_bytes=config.MAX_STREAM_TEXT_OUTPUT,
                timeout=config.STREAM_TIMEOUT_SECONDS, text=True
            )
            packets, truncated = parse_hexdump(stdout, config.MAX_HEXDUMP_PACKETS, MAX_TRANSCRIPT_SIZE)
            self._send_json({'packets': packets, 'truncated': truncated or raw_truncated})
        except subprocess.TimeoutExpired:
            self._send_error(500, 'Hexdump extraction timed out')
        except Exception:
            self._send_error(500, 'Internal server error')

    def _send_bytes(self, data, filename):
        """Exact bytes as a download - application/octet-stream plus the
        global nosniff header means a browser navigating here directly
        never renders them, whatever they contain."""
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def handle_get_raw_stream(self, params):
        """One flow's exact payload bytes (see stream_payload.py) - unlike
        /api/ascii-stream, nothing is decoded, replaced or trimmed.
        direction: 'src' (bytes sent by src:sport), 'dst', or 'both'."""
        result, error, status_code = self._validate_stream_params(params)
        if error:
            self._send_error(status_code, error)
            return
        direction = params.get('direction', ['both'])[0]
        if direction not in STREAM_DIRECTIONS:
            self._send_error(400, 'Invalid direction')
            return
        pcap, src, sport, dst, dport = (result[k] for k in ('pcap', 'src', 'sport', 'dst', 'dport'))
        try:
            # Followed from the flow carved out (see _carved_flow)
            with _carved_flow(pcap, src, sport, dst, dport,
                              config.MAX_STREAM_DOWNLOAD_SIZE) as (flow_pcap, truncated):
                if truncated:
                    self._send_error(413, 'Stream payload too large')
                    return
                payload, too_large = run_follow_raw(
                    _run_capped, flow_pcap, src, sport, dst, dport, direction,
                    max_bytes=config.MAX_RAW_STREAM_SIZE,
                    timeout=config.STREAM_TIMEOUT_SECONDS)
            if too_large:
                # Refuse rather than cut off: a truncated payload would
                # decode wrongly with nothing to say it's incomplete.
                self._send_error(413, 'Stream payload too large')
            elif not payload:
                self._send_error(404, 'No payload found')
            else:
                self._send_bytes(payload, f'stream_{src}_{sport}_to_{dst}_{dport}_{direction}.bin'
                                          .replace(':', '-'))
        except subprocess.TimeoutExpired:
            self._send_error(500, 'Stream payload extraction timed out')
        except _CarveFailed:
            self._send_error(500, "Couldn't read the capture")
        except Exception:
            self._send_error(500, 'Internal server error')

    def handle_get_extracted_file(self, params):
        """One file Suricata extracted from this analysis's traffic - or an
        email analysis's message or attachment - by SHA256 (the fileinfo
        event's fileinfo.sha256)."""
        dir_path, error = self._resolve_md5_dir(params.get('md5', [''])[0])
        if error:
            self._send_error(400, error)
            return
        sha256 = params.get('sha256', [''])[0]
        if not re.fullmatch(r'[a-f0-9]{64}', sha256):  # fullmatch: reject a trailing newline that $ would allow
            self._send_error(400, 'Invalid SHA256')
            return
        path = find_extracted_file(dir_path, sha256)
        if not path:
            # Suricata logs a fileinfo event for every transfer it sees,
            # but only stores the ones it could fully reassemble.
            self._send_error(404, 'Extracted file not found')
            return
        try:
            if os.path.getsize(path) > config.MAX_EXTRACTED_FILE_SIZE:
                self._send_error(413, 'Extracted file too large')
                return
            with open(path, 'rb') as f:
                data = f.read(config.MAX_EXTRACTED_FILE_SIZE + 1)
            if len(data) > config.MAX_EXTRACTED_FILE_SIZE:
                self._send_error(413, 'Extracted file too large')
                return
            self._send_bytes(data, f'{sha256}.bin')
        except OSError:
            self._send_error(500, 'Internal server error')

    def handle_get_analyses(self, params):
        analyses = []
        if os.path.exists(DATA_DIR):
            candidates = finished_analysis_dirs(DATA_DIR, MAX_EVE_SIZE)

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
                    'name': resolve_display_name(dir_path, md5_dir),
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
            self._send_json({'success': True, 'md5': md5, 'file_name': resolve_display_name(dir_path, md5), 'notes': notes})
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

        # Under _REANALYZE_LOCK, so a reanalyze can't start in between
        with _REANALYZE_LOCK:
            if analysis_running(dir_path):
                self._send_error(409, 'Analysis in progress - delete it once it has finished')
                return
            shark_analyzer.cancel(dir_path)
            try:
                shutil.rmtree(dir_path)
            except OSError as e:
                print(f"Could not delete analysis {md5}: {e}")
                self._send_error(500, 'Could not delete the analysis')
                return
        evict_analysis_cache(md5)
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
        _sigma_alert_where) - but the cached unfiltered Sankey and
        aggregation results were computed with the old set, so they go.
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
        evict_analysis_cache(md5)
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
        evict_analysis_cache(md5)
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
        the browser AND logged (deduplicated) server-side - except the one
        violation the bundled CyberChef always causes (see
        cyberchef.is_expected_csp_violation). Always 204.
        """
        body = self._read_post_body(65536)
        if body is None:
            return
        try:
            report = json.loads(body).get('csp-report', {})
        except (json.JSONDecodeError, AttributeError):
            report = {}
        if not isinstance(report, dict):
            report = {}      # garbage posted here gets the same 204, not a 500
        if report and not cyberchef.is_expected_csp_violation(report):
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
        # The body itself is unused, but reading it through _read_json_body
        # enforces the same application/json requirement every other JSON
        # POST has - the CSRF guard a cross-site "simple request" can't meet.
        # This is the most destructive endpoint, so it needs it most.
        if self._read_json_body(config.MAX_REQUEST_BODY_SIZE) is None:
            return
        deleted = 0
        skipped = 0
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
                with _REANALYZE_LOCK:
                    # (left alone, like a single delete - see analysis_running)
                    if analysis_running(dir_path):
                        skipped += 1
                        continue
                    try:
                        shark_analyzer.cancel(dir_path)
                        shutil.rmtree(dir_path)
                        deleted += 1
                    except Exception as e:
                        # The exception text embeds the absolute DATA_DIR path.
                        errors.append(_sanitize_error_text(f'{md5_dir}: {e}'))
        if errors and deleted == 0:
            self._send_error(500, f'Could not delete analyses: {errors[0]}')
            return
        with CACHE_LOCK:
            for cache in ALL_CACHES:
                cache.clear()
        response = {'success': True, 'deleted': deleted}
        if skipped:
            response['skipped'] = skipped
        self._send_json(response)

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
        # classifyRuleset() takes the first match, so the built-in ranges
        # go first here too - same order as classify_alert_ruleset().
        suricata_info['sidRanges'] = (
            [{'min': lo, 'max': hi, 'label': SURICATA_BUILTIN_LABEL}
             for lo, hi in SURICATA_BUILTIN_SID_RANGES]
            + [{'min': min_sid, 'max': max_sid, 'label': label}
               for min_sid, max_sid, _slug, label in SURICATA_SID_RANGES]
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
        if not pattern or not pattern.fullmatch(rule_id):
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
        if not pattern or not pattern.fullmatch(rule_id):
            self._send_error(400, 'Invalid type or id')
            return
        self._send_json({'summary': get_ai_summary(detection_type, rule_id)})

    def handle_get_pcap_path(self, params):
        md5 = params.get('md5', [''])[0]
        dir_path, error = self._resolve_md5_dir(md5)
        if error:
            self._send_error(400, error)
            return
        pcap_file = find_pcap_file(dir_path)
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
        SSRF-hardened path fetch_url_safely() exists for - same reasoning
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
            md5_hash = hash_file(extracted_pcap_path)
        dir_path = os.path.join(DATA_DIR, md5_hash)
        pcap_filename = sanitize_filename(os.path.basename(extracted_pcap_path))
        pcap_path = os.path.join(dir_path, pcap_filename)

        deduped = self._commit_file_or_return_ready(
            dir_path, md5_hash, ('eve.json', 'events.db'),
            lambda: shutil.move(extracted_pcap_path, pcap_path)
        )
        if not deduped:
            with open(os.path.join(dir_path, 'name.txt'), 'w') as f:
                f.write(pcap_filename)
            write_meta(dir_path, safe_filename, pcap_filename, 'pcap')
            spawn_suricata(dir_path, pcap_path, os.path.join(SURICATA_DIR, 'suricata.yaml'), data_dir=DATA_DIR)
        return md5_hash, bool(deduped)

    def _commit_and_analyze_standalone_file(self, extracted_path, safe_filename, md5_hash, prefix):
        """Commit one already-extracted, already-hashed non-pcap file (see
        hash_file_with_prefix) into DATA_DIR/<md5>/ if not already
        analyzed, and dispatch it to log or binary/YARA analysis in the
        background. Mirrors _commit_and_spawn_pcap_analysis for the pcap
        case - md5_hash/prefix are always precomputed by the caller so
        within-zip duplicate content can be recognized before ever
        touching disk (see _process_uploaded_file's within-batch dedup).

        Returns (md5_hash, deduped: bool, detected_type: 'log'|'email'|'binary').
        """
        dir_path = os.path.join(DATA_DIR, md5_hash)
        dest_filename = sanitize_filename(os.path.basename(extracted_path))
        dest_path = os.path.join(dir_path, dest_filename)

        deduped = self._commit_file_or_return_ready(
            dir_path, md5_hash, ('events.db',),
            lambda: shutil.move(extracted_path, dest_path)
        )
        detected = _detect_file_type(prefix, dest_path)
        if not deduped:
            write_meta(dir_path, safe_filename, dest_filename, detected)
            self._analyze_by_type(detected, dir_path, dest_path, dest_filename)
        return md5_hash, bool(deduped), detected

    def _process_uploaded_file(self, src_path, original_filename, passwords=None, effective_max=None):
        """Process uploaded or downloaded file: detect ZIP, extract, find PCAP, compute MD5, dispatch.

        Args:
            src_path: Path to the already-on-disk uploaded/downloaded file
                (e.g. under upload_tmp_dir()). This function takes ownership
                of it -- it's moved into place on success and unlinked in all
                other cases (dedup-return, zip extraction, failure).
            original_filename: Original filename for password derivation.
            passwords: Optional list of bytes passwords for ZIP extraction.
            effective_max: The resolved per-request upload-size ceiling (see
                resolve_upload_size_limit), passed through to zip-bomb
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
                tmp_dir = tempfile.mkdtemp(dir=upload_tmp_dir(DATA_DIR))
                try:
                    extracted_files = extract_zip_contents(src_path, tmp_dir, passwords or [], effective_max)
                    # Every extracted file is analyzed, each as its own
                    # independent analysis - pcaps get network analysis
                    # (_commit_and_spawn_pcap_analysis), everything else
                    # gets log/binary analysis
                    # (_commit_and_analyze_standalone_file). 'filesSkipped'
                    # now only ever reflects genuine per-file failures, not
                    # by-design drops.
                    non_hidden_extracted = [f for f in extracted_files if not os.path.basename(f).startswith('.')]
                    # By extension, or by magic bytes like a direct upload -
                    # an extension-less pcap was otherwise only YARA-scanned.
                    pcap_files = [f for f in extracted_files
                                  if f.lower().endswith(PCAP_EXTENSIONS)
                                  or (f in non_hidden_extracted and is_pcap_path(f))]
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
                        first_md5, first_prefix = hash_file_with_prefix(non_pcap_files[0])
                        primary_md5, primary_deduped, primary_detected = self._commit_and_analyze_standalone_file(
                            non_pcap_files[0], safe_filename, first_md5, first_prefix)
                        primary_phase = _ANALYSIS_PHASES[primary_detected]
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
                            md5_hash = hash_file(extra)
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
                            md5_hash, prefix = hash_file_with_prefix(extra)
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
                md5_hash, prefix = hash_file_with_prefix(src_path)
                dir_path = os.path.join(DATA_DIR, md5_hash)
                dest_filename = safe_filename  # sanitize_filename() raises rather than return ''
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
                else:
                    detected = _detect_file_type(prefix, dest_path)
                    phase = self._analyze_by_type(detected, dir_path, dest_path, dest_filename)
                write_meta(dir_path, dest_filename, dest_filename, detected)
                return {'status': 'processing', 'md5': md5_hash, 'phase': phase}
        finally:
            if os.path.exists(src_path):
                os.unlink(src_path)

    def _analyze_standalone_file(self, dir_path, file_path, safe_filename):
        """Run standalone YARA analysis on a non-PCAP file in the background."""
        def run_analysis():
            _set_phase(dir_path, 'files')

            try:
                analyze_standalone_file(dir_path, file_path, DATA_DIR)
                with open(os.path.join(dir_path, 'name.txt'), 'w') as f:
                    f.write(safe_filename)
            except Exception as e:
                _set_error(dir_path, f'Analysis failed: {e}')
            finally:
                _clear_phase(dir_path)

        threading.Thread(target=run_analysis, daemon=True).start()

    def _analyze_by_type(self, detected, dir_path, file_path, safe_filename):
        """Start the background analysis for a non-pcap file's detected type
        (see _detect_file_type). Returns its phase.

        .phase is written here, before the thread starts (which writes it
        again): written only in the thread, a second Reanalyze click
        arriving first saw no .phase under _REANALYZE_LOCK and started a
        second run in the same directory."""
        _set_phase(dir_path, _ANALYSIS_PHASES[detected])
        if detected == 'email':
            self._analyze_email_file(dir_path, file_path, safe_filename)
        elif detected == 'log':
            self._analyze_log_file(dir_path, file_path, safe_filename)
        else:
            self._analyze_standalone_file(dir_path, file_path, safe_filename)
        return _ANALYSIS_PHASES[detected]

    def _analyze_email_file(self, dir_path, file_path, safe_filename):
        """Parse an email message (.eml) in the background - its headers,
        links and attachments become events, and the attachments are
        stored and YARA-scanned (see email_analyzer.py)."""
        def run_analysis():
            _set_phase(dir_path, 'email')
            try:
                db_file = os.path.join(dir_path, 'events.db')
                # network_allowed=False - see yara_analyzer.analyze_standalone_file.
                rules_file = setup_yara_rules(DATA_DIR, network_allowed=False)
                failures = []
                scan = functools.partial(scan_single_file, failures=failures) \
                    if (rules_file and check_yara_executable()) else None
                try:
                    events = analyze_message(dir_path, file_path, rules_file, scan)
                except Exception as e:
                    _set_error(dir_path, f'Email analysis failed: {e}')
                    events = []
                for reason in dict.fromkeys(failures):
                    add_analysis_warning(dir_path, f'The YARA scan of the message or its attachments failed - '
                                                   f'File Alerts may be missing: {reason}')
                create_email_analysis_db(db_file, events)
                with open(os.path.join(dir_path, 'name.txt'), 'w') as f:
                    f.write(safe_filename)
            except Exception as e:
                _set_error(dir_path, f'Email analysis failed: {e}')
            finally:
                _clear_phase(dir_path)

        threading.Thread(target=run_analysis, daemon=True).start()

    def _analyze_log_file(self, dir_path, file_path, safe_filename):
        """Run Zircolite Sigma analysis on a log file in the background."""
        def run_analysis():
            _set_phase(dir_path, 'logs')

            try:
                error = analyze_log_file(dir_path, file_path, DATA_DIR)
                if error:
                    _set_error(dir_path, error)
                with open(os.path.join(dir_path, 'name.txt'), 'w') as f:
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
        effective_max = resolve_upload_size_limit(self.headers.get('X-Max-Upload-Size'))
        content_length = self._parse_content_length(effective_max)
        if content_length is None:
            return
        if not self._check_disk_space(effective_max):
            return

        content_type = self.headers.get('Content-Type', '')
        src_path, original_filename = self._parse_multipart_stream(
            self.rfile, content_length, content_type, upload_tmp_dir(DATA_DIR)
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

        effective_max = resolve_upload_size_limit(data.get('maxUploadSize'))
        if not self._check_disk_space(effective_max):
            return

        try:
            src_path = fetch_url_safely(url, config.URL_DOWNLOAD_TIMEOUT, effective_max, upload_tmp_dir(DATA_DIR))

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
        except FileTooLargeError:
            self._send_error(413, 'File too large')
        except ValueError as exc:
            self._send_error(400, str(exc))
        except Exception:
            self._send_error(500, 'Internal server error')

    def handle_post_load_sample(self):
        """Analyze one of the samples built into SO-CRATES (samples.SAMPLES)
        by name - generated here, so it needs no internet access - through
        the same path as an upload."""
        data = self._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        if data is None:
            return
        name = data.get('name')
        sample = SAMPLES.get(name) if isinstance(name, str) else None
        if not sample:
            self._send_error(400, 'Unknown sample')
            return
        filename, build = sample
        try:
            fd, src_path = tempfile.mkstemp(dir=upload_tmp_dir(DATA_DIR), suffix='.sample')
            try:
                with os.fdopen(fd, 'wb') as f:
                    f.write(build())
            except Exception:
                # _process_uploaded_file removes src_path itself once it has it.
                os.unlink(src_path)
                raise
            self._send_json(self._process_uploaded_file(src_path, filename))
        except ValueError as exc:
            self._send_error(400, str(exc))
        except Exception:
            self._send_error(500, 'Internal server error')

    def _build_status_response(self, dir_path):
        """Shared status-check logic for both GET /api/status and POST /api/check-status."""
        db_file = os.path.join(dir_path, 'events.db')

        # An error first (highest priority)
        error_msg = read_error(dir_path)
        if error_msg is not None:
            return {'status': 'error', 'message': _sanitize_error_text(error_msg)}

        phase = read_phase(dir_path)
        phase_still_active = phase is not None

        meta = read_meta(dir_path)
        # events.db is created the instant create_sqlite_db opens its
        # connection - well before the row-by-row ingest finishes - so its
        # mere existence isn't sufficient for 'ready'. .phase stays set for
        # exactly that import window (cleared only after ingest completes),
        # so it must also be absent.
        is_ready = os.path.exists(db_file) and not phase_still_active
        response = {'status': 'ready' if is_ready else 'processing'}
        if not is_ready:
            response['phase'] = phase or ''
        else:
            # What went wrong without failing it (storage.add_analysis_warning)
            warnings = [_sanitize_error_text(w) for w in read_analysis_warnings(dir_path)]
            if warnings:
                response['warnings'] = warnings
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

    def _shark_status(self, dir_path, start=False):
        """_shark_status_raw, with an error's message redacted of server
        paths as Suricata's .error is (tshark's stderr names the capture's
        full path, editcap's failures their whole command line)."""
        status = self._shark_status_raw(dir_path, start)
        if isinstance(status.get('message'), str):
            status['message'] = _sanitize_error_text(status['message'])
        return status

    def _shark_status_raw(self, dir_path, start=False):
        """Where tshark stands for a PCAP analysis (see shark_analyzer.status),
        with 'merged' once it's ready: whether its rows have joined
        Suricata's in events.db (if not, the merge is started).

        A capture small enough for the background that has never been
        queued - analyzed before tshark ran alongside Suricata, or whose
        queued run was lost to a server restart - is queued here, on the
        first status request. start=True (the user asked) queues it
        whatever its size. 'waiting' means Suricata hasn't finished;
        'unavailable' that this isn't a PCAP analysis; 'disabled' that
        tshark is switched off in Settings."""
        pcap_file = find_pcap_file(dir_path)
        if not pcap_file:
            return {'status': 'unavailable'}
        if not shark_analyzer.enabled(DATA_DIR):
            return {'status': 'disabled'}
        pcap_path = os.path.join(dir_path, pcap_file)
        if os.path.exists(os.path.join(dir_path, '.phase')):
            # Suricata is still working; tshark, started alongside it, may be too
            status = shark_analyzer.status(dir_path, pcap_path)
            return {'status': 'waiting'} if status['status'] in ('not_started', 'ready') else status
        status = shark_analyzer.status(dir_path, pcap_path)
        if status['status'] == 'not_started' or (start and status['status'] in ('too_large', 'error')):
            shark_analyzer.enqueue(dir_path, pcap_path)
            status = shark_analyzer.status(dir_path, pcap_path)
        if status['status'] == 'ready':
            status['merged'] = shark_analyzer.merged(dir_path)
            if not status['merged']:
                # Built before tshark's rows joined Suricata's in events.db
                # (or the merge was missed): add them now, in the background
                shark_analyzer.merge_soon(dir_path)
            else:
                # The types it added - so the page knows, before reloading
                # anything, whether there's anything new to show
                status['types'] = tshark_types(os.path.join(dir_path, 'events.db'))
        return status

    def handle_get_shark_status(self, params):
        dir_path, error = self._resolve_existing_analysis_dir(params.get('md5', [''])[0])
        if error:
            self._send_error(*error)
            return
        self._send_json(self._shark_status(dir_path))

    def handle_get_shark_settings(self, params):
        self._send_json({'enabled': shark_analyzer.enabled(DATA_DIR)})

    def handle_post_shark_settings(self):
        """Turn tshark on or off for every analysis. Off stops new runs (a
        running one finishes); analyses keep the protocols already added."""
        data = self._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        if data is None:
            return
        if not isinstance(data.get('enabled'), bool):
            self._send_error(400, 'enabled must be true or false')
            return
        try:
            shark_analyzer.set_enabled(DATA_DIR, data['enabled'])
        except OSError:
            self._send_error(500, 'Could not save the setting')
            return
        self._send_json({'enabled': data['enabled']})

    def handle_post_shark_start(self):
        """Run tshark for an analysis on request - for a capture over the
        background packet limit, or to retry after an error."""
        data = self._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        if data is None:
            return
        dir_path, error = self._resolve_existing_analysis_dir(data.get('md5', ''))
        if error:
            self._send_error(*error)
            return
        self._send_json(self._shark_status(dir_path, start=True))

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

    def handle_post_reanalyze(self):
        data = self._read_json_body(config.MAX_REQUEST_BODY_SIZE)
        if data is None:
            return
        md5 = data.get('md5', '')
        dir_path, error = self._resolve_existing_analysis_dir(md5)
        if error:
            self._send_error(*error)
            return

        # Held from the in-progress check until Suricata/the file analysis
        # has been launched: otherwise two concurrent reanalyze requests
        # could both pass the check, and the second would delete the
        # first's .phase lock and in-progress output (its artifact sweep
        # includes .phase) and start a second Suricata on the same
        # directory. Launching returns quickly - the analysis itself runs
        # in the background, outside the lock.
        with _REANALYZE_LOCK:
            phase_file = os.path.join(dir_path, '.phase')
            if os.path.exists(phase_file):
                self._send_error(409, 'Analysis already in progress')
                return

            evict_analysis_cache(md5)

            pcap_file = find_pcap_file(dir_path)
            non_pcap_files = non_artifact_files(dir_path, pcap_file=pcap_file)

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

                shark_analyzer.cancel(dir_path)
                # Held until the new run's .phase is written (spawn_suricata),
                # which any merge waiting on it then sees and stops at - see
                # shark_analyzer.merge_lock
                with shark_analyzer.merge_lock(dir_path):
                    remove_artifacts(dir_path, PCAP_ANALYSIS_ARTIFACTS)

                    # Clean up extracted files from previous analysis
                    filestore_dir = os.path.join(dir_path, 'filestore')
                    if os.path.isdir(filestore_dir):
                        try:
                            shutil.rmtree(filestore_dir)
                        except OSError:
                            pass

                    restore_meta(meta_path, preserved_meta)

                    started = spawn_suricata(dir_path, pcap_path, os.path.join(SURICATA_DIR, 'suricata.yaml'), data_dir=DATA_DIR)
                if started:
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
                remove_artifacts(dir_path, FILE_ANALYSIS_ARTIFACTS)
                # An email analysis's stored message and attachments.
                remove_filestore(dir_path)

                # The same test upload used (content or extension), so a log
                # recognized by its content - JSON/CSV/EVTX without a log
                # extension - isn't reanalyzed as a binary.
                try:
                    with open(file_path, 'rb') as fh:
                        prefix = fh.read(4096)
                except OSError:
                    prefix = b''
                detected = _detect_file_type(prefix, file_path)
                # Detection can change between versions (4.4.0 stopped
                # reading an email whose first header has a comma as a CSV
                # log) - record what it is now, so reanalyze also repairs
                # an analysis the old detection got wrong.
                if preserved_meta:
                    preserved_meta['detected_type'] = detected
                restore_meta(meta_path, preserved_meta)
                phase = self._analyze_by_type(detected, dir_path, file_path, non_pcap_files[0])
                self._send_json({'status': 'processing', 'md5': md5, 'phase': phase})
            else:
                self._send_error(404, 'No analysis file found')


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

def _install_sigterm_handler():
    """Exit cleanly on SIGTERM. In the container, python3 is PID 1 (the
    entrypoint execs it), and the kernel gives PID 1 no default action for
    SIGTERM - without a handler, 'docker/podman stop' was silently ignored
    and always fell back to SIGKILL after its 10-second grace period.
    SystemExit unwinds serve_forever() and the server's 'with' block like
    Ctrl-C's KeyboardInterrupt does; request and analysis threads are all
    daemons, so nothing holds the process open after that."""
    def _handle_sigterm(signum, frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, _handle_sigterm)


def main():
    """Run SO-CRATES server."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(os.path.join(DATA_DIR, config.UPLOAD_TMP_SUBDIR), exist_ok=True)
    cleanup_upload_tmp_dir(DATA_DIR)
    cleanup_stale_tmp([(FLOW_CARVE_PREFIX, '.pcap'), (shark_analyzer.RUN_TMP_PREFIX, '')]
                      + [(prefix, '') for prefix in shark_analyzer.LEGACY_TMP_PREFIXES])
    remove_imported_eve_files(DATA_DIR)

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
    
    _install_sigterm_handler()
    try:
        with ThreadedTCPServer((BIND_ADDRESS, PORT), Handler) as httpd:
            httpd.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass  # Ctrl-C, or SIGTERM via the handler above - a normal stop, not an error
    print('SO-CRATES stopped')


if __name__ == '__main__':
    main()
