#!/usr/bin/env python3
"""Sigma rule analysis integration for SO-CRATES using Zircolite.

Zircolite is optional. If installed, log files (EVTX, JSON, CSV, XML)
are scanned with Sigma rules after upload. Rules are baked into Docker
images; non-Docker deployments download on first run if internet is available.
"""

import json
import os
import re
import shutil
import sqlite3
import subprocess
import urllib.error
import urllib.request

import config
from db import import_log_events
from validators import is_host_reachable, is_file_stale, gunzip_atomically

ZIRCOLITE_RULES_URLS = {
    'windows': 'https://raw.githubusercontent.com/wagga40/Zircolite-Rules-v2/main/rules_windows_merged.json',
    'linux': 'https://raw.githubusercontent.com/wagga40/Zircolite-Rules-v2/main/rules_linux.json',
}
BAKED_IN_SIGMA_DIR = '/usr/share/sigma-rules'


ZIRCOLITE_BUNDLED_PATH = os.path.expanduser('~/socrates-data/zircolite/zircolite.py')
ZIRCOLITE_CONFIG_PATHS = [
    os.path.expanduser('~/socrates-data/zircolite/config/config.yaml'),
    '/usr/local/lib/zircolite/config/config.yaml',
    '/usr/share/zircolite/config/config.yaml',
]
ZIRCOLITE_VENV_PYTHON = '/usr/local/lib/zircolite-venv/bin/python3'


def is_zircolite_available():
    """Return True if the zircolite CLI is available."""
    return (_zircolite_cmd() is not None)


def _zircolite_cmd():
    """Return the best available Zircolite executable path."""
    # Check PATH first
    for cmd in ('zircolite', 'zircolite.py'):
        path = shutil.which(cmd)
        if path:
            return path
    # Check bundled copy
    if os.path.isfile(ZIRCOLITE_BUNDLED_PATH):
        return ZIRCOLITE_BUNDLED_PATH
    return None


def _zircolite_config():
    """Return the first available Zircolite config file path."""
    for path in ZIRCOLITE_CONFIG_PATHS:
        if os.path.isfile(path):
            return path
    return None


def get_sigma_rules_info(data_dir=None):
    """Return {'windows': {'count': int|None, 'updated': epoch|None,
    'stale': bool|None}, 'linux': {...}} - each Sigma ruleset file is a
    plain JSON array of rule objects, so len(json.load(f)) gives the count
    directly (verified against the real files). 'stale' is True once that
    ruleset's file is older than config.RULES_MAX_AGE_HOURS - purely a
    local mtime check, no network access, safe to call unconditionally
    (see static/socrates.js's checkForStaleRules(), which is opt-in).
    Never raises - None fields per-ruleset if that file doesn't exist or
    fails to parse."""
    if data_dir is None:
        data_dir = os.path.expanduser('~/socrates-data')
    rules_dir = os.path.join(data_dir, config.SIGMA_RULES_SUBDIR)
    result = {}
    for ruleset_name in ZIRCOLITE_RULES_URLS:
        rules_file = os.path.join(rules_dir, f'{ruleset_name}.json')
        if not os.path.isfile(rules_file):
            result[ruleset_name] = {'count': None, 'updated': None, 'stale': None}
            continue
        try:
            with open(rules_file, 'r', errors='ignore') as f:
                data = json.load(f)
            count = len(data) if isinstance(data, list) else None
            result[ruleset_name] = {
                'count': count,
                'updated': os.path.getmtime(rules_file),
                'stale': is_file_stale(rules_file, config.RULES_MAX_AGE_HOURS),
            }
        except (OSError, json.JSONDecodeError):
            result[ruleset_name] = {'count': None, 'updated': None, 'stale': None}
    return result


def setup_sigma_rules(data_dir=None, on_progress=print, network_allowed=True, force=False):
    """Ensure Sigma (Zircolite JSON) rules are available.

    Priority:
    1. Cached rules in ~/socrates-data/sigma-rules/ -- each ruleset
       refreshed in place if older than config.RULES_MAX_AGE_HOURS and
       internet is reachable; falls back to the stale copy on any refresh
       failure rather than leaving rules unavailable.
    2. Baked-in rules in /usr/share/sigma-rules (Docker)
    3. Download from Zircolite-Rules-v2 if internet is available

    on_progress: callable receiving one progress-message string at a time
    (defaults to print - callers that want to capture/stream progress
    instead of just logging to stdout pass their own).

    network_allowed: when False, skips reachability checks and any
    download entirely, using only what's already cached/baked-in (used at
    server startup so it never blocks on the network; callers that want
    on-demand refresh pass True, the default).

    force: when True, checks for an update even if the cached copy isn't
    stale yet - used by the on-demand "check for rule updates" action, so
    it actually checks rather than just reporting the cached copy as fine
    because the 24h cache window hasn't expired. Has no effect if there's
    no cached copy to begin with. When network_allowed is False, force
    also controls whether a "using cached" message is emitted: a plain
    staleness check (server startup, per-file background scans) stays
    silent since nothing changed, while an explicit forced check that
    happens to run offline still reports the cached-copy outcome so the
    action doesn't look like it did nothing.

    Returns dict mapping 'windows'/'linux' to file path, or None for each.
    """
    if data_dir is None:
        data_dir = os.path.expanduser('~/socrates-data')
    rules_dir = os.path.join(data_dir, config.SIGMA_RULES_SUBDIR)
    os.makedirs(rules_dir, exist_ok=True)

    result = {}
    # Lazily computed and cached across loop iterations, not re-probed per
    # ruleset - windows and linux are two iterations of the same loop, and
    # would otherwise both hit the same host separately (e.g. both stale,
    # or both never downloaded, on the same setup_sigma_rules() call).
    reachable = None

    def _reachable():
        nonlocal reachable
        if reachable is None:
            reachable = network_allowed and is_host_reachable('github.com', 443, timeout=5)
        return reachable

    for ruleset_name, url in ZIRCOLITE_RULES_URLS.items():
        rules_file = os.path.join(rules_dir, f'{ruleset_name}.json')

        # Already downloaded/cached
        if os.path.isfile(rules_file):
            stale = is_file_stale(rules_file, config.RULES_MAX_AGE_HOURS)
            if force or stale:
                if _reachable():
                    on_progress(f'Checking Sigma rules ({ruleset_name}) for updates...')
                    try:
                        _download_rule_file(url, rules_file)
                        on_progress(f'Sigma rules ({ruleset_name}) refreshed successfully')
                    except (OSError, urllib.error.URLError) as e:
                        on_progress(f'Warning: could not refresh Sigma rules ({ruleset_name}), using cached copy: {e}')
                elif network_allowed:
                    on_progress(f'No internet access detected — using cached Sigma rules ({ruleset_name})')
                elif force:
                    on_progress(f'Using cached Sigma rules ({ruleset_name})')
            elif network_allowed:
                on_progress(f'Sigma rules ({ruleset_name}) already present — using cached rules')
            result[ruleset_name] = rules_file
            continue

        # Baked-in rules (Docker image) - gzip-compressed (windows.json is
        # ~7.4MB uncompressed, ~0.9MB compressed - see the Dockerfile's
        # Sigma rules bake step), decompressed here into the plain .json
        # file every other reader in this module already expects.
        baked_in = os.path.join(BAKED_IN_SIGMA_DIR, f'{ruleset_name}.json.gz')
        if os.path.isfile(baked_in):
            try:
                gunzip_atomically(baked_in, rules_file)
                result[ruleset_name] = rules_file
                continue
            except OSError as e:
                on_progress(f'Warning: could not copy baked-in Sigma rules: {e}')

        # Try to download
        if _reachable():
            try:
                _download_rule_file(url, rules_file)
                result[ruleset_name] = rules_file
                continue
            except (OSError, urllib.error.URLError) as e:
                on_progress(f'Warning: could not download Sigma rules ({ruleset_name}): {e}')
        elif network_allowed:
            on_progress(f'No internet access detected — Sigma rules ({ruleset_name}) not available')
        else:
            on_progress(f'WARNING! No Sigma rules ({ruleset_name}) found')

    return result


def _download_rule_file(url, dest_file):
    """Download a single rule file from URL to dest_file.

    Writes to a temp file and atomically renames into place, so a refresh
    that overwrites an already-good cached copy (see setup_sigma_rules)
    never leaves a truncated/partial file behind if the download fails
    partway through - the prior cached copy stays intact until the new
    one is fully written.
    """
    os.makedirs(os.path.dirname(dest_file), exist_ok=True)
    tmp_dest = dest_file + '.new'
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=config.RULES_DOWNLOAD_TIMEOUT) as resp:
            body = resp.read()
        try:
            json.loads(body)
        except json.JSONDecodeError as e:
            # A transient bad response (rate-limit/outage page, truncated-
            # but-200 body) must not silently replace a good cached
            # ruleset - raised as OSError so it lands in the same
            # fall-back-to-cached-copy handling callers already have for
            # download failures, rather than needing a new except clause.
            raise OSError(f'downloaded rules file is not valid JSON: {e}') from e
        with open(tmp_dest, 'wb') as f:
            f.write(body)
        os.replace(tmp_dest, dest_file)
    finally:
        if os.path.exists(tmp_dest):
            os.unlink(tmp_dest)


def _detect_log_type(log_path):
    """Auto-detect whether a log file is Windows or Linux flavored.

    Returns 'windows', 'linux', or None.
    """
    # Quick filename-based hints
    basename = os.path.basename(log_path).lower()
    if basename.endswith('.evtx'):
        return 'windows'

    # Content-based detection
    try:
        with open(log_path, 'rb') as f:
            # Read up to 64KB for inspection
            sample = f.read(64 * 1024)
    except OSError:
        return None

    text = sample.decode('utf-8', errors='ignore')

    # Windows EVTX XML export or JSON with Windows-specific fields
    win_indicators = [
        'EventID',
        'Channel',
        'ProviderName',
        'ComputerName',
        'Microsoft-Windows-Sysmon',
        'Security',
        'System',
        'EventRecordID',
    ]
    linux_indicators = [
        'auditd',
        'type=SYSCALL',
        'type=EXECVE',
        'auid=',
        'uid=',
        'exe=',
        'sysmon-for-linux',
    ]

    win_score = sum(1 for ind in win_indicators if ind in text)
    linux_score = sum(1 for ind in linux_indicators if ind in text)

    if win_score > linux_score and win_score >= 2:
        return 'windows'
    if linux_score > win_score and linux_score >= 2:
        return 'linux'

    # Fallback: if we see common Windows event IDs (4-digit numbers in JSON),
    # lean toward Windows
    if basename.endswith('.json') or basename.endswith('.jsonl'):
        if re.search(r'"EventID"\s*:\s*\d{3,5}', text):
            return 'windows'

    return None


def run_zircolite(log_path, rules_file, output_json, output_db=None):
    """Run Zircolite on a log file and write results to output_json.

    If output_db is provided, also writes a unified SQLite database with
    all parsed events (not just matches).

    Returns (success, db_path) where db_path is output_db if it was created.
    """
    zircolite = _zircolite_cmd()
    if not zircolite:
        print('Zircolite not available — skipping Sigma analysis')
        return False, None

    if not os.path.isfile(rules_file):
        print(f'Sigma rules file not found: {rules_file}')
        return False, None

    config_file = _zircolite_config()
    if not config_file:
        print('Zircolite config file not found — Sigma analysis cannot run')
        return False, None

    # Zircolite requires --no-parallel when using --dbfile with single file,
    # and --unified-db to write all events into one DB.
    temp_db = output_db or os.path.join(os.path.dirname(output_json), '.zircolite_events.db')

    # Write Zircolite's own log file to the analysis directory, not the project root
    zircolite_log = os.path.join(os.path.dirname(output_json), 'zircolite.log')

    python_cmd = ZIRCOLITE_VENV_PYTHON if os.path.isfile(ZIRCOLITE_VENV_PYTHON) else 'python3'
    try:
        cmd = [
            python_cmd, zircolite,
            '--events', log_path,
            '--ruleset', rules_file,
            '-o', output_json,
            '-c', config_file,
            '-d', temp_db,
            '-l', zircolite_log,
            '--unified-db',
            '--no-parallel',
            '--no-event-filter',
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=config.SIGMA_RUN_TIMEOUT
        )
        if result.returncode != 0:
            # Zircolite may write warnings to stderr; only treat as error
            # if output file was not produced
            if not os.path.exists(output_json):
                print(f'Zircolite error: {result.stderr}')
                return False, None
        return True, temp_db
    except subprocess.TimeoutExpired:
        print(f'Zircolite timed out after {config.SIGMA_RUN_TIMEOUT}s')
        return False, None
    except OSError as e:
        print(f'Zircolite execution error: {e}')
        return False, None


def _safe_int_port(value):
    """A single malformed/non-numeric SourcePort or DestinationPort value
    anywhere in a Zircolite import must not abort the entire batch - fail
    closed to 0 (matching the existing "falsy -> 0" default) for that one
    field instead of raising ValueError out of the whole import loop."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def import_zircolite_logs(zircolite_db_path, events_db_path):
    """Import all log events from a Zircolite unified DB into SO-CRATES's events table.

    Reads every row from the Zircolite 'logs' table and converts it into an
    event dict suitable for db.import_log_events().

    Returns the number of events imported.
    """
    if not os.path.exists(zircolite_db_path):
        return 0

    log_events = []
    conn = None
    try:
        conn = sqlite3.connect(zircolite_db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.execute('SELECT * FROM logs')
        columns = [d[0] for d in cur.description]
        for row in cur.fetchall():
            row_dict = {col: row[idx] for idx, col in enumerate(columns)}

            # Build a JSON-serializable dict for the event
            # Zircolite rows may have None for many columns; keep only non-None
            clean_dict = {k: v for k, v in row_dict.items() if v is not None}

            # Timestamp
            timestamp = (
                clean_dict.get('SystemTime') or
                clean_dict.get('UtcTime') or
                clean_dict.get('timestamp') or
                clean_dict.get('TimeCreated') or
                clean_dict.get('TimeCreated_systemTime') or
                ''
            )

            # Network fields (Sysmon network events have these)
            src_ip = clean_dict.get('SourceIp', '') or ''
            dest_ip = clean_dict.get('DestinationIp', '') or ''
            src_port = clean_dict.get('SourcePort', 0) or 0
            dest_port = clean_dict.get('DestinationPort', 0) or 0

            # Protocol / Channel
            protocol = clean_dict.get('Protocol', '') or ''
            app_proto = clean_dict.get('Channel', '') or clean_dict.get('Provider_Name', '') or ''

            log_events.append({
                'event_type': 'log',
                'timestamp': timestamp,
                'src_ip': src_ip,
                'src_port': _safe_int_port(src_port),
                'dest_ip': dest_ip,
                'dest_port': _safe_int_port(dest_port),
                'protocol': protocol,
                'app_proto': app_proto,
                'json_data': clean_dict,
            })
    except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
        print(f'Warning: could not read Zircolite events DB: {e}')
        return 0
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass

    if log_events:
        import_log_events(events_db_path, log_events)

    return len(log_events)


def parse_zircolite_results(output_json):
    """Parse Zircolite JSON output into a list of alert dicts.

    One alert dict is emitted per matched event (not per rule), so that each
    row in the Sigma Alerts table represents an individual detection.

    Zircolite v3 output format (list of detection objects):
        {
            'title': 'Rule Name',
            'id': 'uuid',
            'rule_level': 'high',
            'tags': ['attack.t1033', 'attack.discovery'],
            'count': 3,
            'matches': [{...event fields...}]
        }

    Each alert dict contains:
        - timestamp (from the specific match)
        - rule_title
        - rule_id
        - severity (from rule_level)
        - level (same as severity)
        - logsource (from detection or match)
        - tags
        - mitre_techniques
        - original_log (the specific matched event)
        - json_data (the Zircolite result entry minus its 'matches' list)
    """
    if not os.path.exists(output_json):
        return []

    try:
        with open(output_json, 'r') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    alerts = []
    # Zircolite v3 output format: list of detection objects
    if isinstance(data, list):
        detections = data
    elif isinstance(data, dict):
        detections = data.get('detections', data.get('results', []))
    else:
        detections = []

    for detection in detections:
        if not isinstance(detection, dict):
            continue

        # Extract MITRE technique IDs from tags
        tags = detection.get('tags', [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(',') if t.strip()]
        mitre_techniques = [t for t in tags if t.startswith('attack.t') or t.startswith('attack.T')]

        # Resolve the list of matched events
        matches = detection.get('matches', [])
        if not matches:
            # Legacy Zircolite output uses 'event' instead of 'matches'
            single_event = detection.get('event', {})
            if single_event:
                matches = [single_event]
            else:
                continue

        # Detection-level logsource
        detection_logsource = detection.get('channel', detection.get('logsource', ''))

        for match in matches:
            # Try to extract timestamp from the match
            timestamp = ''
            for ts_field in ('SystemTime', 'UtcTime', 'timestamp', 'TimeCreated', 'TimeCreated_systemTime'):
                if ts_field in match:
                    timestamp = match[ts_field]
                    break

            # Fallback logsource from the matched event itself
            logsource = detection_logsource
            if not logsource:
                logsource = match.get('Channel') or match.get('Provider_Name', '')

            rule_level = (detection.get('rule_level') or 'low').lower()

            alert = {
                'timestamp': timestamp,
                'rule_title': detection.get('title', 'Unknown'),
                'rule_id': detection.get('id', ''),
                'severity': rule_level,
                'level': rule_level,
                'logsource': logsource,
                'tags': tags,
                'mitre_techniques': mitre_techniques,
                'original_log': json.dumps(match),
                # The rule-level detection WITHOUT its 'matches' list: each
                # alert already carries its own event in original_log, and
                # a copy of every match in every one of a rule's N alerts
                # is N x N events - a rule matching 5,000 ~1.5KB events
                # stored ~37GB. It also made search wrong: a term found in
                # any other match of the same rule matched every alert of it.
                'json_data': json.dumps({k: v for k, v in detection.items() if k != 'matches'}),
            }
            alerts.append(alert)

    return alerts


def run_sigma_pipeline(dir_path, log_path, data_dir=None):
    """Full Sigma pipeline: detect log type, run Zircolite, write results.

    Returns (success, zircolite_db_path) where zircolite_db_path is the path
    to the unified events DB if it was created, or None on failure.
    """
    if not is_zircolite_available():
        print('Zircolite not available — skipping Sigma analysis')
        return False, None

    if data_dir is None:
        data_dir = os.path.expanduser('~/socrates-data')
    # network_allowed=False: analysis must never silently reach out to
    # refresh rules on its own - that's now an explicit, opt-in action
    # (Rules modal, or the checkForStaleRules() notification). Uses
    # whatever's already cached/baked-in, however old.
    rules = setup_sigma_rules(data_dir, network_allowed=False)
    if not rules:
        print('Sigma rules not available')
        return False, None

    # Auto-detect log type and select ruleset
    detected = _detect_log_type(log_path)
    if detected == 'linux' and rules.get('linux'):
        ruleset = rules['linux']
    elif detected == 'windows' and rules.get('windows'):
        ruleset = rules['windows']
    else:
        # Fallback: use windows rules (largest coverage) if available,
        # otherwise linux
        ruleset = rules.get('windows') or rules.get('linux')

    output_json = os.path.join(dir_path, 'sigma_matches.json')
    temp_db = os.path.join(dir_path, '.zircolite_events.db')
    success, _ = run_zircolite(log_path, ruleset, output_json, output_db=temp_db)
    if success and os.path.exists(temp_db):
        return True, temp_db
    return success, None
