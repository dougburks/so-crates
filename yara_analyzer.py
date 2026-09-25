#!/usr/bin/env python3
"""YARA scanning integration for SO-CRATES.

YARA is optional. If installed, extracted files are scanned after Suricata
finishes. Rules are baked into Docker images; non-Docker deployments download
on first run if internet is available.
"""

import config
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
import zipfile

from file_analyzer import analyze_file
from validators import is_host_reachable, is_file_stale, gunzip_atomically

YARA_FORGE_URL = (
    'https://github.com/YARAHQ/yara-forge/releases/latest/download/'
    'yara-forge-rules-full.zip'
)
# Baked in gzip-compressed (~19MB -> 3MB - see the Dockerfile's YARA Forge
# bake step) and decompressed here into the plain .yar file every other
# reader in this module already expects.
BAKED_IN_YARA_FILE = '/usr/share/yara-rules/yara-rules-full.yar.gz'
YARA_RULES_SUBDIR = 'yara-rules'
YARA_FORGE_FILENAME = 'yara-rules-full.yar'


def check_yara_executable():
    """Return True if the yara CLI is available."""
    return shutil.which('yara') is not None


def get_yara_rules_info(data_dir=None):
    """Return {'count': int|None, 'updated': epoch|None, 'stale': bool|None}
    for the current YARA Forge ruleset. Rules are declared as 'rule <name>
    ...' at the start of a line (verified against the real file). 'stale'
    is True once the rules file is older than config.RULES_MAX_AGE_HOURS -
    purely a local mtime check, no network access, safe to call
    unconditionally (see static/socrates.js's checkForStaleRules(), which
    is opt-in). Never raises - returns None fields if the rules file
    doesn't exist yet."""
    if data_dir is None:
        data_dir = os.path.expanduser('~/socrates-data')
    rules_file = os.path.join(data_dir, YARA_RULES_SUBDIR, YARA_FORGE_FILENAME)
    if not os.path.isfile(rules_file):
        return {'count': None, 'updated': None, 'stale': None}
    try:
        count = 0
        with open(rules_file, 'r', errors='ignore') as f:
            for line in f:
                if re.match(r'^\s*rule\s+', line):
                    count += 1
        return {
            'count': count,
            'updated': os.path.getmtime(rules_file),
            'stale': is_file_stale(rules_file, config.RULES_MAX_AGE_HOURS),
        }
    except OSError:
        return {'count': None, 'updated': None, 'stale': None}


def setup_yara_rules(data_dir=None, on_progress=print, network_allowed=True, force=False):
    """Ensure YARA Forge rules are available.

    Priority:
    1. ~/socrates-data/yara-rules/yara-rules-full.yar (already downloaded) --
       refreshed in place if older than config.RULES_MAX_AGE_HOURS and
       internet is reachable; falls back to the stale copy on any refresh
       failure rather than leaving rules unavailable.
    2. Baked-in rules in /usr/share/yara-rules (Docker)
    3. Download latest YARA Forge release if internet is available

    on_progress: callable receiving one progress-message string at a time
    (defaults to print - callers that want to capture/stream progress
    instead of just logging to stdout pass their own).

    network_allowed: when False, skips reachability checks and any
    download entirely, using only what's already cached/baked-in (used at
    server startup so it never blocks on the network; callers that want
    on-demand refresh pass True, the default).

    force: when True, checks for an update even if the cached copy isn't
    stale yet - used by the on-demand "check for rule updates" action,
    where staying silent just because the config.RULES_MAX_AGE_HOURS cache window hasn't expired
    would defeat the point of the user explicitly asking for a check right
    now. Has no effect if there's no cached copy to begin with (that path
    always checks/downloads already). When network_allowed is False, force
    also controls whether a "using cached" message is emitted: a plain
    staleness check (server startup, per-file background scans) stays
    silent since nothing changed, while an explicit forced check that
    happens to run offline still reports the cached-copy outcome so the
    action doesn't look like it did nothing.

    Returns the rules file path or None if no rules are available.
    """
    if data_dir is None:
        data_dir = os.path.expanduser('~/socrates-data')
    rules_file = os.path.join(data_dir, YARA_RULES_SUBDIR, YARA_FORGE_FILENAME)

    # Already downloaded/cached
    if os.path.isfile(rules_file):
        stale = is_file_stale(rules_file, config.RULES_MAX_AGE_HOURS)
        if force or stale:
            if network_allowed and is_host_reachable('github.com', 443, timeout=5):
                on_progress('Checking for YARA Forge rule updates...')
                try:
                    _download_yara_forge_rules(rules_file)
                    on_progress('YARA Forge rules refreshed successfully')
                except (OSError, urllib.error.URLError, zipfile.BadZipFile, KeyError) as e:
                    on_progress(f'Warning: could not refresh YARA Forge rules, using cached copy: {e}')
            elif network_allowed:
                on_progress('No internet access detected — using cached YARA Forge rules')
            elif force:
                on_progress('Using cached YARA Forge rules')
        elif network_allowed:
            on_progress('YARA Forge rules already present — using cached rules')
        return rules_file

    # Baked-in rules (Docker image)
    if os.path.isfile(BAKED_IN_YARA_FILE):
        os.makedirs(os.path.dirname(rules_file), exist_ok=True)
        try:
            gunzip_atomically(BAKED_IN_YARA_FILE, rules_file)
            return rules_file
        except OSError as e:
            on_progress(f'Warning: could not copy baked-in rules: {e}')

    # Try to download
    if network_allowed and is_host_reachable('github.com', 443, timeout=5):
        on_progress('Internet access detected — downloading YARA Forge rules...')
        try:
            _download_yara_forge_rules(rules_file)
            on_progress('YARA Forge rules downloaded successfully')
            return rules_file
        except (OSError, urllib.error.URLError, zipfile.BadZipFile, KeyError) as e:
            on_progress(f'Warning: could not download YARA Forge rules: {e}')
    elif network_allowed:
        on_progress('No internet access detected — YARA Forge rules not available')
    else:
        on_progress('WARNING! No YARA rules found')

    return None


def _download_yara_forge_rules(dest_file):
    """Download latest YARA Forge full rules ZIP and extract the .yar file.

    Writes to a temp file and atomically renames into place, so a refresh
    that overwrites an already-good cached copy (see setup_yara_rules)
    never leaves a truncated/partial file behind if the download fails
    partway through - the prior cached copy stays intact until the new
    one is fully written.
    """
    os.makedirs(os.path.dirname(dest_file), exist_ok=True)
    tmp_zip = dest_file + '.zip'
    tmp_dest = dest_file + '.new'

    try:
        req = urllib.request.Request(YARA_FORGE_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=config.RULES_DOWNLOAD_TIMEOUT) as resp:
            with open(tmp_zip, 'wb') as f:
                f.write(resp.read())

        with zipfile.ZipFile(tmp_zip, 'r') as zf:
            member = 'packages/full/yara-rules-full.yar'
            with zf.open(member) as src, open(tmp_dest, 'wb') as dst:
                dst.write(src.read())

        os.replace(tmp_dest, dest_file)
    finally:
        for tmp in (tmp_zip, tmp_dest):
            if os.path.exists(tmp):
                os.unlink(tmp)


def _run_yara_with_index(rules_file, list_path, filestore_dir=None, known_paths=None):
    """Run YARA against a rules file and return parsed matches.

    known_paths, if provided, is the exact list of file paths written to
    list_path (i.e. what --scan-list is scanning) - passed through to
    _parse_yara_output() so it can resolve each match's file path reliably
    even when a path contains whitespace.
    """
    if not os.path.isfile(rules_file):
        return []

    try:
        result = subprocess.run(
            [
                'yara', '-r', '-g', '-m', '-w',
                '-d', 'filename=""',
                '-d', 'filepath=""',
                '-d', 'extension=""',
                '-d', 'filetype=""',
                '-d', 'owner=""',
                '--scan-list', rules_file, list_path
            ],
            capture_output=True, text=True, timeout=config.YARA_SCAN_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        print(f'YARA scan timed out for {os.path.basename(rules_file)}')
        return []
    except OSError as e:
        print(f'YARA scan error for {os.path.basename(rules_file)}: {e}')
        return []

    if result.returncode != 0:
        # Without this check, a compile/scan failure (corrupted rules file,
        # incompatible module, bad --scan-list entry) was indistinguishable
        # from a clean scan that simply found nothing.
        print(f'YARA scan error for {os.path.basename(rules_file)}: {result.stderr.strip()}')
        return []

    return _parse_yara_output(result.stdout, filestore_dir, known_paths=known_paths)


def _dedup_matches(matches, key_fn):
    """Deduplicate YARA matches, keeping the first occurrence of each key.

    key_fn is applied to every match (including duplicates) so callers can
    also normalize matches as a side effect.
    """
    seen = set()
    unique = []
    for m in matches:
        key = key_fn(m)
        if key not in seen:
            seen.add(key)
            unique.append(m)
    return unique


def run_yara_scan(filestore_dir, rules_file):
    """Run YARA on extracted files and return list of matches.

    Each match is a dict:
        {
            'rule_name': str,
            'sha256': str,
            'file_path': str,
            'tags': list[str],
            'meta': dict,
        }
    """
    if not os.path.isdir(filestore_dir):
        return []

    # Collect all extracted files
    target_files = []
    for root, _dirs, files in os.walk(filestore_dir):
        for f in files:
            if f.endswith('.json'):
                continue
            target_files.append(os.path.join(root, f))

    if not target_files:
        return []

    # Write file list for --scan-list
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as list_file:
        for f in target_files:
            list_file.write(f + '\n')
        list_path = list_file.name

    try:
        return _dedup_matches(
            _run_yara_with_index(rules_file, list_path, filestore_dir, known_paths=target_files),
            key_fn=lambda m: (m['rule_name'], m['sha256'])
        )
    finally:
        try:
            os.unlink(list_path)
        except OSError:
            pass


def _parse_yara_output(output, filestore_dir=None, known_paths=None):
    """Parse YARA CLI output.

    YARA output formats (depending on flags):
        RuleName [Tags] [Metadata] FilePath   (with -g -m)
        RuleName [Tags] FilePath               (with -g)
        RuleName [Metadata] FilePath           (with -m)
        RuleName FilePath                      (default)

    Tags contain only simple identifiers (no '=').
    Metadata contains key=value pairs.

    known_paths, if provided, is the exact set of file paths --scan-list
    was given - used to resolve each line's file path by longest-suffix
    match against that known set, falling back to the last
    whitespace-delimited token only if nothing matches. The naive
    last-token split silently truncates any path containing whitespace
    (e.g. a user-uploaded "My Invoice.pdf"), which matters here since rule
    names never contain whitespace but arbitrary uploaded filenames do.
    """
    known_paths_set = set(known_paths or ())
    sorted_known_paths = sorted(known_paths_set, key=len, reverse=True)
    # A last-whitespace-token match is only trustworthy on its own when no
    # longer known path also ends with it - otherwise that longer path is
    # the correct (and original algorithm's) answer, e.g. known paths "a
    # b.txt" and "b.txt" both present: the naive last token for "a b.txt"
    # is "b.txt", which is itself a distinct known path and must not
    # shadow the real, longer match. Computed once per run (O(known_paths^2)
    # worst case) rather than doing the full suffix scan on every line.
    ambiguous_last_tokens = {
        p for p in known_paths_set
        if any(len(other) > len(p) and other.endswith(p) for other in known_paths_set)
    }
    matches = []
    for line in output.strip().split('\n'):
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        # Fast path: the overwhelming majority of filenames contain no
        # whitespace, so the last token is already the exact path - an O(1)
        # set lookup confirms that without scanning every known path. Only
        # a whitespace-containing filename (split across multiple tokens),
        # or one whose last token collides with a shorter known path, needs
        # the O(known_paths) suffix scan below.
        if parts[-1] in known_paths_set and parts[-1] not in ambiguous_last_tokens:
            file_path = parts[-1]
        else:
            file_path = next((p for p in sorted_known_paths if line.endswith(p)), None) or parts[-1]
        if filestore_dir:
            # Use commonpath to prevent directory traversal via path manipulation
            try:
                if os.path.commonpath([os.path.realpath(file_path), os.path.realpath(filestore_dir)]) != os.path.realpath(filestore_dir):
                    continue
            except ValueError:
                # Different drives / no common path
                continue

        # Derive SHA256 from filename (Suricata file-store names files by SHA256)
        sha256 = os.path.basename(file_path)
        if not re.match(r'^[a-f0-9]{64}$', sha256):
            # Fallback: try to read from metadata sidecar
            sha256 = _sha256_from_meta(file_path)

        rule_name = parts[0]

        # Extract the section between rule name and file path
        middle = line[len(rule_name):line.rfind(file_path)].strip()

        # Find all bracketed sections in the middle
        bracketed = re.findall(r'\[([^\]]*)\]', middle)

        tags = []
        meta = {}
        meta_section = ''

        for section in bracketed:
            # Tags sections have no '='; metadata sections do
            if '=' in section:
                meta_section = section
            else:
                tags = [t.strip() for t in section.split(',') if t.strip()]

        # Also handle metadata not in brackets (rare, but possible)
        # Remove bracketed parts from middle to get any remaining text
        remaining = re.sub(r'\[[^\]]*\]', '', middle).strip()
        if remaining and '=' in remaining:
            meta_section = remaining

        # Parse key=value pairs from metadata section
        for m in re.finditer(r'(\w+)="([^"]+)"', meta_section):
            meta[m.group(1)] = m.group(2)
        for m in re.finditer(r'(\w+)=([^\s"]+)', meta_section):
            if m.group(1) not in meta:
                meta[m.group(1)] = m.group(2)

        matches.append({
            'rule_name': rule_name,
            'sha256': sha256 or '',
            'file_path': file_path,
            'tags': tags,
            'meta': meta,
        })

    return matches


def _sha256_from_meta(file_path):
    """Try to read SHA256 from Suricata file-store metadata sidecar."""
    meta_path = file_path + '.json'
    if os.path.exists(meta_path):
        try:
            with open(meta_path, 'r') as f:
                data = json.load(f)
            return data.get('fileinfo', {}).get('sha256', '')
        except (json.JSONDecodeError, OSError):
            pass
    return ''


def write_yara_matches_json(dir_path, matches):
    """Write YARA match results to yara_matches.json in the analysis directory."""
    out_path = os.path.join(dir_path, 'yara_matches.json')
    with open(out_path, 'w') as f:
        json.dump(matches, f)


def run_yara_pipeline(dir_path, data_dir=None):
    """Full YARA pipeline: setup rules, scan filestore, write results.

    Also extracts metadata for files with zero YARA matches and writes
    file_metadata.json keyed by SHA256.

    Returns True if scanning completed (even with zero matches).
    Returns False if YARA is unavailable or rules could not be obtained.
    """
    if not check_yara_executable():
        print('YARA not available — skipping file scan')
        return False

    if data_dir is None:
        data_dir = os.path.expanduser('~/socrates-data')
    rules_file = os.path.join(data_dir, YARA_RULES_SUBDIR, YARA_FORGE_FILENAME)
    if not os.path.isfile(rules_file):
        print(f'YARA Forge rules file not found: {rules_file}')
        return False

    filestore_dir = os.path.join(dir_path, 'filestore')
    if not os.path.isdir(filestore_dir):
        print('No extracted files to scan (filestore empty)')
        return False

    matches = run_yara_scan(filestore_dir, rules_file)
    write_yara_matches_json(dir_path, matches)

    # Extract metadata for files with zero YARA matches
    matched_sha256s = {m.get('sha256', '') for m in matches}
    file_metadata = {}
    for root, _dirs, files in os.walk(filestore_dir):
        for f in files:
            if f.endswith('.json'):
                continue
            file_path = os.path.join(root, f)
            sha256 = os.path.basename(file_path)
            if not re.match(r'^[a-f0-9]{64}$', sha256):
                continue
            if sha256 in matched_sha256s:
                continue
            metadata = analyze_file(file_path)
            if metadata.get('file_type') or metadata.get('entropy', 0) > 0:
                file_metadata[sha256] = metadata

    if file_metadata:
        meta_path = os.path.join(dir_path, 'file_metadata.json')
        try:
            with open(meta_path, 'w') as f:
                json.dump(file_metadata, f)
        except OSError as e:
            print(f'Warning: could not write file_metadata.json: {e}')

    return True


def scan_single_file(file_path, rules_file):
    """Run YARA on a single arbitrary file and return match results with hashes and metadata.

    Returns a tuple: (matches, sha256, md5, sha1, metadata)
        matches: list of dicts (same format as run_yara_scan)
        sha256: str
        md5: str
        sha1: str
        metadata: dict from file_analyzer.analyze_file
    """
    if not os.path.isfile(file_path):
        return [], '', '', '', {}

    # Compute hashes
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(config.HASH_CHUNK_SIZE), b''):
            sha256.update(chunk)
            md5.update(chunk)
            sha1.update(chunk)

    file_sha256 = sha256.hexdigest()
    file_md5 = md5.hexdigest()
    file_sha1 = sha1.hexdigest()

    # Extract metadata
    metadata = analyze_file(file_path)

    # Write file list for --scan-list
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as list_file:
        list_file.write(file_path + '\n')
        list_path = list_file.name

    try:
        def dedup_and_fix(m):
            m['sha256'] = file_sha256
            return (m['rule_name'], file_sha256)

        matches = _dedup_matches(
            _run_yara_with_index(rules_file, list_path, known_paths=[file_path]),
            key_fn=dedup_and_fix
        )
        return matches, file_sha256, file_md5, file_sha1, metadata
    finally:
        try:
            os.unlink(list_path)
        except OSError:
            pass
