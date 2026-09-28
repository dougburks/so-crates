"""Files on disk for uploads and analyses: the upload scratch directory,
ZIP extraction, hashing, and what an analysis directory (DATA_DIR/<md5>/)
contains - its .meta file, its pcap, and its analysis artifacts.

Functions that need DATA_DIR take it as a parameter rather than reading a
module constant, so they follow socrates.DATA_DIR when it is reassigned
(as the test suite does).
"""

import hashlib
import json
import os
import shutil
import zipfile
from datetime import datetime

import config
from validators import is_pcap_file, validate_zip_extraction

PCAP_EXTENSIONS = ('.pcap', '.pcapng', '.cap', '.trace')

# Pipeline output artifacts removed by /api/reanalyze before re-running analysis
# fast.log/stats.log/suricata.log are Suricata's own logs, written in append
# mode - left in place, every reanalyze added another copy of each.
PCAP_ANALYSIS_ARTIFACTS = ('eve.json', 'events.db', '.phase', '.error', 'yara_matches.json', 'sigma_matches.json', '.meta', 'file_metadata.json', 'fast.log', 'stats.log', 'suricata.log')
FILE_ANALYSIS_ARTIFACTS = ('events.db', '.error', 'yara_matches.json', 'sigma_matches.json', '.meta', 'zircolite.log', '.zircolite_events.db')


def upload_tmp_dir(data_dir):
    """Scratch dir for in-progress uploads, on the same filesystem as DATA_DIR
    so the final move into DATA_DIR/<md5>/... is an atomic rename rather than
    a cross-device copy.
    """
    d = os.path.join(data_dir, config.UPLOAD_TMP_SUBDIR)
    os.makedirs(d, exist_ok=True)
    return d


def cleanup_upload_tmp_dir(data_dir):
    """Remove any leftover entries from upload_tmp_dir(). Meant to be called
    once at startup, before the server accepts requests -- at that point,
    anything found here is guaranteed orphaned (no upload can legitimately
    be in progress yet), left behind by a process that died mid-upload
    (crash, OOM-kill, kill -9) before its own request-scoped cleanup in
    _process_uploaded_file/fetch_url_safely/_parse_multipart_stream could
    run. Those normal completion/exception paths already clean up after
    themselves within a single request's lifetime; this just catches what
    a hard process death leaves behind, which would otherwise accumulate
    forever across restarts.
    """
    tmp_dir = upload_tmp_dir(data_dir)
    for entry in os.listdir(tmp_dir):
        path = os.path.join(tmp_dir, entry)
        try:
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                os.unlink(path)
        except OSError:
            pass


def resolve_upload_size_limit(requested):
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


def attempt_zip_extract(zip_ref, extract_dir, passwords, max_size=None):
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


def extract_zip_contents(zip_path, extract_dir, passwords=None, max_size=None):
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
        if not attempt_zip_extract(zip_ref, extract_dir, passwords, max_size):
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


def hash_file(path):
    """MD5 of a file, streamed in HASH_CHUNK_SIZE chunks (mirrors the hashing
    pattern in yara_analyzer.scan_single_file)."""
    return hash_file_with_prefix(path)[0]


def hash_file_with_prefix(path, prefix_len=4096):
    """Like hash_file, but also returns the first prefix_len bytes in the
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


def is_pcap_path(path):
    """is_pcap_file() on a file's first bytes - for extracted ZIP members,
    which, like a direct upload, may be a real pcap with no recognized
    extension (e.g. Security Onion's so-pcap.<timestamp>)."""
    try:
        with open(path, 'rb') as fh:
            return is_pcap_file(fh.read(4))
    except OSError:
        return False


def write_meta(dir_path, original, extracted, detected_type):
    """Write analysis metadata for frontend routing."""
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


def read_meta(dir_path):
    """Read analysis metadata if it exists."""
    meta_path = os.path.join(dir_path, '.meta')
    if os.path.exists(meta_path):
        try:
            with open(meta_path) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            pass
    return None


def find_pcap_file(dir_path):
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
