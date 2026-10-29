"""Files on disk for uploads and analyses: the upload scratch directory,
what a server that died left in /tmp, ZIP extraction, hashing, and what an analysis directory (DATA_DIR/<md5>/)
contains - its .meta file, its pcap, and its analysis artifacts.

Functions that need DATA_DIR take it as a parameter rather than reading a
module constant, so they follow socrates.DATA_DIR when it is reassigned
(as the test suite does).
"""

import hashlib
import json
import os
import re
import shutil
import tempfile
import time
import zipfile
import zlib
from datetime import datetime

import config
from validators import is_pcap_file, is_safe_path, validate_zip_extraction

PCAP_EXTENSIONS = ('.pcap', '.pcapng', '.cap', '.trace')

# Pipeline output artifacts removed by /api/reanalyze before re-running analysis
# fast.log/stats.log/suricata.log are Suricata's own logs, written in append
# mode - left in place, every reanalyze added another copy of each.
PCAP_ANALYSIS_ARTIFACTS = ('eve.json', 'events.db', 'events.db-wal', 'events.db-shm', '.phase', '.error', '.warnings', 'yara_matches.json', 'sigma_matches.json', '.meta', 'file_metadata.json', 'fast.log', 'stats.log', 'suricata.log',
                           # tshark - shark_analyzer.SHARK_ARTIFACTS (a test keeps the two in step)
                           'shark.db', 'shark.db-wal', 'shark.db-shm', 'shark.db.tmp', '.shark_error')
FILE_ANALYSIS_ARTIFACTS = ('events.db', 'events.db-wal', 'events.db-shm', '.error', '.warnings', 'yara_matches.json', 'sigma_matches.json', '.meta', 'zircolite.log', '.zircolite_events.db')


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


def cleanup_stale_tmp(names, max_age=config.STALE_TMP_SECONDS):
    """Remove what a server that died (crash, OOM-kill, kill -9) left in
    the system temp directory: entries named by names - (prefix, suffix)
    pairs around tempfile's 8 random characters - that are this user's
    and older than max_age. Unlike upload_tmp_dir(), /tmp may be shared
    with another SO-CRATES running on the same computer, so what's still
    young enough to be in use there is left alone; on a container restart,
    what's left there goes the next time. Called once at startup."""
    pattern = re.compile('|'.join(re.escape(prefix) + '[a-z0-9_]{8}' + re.escape(suffix)
                                  for prefix, suffix in names))
    tmp_dir = tempfile.gettempdir()
    now = time.time()
    try:
        entries = os.listdir(tmp_dir)
    except OSError:
        return
    for entry in entries:
        if not pattern.fullmatch(entry):
            continue
        path = os.path.join(tmp_dir, entry)
        try:
            st = os.lstat(path)
            if st.st_uid != os.getuid() or now - st.st_mtime < max_age:
                continue
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                os.unlink(path)
        except OSError:
            pass


def remove_imported_eve_files(data_dir):
    """Remove eve.json from every finished PCAP analysis in data_dir.
    events.db keeps each of its events in full, and nothing reads eve.json
    once it has been imported, so it only doubles the disk an analysis
    takes (spawn_suricata removes it itself as soon as the import
    succeeds - this catches analyses made before it did). One still
    running (.phase) or with an error (.error, which may be a failed
    import) keeps it. Meant to be called once at startup, before
    any analysis can be under way. Returns the bytes freed."""
    freed = 0
    for entry in os.listdir(data_dir):
        dir_path = os.path.join(data_dir, entry)
        eve_path = os.path.join(dir_path, 'eve.json')
        if not os.path.isfile(eve_path) or not os.path.isfile(os.path.join(dir_path, 'events.db')) or \
                any(os.path.exists(os.path.join(dir_path, f)) for f in ('.phase', '.error')):
            continue
        try:
            size = os.path.getsize(eve_path)
            os.unlink(eve_path)
            freed += size
        except OSError:
            pass
    return freed


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


# What extracting raises for an archive this password doesn't open:
# RuntimeError for a bad or missing password; NotImplementedError,
# zipfile's own signal for strong encryption (AES) or an unsupported
# compression method - real, and fairly common in malware-sample
# archives; and BadZipFile (a bad CRC), zlib.error or EOFError when a wrong
# ZipCrypto password slips past its one-byte check (1 in 256) and the
# result is garbage - so the next password is still tried.
_ZIP_EXTRACT_ERRORS = (RuntimeError, NotImplementedError, zipfile.BadZipFile, zlib.error, EOFError)


# An analysis's warnings: what went wrong without failing it - its results
# are shown, with these above them (a YARA scan that failed, so its file
# alerts may be missing). .error, by contrast, is an analysis that failed.
WARNINGS_FILE = '.warnings'
_MAX_WARNINGS = 20


def add_analysis_warning(dir_path, message):
    warnings = read_analysis_warnings(dir_path)
    if message in warnings or len(warnings) >= _MAX_WARNINGS:
        return
    try:
        with open(os.path.join(dir_path, WARNINGS_FILE), 'w') as f:
            json.dump(warnings + [message[:500]], f)
    except OSError:
        pass


def read_analysis_warnings(dir_path):
    try:
        with open(os.path.join(dir_path, WARNINGS_FILE)) as f:
            warnings = json.load(f)
    except (OSError, ValueError):
        return []
    return [w for w in warnings if isinstance(w, str)] if isinstance(warnings, list) else []


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
    except _ZIP_EXTRACT_ERRORS:
        pass

    if not extracted and passwords:
        for pwd in passwords:
            try:
                zip_ref.extractall(extract_dir, pwd=pwd)
                extracted = True
                break
            except _ZIP_EXTRACT_ERRORS:
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
    try:
        zip_ref = zipfile.ZipFile(zip_path, 'r')
    except (zipfile.BadZipFile, EOFError, OSError):
        raise ValueError('This ZIP file is damaged and could not be read.')
    with zip_ref:
        if not attempt_zip_extract(zip_ref, extract_dir, passwords, max_size):
            raise ValueError('The ZIP could not be extracted: its password is not one tried here, it uses '
                             'encryption or compression that can\'t be read (such as AES), or it is damaged.')

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


def non_artifact_files(dir_path, pcap_file=None):
    """List the real user-uploaded file(s) in an analysis dir, excluding
    PCAPs/ZIPs, dotfiles, and known pipeline-artifact filenames.

    Shared by resolve_display_name() (display-name fallback) and
    socrates.py's handle_post_reanalyze() (finding the file to re-run analysis on) -
    these two used to have separately hand-rolled, drifted versions of
    this same listing.

    Exact artifact filenames, not a blanket extension exclusion - a
    user-uploaded log file legitimately ends in .log, and a standalone
    (non-log) upload can legitimately end in .txt/.json/.db too, and
    must still be found here. zircolite.log specifically used to slip
    through an earlier, looser check and could transiently win a
    directory listing race against the real uploaded file's name.

    pcap_file, if the caller already knows it (e.g. from
    find_pcap_file(), which also matches extension-less pcaps via
    magic bytes - not just this function's own PCAP_EXTENSIONS check),
    is excluded by exact name too.
    """
    if not os.path.exists(dir_path):
        return []
    exact_artifacts = set(PCAP_ANALYSIS_ARTIFACTS) | set(FILE_ANALYSIS_ARTIFACTS) | {'name.txt', 'notes.txt'}
    # Regular files only: filestore/ (Suricata's extracted files, or an
    # email's attachments) is a directory, and could otherwise win the
    # listing and be "reanalyzed".
    return [f for f in os.listdir(dir_path)
            if f != pcap_file
            and not f.lower().endswith(PCAP_EXTENSIONS + ('.zip',))
            and not f.startswith('.')
            and f not in exact_artifacts
            and os.path.isfile(os.path.join(dir_path, f))]


def resolve_display_name(dir_path, md5):
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

    non_pcap_files = non_artifact_files(dir_path)
    if non_pcap_files:
        return non_pcap_files[0]

    return md5


def remove_artifacts(dir_path, artifacts):
    """Delete each named artifact file from dir_path if present.
    Best-effort per-file (a stuck/permission-denied file doesn't block
    cleanup of the rest) - shared by socrates.py's handle_post_reanalyze's
    pcap and non-pcap branches, which previously each inlined an identical copy
    of this loop over their own artifact tuple.
    """
    for artifact in artifacts:
        artifact_path = os.path.join(dir_path, artifact)
        if os.path.exists(artifact_path):
            try:
                os.unlink(artifact_path)
            except OSError:
                pass


def restore_meta(meta_path, preserved_meta):
    """Rewrite .meta after a reanalyze cleanup, so the frontend
    retains detected_type across the reanalyze - best-effort, same
    reasoning as remove_artifacts. Shared by handle_post_reanalyze's
    pcap and non-pcap branches.
    """
    if preserved_meta:
        try:
            with open(meta_path, 'w') as f:
                json.dump(preserved_meta, f)
        except OSError:
            pass


_MD5_DIR_RE = re.compile(r'\A[a-f0-9]{32}\Z')


def finished_analysis_dirs(data_dir, max_eve_size=config.MAX_EVE_SIZE):
    """(md5, dir_path, events.db's path or None) for each analysis in
    data_dir with results to list - an events.db, or an eve.json not yet
    imported that's no bigger than max_eve_size."""
    found = []
    if not os.path.exists(data_dir):
        return found
    for md5_dir in os.listdir(data_dir):
        if not _MD5_DIR_RE.match(md5_dir):
            continue
        dir_path = os.path.join(data_dir, md5_dir)
        if not os.path.isdir(dir_path):
            continue
        eve_path = os.path.join(dir_path, 'eve.json')
        db_path = os.path.join(dir_path, 'events.db')
        if os.path.exists(eve_path):
            eve_size = os.path.getsize(eve_path)
            if eve_size > max_eve_size:
                continue

        if os.path.exists(eve_path) or os.path.exists(db_path):
            found.append((md5_dir, dir_path, db_path if os.path.exists(db_path) else None))
    return found
