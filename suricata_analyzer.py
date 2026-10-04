#!/usr/bin/env python3
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time

import config
from db import create_sqlite_db
from validators import is_host_reachable, is_epoch_stale, gunzip_atomically
from yara_analyzer import run_yara_pipeline

REQUIRED_EXECUTABLES = ['tcpdump', 'tshark', 'suricata', 'suricata-update']

# Curated, free/non-commercial subset of OISF's suricata-intel-index
# (https://raw.githubusercontent.com/OISF/suricata-intel-index/refs/heads/master/index.yaml),
# excluding Commercial-licensed, obsolete, and source-deprecated entries.
# 'et/open' is the long-standing default (suricata-update's own implicit
# behavior when no source is explicitly enabled) and stays the sole
# default here too - everything else is opt-in via the Rules modal.
SURICATA_RULE_SOURCES = {
    'et/open': {'label': 'Emerging Threats Open', 'url': 'https://rules.emergingthreats.net/'},
    'oisf/trafficid': {'label': 'Suricata Traffic ID', 'url': 'https://openinfosecfoundation.org/rules/trafficid/trafficid.rules'},
    'abuse.ch/sslbl-blacklist': {'label': 'Abuse.ch SSL Blacklist', 'url': 'https://sslbl.abuse.ch/'},
    'abuse.ch/sslbl-ja3': {'label': 'Abuse.ch JA3 Fingerprints', 'url': 'https://sslbl.abuse.ch/ja3-fingerprints/'},
    'abuse.ch/feodotracker': {'label': 'Abuse.ch Feodo Tracker', 'url': 'https://feodotracker.abuse.ch/'},
    'abuse.ch/urlhaus': {'label': 'Abuse.ch URLhaus', 'url': 'https://urlhaus.abuse.ch/'},
    'etnetera/aggressive': {'label': 'Etnetera Aggressive IP Blacklist', 'url': 'https://security.etnetera.cz/'},
    'ptrules/open': {'label': 'Positive Technologies PT Rules (Open)', 'url': 'https://rules.ptsecurity.com'},
    'pawpatrules': {'label': 'PAW Patrules', 'url': 'https://pawpatrules.fr/'},
    'stamus/lateral': {'label': 'Stamus Lateral Movement', 'url': 'https://www.stamus-networks.com/'},
    'tgreen/hunting': {'label': 'Threat Hunting Rules (tgreen)', 'url': 'https://github.com/travisbgreen/hunting-rules'},
    'aleksibovellan/nmap': {'label': 'NMAP Scan Detection', 'url': 'https://github.com/aleksibovellan/opnsense-suricata-nmaps'},
    'julioliraup/antiphishing': {'label': 'Antiphishing', 'url': 'https://github.com/julioliraup/Antiphishing'},
    'the-hunters-ledger/open': {'label': "The Hunter's Ledger", 'url': 'https://the-hunters-ledger.com/'},
    # Last, deliberately - unlike every other entry above, this is a
    # content-*filtering* blocklist rather than threat detection (see
    # BAKED_IN_SURICATA_SOURCES's comment below) and is by far the largest/
    # slowest to fetch, so it's kept visually separate at the end of the
    # list rather than alphabetized in with the rest.
    'ipfire/dbl': {'label': 'IPFire DBL', 'url': 'https://www.ipfire.org/dbl/', 'note': 'Large ruleset (~51 MiB) - first fetch can take a while'},
}
DEFAULT_SURICATA_SOURCES = ['et/open']

# ipfire/dbl deliberately excluded from what the Docker image bakes in -
# it's the single biggest source in the curated set (~51 MiB on its own,
# via its dataset:-based domain lists - the other 14 together are ~84 MB
# uncompressed, measured 2026-09-25) and is actually a content-*filtering*
# blocklist (ads/dating/gambling/social/streaming/etc. categories), not
# threat detection - most of it would just add alert noise on ordinary
# browsing traffic. It stays in
# SURICATA_RULE_SOURCES so online users can still fetch it on demand via
# the Rules modal; Dockerfile's bake loop derives its own list from this
# (BAKED_IN_SURICATA_SOURCES), not a separately hand-maintained one.
BAKED_IN_SURICATA_SOURCES = [s for s in SURICATA_RULE_SOURCES if s != 'ipfire/dbl']


def _source_filename(slug):
    """Map a SURICATA_RULE_SOURCES key to its on-disk rules filename (e.g.
    'abuse.ch/urlhaus' -> 'abuse.ch-urlhaus.rules') - single source of
    truth for naming, used by both the Dockerfile's per-source bake loop
    and every runtime path that reads/writes a source's file (the
    rules-available/ library, the active rules/ dir, and the static
    rule-files: list in suricata.yaml), so they can never disagree."""
    return slug.replace('/', '-') + '.rules'


# Every curated source's on-disk filename - the only files in the active
# rules/ dir that represent a real enable/disable choice. The active dir
# also always contains Suricata's own bundled per-protocol event files
# (app-layer-events.rules, decoder-events.rules, etc. - copied in from
# /etc/suricata's own rules/ subdirectory alongside suricata.yaml on first
# run, unrelated to any curated source), which also end in .rules -
# verified against a real install that these two sets are otherwise
# indistinguishable by filename alone, so anything checking "is there real
# curated ruleset coverage" (get_suricata_rules_info, the baked-in-library
# seeding fallback) must filter to this set specifically, not just any
# *.rules file, or it would always see "rules exist" from the bundled
# event files alone even with zero curated sources active.
_CURATED_RULE_FILENAMES = {_source_filename(slug) for slug in SURICATA_RULE_SOURCES}


def check_executables():
    """Check all required executables exist. Returns list of missing tools."""
    missing = []
    for tool in REQUIRED_EXECUTABLES:
        if shutil.which(tool) is None:
            missing.append(tool)
    return missing


def has_internet_access():
    return is_host_reachable('rules.emergingthreats.net', 80, timeout=5)


def _enable_app_layer_protocols(config_content, protocols=('pgsql', 'modbus', 'dnp3', 'enip')):
    """Enable disabled app-layer protocols in a suricata.yaml string.

    Suricata sometimes places comment lines between the protocol header and
    the `enabled:` key (e.g. modbus), so the regex tolerates intervening
    comments/blank lines.
    """
    for proto in protocols:
        config_content = re.sub(
            rf'(?m)^(\s+{proto}:\s*\n(?:\s*#.*\n)*\s+)enabled:\s*no',
            r'\1enabled: yes',
            config_content
        )
    return config_content


def _enable_eve_log_protocol_types(config_content, protocols=('modbus', 'dnp3', 'enip', 'ntp')):
    """Enable EVE logging for protocols that are supported but not logged by default.

    Suricata supports `event_type: modbus`, `event_type: dnp3`,
    `event_type: enip`, and `event_type: ntp` records, but none of them is
    listed in the default eve-log `types` block - confirmed against the
    shipped /etc/suricata/suricata.yaml (only pgsql is listed there, and it's
    disabled by default). This helper turns on the pgsql logger and adds the
    others just before the `stats` entry so they appear as standalone events.

    'enip'/'ntp' history: this app originally shipped on Suricata 7.0.10,
    where their app-layer parsers detected traffic fine (confirmed: a real
    NTP capture showed 15 flows correctly tagged app_proto=ntp) but neither
    had an eve-log *output module* compiled in at all - `No output module
    named eve-log.ntp`/`eve-log.enip` at startup, zero events regardless of
    config. Checked against Suricata's own source: rust/src/ntp/ had no
    log.rs and rust/src/enip/ didn't exist yet at the `suricata-7.0.10` tag.
    Now that this app runs on Suricata 8.0.6 (enip logging landed in 8.0.0,
    ntp logging in 8.0.5 - confirmed against those release tags), both
    loggers exist and 'enip'/'ntp' are back in the default tuple for real.
    If this ever runs against an older Suricata again, re-check for the
    `No output module` warning before assuming this config change does
    anything.

    REGRESSION (independent of the enip/ntp version history above): this
    used to be one regex requiring `- pgsql:` to be followed only by
    indented property lines up to `- stats:`. That's true only on a pristine
    config - once a previous run had already inserted bare `- modbus:` /
    `- dnp3:` header lines in between (exactly what this function itself
    does), the regex could never match again, so re-running setup on an
    already-provisioned install would silently stop adding any newly-added
    protocol at all (confirmed by reproducing it: re-running against a real
    already-processed suricata.yaml added nothing, while the same code
    worked fine against a pristine /etc/suricata/suricata.yaml). Enabling
    pgsql's logger and inserting the missing bare headers are now two
    independent, idempotent steps instead of one fragile combined regex, so
    this is safe to call repeatedly and safe to extend with new protocols
    whenever that becomes appropriate.
    """
    # Enable the pgsql logger if it is currently disabled - a no-op if it's
    # already enabled or the pgsql block isn't found.
    config_content = re.sub(
        r'(?m)(^        - pgsql:\s*\n            )enabled: no$',
        r'\1enabled: yes',
        config_content
    )

    new_types = [f'        - {p}:\n' for p in protocols
                 if f'        - {p}:' not in config_content]
    if not new_types:
        return config_content

    return re.sub(
        r'(?m)^        - stats:',
        lambda m: ''.join(new_types) + m.group(0),
        config_content,
        count=1
    )


def _enable_eve_log_arp(config_content):
    """Enable the 'arp' eve-log entry, which ships disabled by default.

    New in Suricata 8 (a decode-layer packet logger, not an app-layer
    protocol - src_mac/src_ip/dest_mac/dest_ip/opcode per ARP packet, no
    ports). Suricata's own shipped config comment says why it's off by
    default: "Many events can be logged." Unlike modbus/dnp3/enip/ntp/pgsql
    (which this app always force-enables because they're low-volume and
    clearly valuable), arp's volume/signal tradeoff on a live network is a
    real judgment call - so this is opt-in only, gated behind
    setup_suricata_config()'s enable_arp parameter (set via the
    ENABLE_ARP_LOGGING environment variable - see socrates.py's main()),
    not force-enabled for every install.
    """
    return re.sub(
        r'(?m)(^        - arp:\s*\n            )enabled: no\b',
        r'\1enabled: yes',
        config_content
    )


def _enable_ja3_ja4_fingerprints(config_content):
    """Enable JA3/JA3S/JA4 TLS client/server fingerprinting, which ships
    as `auto` (commented out) by default - Suricata only computes them
    when an active rule's signature keyword requires it, so without this
    the fields are silently absent from `tls` events whenever none of the
    currently-enabled curated rule sources happen to reference ja3/ja4.

    Forced on unconditionally, like community-id (see _enable_community_id)
    rather than gated behind a parameter like arp - JA3/JA4 are core
    malware-family/C2 TLS fingerprints analysts rely on for hunting and
    threat-intel matching, and computing them is cheap (per-handshake, not
    a new event type), so there's no real volume/signal tradeoff to weigh
    the way arp's live-network packet volume is.

    The regex must anchor on the commented-out `#...: auto` form
    specifically, not just the key name, so a re-run against an
    already-enabled config (this function runs on every
    setup_suricata_config() call, including every server restart) is a
    harmless no-op instead of re-matching and clobbering an explicit
    operator override.
    """
    config_content = re.sub(
        r'(?m)^(\s+)#ja3-fingerprints:\s*auto$',
        r'\1ja3-fingerprints: yes',
        config_content
    )
    config_content = re.sub(
        r'(?m)^(\s+)#ja4-fingerprints:\s*auto$',
        r'\1ja4-fingerprints: yes',
        config_content
    )
    return config_content


def _enable_community_id(config_content):
    """Enable Suricata's community-id output, which ships disabled by
    default (`community-id: false`).

    Unlike the arp eve-log entry (a real volume/signal tradeoff, kept
    opt-in - see _enable_eve_log_arp), community-id adds a single
    deterministic `community_id` field to flow/alert records rather than
    new events, so it's forced on unconditionally like the other five
    file-store tweaks below rather than gated behind a parameter. It lets
    so-crates' output correlate against Zeek/other community-id-aware
    tools without a user ever discovering the setting exists.

    The regex must anchor on the trailing `: false` value, not just the
    `community-id` key name, so it can never also match the neighboring
    `community-id-seed: 0` line.
    """
    return re.sub(
        r'(?m)^(\s+community-id:\s*)false$',
        r'\1true',
        config_content
    )


def get_suricata_enabled_sources(data_dir=None):
    """Return the list of currently-enabled suricata-update source names,
    filtered to SURICATA_RULE_SOURCES (so a curated entry removed in a
    later version can't linger forever just because it's still in an old
    enabled_sources.json). Defaults to DEFAULT_SURICATA_SOURCES if the
    state file doesn't exist yet (fresh install, or one that has never
    triggered a reconciliation) or fails to parse.

    Deliberately a plain file read, not a suricata-update subprocess call -
    this is read on every /api/rules-info poll (every 2s while the Rules
    modal is open), so it needs to stay as cheap as
    get_yara_rules_info()/get_sigma_rules_info() already are. The
    JSON file itself is written by _reconcile_suricata_sources() below,
    which is the only thing that ever changes what's actually enabled in
    suricata-update's own state.
    """
    if data_dir is None:
        data_dir = os.path.expanduser('~/socrates-data')
    path = os.path.join(data_dir, 'suricata', 'enabled_sources.json')
    try:
        with open(path, 'r') as f:
            names = json.load(f)
        filtered = [n for n in names if n in SURICATA_RULE_SOURCES]
        return filtered or list(DEFAULT_SURICATA_SOURCES)
    except (OSError, ValueError, TypeError):
        return list(DEFAULT_SURICATA_SOURCES)


def get_suricata_show_protocol_decode_alerts(data_dir=None):
    """Whether Suricata's own bundled protocol-command-decode event rules
    (e.g. SID 2210054 "SURICATA STREAM excessive retransmissions") should
    be left active instead of suppressed. False (suppressed) by default -
    these are noisy built-in stream/decoder anomaly events bundled
    identically into every curated source's own fetched output (they don't
    have their own feed/URL to pick from independently), not really
    "alerts" about traffic content. Persisted in
    show_protocol_decode_alerts.json, written by setup_suricata_config()
    whenever the Rules modal explicitly submits a value - mirrors
    get_suricata_enabled_sources()'s own read/write split against
    enabled_sources.json.
    """
    if data_dir is None:
        data_dir = os.path.expanduser('~/socrates-data')
    path = os.path.join(data_dir, 'suricata', 'show_protocol_decode_alerts.json')
    try:
        with open(path, 'r') as f:
            return bool(json.load(f))
    except (OSError, ValueError, TypeError):
        return False


def _active_rules_exist(suricata_rules_dir):
    """True if the active rules/ directory has at least one *curated*
    source's .rules file active - the multi-file equivalent of the old
    single-suricata.rules existence check. Must check against
    _CURATED_RULE_FILENAMES specifically, not just any *.rules file - see
    its comment for why (Suricata's own bundled per-protocol event files
    also end in .rules and are always present regardless of source
    selection)."""
    try:
        return any(f in _CURATED_RULE_FILENAMES for f in os.listdir(suricata_rules_dir))
    except OSError:
        return False


def _fetch_single_source(suricata_dir, name, dest_path, on_progress):
    """Fetch exactly one source's rules into dest_path via an isolated
    suricata-update run against a scratch --data-dir/--output - mirrors
    exactly what the Docker image's own per-source bake loop does (see
    Dockerfile), so a runtime-fetched rules-available/ library file and a
    baked-in one are produced identically. dest_path is only ever written
    after a fully clean run (moved into place at the very end), never left
    partially written on failure.

    Deliberately reports one concise progress line per source rather than
    streaming suricata-update's full internal log the way the old
    single-merged-fetch path did - doing that for every one of up to ~14
    sources on a single Update click would make the Rules modal's log
    unreadably long. Only the actual network fetch is reported at all -
    _reconcile_suricata_sources() deliberately says nothing when it then
    activates the result (or reactivates an already-staged source with no
    fetch involved at all) - a local file copy/delete isn't worth a log
    line, and activating a dozen already-staged sources at once (e.g.
    "Enable All") used to spam one "Enabled source: X" line per source for
    what is, from the user's point of view, an instant, uninteresting
    bookkeeping step.
    """
    start = time.monotonic()
    scratch_data = tempfile.mkdtemp(dir=suricata_dir, prefix='.fetch-data-')
    scratch_out = tempfile.mkdtemp(dir=suricata_dir, prefix='.fetch-out-')
    try:
        try:
            subprocess.run(
                ['suricata-update', 'update-sources', '--data-dir', scratch_data],
                capture_output=True, text=True, timeout=config.SURICATA_SOURCE_RECONCILE_TIMEOUT,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass  # falls back to the bundled index, same as elsewhere

        try:
            enable_result = subprocess.run(
                ['suricata-update', 'enable-source', name, '--data-dir', scratch_data],
                capture_output=True, text=True, timeout=config.SURICATA_SOURCE_RECONCILE_TIMEOUT,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            on_progress(f'Warning: could not fetch {name}: {e}')
            return False
        if enable_result.returncode != 0:
            on_progress(f'Warning: could not fetch {name} (not available or incompatible)')
            return False
        # enable-source on a brand-new --data-dir always ALSO silently
        # auto-enables et/open as its own "default source" regardless of
        # what was actually requested (verified against the real binary -
        # a fresh scratch dir enabling e.g. oisf/trafficid alone produced
        # a merged file containing et/open's full ~52k rules too, not just
        # trafficid's 34). Must be explicitly disabled again for every
        # other source, or this "isolated single-source fetch" isn't
        # actually isolated at all.
        if name != 'et/open':
            try:
                subprocess.run(
                    ['suricata-update', 'disable-source', 'et/open', '--data-dir', scratch_data],
                    capture_output=True, text=True, timeout=config.SURICATA_SOURCE_RECONCILE_TIMEOUT,
                )
            except (OSError, subprocess.TimeoutExpired) as e:
                on_progress(f'Warning: could not fetch {name}: {e}')
                return False

        try:
            fetch_result = subprocess.run(
                ['suricata-update', '--no-test', '--suricata-conf', os.path.join(suricata_dir, 'suricata.yaml'),
                 '--data-dir', scratch_data, '--output', scratch_out,
                 # Each source's fetch uses its own fresh, empty scratch
                 # --data-dir (see this function's docstring), so
                 # suricata-update's own default disable.conf lookup
                 # (relative to --data-dir) would never find the shared one
                 # setup_suricata_config() writes to suricata_dir - must be
                 # pointed at explicitly here, or it's silently never
                 # applied. A missing file at this path is a harmless
                 # warning to suricata-update, not an error (verified by
                 # hand), so this is safe even before setup_suricata_config()
                 # has ever written it (e.g. direct test calls).
                 '--disable-conf', os.path.join(suricata_dir, 'disable.conf')],
                capture_output=True, text=True, timeout=config.SURICATA_UPDATE_TIMEOUT,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            on_progress(f'Warning: could not fetch {name}: {e}')
            return False
        if fetch_result.returncode != 0:
            on_progress(f'Warning: could not fetch {name} (suricata-update exited with code {fetch_result.returncode})')
            return False

        fetched_file = os.path.join(scratch_out, 'suricata.rules')
        if not os.path.isfile(fetched_file):
            on_progress(f'Warning: {name} fetch produced no rules file')
            return False
        try:
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            shutil.move(fetched_file, dest_path)
        except OSError as e:
            on_progress(f'Warning: could not save {name}: {e}')
            return False
        elapsed = round(time.monotonic() - start)
        on_progress(f'Fetched {name} in {elapsed} second{"s" if elapsed != 1 else ""}')
        return True
    finally:
        shutil.rmtree(scratch_data, ignore_errors=True)
        shutil.rmtree(scratch_out, ignore_errors=True)


def _activate_from_library(library_path, active_path, name, on_progress, verb='activate'):
    """Copy a source's library file into the active rules/ dir - shared by
    _reconcile_suricata_sources()'s add-loop and setup_suricata_config()'s
    refresh loop, which otherwise each wrote out the same copy2/OSError-
    handling pattern by hand. verb only changes the warning wording
    ('could not activate X' vs 'could not activate refreshed X') to match
    what each caller already said before this was factored out."""
    try:
        shutil.copy2(library_path, active_path)
        return True
    except OSError as e:
        on_progress(f'Warning: could not {verb} {name}: {e}')
        return False


def _reconcile_suricata_sources(suricata_dir, data_dir, desired_names, on_progress, network_allowed):
    """Make the active rules/ directory contain exactly one file per
    desired source, backed by the permanent rules-available/ library, then
    record the confirmed result in enabled_sources.json.

    Unlike the old suricata-update-CLI-based design (enable-source/
    disable-source, whose state lived in a --data-dir with no relationship
    between build-time/image and run-time/DATA_DIR), toggling a source that's already in the library
    is pure local file copy/delete, no network at all - this is what lets
    an airgapped user choose among whatever was baked into the image.
    Only a source that has never been staged locally (not baked in, never
    fetched before) needs an actual network fetch, checked once up front
    here rather than per-source, so an actually-offline caller fails fast
    with one clear message per source instead of N slow individual
    timeouts. network_allowed mirrors every other "does this caller even
    permit reaching out" gate in this module (never true for server
    startup/background-scan callers, which never pass enabled_sources
    anyway).

    Returns the set of names that were freshly fetched over the network
    during this call (as opposed to reactivated from an already-staged
    library file) - setup_suricata_config()'s subsequent "refresh every
    active source" pass must skip these, or a source enabled for the
    first time gets fetched twice in a row (once here, once by that
    refresh) - noticeable and slow specifically when enabling many
    sources at once via "Enable All".
    """
    desired = [n for n in desired_names if n in SURICATA_RULE_SOURCES]
    if not desired:
        desired = list(DEFAULT_SURICATA_SOURCES)
    current = get_suricata_enabled_sources(data_dir)
    if set(desired) == set(current):
        return set()

    library_dir = os.path.join(data_dir, 'suricata', 'rules-available')
    active_dir = os.path.join(suricata_dir, 'rules')
    os.makedirs(library_dir, exist_ok=True)
    os.makedirs(active_dir, exist_ok=True)

    to_add = [n for n in desired if n not in current]
    needs_fetch = [n for n in to_add if not os.path.isfile(os.path.join(library_dir, _source_filename(n)))]
    internet_reachable = bool(needs_fetch) and network_allowed and has_internet_access()
    if needs_fetch and not internet_reachable:
        for name in needs_fetch:
            on_progress(f'Warning: {name} is not available offline yet — needs internet the first time')

    confirmed = [n for n in current if n in desired]
    freshly_fetched = set()
    for name in to_add:
        filename = _source_filename(name)
        library_path = os.path.join(library_dir, filename)
        if not os.path.isfile(library_path):
            if name not in needs_fetch or not internet_reachable or not _fetch_single_source(suricata_dir, name, library_path, on_progress):
                continue
            freshly_fetched.add(name)
        # No progress line for the activation itself (just a local file
        # copy) - see _fetch_single_source()'s docstring for why.
        if _activate_from_library(library_path, os.path.join(active_dir, filename), name, on_progress):
            confirmed.append(name)

    # No progress line for disabling either - same reasoning as the
    # activation loop above (see _fetch_single_source()'s docstring): a
    # local file delete isn't worth a log line, and "Revert to Default"
    # disabling a dozen sources at once used to spam one "Disabled source:
    # X" line per source for what is, from the user's point of view, an
    # instant, uninteresting bookkeeping step.
    for name in current:
        if name in desired:
            continue
        active_path = os.path.join(active_dir, _source_filename(name))
        try:
            if os.path.exists(active_path):
                os.remove(active_path)
        except OSError as e:
            on_progress(f'Warning: could not disable {name}: {e}')

    state_path = os.path.join(data_dir, 'suricata', 'enabled_sources.json')
    try:
        os.makedirs(os.path.dirname(state_path), exist_ok=True)
        with open(state_path, 'w') as f:
            json.dump(confirmed, f)
    except OSError as e:
        on_progress(f'Warning: could not save ruleset selection: {e}')

    return freshly_fetched


def _seed_active_from_library(baked_in_library_dir, data_dir, source_names, on_progress):
    """Copy the image's baked-in per-source library into the local
    rules-available/ library - never overwriting an already-present local
    file, so a locally fetched/refreshed copy always wins over the image's
    static snapshot - then activate whichever of source_names are actually
    present there, and record the *actually activated* set in
    enabled_sources.json (not the requested one, in case a file is
    missing/corrupt) so the Rules modal never claims something is enabled
    that isn't. Used both for the very first startup on a fresh volume and
    as a last-resort fallback if every live refresh attempt fails.

    The image bakes these in gzip-compressed (`<name>.rules.gz` - see the
    Dockerfile's bake loop; plain-text Suricata rules compress ~93%, ~84MB
    down to ~6MB across the 14 baked-in sources, measured 2026-09-25) -
    decompressed here into the
    plain `.rules` filename every other reader in this module already
    expects, so nothing downstream needs to know the baked-in copy was ever
    compressed.
    """
    suricata_dir = os.path.join(data_dir, 'suricata')
    library_dir = os.path.join(suricata_dir, 'rules-available')
    active_dir = os.path.join(suricata_dir, 'rules')
    os.makedirs(library_dir, exist_ok=True)
    os.makedirs(active_dir, exist_ok=True)
    try:
        for filename in os.listdir(baked_in_library_dir):
            dest_filename = filename[:-len('.gz')] if filename.endswith('.gz') else filename
            dest = os.path.join(library_dir, dest_filename)
            if os.path.exists(dest):
                continue
            src = os.path.join(baked_in_library_dir, filename)
            if filename.endswith('.gz'):
                # Atomic, and carries the baked-in mtime over (as copy2
                # does below) - see gunzip_atomically.
                gunzip_atomically(src, dest)
            else:
                shutil.copy2(src, dest)
    except OSError as e:
        on_progress(f'Warning: could not copy baked-in rules library: {e}')
        return

    activated = []
    for name in source_names:
        filename = _source_filename(name)
        library_path = os.path.join(library_dir, filename)
        if os.path.isfile(library_path):
            try:
                shutil.copy2(library_path, os.path.join(active_dir, filename))
                activated.append(name)
            except OSError as e:
                on_progress(f'Warning: could not activate baked-in {name}: {e}')
    if activated:
        on_progress("Baked-in rules copied successfully")

    state_path = os.path.join(suricata_dir, 'enabled_sources.json')
    try:
        with open(state_path, 'w') as f:
            json.dump(activated, f)
    except OSError as e:
        on_progress(f'Warning: could not save ruleset selection: {e}')


def get_suricata_rules_info(data_dir=None):
    """Return {'count': int|None, 'updated': epoch|None, 'stale': bool|None}
    summarizing every currently-active *curated* Suricata source file (the
    active rules/ dir now holds one file per enabled source, not a single
    merged suricata.rules) - filtered to _CURATED_RULE_FILENAMES
    specifically, not just any *.rules file, since Suricata's own bundled
    per-protocol event files also live in that directory and would
    otherwise inflate the count with irrelevant pseudo-rules. Disabled
    rules are '#'-commented, so counting non-blank, non-'#' lines across
    all active curated files gives the real enabled-rule count. 'stale' is
    True once the *oldest* active file is older than
    config.RULES_MAX_AGE_HOURS - the least-fresh active source is what
    "stale" should mean now, not whichever happened to be refreshed most
    recently. Purely local mtime checks, no network access, safe to call
    unconditionally (see static/socrates.js's checkForStaleRules(), which
    is opt-in). Never raises - returns None fields if there are no active
    curated rule files yet."""
    if data_dir is None:
        data_dir = os.path.expanduser('~/socrates-data')
    suricata_rules_dir = os.path.join(data_dir, 'suricata', 'rules')
    try:
        rule_files = [f for f in os.listdir(suricata_rules_dir) if f in _CURATED_RULE_FILENAMES]
    except OSError:
        rule_files = []
    if not rule_files:
        return {'count': None, 'updated': None, 'stale': None}

    total_count = 0
    oldest_mtime = None
    for filename in rule_files:
        path = os.path.join(suricata_rules_dir, filename)
        try:
            with open(path, 'r', errors='ignore') as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith('#'):
                        total_count += 1
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        oldest_mtime = mtime if oldest_mtime is None else min(oldest_mtime, mtime)

    if oldest_mtime is None:
        return {'count': None, 'updated': None, 'stale': None}
    return {
        'count': total_count,
        'updated': oldest_mtime,
        'stale': is_epoch_stale(oldest_mtime, config.RULES_MAX_AGE_HOURS),
    }


def setup_suricata_config(data_dir=None, enable_arp=False, on_progress=print, network_allowed=True, enabled_sources=None, show_protocol_decode_alerts=None):
    """Ensure Suricata is configured and has rules available.

    Priority when network_allowed and internet is reachable: refresh every
    currently-active source's rules, falling back to existing on-disk
    rules or the baked-in library if every refresh fails.

    Priority otherwise (including every server startup, which always
    calls this with network_allowed=False): existing on-disk rules take
    priority over the baked-in library, since this path runs
    unconditionally on every restart - checking the baked-in library first
    here would silently overwrite a previously-fetched, larger/fresher
    ruleset every time.

    enabled_sources: optional list of source names (see
    SURICATA_RULE_SOURCES) to reconcile the active set to - None (the
    default, used by server startup, per-file background scans, and a
    plain "Update All") skips reconciliation and just refreshes whatever's
    already active. Reconciliation itself (activating/deactivating
    already-locally-staged sources) runs regardless of network
    reachability - only fetching a source that's never been staged before
    needs real internet (see _reconcile_suricata_sources), which is what
    lets an airgapped user toggle among whatever was baked into the image.

    show_protocol_decode_alerts: optional bool controlling whether
    Suricata's own bundled protocol-command-decode event rules stay active
    rather than suppressed (see get_suricata_show_protocol_decode_alerts) -
    None (the default, used by server startup, per-file background scans,
    and a plain "Update All") leaves whatever was last persisted
    untouched; an explicit True/False (from the Rules modal) updates and
    persists the setting before this run applies it.
    """
    if data_dir is None:
        data_dir = os.path.expanduser('~/socrates-data')
    suricata_dir = os.path.join(data_dir, 'suricata')
    suricata_rules_dir = os.path.join(suricata_dir, 'rules')
    library_dir = os.path.join(suricata_dir, 'rules-available')

    os.makedirs(suricata_dir, exist_ok=True)
    os.makedirs(suricata_rules_dir, exist_ok=True)
    os.makedirs(library_dir, exist_ok=True)

    if os.path.isdir('/etc/suricata'):
        needs_copy = False
        if not os.path.exists(os.path.join(suricata_dir, 'suricata.yaml')):
            needs_copy = True

        if needs_copy:
            for item in os.listdir('/etc/suricata'):
                src = os.path.join('/etc/suricata', item)
                dst = os.path.join(suricata_dir, item)
                if os.path.isfile(src):
                    try:
                        shutil.copy2(src, dst)
                    except OSError as e:
                        on_progress(f'Warning: could not copy {src} to {dst}: {e}')
                elif os.path.isdir(src):
                    try:
                        shutil.copytree(src, dst, dirs_exist_ok=True)
                    except OSError as e:
                        on_progress(f'Warning: could not copy directory {src} to {dst}: {e}')

    suricata_config = os.path.join(suricata_dir, 'suricata.yaml')
    if os.path.exists(suricata_config):
        with open(suricata_config, 'r') as f:
            config_content = f.read()
        config_content = config_content.replace('/var/lib/suricata/rules', suricata_rules_dir)
        config_content = _enable_app_layer_protocols(config_content)
        config_content = _enable_eve_log_protocol_types(config_content)
        config_content = _enable_community_id(config_content)
        config_content = _enable_ja3_ja4_fingerprints(config_content)
        if enable_arp:
            config_content = _enable_eve_log_arp(config_content)
        # Enable file-store output for extracted file analysis
        config_content = re.sub(
            r'(\s+file-store:\s*\n\s+version:\s*\d+\s*\n\s+)enabled:\s*no',
            r'\1enabled: yes',
            config_content
        )
        # These five rely on Suricata's default-shipped suricata.yaml having
        # this exact commented-out text at this exact 6-space indentation
        # (matching the fragility already called out in
        # _enable_app_layer_protocols/_enable_eve_log_protocol_types/
        # _enable_eve_log_arp above) - if a future Suricata version reflows
        # this block, these become silent no-ops rather than a clean failure.
        config_content = config_content.replace('      #dir: filestore', '      dir: filestore')
        config_content = config_content.replace('      #write-fileinfo: yes', '      write-fileinfo: yes')
        config_content = config_content.replace('      #force-filestore: yes', '      force-filestore: yes')
        config_content = config_content.replace('      #stream-depth: 0', '      stream-depth: 0')
        config_content = config_content.replace('      #force-hash: [sha1, md5]', '      force-hash: [md5, sha1, sha256]')
        # Static list of every curated source's filename, generated from
        # SURICATA_RULE_SOURCES (not hand-written) so it can never drift -
        # written unconditionally every call (idempotent, matching the
        # mutations above), replacing whatever's currently there (either
        # Suricata's pristine single-file default or our own prior output).
        # A listed file that isn't currently active just gets skipped with
        # a harmless warning (verified against a real Suricata run - see
        # this module's tests) - this is what lets enabling a
        # not-yet-active source take effect on the next analysis without
        # ever touching this file again.
        rule_files_block = 'rule-files:\n' + ''.join(
            f'  - {_source_filename(slug)}\n' for slug in SURICATA_RULE_SOURCES
        )
        config_content = re.sub(
            r'(?m)^rule-files:\n(?:  - .*\n)*',
            lambda _m: rule_files_block,
            config_content,
            count=1,
        )
        with open(suricata_config, 'w') as f:
            f.write(config_content)

    if show_protocol_decode_alerts is not None:
        state_path = os.path.join(suricata_dir, 'show_protocol_decode_alerts.json')
        try:
            with open(state_path, 'w') as f:
                json.dump(bool(show_protocol_decode_alerts), f)
        except OSError as e:
            on_progress(f'Warning: could not save protocol-decode-alerts setting: {e}')
        show_decode = bool(show_protocol_decode_alerts)
    else:
        show_decode = get_suricata_show_protocol_decode_alerts(data_dir)

    disable_conf = os.path.join(suricata_dir, 'disable.conf')
    # Suppress noisy protocol-command-decode event rules while still leaving
    # the protocol parsers enabled. This keeps the protocol event metadata
    # (e.g. event_type: modbus) without generating an alert for every parser
    # anomaly. Applied by _fetch_single_source() passing --disable-conf at
    # this same path. Written empty (disabling nothing) when show_decode is
    # True, so a user who wants these events can opt back in via the Rules
    # modal instead of them being permanently, silently off.
    with open(disable_conf, 'w') as f:
        if not show_decode:
            f.write('re:classtype:protocol-command-decode\n')

    # Reconciliation is mostly local filesystem work (see its own
    # docstring) - it runs regardless of network reachability, not gated
    # behind has_internet_access() like the old design. Only fetching a
    # source that's never been staged locally needs real internet, checked
    # once inside it.
    freshly_fetched = set()
    if enabled_sources is not None:
        freshly_fetched = _reconcile_suricata_sources(suricata_dir, data_dir, enabled_sources, on_progress, network_allowed)

    active_rules_exist = _active_rules_exist(suricata_rules_dir)
    baked_in_library_dir = '/usr/share/suricata/rules-available'
    baked_in_library_exists = os.path.isdir(baked_in_library_dir) and bool(os.listdir(baked_in_library_dir))

    if network_allowed and has_internet_access():
        active_sources = get_suricata_enabled_sources(data_dir)
        # Sources reconciliation just fetched for the first time (above)
        # are already maximally fresh - re-fetching them here immediately
        # afterward would be pure redundant work, most noticeable (and
        # slowest) right after "Enable All" enables everything at once.
        any_succeeded = bool(freshly_fetched)
        for name in active_sources:
            if name in freshly_fetched:
                continue
            filename = _source_filename(name)
            library_path = os.path.join(library_dir, filename)
            if _fetch_single_source(suricata_dir, name, library_path, on_progress) and _activate_from_library(
                    library_path, os.path.join(suricata_rules_dir, filename), name, on_progress, verb='activate refreshed'):
                any_succeeded = True
        active_rules_exist = _active_rules_exist(suricata_rules_dir)

        if any_succeeded:
            on_progress("Suricata rules updated successfully")
        elif active_rules_exist:
            # The reachability probe passing doesn't guarantee every fetch
            # actually succeeds (proxy blocking the real mirrors, cert
            # error, disk full, etc.) - fall back to whatever's already
            # usable instead of silently leaving Suricata with stale-but-
            # present rules unexplained, mirroring the same resilience
            # setup_yara_rules/setup_sigma_rules already have.
            on_progress("Using existing Suricata rules despite the failed update")
        else:
            if baked_in_library_exists:
                on_progress("Falling back to baked-in Suricata rules after the failed update")
                _seed_active_from_library(baked_in_library_dir, data_dir, active_sources, on_progress)
                active_rules_exist = _active_rules_exist(suricata_rules_dir)
            if not active_rules_exist:
                on_progress("Warning: suricata-update failed and no fallback rules are available")
    elif active_rules_exist:
        # Rules already on disk (e.g. from a previous run's live update, in a
        # persistent DATA_DIR volume) take priority over the generic
        # baked-in snapshot - this runs unconditionally on every startup
        # (network_allowed=False), so checking the baked-in library first
        # here would silently overwrite a previously-fetched, larger/fresher
        # ruleset with the baked-in copy on every single restart.
        if network_allowed:
            on_progress("No internet access — using existing Suricata rules from a previous run")
    elif baked_in_library_exists:
        _seed_active_from_library(baked_in_library_dir, data_dir, DEFAULT_SURICATA_SOURCES, on_progress)
    elif network_allowed:
        on_progress("Warning: no baked-in rules found and no internet access — Suricata may not have rules to use")
    else:
        on_progress("WARNING! No Suricata rules found")


def spawn_suricata(dir_path, pcap_path, suricata_config_path=None, data_dir=None):
    """Spawn Suricata in the background to analyze a PCAP.

    Returns True if a new Suricata process was started.
    Returns False either because analysis is already in progress (a
    .phase lock exists) or because Suricata itself failed to start
    (OSError/PermissionError) - callers that need to tell these apart
    should check for a fresh .error file after a False return (only the
    startup-failure case writes one; the already-in-progress case returns
    early before ever calling _set_error/_clear_error).
    """
    if data_dir is None:
        data_dir = os.path.expanduser('~/socrates-data')
    if suricata_config_path is None:
        suricata_config_path = os.path.join(data_dir, 'suricata', 'suricata.yaml')

    phase_file = os.path.join(dir_path, '.phase')
    if os.path.exists(phase_file):
        return False

    _clear_error(dir_path)
    _set_phase(dir_path, 'network')

    def on_suricata_done():
        # Phase 2: Run YARA scan on extracted files
        _set_phase(dir_path, 'files')
        try:
            run_yara_pipeline(dir_path, data_dir=data_dir)
        except Exception as e:
            _set_error(dir_path, f'YARA scan failed: {e}')
        # Phase 3: Build SQLite database
        _set_phase(dir_path, 'importing')
        eve_file = os.path.join(dir_path, 'eve.json')
        db_file = os.path.join(dir_path, 'events.db')
        if os.path.exists(eve_file) and not os.path.exists(db_file):
            try:
                create_sqlite_db(db_file, eve_file)
            except Exception as e:
                _set_error(dir_path, f'Database creation failed: {e}')
        # Clear phase only after DB (with YARA matches) is ready
        _clear_phase(dir_path)

    try:
        proc = subprocess.Popen(
            ['suricata', '-r', pcap_path, '-c', suricata_config_path,
             '-l', dir_path,
             '-k', 'none', '--runmode', 'single',
             '--set', 'outputs.1.eve-log.types.0.alert.metadata.rule.raw=true'],
            cwd=dir_path,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        def _suricata_watchdog():
            """Kill Suricata if it runs longer than the configured timeout."""
            try:
                try:
                    proc.wait(timeout=config.SURICATA_RUN_TIMEOUT)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    _set_error(dir_path, f'Suricata timed out after {config.SURICATA_RUN_TIMEOUT}s')
                    _clear_phase(dir_path)
                    return
                on_suricata_done()
            except Exception as e:
                # This runs in a daemon thread, where an uncaught exception
                # is silently swallowed (never surfaced to the user or to
                # spawn_suricata()'s caller) rather than propagated - and
                # without this, any failure here besides a timeout (e.g. an
                # OSError from proc.wait() itself, or from _set_phase/
                # _clear_phase's own file I/O) would leave .phase in place
                # forever. spawn_suricata()'s own re-entry guard refuses to
                # start a new run while .phase exists, so this analysis
                # directory would become permanently stuck "in progress"
                # with no way to recover except deleting it outright.
                _set_error(dir_path, f'Suricata analysis failed unexpectedly: {e}')
                _clear_phase(dir_path)

        threading.Thread(target=_suricata_watchdog, daemon=True).start()
        return True
    except (OSError, PermissionError) as e:
        _set_error(dir_path, f'Suricata failed to start: {e}')
        _clear_phase(dir_path)
        return False


_SHA256_RE = re.compile(r'^[a-f0-9]{64}$')


def find_extracted_file(dir_path, sha256):
    """Path of the file Suricata extracted with this SHA256 in the analysis
    at dir_path - or an email analysis's message or attachment, stored the
    same way (email_analyzer.store_file) - or None. Suricata's file-store
    (v2) names every file by
    its SHA256 under a two-hex-character subdirectory:
    filestore/<sha256[:2]>/<sha256>. sha256 is validated before it touches
    the filesystem, and the resolved real path must still be a regular
    file inside filestore/ - so neither a crafted hash nor a symlink
    placed in the filestore can reach anything else."""
    if not isinstance(sha256, str) or not _SHA256_RE.match(sha256):
        return None
    filestore_dir = os.path.realpath(os.path.join(dir_path, 'filestore'))
    path = os.path.realpath(os.path.join(filestore_dir, sha256[:2], sha256))
    try:
        if os.path.commonpath([path, filestore_dir]) != filestore_dir:
            return None
    except ValueError:
        return None
    if not os.path.isfile(path):
        return None
    return path


def _set_phase(dir_path, phase):
    """Write the current analysis phase to the .phase file."""
    phase_file = os.path.join(dir_path, '.phase')
    try:
        with open(phase_file, 'w') as f:
            f.write(phase)
    except OSError:
        pass


def _clear_phase(dir_path):
    """Remove the .phase file to indicate analysis is complete."""
    phase_file = os.path.join(dir_path, '.phase')
    try:
        if os.path.exists(phase_file):
            os.unlink(phase_file)
    except OSError:
        pass


def _set_error(dir_path, message):
    """Write an error message to the .error file."""
    error_file = os.path.join(dir_path, '.error')
    try:
        with open(error_file, 'w') as f:
            f.write(message)
    except OSError:
        pass


def _clear_error(dir_path):
    """Remove the .error file."""
    error_file = os.path.join(dir_path, '.error')
    try:
        if os.path.exists(error_file):
            os.unlink(error_file)
    except OSError:
        pass
