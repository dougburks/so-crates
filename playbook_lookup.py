#!/usr/bin/env python3
"""Security Onion Playbooks lookup for SO-CRATES.

Playbooks are short, plain-English investigation guidance ("questions to
ask") per detection rule, baked into the Docker image the same way
Suricata/YARA/Sigma rules are (see Dockerfile's resources-builder stage).
Unlike those, this is static reference content with no runtime refresh -
see AGENTS.md's "Detection Rule Freshness" section for why that's a
deliberate choice, not an oversight.

Each baked-in file is one gzip-compressed JSON dict per detection type:
{"<rule_id>": {"name": ..., "description": ..., "questions": [...]},
 "_default": {...the engine-wide fallback entry...}}
"""

import gzip
import json
import os

# Overridable the same way DATA_DIR is (socrates.py) - lets a local dev
# server point at a real playbooks dataset (e.g. one built by hand from
# the upstream repo, for testing without a Docker build) without editing
# source. Production/Docker never sets this, so it defaults to the same
# path the Dockerfile's resources-builder stage bakes into.
BAKED_IN_PLAYBOOKS_DIR = os.environ.get('PLAYBOOKS_DIR', '/usr/share/playbooks')

_playbook_index_cache = {}  # (base_dir, detection_type) -> index dict


def _load_playbook_index(detection_type, base_dir):
    """Loads and decompresses <base_dir>/<detection_type>.json.gz exactly
    once per (base_dir, detection_type), caching the whole parsed dict in
    process memory - every lookup after the first is a plain dict access,
    no further disk I/O or decompression. Returns {} (not None) on a
    missing/corrupt file so callers never need a None-check before
    indexing into it."""
    cache_key = (base_dir, detection_type)
    if cache_key in _playbook_index_cache:
        return _playbook_index_cache[cache_key]
    index_path = os.path.join(base_dir, f'{detection_type}.json.gz')
    try:
        with gzip.open(index_path, 'rt', encoding='utf-8') as f:
            index = json.load(f)
        if not isinstance(index, dict):
            index = {}
    except (OSError, gzip.BadGzipFile, json.JSONDecodeError):
        index = {}
    _playbook_index_cache[cache_key] = index
    return index


def get_playbook(detection_type, rule_id, base_dir=None):
    """detection_type is 'nids' or 'sigma'. Returns the most specific
    playbook available for rule_id - an exact match if one exists, else
    the generic '_default' entry (always present if the image was built
    with playbooks baked in), else None (e.g. a local dev run with
    nothing baked in). Never raises."""
    index = _load_playbook_index(detection_type, base_dir or BAKED_IN_PLAYBOOKS_DIR)
    return index.get(str(rule_id)) or index.get('_default')
