#!/usr/bin/env python3
"""Bundled CyberChef support for SO-CRATES.

CyberChef (GCHQ's static, fully client-side data-decoding app) is baked
into the Docker image by scripts/fetch-cyberchef.sh and served at
/cyberchef/, so the pivot menu's CyberChef lookup works with no internet
access. This module only knows where that copy lives and which
Content-Security-Policy it needs - the HTTP handling is in socrates.py.
"""

import base64
import hashlib
import os
import re

# Overridable the same way PLAYBOOKS_DIR/AI_SUMMARIES_DIR are - a local dev
# server can point it at a copy fetched by hand with
# scripts/fetch-cyberchef.sh. Production/Docker never sets this, so it
# defaults to the path the Dockerfile's resources-builder stage bakes into.
CYBERCHEF_DIR = os.environ.get('CYBERCHEF_DIR', '/usr/share/cyberchef')

# SO-CRATES's own policy (script-src 'self', nothing else) stops CyberChef
# from loading at all. Each carve-out below was measured against the real
# v11.5.0 build in Chromium - this policy passes every operation tested
# that also passes with no CSP at all:
#   - the two inline <script>s in index.html (theme/loader bootstrap, IE
#     warning) are allowed by hash, not 'unsafe-inline' - see
#     _inline_script_hashes()
#   - worker-src blob: - every CyberChef worker is built from inline code
#   - 'wasm-unsafe-eval' - WebAssembly inside those workers
#   - 'unsafe-eval' - needed only by the YARA Rules operation (Yara.js)
#   - img-src blob:, connect-src data: - rendered images, and YARA's
#     module loading itself from a data: URL
#   - object-src data: - the "Bombe" loading animation. Its <object> is
#     still refused by frame-src, which is deliberately left at 'self':
#     allowing it only moves the refusal to the SVG's own inline script,
#     and the animation is purely cosmetic.
# This looser policy applies to /cyberchef/ responses only. CyberChef
# shares SO-CRATES's origin (the point of Send to CyberChef), so anything
# injected into it could reach /api/* - acceptable only because this is an
# unmodified, checksum-pinned official release.
_CSP_TEMPLATE = (
    "default-src 'self'; "
    "script-src 'self' 'wasm-unsafe-eval' 'unsafe-eval'{hashes}; "
    "worker-src 'self' blob:; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "object-src data:; "
    "connect-src 'self' data:; "
    "form-action 'self'; "
    "base-uri 'self'; "
    "report-uri /api/csp-report;"
)

_SCRIPT_RE = re.compile(r'<script\b([^>]*)>(.*?)</script\s*>', re.IGNORECASE | re.DOTALL)

_csp_cache = {}  # base_dir -> policy string


def _inline_script_hashes(index_html):
    """CSP source expressions ('sha256-...') for every non-empty inline
    <script> in index_html. The browser hashes a script element's text
    exactly as it appears in the source, so this must too - no stripping.
    Computed from the file itself rather than pinned, so a CyberChef
    upgrade that changes those scripts needs no matching edit here."""
    hashes = []
    for attrs, body in _SCRIPT_RE.findall(index_html):
        if not body or re.search(r'\bsrc\s*=', attrs, re.IGNORECASE):
            continue
        digest = hashlib.sha256(body.encode('utf-8')).digest()
        hashes.append(f"'sha256-{base64.b64encode(digest).decode()}'")
    return hashes


def build_csp(index_html):
    """The Content-Security-Policy for /cyberchef/ responses, given the
    text of CyberChef's index.html. Pure function - see get_csp()."""
    hashes = ''.join(' ' + h for h in _inline_script_hashes(index_html))
    return _CSP_TEMPLATE.format(hashes=hashes)


def get_csp(base_dir=None):
    """build_csp() for the bundled copy's index.html, read once per
    base_dir and cached. A missing copy (a local dev run with nothing
    fetched) still gets a valid policy - just with no inline-script
    hashes - so this never raises."""
    base_dir = base_dir or CYBERCHEF_DIR
    if base_dir not in _csp_cache:
        try:
            with open(os.path.join(base_dir, 'index.html'), encoding='utf-8') as f:
                index_html = f.read()
        except OSError:
            index_html = ''
        _csp_cache[base_dir] = build_csp(index_html)
    return _csp_cache[base_dir]
