"""MkDocs hook: the container image's total download count, for the
repository widget in the docs header (overrides/partials/source.html and
docs/javascripts/source-downloads.js).

GitHub's API has no public download count for container packages, but the
package page itself shows it to anyone, so this reads it from there once
per build and exposes it as config.extra.container_downloads. Any failure
- offline, a timeout, GitHub changing the page - leaves it unset and the
widget simply shows no download count; it never fails the build.
"""

import logging
import re
import urllib.request

PACKAGE_URL = 'https://github.com/users/dougburks/packages/container/package/so-crates'
TIMEOUT_SECONDS = 10

# <span ...>Total downloads</span>
# <h3 title="2338954">2.34M</h3>
_TOTAL_RE = re.compile(r'Total downloads\s*</span>\s*<h3[^>]*\btitle="(\d+)"')

log = logging.getLogger('mkdocs.hooks.ghcr_downloads')

# mkdocs serve calls on_config on every rebuild; fetch once per process.
_cached = None


def parse_total_downloads(html):
    """The exact total from the package page's HTML, or None."""
    match = _TOTAL_RE.search(html)
    return int(match.group(1)) if match else None


def fetch_total_downloads(url=PACKAGE_URL, timeout=TIMEOUT_SECONDS):
    req = urllib.request.Request(url, headers={'User-Agent': 'so-crates-docs-build'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        html = resp.read().decode('utf-8', errors='replace')
    return parse_total_downloads(html)


def on_config(config):
    global _cached
    if _cached is None:
        try:
            _cached = fetch_total_downloads()
        except Exception as exc:
            log.info(f'Container download count unavailable: {exc}')
            _cached = False
        if _cached is None:
            log.info('Container download count not found on the package page')
            _cached = False
    if _cached:
        config['extra']['container_downloads'] = _cached
    return config
