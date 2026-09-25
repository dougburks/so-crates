"""Tests for the docs site's MkDocs hooks (hooks/*.py)."""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'hooks'))

import ghcr_downloads  # noqa: E402

# Trimmed from the real package page.
PACKAGE_PAGE = '''
<div class="lh-condensed d-flex flex-column flex-items-baseline tmp-pr-1">
            <span class="d-block color-fg-muted text-small tmp-mb-1">Total downloads</span>
            <h3 title="2338954">2.34M</h3>
          </div>
'''


class TestGhcrDownloads(unittest.TestCase):
    def setUp(self):
        ghcr_downloads._cached = None

    def tearDown(self):
        ghcr_downloads._cached = None

    def test_parses_exact_total_not_rounded_label(self):
        self.assertEqual(ghcr_downloads.parse_total_downloads(PACKAGE_PAGE), 2338954)

    def test_missing_total_returns_none(self):
        self.assertIsNone(ghcr_downloads.parse_total_downloads('<h3 title="5">5</h3>'))

    def test_on_config_sets_extra(self):
        config = {'extra': {}}
        with mock.patch.object(ghcr_downloads, 'fetch_total_downloads', return_value=42) as fetch:
            ghcr_downloads.on_config(config)
            ghcr_downloads.on_config(config)
        self.assertEqual(config['extra']['container_downloads'], 42)
        fetch.assert_called_once()

    def test_fetch_failure_leaves_extra_unset(self):
        config = {'extra': {}}
        with mock.patch.object(ghcr_downloads, 'fetch_total_downloads', side_effect=OSError('offline')):
            ghcr_downloads.on_config(config)
        self.assertNotIn('container_downloads', config['extra'])

    def test_page_without_total_leaves_extra_unset(self):
        config = {'extra': {}}
        with mock.patch.object(ghcr_downloads, 'fetch_total_downloads', return_value=None):
            ghcr_downloads.on_config(config)
        self.assertNotIn('container_downloads', config['extra'])


if __name__ == '__main__':
    unittest.main()
