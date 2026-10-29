#!/usr/bin/env python3
"""Tests for yara_analyzer.py."""

import gzip
import os
import sys
import tempfile
import shutil
import unittest
import unittest.mock
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import yara_analyzer


class TestSetupYaraRulesBakedInGzip(unittest.TestCase):
    """The real Docker image bakes BAKED_IN_YARA_FILE gzip-compressed (see
    the Dockerfile's YARA Forge bake step) - must be decompressed into the
    plain .yar file setup_yara_rules() promises its caller."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.baked_in_dir = tempfile.mkdtemp()
        self.baked_in_gz = os.path.join(self.baked_in_dir, 'yara-rules-full.yar.gz')
        self.rule_content = b'rule dummy { condition: true }'
        with gzip.open(self.baked_in_gz, 'wb') as f:
            f.write(self.rule_content)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        shutil.rmtree(self.baked_in_dir, ignore_errors=True)

    def test_decompresses_baked_in_gzip_file(self):
        with unittest.mock.patch('yara_analyzer.BAKED_IN_YARA_FILE', self.baked_in_gz):
            rules_file = yara_analyzer.setup_yara_rules(self.tmpdir, network_allowed=False)
        self.assertTrue(os.path.isfile(rules_file))
        with open(rules_file, 'rb') as f:
            self.assertEqual(f.read(), self.rule_content)


class TestSetupYaraRulesForceNoNetwork(unittest.TestCase):
    """REGRESSION: force=True + a cached copy that isn't stale yet +
    network_allowed=False used to silently call on_progress zero times -
    the exact case of a user explicitly clicking "check for updates" while
    offline produced no feedback at all in the Rules modal."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        rules_dir = os.path.join(self.tmpdir, yara_analyzer.YARA_RULES_SUBDIR)
        os.makedirs(rules_dir, exist_ok=True)
        self.rules_file = os.path.join(rules_dir, yara_analyzer.YARA_FORGE_FILENAME)
        with open(self.rules_file, 'w') as f:
            f.write('rule dummy { condition: true }')

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_force_with_fresh_cache_and_no_network_reports_progress(self):
        """REGRESSION: this message must not claim "no internet access" -
        network_allowed=False means the caller opted out of checking
        (e.g. server startup), not that a reachability check actually
        failed. See TestNetworkAllowedFalseDoesNotClaimNoInternet for the
        dedicated check of that distinction."""
        messages = []
        yara_analyzer.setup_yara_rules(
            self.tmpdir, on_progress=messages.append, network_allowed=False, force=True)
        self.assertTrue(messages, 'on_progress must be called even when force=True, cache is fresh, and offline')
        self.assertTrue(any('using cached' in m.lower() for m in messages), messages)
        self.assertFalse(any('no internet' in m.lower() for m in messages), messages)


class TestRefreshFallsBackToCacheOnBadDownload(unittest.TestCase):
    """REGRESSION: a refresh's except clause only caught (OSError,
    urllib.error.URLError), but _download_yara_forge_rules can also raise
    zipfile.BadZipFile (a truncated/rate-limited/HTML-error response that
    isn't actually a zip) or KeyError (if the expected member is ever
    renamed upstream) - neither is an OSError subclass, so both escaped
    setup_yara_rules() entirely even with a perfectly good cached copy on
    disk, and propagated up into the standalone-file analysis's single broad
    except Exception as a whole-file-analysis failure instead of silently
    falling back to the cache like the docstring promises."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        rules_dir = os.path.join(self.tmpdir, yara_analyzer.YARA_RULES_SUBDIR)
        os.makedirs(rules_dir, exist_ok=True)
        self.rules_file = os.path.join(rules_dir, yara_analyzer.YARA_FORGE_FILENAME)
        with open(self.rules_file, 'w') as f:
            f.write('rule dummy { condition: true }')

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_bad_zip_falls_back_to_cached_copy(self):
        messages = []
        with unittest.mock.patch('yara_analyzer.is_file_stale', return_value=True), \
             unittest.mock.patch('yara_analyzer.is_host_reachable', return_value=True), \
             unittest.mock.patch('yara_analyzer._download_yara_forge_rules',
                                  side_effect=zipfile.BadZipFile('not a zip')):
            result = yara_analyzer.setup_yara_rules(
                self.tmpdir, on_progress=messages.append, network_allowed=True, force=True)

        self.assertEqual(result, self.rules_file, 'must fall back to the cached rules file, not raise')
        self.assertTrue(any('warning' in m.lower() for m in messages), messages)

    def test_missing_zip_member_falls_back_to_cached_copy(self):
        messages = []
        with unittest.mock.patch('yara_analyzer.is_file_stale', return_value=True), \
             unittest.mock.patch('yara_analyzer.is_host_reachable', return_value=True), \
             unittest.mock.patch('yara_analyzer._download_yara_forge_rules',
                                  side_effect=KeyError('packages/full/yara-rules-full.yar')):
            result = yara_analyzer.setup_yara_rules(
                self.tmpdir, on_progress=messages.append, network_allowed=True, force=True)

        self.assertEqual(result, self.rules_file, 'must fall back to the cached rules file, not raise')
        self.assertTrue(any('warning' in m.lower() for m in messages), messages)


class TestNetworkAllowedFalseDoesNotClaimNoInternet(unittest.TestCase):
    """REGRESSION: with no cached copy and no baked-in file, the final
    "not available" message used to say "No internet access detected"
    unconditionally - including when network_allowed=False (e.g. server
    startup, which never checks reachability at all by design). A real
    user on a machine WITH internet access saw this exact message at
    startup and reasonably assumed something was broken. The message
    must now distinguish "we checked and it failed" from "we didn't
    check"."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_network_allowed_false_does_not_say_no_internet(self):
        messages = []
        yara_analyzer.setup_yara_rules(
            self.tmpdir, on_progress=messages.append, network_allowed=False)
        self.assertFalse(any('no internet' in m.lower() for m in messages), messages)
        self.assertIn('WARNING! No YARA rules found', messages)

    def test_network_allowed_true_and_unreachable_still_says_no_internet(self):
        messages = []
        with unittest.mock.patch('yara_analyzer.is_host_reachable', return_value=False):
            yara_analyzer.setup_yara_rules(
                self.tmpdir, on_progress=messages.append, network_allowed=True)
        self.assertTrue(any('no internet' in m.lower() for m in messages), messages)


class TestGetYaraRulesInfoStaleness(unittest.TestCase):
    """'stale' must be False for a just-written file and True once its
    mtime is older than config.RULES_MAX_AGE_HOURS - purely a local
    os.path.getmtime() comparison via validators.is_file_stale(), no
    network access."""

    def test_stale_field_reflects_file_age(self):
        import config
        import time
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_dir = os.path.join(tmpdir, yara_analyzer.YARA_RULES_SUBDIR)
            os.makedirs(rules_dir, exist_ok=True)
            rules_file = os.path.join(rules_dir, yara_analyzer.YARA_FORGE_FILENAME)
            with open(rules_file, 'w') as f:
                f.write('rule test_rule { condition: true }')

            fresh = yara_analyzer.get_yara_rules_info(data_dir=tmpdir)
            self.assertFalse(fresh['stale'], 'a just-written rules file must not be stale')

            old_time = time.time() - (config.RULES_MAX_AGE_HOURS + 1) * 3600
            os.utime(rules_file, (old_time, old_time))
            stale = yara_analyzer.get_yara_rules_info(data_dir=tmpdir)
            self.assertTrue(stale['stale'], 'a rules file older than RULES_MAX_AGE_HOURS must be stale')


if __name__ == '__main__':
    unittest.main()
