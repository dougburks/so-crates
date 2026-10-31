#!/usr/bin/env python3
"""Tests for suricata_analyzer.py's multi-ruleset source support:
SURICATA_RULE_SOURCES, _source_filename(), get_suricata_enabled_sources(),
_reconcile_suricata_sources(), _fetch_single_source(),
_seed_active_from_library(), and _active_rules_exist() - separate from the
bulk of Suricata tests in test_socrates_server.py, mirroring the existing
test_sigma_analyzer_rules_setup.py/test_yara_analyzer.py split.

Architecture under test (see suricata_analyzer.py's module-level docs):
"enabled" is a local filesystem fact - a source's file either exists in
the permanent rules-available/ library and is copied into the active
rules/ dir, or it isn't. Toggling an already-staged source is pure local
I/O (no network); only fetching a source that's never been staged before
needs real internet. This deliberately replaced an earlier design that
drove everything through suricata-update's own enable-source/
disable-source CLI state, which turned out to have no way to work
offline (see git history / conversation - that state lived in a
--data-dir with no relationship between build-time image and run-time
DATA_DIR)."""

import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import suricata_analyzer


def _write_fake_rule_file(path, sid=1, extra_lines=1):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        for i in range(extra_lines):
            f.write(f'alert tcp any any -> any any (msg:"fake"; sid:{sid + i}; rev:1;)\n')


class TestSourceFilename(unittest.TestCase):
    def test_maps_slashes_to_dashes(self):
        self.assertEqual(suricata_analyzer._source_filename('abuse.ch/feodotracker'), 'abuse.ch-feodotracker.rules')

    def test_simple_slug(self):
        self.assertEqual(suricata_analyzer._source_filename('et/open'), 'et-open.rules')

    def test_no_slash_slug(self):
        self.assertEqual(suricata_analyzer._source_filename('pawpatrules'), 'pawpatrules.rules')

    def test_every_curated_source_maps_to_a_unique_filename(self):
        filenames = [suricata_analyzer._source_filename(s) for s in suricata_analyzer.SURICATA_RULE_SOURCES]
        self.assertEqual(len(filenames), len(set(filenames)), 'no two curated sources may collide on filename')

    def test_baked_in_sources_excludes_ipfire_dbl(self):
        """ipfire/dbl is deliberately never baked into the Docker image -
        see suricata_analyzer.py's comment for why (biggest space cost of
        the curated set, and a content-filtering blocklist rather than
        threat detection)."""
        self.assertNotIn('ipfire/dbl', suricata_analyzer.BAKED_IN_SURICATA_SOURCES)
        self.assertIn('ipfire/dbl', suricata_analyzer.SURICATA_RULE_SOURCES,
                       'must stay selectable for online users even though never baked in')
        self.assertEqual(
            set(suricata_analyzer.BAKED_IN_SURICATA_SOURCES),
            set(suricata_analyzer.SURICATA_RULE_SOURCES) - {'ipfire/dbl'})


class TestGetSuricataEnabledSources(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_defaults_to_et_open_when_no_state_file(self):
        self.assertEqual(
            suricata_analyzer.get_suricata_enabled_sources(self.tmpdir),
            ['et/open'])

    def test_reads_back_written_state_file(self):
        suricata_dir = os.path.join(self.tmpdir, 'suricata')
        os.makedirs(suricata_dir, exist_ok=True)
        with open(os.path.join(suricata_dir, 'enabled_sources.json'), 'w') as f:
            json.dump(['et/open', 'abuse.ch/feodotracker'], f)
        self.assertEqual(
            suricata_analyzer.get_suricata_enabled_sources(self.tmpdir),
            ['et/open', 'abuse.ch/feodotracker'])

    def test_filters_out_names_no_longer_curated(self):
        suricata_dir = os.path.join(self.tmpdir, 'suricata')
        os.makedirs(suricata_dir, exist_ok=True)
        with open(os.path.join(suricata_dir, 'enabled_sources.json'), 'w') as f:
            json.dump(['et/open', 'some/retired-source'], f)
        self.assertEqual(
            suricata_analyzer.get_suricata_enabled_sources(self.tmpdir),
            ['et/open'])

    def test_falls_back_to_default_on_corrupt_state_file(self):
        suricata_dir = os.path.join(self.tmpdir, 'suricata')
        os.makedirs(suricata_dir, exist_ok=True)
        with open(os.path.join(suricata_dir, 'enabled_sources.json'), 'w') as f:
            f.write('not valid json{')
        self.assertEqual(
            suricata_analyzer.get_suricata_enabled_sources(self.tmpdir),
            ['et/open'])

    def test_falls_back_to_default_when_all_confirmed_names_filtered_out(self):
        suricata_dir = os.path.join(self.tmpdir, 'suricata')
        os.makedirs(suricata_dir, exist_ok=True)
        with open(os.path.join(suricata_dir, 'enabled_sources.json'), 'w') as f:
            json.dump(['some/retired-source'], f)
        self.assertEqual(
            suricata_analyzer.get_suricata_enabled_sources(self.tmpdir),
            ['et/open'])


class TestGetSuricataShowProtocolDecodeAlerts(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_defaults_to_false_when_no_state_file(self):
        self.assertIs(
            suricata_analyzer.get_suricata_show_protocol_decode_alerts(self.tmpdir),
            False)

    def test_reads_back_written_state_file(self):
        suricata_dir = os.path.join(self.tmpdir, 'suricata')
        os.makedirs(suricata_dir, exist_ok=True)
        with open(os.path.join(suricata_dir, 'show_protocol_decode_alerts.json'), 'w') as f:
            json.dump(True, f)
        self.assertIs(
            suricata_analyzer.get_suricata_show_protocol_decode_alerts(self.tmpdir),
            True)

    def test_falls_back_to_false_on_corrupt_state_file(self):
        suricata_dir = os.path.join(self.tmpdir, 'suricata')
        os.makedirs(suricata_dir, exist_ok=True)
        with open(os.path.join(suricata_dir, 'show_protocol_decode_alerts.json'), 'w') as f:
            f.write('not valid json{')
        self.assertIs(
            suricata_analyzer.get_suricata_show_protocol_decode_alerts(self.tmpdir),
            False)


class TestActiveRulesExist(unittest.TestCase):
    """REGRESSION: found while building this feature - Suricata's own
    bundled per-protocol event files (app-layer-events.rules,
    decoder-events.rules, etc., copied in from /etc/suricata's own rules/
    subdirectory alongside suricata.yaml on first run) also end in
    .rules, and are always present regardless of which curated sources are
    active. A naive "any *.rules file" check would report rules as
    present even with zero curated sources ever enabled, which would have
    broken the baked-in-library seeding fallback (it would never fire) and
    inflated get_suricata_rules_info()'s counts with irrelevant
    pseudo-rules."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_false_when_only_builtin_event_files_present(self):
        _write_fake_rule_file(os.path.join(self.tmpdir, 'decoder-events.rules'))
        _write_fake_rule_file(os.path.join(self.tmpdir, 'app-layer-events.rules'))
        self.assertFalse(suricata_analyzer._active_rules_exist(self.tmpdir))

    def test_true_when_a_curated_source_file_present(self):
        _write_fake_rule_file(os.path.join(self.tmpdir, 'decoder-events.rules'))
        _write_fake_rule_file(os.path.join(self.tmpdir, 'et-open.rules'))
        self.assertTrue(suricata_analyzer._active_rules_exist(self.tmpdir))

    def test_false_for_missing_directory(self):
        self.assertFalse(suricata_analyzer._active_rules_exist(os.path.join(self.tmpdir, 'does-not-exist')))


class TestGetSuricataRulesInfo(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.rules_dir = os.path.join(self.tmpdir, 'suricata', 'rules')
        os.makedirs(self.rules_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_none_fields_when_no_curated_files_active(self):
        _write_fake_rule_file(os.path.join(self.rules_dir, 'decoder-events.rules'))
        self.assertEqual(
            suricata_analyzer.get_suricata_rules_info(self.tmpdir),
            {'count': None, 'updated': None, 'stale': None})

    def test_sums_counts_across_active_curated_files_only(self):
        _write_fake_rule_file(os.path.join(self.rules_dir, 'decoder-events.rules'), extra_lines=100)
        _write_fake_rule_file(os.path.join(self.rules_dir, 'et-open.rules'), sid=1, extra_lines=3)
        _write_fake_rule_file(os.path.join(self.rules_dir, 'oisf-trafficid.rules'), sid=100, extra_lines=2)
        info = suricata_analyzer.get_suricata_rules_info(self.tmpdir)
        self.assertEqual(info['count'], 5, 'must sum only et-open.rules + oisf-trafficid.rules, not the builtin file')

    def test_staleness_driven_by_oldest_active_file(self):
        fresh = os.path.join(self.rules_dir, 'et-open.rules')
        stale = os.path.join(self.rules_dir, 'oisf-trafficid.rules')
        _write_fake_rule_file(fresh)
        _write_fake_rule_file(stale)
        old_time = 0  # 1970 - guaranteed older than any RULES_MAX_AGE_HOURS threshold
        os.utime(stale, (old_time, old_time))
        info = suricata_analyzer.get_suricata_rules_info(self.tmpdir)
        self.assertTrue(info['stale'], 'the oldest active file being ancient must mark the whole set stale')
        self.assertEqual(info['updated'], old_time)


class TestFetchSingleSource(unittest.TestCase):
    """Exercises the real suricata-update binary for the mechanics that
    matter most to get right (isolation from other sources), and mocks
    subprocess for the failure paths that would otherwise require
    contriving real-world failures."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.suricata_dir = os.path.join(self.tmpdir, 'suricata')
        os.makedirs(self.suricata_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_fetch_is_isolated_from_et_open_default_source(self):
        """REGRESSION: suricata-update's enable-source on a brand-new
        --data-dir silently ALSO auto-enables et/open as its own "default
        source" regardless of what was actually requested - confirmed by
        hand (a fetch of oisf/trafficid alone produced a merged file with
        et/open's full ~52k rules mixed in, not just trafficid's own much
        smaller set) before this test/the disable-source-et/open fix
        existed. A fetch of any non-et/open source must not pull in
        et/open's content."""
        dest = os.path.join(self.tmpdir, 'oisf-trafficid.rules')
        ok = suricata_analyzer._fetch_single_source(self.suricata_dir, 'oisf/trafficid', dest, lambda m: None)
        self.assertTrue(ok)
        with open(dest) as f:
            content = f.read()
        # et/open's rules all carry the classic "ET " msg prefix (see this
        # session's own SID-range research) - a genuinely isolated
        # trafficid-only fetch must not contain any.
        self.assertNotIn('msg:"ET ', content)
        self.assertLess(os.path.getsize(dest), 1024 * 1024, 'an isolated trafficid fetch should be well under 1MB, not ~45MB')

    def test_fetch_reports_elapsed_time(self):
        """'Fetched X' now says how long the isolated suricata-update run
        took - e.g. 'Fetched et/open in 4 seconds' - so a slow source (or a
        slow mirror) is visible in the log rather than all sources looking
        the same regardless of how long they actually took."""
        messages = []
        with unittest.mock.patch('suricata_analyzer.subprocess.run') as mock_run, \
             unittest.mock.patch('suricata_analyzer.shutil.move'), \
             unittest.mock.patch('suricata_analyzer.os.path.isfile', return_value=True), \
             unittest.mock.patch('suricata_analyzer.time.monotonic', side_effect=[100.0, 104.4]):
            mock_run.return_value = unittest.mock.Mock(returncode=0)
            ok = suricata_analyzer._fetch_single_source(
                self.suricata_dir, 'et/open', os.path.join(self.tmpdir, 'et-open.rules'), messages.append)
        self.assertTrue(ok)
        self.assertIn('Fetched et/open in 4 seconds', messages)

    def test_fetch_elapsed_time_is_singular_for_one_second(self):
        messages = []
        with unittest.mock.patch('suricata_analyzer.subprocess.run') as mock_run, \
             unittest.mock.patch('suricata_analyzer.shutil.move'), \
             unittest.mock.patch('suricata_analyzer.os.path.isfile', return_value=True), \
             unittest.mock.patch('suricata_analyzer.time.monotonic', side_effect=[100.0, 100.6]):
            mock_run.return_value = unittest.mock.Mock(returncode=0)
            suricata_analyzer._fetch_single_source(
                self.suricata_dir, 'et/open', os.path.join(self.tmpdir, 'et-open.rules'), messages.append)
        self.assertIn('Fetched et/open in 1 second', messages)

    def test_dest_path_not_created_on_enable_failure(self):
        dest = os.path.join(self.tmpdir, 'bogus.rules')
        with unittest.mock.patch('suricata_analyzer.subprocess.run') as mock_run:
            fail_result = unittest.mock.Mock(returncode=1)
            mock_run.return_value = fail_result
            ok = suricata_analyzer._fetch_single_source(self.suricata_dir, 'et/open', dest, lambda m: None)
        self.assertFalse(ok)
        self.assertFalse(os.path.exists(dest))

    def test_reports_warning_and_returns_false_on_timeout(self):
        import subprocess as _subprocess
        messages = []
        with unittest.mock.patch('suricata_analyzer.subprocess.run', side_effect=_subprocess.TimeoutExpired('suricata-update', 5)):
            ok = suricata_analyzer._fetch_single_source(
                self.suricata_dir, 'et/open', os.path.join(self.tmpdir, 'et-open.rules'), messages.append)
        self.assertFalse(ok)
        self.assertTrue(any('could not fetch et/open' in m for m in messages), messages)

    def test_fetch_passes_disable_conf_pointing_at_shared_suricata_dir(self):
        """REGRESSION: each source's fetch runs against its own fresh,
        empty scratch --data-dir, so suricata-update's own default
        disable.conf lookup (relative to --data-dir) never finds the
        shared one setup_suricata_config() writes to suricata_dir - it
        must be passed explicitly via --disable-conf, or noisy built-in
        rules like "SURICATA STREAM excessive retransmissions" silently
        stay active regardless of the user's suppression setting."""
        with unittest.mock.patch('suricata_analyzer.subprocess.run') as mock_run, \
             unittest.mock.patch('suricata_analyzer.shutil.move'), \
             unittest.mock.patch('suricata_analyzer.os.path.isfile', return_value=True):
            mock_run.return_value = unittest.mock.Mock(returncode=0)
            suricata_analyzer._fetch_single_source(
                self.suricata_dir, 'et/open', os.path.join(self.tmpdir, 'et-open.rules'), lambda m: None)
        fetch_call = mock_run.call_args_list[-1]
        cmd = fetch_call.args[0]
        self.assertIn('--disable-conf', cmd)
        disable_conf_arg = cmd[cmd.index('--disable-conf') + 1]
        self.assertEqual(disable_conf_arg, os.path.join(self.suricata_dir, 'disable.conf'))

    def test_fetch_with_real_binary_suppresses_protocol_command_decode_when_disabled(self):
        """End-to-end against the real suricata-update binary: a
        disable.conf containing the classtype:protocol-command-decode
        regex must actually suppress SID 2210054 ("SURICATA STREAM
        excessive retransmissions", Suricata's own bundled stream-anomaly
        rule and the concrete complaint that motivated this feature) from
        the merged fetch output, proving --disable-conf is both passed and
        honored (not just present on the command line).

        Deliberately checks this one specific SID rather than asserting
        zero active classtype:protocol-command-decode rules overall -
        et/open also ships legitimate protocol-decode rules that
        suricata-update's own flowbit-dependency resolution force-reenables
        even when disable.conf targets their classtype (existing behavior
        of the classtype-regex mechanism, unrelated to this fix)."""
        with open(os.path.join(self.suricata_dir, 'disable.conf'), 'w') as f:
            f.write('re:classtype:protocol-command-decode\n')
        dest = os.path.join(self.tmpdir, 'et-open.rules')
        ok = suricata_analyzer._fetch_single_source(self.suricata_dir, 'et/open', dest, lambda m: None)
        self.assertTrue(ok)
        with open(dest) as f:
            content = f.read()
        active_lines = [line for line in content.splitlines() if line.strip() and not line.strip().startswith('#')]
        self.assertFalse(
            any('sid:2210054;' in line for line in active_lines),
            'SID 2210054 ("SURICATA STREAM excessive retransmissions") must not be active when disable.conf suppresses it')

    def test_scratch_dirs_cleaned_up_regardless_of_outcome(self):
        before = set(os.listdir(self.suricata_dir))
        suricata_analyzer._fetch_single_source(
            self.suricata_dir, 'oisf/trafficid', os.path.join(self.tmpdir, 'x.rules'), lambda m: None)
        after = set(os.listdir(self.suricata_dir))
        self.assertEqual(before, after, 'no .fetch-data-*/.fetch-out-* scratch dirs left behind')


class TestReconcileSuricataSources(unittest.TestCase):
    """Tests reconciliation's own orchestration logic (add/remove
    decisions, offline handling, enabled_sources.json bookkeeping) against
    a mocked _fetch_single_source - the real fetch mechanics are
    TestFetchSingleSource's job above, kept separate so these run fast and
    deterministic."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.suricata_dir = os.path.join(self.tmpdir, 'suricata')
        os.makedirs(self.suricata_dir, exist_ok=True)
        self.library_dir = os.path.join(self.tmpdir, 'suricata', 'rules-available')
        self.active_dir = os.path.join(self.suricata_dir, 'rules')

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _stage(self, name):
        """Pre-populate the library with a source's file, as if it had
        been baked in or fetched before."""
        _write_fake_rule_file(os.path.join(self.library_dir, suricata_analyzer._source_filename(name)))

    def _fake_fetch_success(self, suricata_dir, name, dest_path, on_progress):
        _write_fake_rule_file(dest_path)
        return True

    def _fake_fetch_with_progress(self, suricata_dir, name, dest_path, on_progress):
        """Mirrors the real _fetch_single_source's own 'Fetched X' progress
        line (unlike _fake_fetch_success, which ignores on_progress
        entirely) - needed to verify reconciliation doesn't add a second
        line on top of it when activating the result."""
        _write_fake_rule_file(dest_path)
        on_progress(f'Fetched {name}')
        return True

    def test_activating_an_already_staged_source_needs_no_fetch(self):
        self._stage('oisf/trafficid')
        messages = []
        with unittest.mock.patch('suricata_analyzer._fetch_single_source') as mock_fetch:
            suricata_analyzer._reconcile_suricata_sources(
                self.suricata_dir, self.tmpdir, ['et/open', 'oisf/trafficid'], messages.append, network_allowed=False)
        mock_fetch.assert_not_called()
        self.assertTrue(os.path.isfile(os.path.join(self.active_dir, 'oisf-trafficid.rules')))
        self.assertEqual(messages, [], 'activating an already-staged source is silent - see _fetch_single_source()\'s docstring')

    def test_activating_a_not_yet_staged_source_offline_warns_and_skips(self):
        messages = []
        with unittest.mock.patch('suricata_analyzer._fetch_single_source') as mock_fetch:
            suricata_analyzer._reconcile_suricata_sources(
                self.suricata_dir, self.tmpdir, ['et/open', 'oisf/trafficid'], messages.append, network_allowed=False)
        mock_fetch.assert_not_called()
        self.assertFalse(os.path.exists(os.path.join(self.active_dir, 'oisf-trafficid.rules')))
        self.assertTrue(any('oisf/trafficid is not available offline yet' in m for m in messages), messages)
        self.assertEqual(suricata_analyzer.get_suricata_enabled_sources(self.tmpdir), ['et/open'],
                          'et/open (already staged, or falls back to default) should still be confirmed even though trafficid was skipped')

    def test_activating_a_not_yet_staged_source_online_fetches_it(self):
        messages = []
        with unittest.mock.patch('suricata_analyzer._fetch_single_source', side_effect=self._fake_fetch_success), \
             unittest.mock.patch('suricata_analyzer.has_internet_access', return_value=True):
            suricata_analyzer._reconcile_suricata_sources(
                self.suricata_dir, self.tmpdir, ['et/open', 'oisf/trafficid'], messages.append, network_allowed=True)
        self.assertTrue(os.path.isfile(os.path.join(self.library_dir, 'oisf-trafficid.rules')))
        self.assertTrue(os.path.isfile(os.path.join(self.active_dir, 'oisf-trafficid.rules')))
        self.assertEqual(
            set(suricata_analyzer.get_suricata_enabled_sources(self.tmpdir)),
            {'et/open', 'oisf/trafficid'})

    def test_activating_a_freshly_fetched_source_reports_only_the_fetch(self):
        """A source fetched for the first time reports _fetch_single_source's
        own "Fetched X" line - reconciliation then activates it (a local
        file copy) silently, same as the already-staged case above, rather
        than adding a second "Enabled source: X"/"Enabled and fetched X"
        line for the same source."""
        messages = []
        with unittest.mock.patch('suricata_analyzer._fetch_single_source', side_effect=self._fake_fetch_with_progress), \
             unittest.mock.patch('suricata_analyzer.has_internet_access', return_value=True):
            suricata_analyzer._reconcile_suricata_sources(
                self.suricata_dir, self.tmpdir, ['et/open', 'oisf/trafficid'], messages.append, network_allowed=True)
        self.assertEqual(messages, ['Fetched oisf/trafficid'])

    def test_disabling_a_source_removes_it_from_active_but_keeps_library(self):
        self._stage('et/open')
        self._stage('oisf/trafficid')
        os.makedirs(self.active_dir, exist_ok=True)
        for name in ('et/open', 'oisf/trafficid'):
            shutil.copy2(
                os.path.join(self.library_dir, suricata_analyzer._source_filename(name)),
                os.path.join(self.active_dir, suricata_analyzer._source_filename(name)))
        with open(os.path.join(self.suricata_dir, 'enabled_sources.json'), 'w') as f:
            json.dump(['et/open', 'oisf/trafficid'], f)

        messages = []
        suricata_analyzer._reconcile_suricata_sources(
            self.suricata_dir, self.tmpdir, ['et/open'], messages.append, network_allowed=False)

        self.assertFalse(os.path.exists(os.path.join(self.active_dir, 'oisf-trafficid.rules')))
        self.assertTrue(os.path.isfile(os.path.join(self.library_dir, 'oisf-trafficid.rules')),
                         'the library copy must survive disabling - it is the whole point of the local cache')
        self.assertEqual(messages, [], 'disabling an already-inactive-locally source is silent, same as activating one')
        self.assertEqual(suricata_analyzer.get_suricata_enabled_sources(self.tmpdir), ['et/open'])

    def test_toggle_offline_is_fast_pure_local_io(self):
        """The whole point of this architecture: an airgapped user can
        toggle among whatever's already staged with zero network calls."""
        self._stage('et/open')
        self._stage('oisf/trafficid')
        with unittest.mock.patch('suricata_analyzer.has_internet_access', side_effect=AssertionError(
                'must not even check internet access when nothing needs fetching')):
            suricata_analyzer._reconcile_suricata_sources(
                self.suricata_dir, self.tmpdir, ['et/open', 'oisf/trafficid'], lambda m: None, network_allowed=False)
        self.assertEqual(
            set(suricata_analyzer.get_suricata_enabled_sources(self.tmpdir)),
            {'et/open', 'oisf/trafficid'})

    def test_noop_when_desired_matches_current(self):
        with open(os.path.join(self.suricata_dir, 'enabled_sources.json'), 'w') as f:
            json.dump(['et/open'], f)
        with unittest.mock.patch('suricata_analyzer._fetch_single_source') as mock_fetch:
            messages = []
            suricata_analyzer._reconcile_suricata_sources(
                self.suricata_dir, self.tmpdir, ['et/open'], messages.append, network_allowed=True)
        mock_fetch.assert_not_called()
        self.assertEqual(messages, [])

    def test_empty_desired_falls_back_to_default(self):
        messages = []
        suricata_analyzer._reconcile_suricata_sources(
            self.suricata_dir, self.tmpdir, [], messages.append, network_allowed=False)
        self.assertEqual(suricata_analyzer.get_suricata_enabled_sources(self.tmpdir), ['et/open'])

    def test_a_failed_fetch_is_dropped_gracefully_not_aborting_the_batch(self):
        def flaky_fetch(suricata_dir, name, dest_path, on_progress):
            if name == 'stamus/lateral':
                on_progress(f'Warning: could not fetch {name} (not available or incompatible)')
                return False
            _write_fake_rule_file(dest_path)
            return True

        with unittest.mock.patch('suricata_analyzer._fetch_single_source', side_effect=flaky_fetch), \
             unittest.mock.patch('suricata_analyzer.has_internet_access', return_value=True):
            messages = []
            suricata_analyzer._reconcile_suricata_sources(
                self.suricata_dir, self.tmpdir,
                ['et/open', 'oisf/trafficid', 'stamus/lateral'], messages.append, network_allowed=True)

        enabled = suricata_analyzer.get_suricata_enabled_sources(self.tmpdir)
        self.assertIn('oisf/trafficid', enabled)
        self.assertNotIn('stamus/lateral', enabled)
        self.assertTrue(any('could not fetch stamus/lateral' in m for m in messages), messages)


class TestSeedActiveFromLibrary(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.baked_in_dir = tempfile.mkdtemp()
        _write_fake_rule_file(os.path.join(self.baked_in_dir, 'et-open.rules'))
        _write_fake_rule_file(os.path.join(self.baked_in_dir, 'abuse.ch-feodotracker.rules'))

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        shutil.rmtree(self.baked_in_dir, ignore_errors=True)

    def test_copies_whole_library_but_activates_only_requested(self):
        suricata_analyzer._seed_active_from_library(
            self.baked_in_dir, self.tmpdir, ['et/open'], lambda m: None)
        library_dir = os.path.join(self.tmpdir, 'suricata', 'rules-available')
        active_dir = os.path.join(self.tmpdir, 'suricata', 'rules')
        self.assertEqual(sorted(os.listdir(library_dir)), ['abuse.ch-feodotracker.rules', 'et-open.rules'])
        self.assertEqual(os.listdir(active_dir), ['et-open.rules'])

    def test_writes_enabled_sources_json_matching_actually_activated(self):
        suricata_analyzer._seed_active_from_library(
            self.baked_in_dir, self.tmpdir, ['et/open'], lambda m: None)
        self.assertEqual(suricata_analyzer.get_suricata_enabled_sources(self.tmpdir), ['et/open'])

    def test_never_overwrites_an_already_present_local_library_file(self):
        """A locally fetched/refreshed copy always wins over the image's
        static bake snapshot."""
        library_dir = os.path.join(self.tmpdir, 'suricata', 'rules-available')
        os.makedirs(library_dir, exist_ok=True)
        local_path = os.path.join(library_dir, 'et-open.rules')
        _write_fake_rule_file(local_path, sid=999999)
        with open(local_path) as f:
            local_content_before = f.read()
        suricata_analyzer._seed_active_from_library(
            self.baked_in_dir, self.tmpdir, ['et/open'], lambda m: None)
        with open(local_path) as f:
            self.assertEqual(f.read(), local_content_before)

    def test_activated_set_can_be_a_subset_if_a_requested_file_is_missing(self):
        suricata_analyzer._seed_active_from_library(
            self.baked_in_dir, self.tmpdir, ['et/open', 'abuse.ch/feodotracker', 'oisf/trafficid'], lambda m: None)
        self.assertEqual(
            set(suricata_analyzer.get_suricata_enabled_sources(self.tmpdir)),
            {'et/open', 'abuse.ch/feodotracker'},
            'oisf/trafficid was never in the fake baked-in dir, so it must not be claimed as active')

    def test_decompresses_gzip_baked_in_files(self):
        """The real Docker image bakes rules-available/*.rules.gz (see the
        Dockerfile's bake loop) - the .rules fixtures used by every other
        test in this class only cover the legacy plain-file fallback, not
        the actual production path."""
        gz_dir = tempfile.mkdtemp()
        try:
            src_path = os.path.join(self.baked_in_dir, 'et-open.rules')
            with open(src_path, 'rb') as f_in, gzip.open(os.path.join(gz_dir, 'et-open.rules.gz'), 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
            with open(src_path, 'rb') as f:
                original_content = f.read()

            suricata_analyzer._seed_active_from_library(
                gz_dir, self.tmpdir, ['et/open'], lambda m: None)

            library_dir = os.path.join(self.tmpdir, 'suricata', 'rules-available')
            active_dir = os.path.join(self.tmpdir, 'suricata', 'rules')
            self.assertEqual(os.listdir(library_dir), ['et-open.rules'],
                              'the .gz suffix must be stripped from the decompressed filename')
            with open(os.path.join(library_dir, 'et-open.rules'), 'rb') as f:
                self.assertEqual(f.read(), original_content)
            self.assertEqual(os.listdir(active_dir), ['et-open.rules'])
        finally:
            shutil.rmtree(gz_dir, ignore_errors=True)


class TestSetupSuricataConfigEnabledSources(unittest.TestCase):
    """setup_suricata_config()'s enabled_sources kwarg triggers
    reconciliation regardless of network reachability (unlike the old
    design) - only the subsequent per-source refresh loop is gated behind
    network_allowed and has_internet_access()."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @unittest.mock.patch('suricata_analyzer._reconcile_suricata_sources')
    def test_reconciles_even_when_offline(self, mock_reconcile):
        """The whole point of the new architecture - reconciliation itself
        doesn't need network for an already-staged source."""
        suricata_analyzer.setup_suricata_config(
            self.tmpdir, network_allowed=False, enabled_sources=['et/open', 'abuse.ch/feodotracker'])
        mock_reconcile.assert_called_once()
        self.assertEqual(mock_reconcile.call_args.args[2], ['et/open', 'abuse.ch/feodotracker'])
        self.assertEqual(mock_reconcile.call_args.args[4], False, 'network_allowed must be threaded through')

    @unittest.mock.patch('suricata_analyzer._reconcile_suricata_sources')
    def test_skips_reconciliation_when_sources_not_given(self, mock_reconcile):
        suricata_analyzer.setup_suricata_config(self.tmpdir, network_allowed=False, enabled_sources=None)
        mock_reconcile.assert_not_called()

    @unittest.mock.patch('suricata_analyzer.has_internet_access', return_value=False)
    @unittest.mock.patch('suricata_analyzer._fetch_single_source')
    def test_refresh_loop_skipped_when_offline(self, mock_fetch, mock_internet):
        suricata_dir = os.path.join(self.tmpdir, 'suricata')
        os.makedirs(os.path.join(suricata_dir, 'rules'), exist_ok=True)
        _write_fake_rule_file(os.path.join(suricata_dir, 'rules', 'et-open.rules'))
        suricata_analyzer.setup_suricata_config(self.tmpdir, network_allowed=True, enabled_sources=None)
        mock_fetch.assert_not_called()

    @unittest.mock.patch('suricata_analyzer.has_internet_access', return_value=True)
    def test_refresh_loop_runs_for_every_active_source_when_online(self, mock_internet):
        suricata_dir = os.path.join(self.tmpdir, 'suricata')
        library_dir = os.path.join(suricata_dir, 'rules-available')
        active_dir = os.path.join(suricata_dir, 'rules')
        os.makedirs(library_dir, exist_ok=True)
        os.makedirs(active_dir, exist_ok=True)
        for name in ('et/open', 'oisf/trafficid'):
            _write_fake_rule_file(os.path.join(library_dir, suricata_analyzer._source_filename(name)))
            _write_fake_rule_file(os.path.join(active_dir, suricata_analyzer._source_filename(name)))
        with open(os.path.join(suricata_dir, 'enabled_sources.json'), 'w') as f:
            json.dump(['et/open', 'oisf/trafficid'], f)

        fetched = []

        def fake_fetch(suricata_dir_arg, name, dest_path, on_progress):
            fetched.append(name)
            _write_fake_rule_file(dest_path)
            return True

        with unittest.mock.patch('suricata_analyzer._fetch_single_source', side_effect=fake_fetch):
            suricata_analyzer.setup_suricata_config(self.tmpdir, network_allowed=True, enabled_sources=None)
        self.assertEqual(set(fetched), {'et/open', 'oisf/trafficid'})

    @unittest.mock.patch('suricata_analyzer.has_internet_access', return_value=True)
    def test_refresh_loop_does_not_redundantly_refetch_sources_reconciliation_just_fetched(self, mock_internet):
        """REGRESSION: reported after shipping - enabling many sources at
        once (e.g. "Enable All") and clicking Update fetched each newly
        enabled source twice: once inside _reconcile_suricata_sources()
        (since it wasn't staged yet) and again immediately after by the
        "refresh every active source" loop, which had no way to know a
        given source was just fetched seconds ago. Only et/open was
        already active beforehand and must still get refreshed
        (unaffected by this fix); oisf/trafficid is being enabled for the
        first time and must be fetched exactly once."""
        fetch_calls = []

        def fake_fetch(suricata_dir_arg, name, dest_path, on_progress):
            fetch_calls.append(name)
            _write_fake_rule_file(dest_path)
            return True

        with unittest.mock.patch('suricata_analyzer._fetch_single_source', side_effect=fake_fetch):
            suricata_analyzer.setup_suricata_config(
                self.tmpdir, network_allowed=True, enabled_sources=['et/open', 'oisf/trafficid'])

        self.assertEqual(fetch_calls.count('oisf/trafficid'), 1,
                          f'a newly-enabled source must be fetched exactly once, not {fetch_calls}')
        self.assertEqual(fetch_calls.count('et/open'), 1,
                          f'an already-active source must still get refreshed once, not {fetch_calls}')


class TestSetupSuricataConfigProtocolDecodeAlerts(unittest.TestCase):
    """setup_suricata_config()'s show_protocol_decode_alerts kwarg controls
    disable.conf's content and, when explicitly set (not None), persists
    the choice to show_protocol_decode_alerts.json for future calls that
    don't pass it (server startup, background scans, plain 'Update All')."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _disable_conf_content(self):
        with open(os.path.join(self.tmpdir, 'suricata', 'disable.conf')) as f:
            return f.read()

    def test_default_suppresses_protocol_command_decode(self):
        suricata_analyzer.setup_suricata_config(self.tmpdir, network_allowed=False)
        self.assertEqual(self._disable_conf_content(), 're:classtype:protocol-command-decode\n')

    def test_explicit_false_suppresses_and_persists(self):
        suricata_analyzer.setup_suricata_config(
            self.tmpdir, network_allowed=False, show_protocol_decode_alerts=False)
        self.assertEqual(self._disable_conf_content(), 're:classtype:protocol-command-decode\n')
        self.assertIs(suricata_analyzer.get_suricata_show_protocol_decode_alerts(self.tmpdir), False)

    def test_explicit_true_leaves_disable_conf_empty_and_persists(self):
        suricata_analyzer.setup_suricata_config(
            self.tmpdir, network_allowed=False, show_protocol_decode_alerts=True)
        self.assertEqual(self._disable_conf_content(), '')
        self.assertIs(suricata_analyzer.get_suricata_show_protocol_decode_alerts(self.tmpdir), True)

    def test_none_leaves_previously_persisted_true_in_effect(self):
        """A plain 'Update All' (or server startup) omits this kwarg
        entirely - it must not silently reset a previously opted-in user
        back to suppressed."""
        suricata_analyzer.setup_suricata_config(
            self.tmpdir, network_allowed=False, show_protocol_decode_alerts=True)
        suricata_analyzer.setup_suricata_config(
            self.tmpdir, network_allowed=False, show_protocol_decode_alerts=None)
        self.assertEqual(self._disable_conf_content(), '')
        self.assertIs(suricata_analyzer.get_suricata_show_protocol_decode_alerts(self.tmpdir), True)



class TestCustomRules(unittest.TestCase):
    """Custom rules on disk: saved only when every check passes, turned
    on or off without losing them, and never touched by source
    reconciliation. Parts of these follow the reference patch in issue
    #75."""

    RULE = 'alert tcp any any -> any any (msg:"local"; content:"x"; sid:1000001; rev:1;)'

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.suricata_dir = os.path.join(self.tmpdir, 'suricata')
        self.saved = os.path.join(self.suricata_dir, 'custom.rules')
        self.active = os.path.join(self.suricata_dir, 'rules', 'custom.rules')
        patcher = unittest.mock.patch('suricata_analyzer.check_rules_with_suricata', return_value=[])
        self.mock_check = patcher.start()
        self.addCleanup(patcher.stop)

    def test_none_saved(self):
        self.assertEqual(suricata_analyzer.get_custom_rules(self.tmpdir), {'count': None, 'updated': None, 'enabled': False})
        self.assertEqual(suricata_analyzer.get_custom_rules(self.tmpdir, include_text=True)['rules'], '')

    def test_save_writes_both_copies_with_unix_line_endings(self):
        count, problems = suricata_analyzer.save_custom_rules(f'# mine\r\n{self.RULE}', self.tmpdir)
        self.assertEqual((count, problems), (1, []))
        for path in (self.saved, self.active):
            with open(path, newline='') as f:
                self.assertEqual(f.read(), f'# mine\n{self.RULE}\n')
        info = suricata_analyzer.get_custom_rules(self.tmpdir, include_text=True)
        self.assertEqual((info['count'], info['enabled']), (1, True))

    def test_problems_write_nothing(self):
        suricata_analyzer.save_custom_rules(self.RULE, self.tmpdir)
        self.mock_check.return_value = [{'line': 1, 'message': "unknown rule keyword 'foo'"}]
        count, problems = suricata_analyzer.save_custom_rules(self.RULE.replace('content:"x"', 'foo:bar'), self.tmpdir)
        self.assertEqual(problems, [{'line': 1, 'message': "unknown rule keyword 'foo'"}])
        for path in (self.saved, self.active):
            with open(path) as f:
                self.assertIn('content:"x"', f.read())

    def test_turning_off_keeps_the_saved_rules(self):
        suricata_analyzer.save_custom_rules(self.RULE, self.tmpdir)
        suricata_analyzer._set_custom_rules_enabled(self.tmpdir, False, lambda m: None)
        self.assertFalse(os.path.exists(self.active))
        self.assertTrue(os.path.exists(self.saved))
        self.assertFalse(suricata_analyzer.get_custom_rules(self.tmpdir)['enabled'])
        suricata_analyzer._set_custom_rules_enabled(self.tmpdir, True, lambda m: None)
        self.assertTrue(os.path.exists(self.active))

    def test_turning_on_with_none_saved_warns(self):
        messages = []
        suricata_analyzer._set_custom_rules_enabled(self.tmpdir, True, messages.append)
        self.assertFalse(os.path.exists(self.active))
        self.assertIn('no custom rules are saved yet', messages[0])

    def test_empty_text_removes_them(self):
        suricata_analyzer.save_custom_rules(self.RULE, self.tmpdir)
        self.assertEqual(suricata_analyzer.save_custom_rules('\n  \n', self.tmpdir), (0, []))
        self.assertFalse(os.path.exists(self.saved) or os.path.exists(self.active))

    def test_reconciling_sources_leaves_custom_rules_alone(self):
        library_dir = os.path.join(self.suricata_dir, 'rules-available')
        _write_fake_rule_file(os.path.join(library_dir, 'et-open.rules'))
        _write_fake_rule_file(os.path.join(library_dir, 'oisf-trafficid.rules'))
        suricata_analyzer.save_custom_rules(self.RULE, self.tmpdir)
        for sources in (['oisf/trafficid'], ['et/open']):
            suricata_analyzer._reconcile_suricata_sources(
                self.suricata_dir, self.tmpdir, sources, lambda m: None, network_allowed=False)
        self.assertTrue(os.path.isfile(self.active))
        # and they aren't counted as a curated source's rules
        self.assertEqual(suricata_analyzer.get_suricata_rules_info(self.tmpdir)['count'], 1)

    def test_setup_lists_custom_rules_and_switches_them(self):
        os.makedirs(self.suricata_dir, exist_ok=True)
        with open(os.path.join(self.suricata_dir, 'suricata.yaml'), 'w') as f:
            f.write('%YAML 1.1\n---\nrule-files:\n  - suricata.rules\n')
        suricata_analyzer.save_custom_rules(self.RULE, self.tmpdir)
        suricata_analyzer.setup_suricata_config(self.tmpdir, on_progress=lambda m: None, network_allowed=False,
                                                custom_rules_enabled=False)
        with open(os.path.join(self.suricata_dir, 'suricata.yaml')) as f:
            self.assertTrue(f.read().endswith('  - custom.rules\n'))
        self.assertFalse(os.path.exists(self.active))
        # None leaves them as they are
        suricata_analyzer.setup_suricata_config(self.tmpdir, on_progress=lambda m: None, network_allowed=False)
        self.assertFalse(os.path.exists(self.active))


class TestCheckRulesWithSuricata(unittest.TestCase):
    """Suricata's own parser check: its errors mapped to the lines they're
    about, and never a pass when the check couldn't run."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        os.makedirs(os.path.join(self.tmpdir, 'suricata'))
        with open(os.path.join(self.tmpdir, 'suricata', 'suricata.yaml'), 'w') as f:
            f.write('%YAML 1.1\n---\n')

    def test_errors_map_to_lines(self):
        output = (
            'i: suricata: This is Suricata version 8.0.7 RELEASE running in SYSTEM mode\n'
            "E: detect-parse: unknown rule keyword 'foo'.\n"
            'E: detect: error parsing signature "alert tcp any any -> any any (foo:bar; sid:1000003;)" from file /tmp/x/custom.rules at line 3\n'
            'E: detect-pcre: pcre2 compile of "/(/" failed at offset 1: missing closing parenthesis\n'
            'E: detect: error parsing signature "alert http any any -> any any (pcre:\"/(/\"; sid:1000004;)" from file /tmp/x/custom.rules at line 5\n'
            'E: suricata: Loading signatures failed.\n')
        self.assertEqual(suricata_analyzer._suricata_rule_problems(output, '/tmp/x/custom.rules'), [
            {'line': 3, 'message': "unknown rule keyword 'foo'"},
            {'line': 5, 'message': 'pcre2 compile of "/(/" failed at offset 1: missing closing parenthesis'},
        ])

    def test_an_error_with_no_line_still_fails(self):
        problems = suricata_analyzer._suricata_rule_problems('E: suricata: failed to load /tmp/x/custom.rules.\n', '/tmp/x/custom.rules')
        self.assertEqual(problems, [{'line': None, 'message': 'failed to load custom.rules'}])

    def test_runs_suricata_on_the_rules_alone(self):
        result = unittest.mock.Mock(returncode=0, stdout='', stderr='')
        with unittest.mock.patch('suricata_analyzer.shutil.which', return_value='/usr/bin/suricata'), \
             unittest.mock.patch('suricata_analyzer.subprocess.run', return_value=result) as mock_run:
            self.assertEqual(suricata_analyzer.check_rules_with_suricata('alert ...', self.tmpdir), [])
        cmd = mock_run.call_args.args[0]
        self.assertEqual(cmd[:2], ['suricata', '-T'])
        self.assertIn('-S', cmd)
        self.assertIn('detect.sgh-mpm-caching=no', cmd)

    def test_never_passes_unchecked(self):
        with unittest.mock.patch('suricata_analyzer.shutil.which', return_value=None):
            self.assertIn("isn't installed", suricata_analyzer.check_rules_with_suricata('x', self.tmpdir)[0]['message'])
        with unittest.mock.patch('suricata_analyzer.shutil.which', return_value='/usr/bin/suricata'):
            empty = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, empty, ignore_errors=True)
            self.assertIn("isn't set up", suricata_analyzer.check_rules_with_suricata('x', empty)[0]['message'])
            with unittest.mock.patch('suricata_analyzer.subprocess.run',
                                     side_effect=subprocess.TimeoutExpired('suricata', 30)):
                self.assertIn('took longer', suricata_analyzer.check_rules_with_suricata('x', self.tmpdir)[0]['message'])


if __name__ == '__main__':
    unittest.main()
