#!/usr/bin/env python3
"""Tests for sigma_analyzer.py."""

import json
import os
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import sigma_analyzer
import validators


class TestLogTypeDetection(unittest.TestCase):
    def test_detect_windows_evtx(self):
        with tempfile.NamedTemporaryFile(suffix='.evtx', delete=False) as f:
            f.write(b'ElfFile\x00')
            path = f.name
        try:
            result = sigma_analyzer._detect_log_type(path)
            self.assertEqual(result, 'windows')
        finally:
            os.unlink(path)

    def test_detect_windows_json(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            f.write(b'{"EventID": 4624, "Channel": "Security"}')
            path = f.name
        try:
            result = sigma_analyzer._detect_log_type(path)
            self.assertEqual(result, 'windows')
        finally:
            os.unlink(path)

    def test_detect_linux_json(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            # Raw auditd-style log in JSON-wrapped format
            f.write(b'type=SYSCALL msg=audit(123): auid=1000 uid=0 exe="/bin/bash"')
            path = f.name
        try:
            result = sigma_analyzer._detect_log_type(path)
            self.assertEqual(result, 'linux')
        finally:
            os.unlink(path)

    def test_detect_ambiguous_returns_none(self):
        with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
            f.write(b'generic log line\n')
            path = f.name
        try:
            result = sigma_analyzer._detect_log_type(path)
            self.assertIsNone(result)
        finally:
            os.unlink(path)


class TestZircoliteResultParsing(unittest.TestCase):
    def test_parse_empty_file(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            f.write(b'[]')
            path = f.name
        try:
            alerts = sigma_analyzer.parse_zircolite_results(path)
            self.assertEqual(alerts, [])
        finally:
            os.unlink(path)

    def test_json_data_does_not_repeat_every_match(self):
        """REGRESSION: each alert stored the whole detection, including
        its full 'matches' list - N copies of N events per rule, so storage
        grew with the square of the match count, and a search term found in
        any other match of the rule matched every one of its alerts."""
        matches = [{'SystemTime': f'2024-01-01T00:00:{i:02d}Z', 'CommandLine': f'cmd-{i}',
                    'Channel': 'Security'} for i in range(50)]
        results = [{'title': 'Brute force', 'id': 'r1', 'rule_level': 'high',
                    'tags': ['attack.t1110'], 'count': 50, 'matches': matches}]
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
            json.dump(results, f)
            path = f.name
        try:
            alerts = sigma_analyzer.parse_zircolite_results(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(alerts), 50)
        for i, alert in enumerate(alerts):
            data = json.loads(alert['json_data'])
            self.assertNotIn('matches', data)
            self.assertEqual(data['title'], 'Brute force')
            self.assertEqual(json.loads(alert['original_log'])['CommandLine'], f'cmd-{i}')
            self.assertNotIn('cmd-', alert['json_data'])

    def test_parse_zircolite_v3_output(self):
        results = [
            {
                'timestamp': '2024-01-01T00:00:00Z',
                'title': 'Suspicious PowerShell',
                'id': 'abc123',
                'rule_level': 'high',
                'logsource': 'windows',
                'tags': ['attack.T1059', 'attack.execution'],
                'event': {'CommandLine': 'powershell -enc abc'}
            }
        ]
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            f.write(json.dumps(results).encode())
            path = f.name
        try:
            alerts = sigma_analyzer.parse_zircolite_results(path)
            self.assertEqual(len(alerts), 1)
            alert = alerts[0]
            self.assertEqual(alert['rule_title'], 'Suspicious PowerShell')
            self.assertEqual(alert['rule_id'], 'abc123')
            self.assertEqual(alert['severity'], 'high')
            self.assertEqual(alert['level'], 'high')
            self.assertEqual(alert['mitre_techniques'], ['attack.T1059'])
        finally:
            os.unlink(path)

    def test_parse_dict_wrapper(self):
        results = {
            'detections': [
                {
                    'timestamp': '2024-01-01T00:00:00Z',
                    'title': 'Test Rule',
                    'id': 'def456',
                    'rule_level': 'medium',
                    'logsource': 'linux',
                    'tags': ['attack.T1078'],
                    'event': {'type': 'SYSCALL'}
                }
            ]
        }
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            f.write(json.dumps(results).encode())
            path = f.name
        try:
            alerts = sigma_analyzer.parse_zircolite_results(path)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]['rule_title'], 'Test Rule')
            self.assertEqual(alerts[0]['severity'], 'medium')
        finally:
            os.unlink(path)

    def test_parse_multiple_matches(self):
        """A detection with 3 matches should emit 3 alert rows."""
        results = [
            {
                'title': 'Multiple Matches Rule',
                'id': 'multi123',
                'rule_level': 'high',
                'tags': ['attack.T1059'],
                'matches': [
                    {'SystemTime': '2024-01-01T10:00:00Z', 'EventID': 4624, 'Channel': 'Security'},
                    {'SystemTime': '2024-01-01T11:00:00Z', 'EventID': 4624, 'Channel': 'Security'},
                    {'SystemTime': '2024-01-01T12:00:00Z', 'EventID': 4624, 'Channel': 'Security'},
                ]
            }
        ]
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            f.write(json.dumps(results).encode())
            path = f.name
        try:
            alerts = sigma_analyzer.parse_zircolite_results(path)
            self.assertEqual(len(alerts), 3)
            for alert in alerts:
                self.assertEqual(alert['rule_title'], 'Multiple Matches Rule')
                self.assertEqual(alert['rule_id'], 'multi123')
                self.assertEqual(alert['severity'], 'high')
            # Each alert should have a distinct timestamp
            timestamps = [a['timestamp'] for a in alerts]
            self.assertEqual(len(set(timestamps)), 3)
            self.assertIn('2024-01-01T10:00:00Z', timestamps)
            self.assertIn('2024-01-01T11:00:00Z', timestamps)
            self.assertIn('2024-01-01T12:00:00Z', timestamps)
            # Log source should be resolved from the match
            self.assertEqual(alerts[0]['logsource'], 'Security')
            # original_log should be the specific match, not the whole detection
            original = json.loads(alerts[0]['original_log'])
            self.assertEqual(original['SystemTime'], '2024-01-01T10:00:00Z')
        finally:
            os.unlink(path)

    def test_parse_logsource_fallback_from_match(self):
        """When detection-level logsource is empty, use match's Channel."""
        results = [
            {
                'title': 'No Logsource Rule',
                'id': 'nols456',
                'rule_level': 'medium',
                'tags': [],
                'matches': [
                    {'SystemTime': '2024-01-01T10:00:00Z', 'Channel': 'Microsoft-Windows-Sysmon/Operational'},
                ]
            }
        ]
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            f.write(json.dumps(results).encode())
            path = f.name
        try:
            alerts = sigma_analyzer.parse_zircolite_results(path)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]['logsource'], 'Microsoft-Windows-Sysmon/Operational')
        finally:
            os.unlink(path)

    def test_parse_no_matches_skipped(self):
        """A detection with no matches and no event should be skipped."""
        results = [
            {
                'title': 'Empty Rule',
                'id': 'empty789',
                'rule_level': 'low',
                'tags': [],
                'matches': []
            }
        ]
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            f.write(json.dumps(results).encode())
            path = f.name
        try:
            alerts = sigma_analyzer.parse_zircolite_results(path)
            self.assertEqual(len(alerts), 0)
        finally:
            os.unlink(path)


class TestImportZircoliteLogs(unittest.TestCase):
    def test_import_empty_db(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as zdb:
            zdb_path = zdb.name
        try:
            with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as edb:
                edb_path = edb.name
            try:
                count = sigma_analyzer.import_zircolite_logs(zdb_path, edb_path)
                self.assertEqual(count, 0)
            finally:
                os.unlink(edb_path)
        finally:
            os.unlink(zdb_path)

    def test_import_sample_logs(self):
        import sqlite3
        # Create a mock Zircolite unified DB
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as zdb:
            zdb_path = zdb.name
        conn = sqlite3.connect(zdb_path)
        conn.execute('''CREATE TABLE logs (
            row_id INTEGER, Channel TEXT, EventID INTEGER, Computer TEXT,
            CommandLine TEXT, SourceIp TEXT, DestinationIp TEXT,
            SourcePort INTEGER, DestinationPort INTEGER, Protocol TEXT,
            SystemTime TEXT, UtcTime TEXT
        )''')
        conn.execute('''INSERT INTO logs VALUES
            (1, 'Security', 4624, 'PC1', 'cmd.exe /c whoami', NULL, NULL, NULL, NULL, NULL, '2024-01-01T12:00:00Z', NULL),
            (2, 'Microsoft-Windows-Sysmon/Operational', 3, 'PC1', NULL, '192.168.1.1', '10.0.0.1', 12345, 80, 'tcp', '2024-01-01T12:01:00Z', NULL)
        ''')
        conn.commit()
        conn.close()

        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as edb:
            edb_path = edb.name
        try:
            count = sigma_analyzer.import_zircolite_logs(zdb_path, edb_path)
            self.assertEqual(count, 2)

            # Verify in DB
            conn2 = sqlite3.connect(edb_path)
            conn2.row_factory = sqlite3.Row
            cur = conn2.execute('SELECT * FROM events WHERE event_type = "log" ORDER BY rowid')
            rows = cur.fetchall()
            self.assertEqual(len(rows), 2)

            # First event
            self.assertEqual(rows[0]['event_type'], 'log')
            self.assertEqual(rows[0]['src_ip'], '')
            self.assertEqual(rows[0]['dest_ip'], '')
            self.assertIn('cmd.exe', rows[0]['json_data'])

            # Second event (network)
            network_row = next((r for r in rows if r['src_ip'] == '192.168.1.1'), None)
            self.assertIsNotNone(network_row)
            self.assertEqual(network_row['dest_ip'], '10.0.0.1')
            self.assertEqual(network_row['src_port'], 12345)
            self.assertEqual(network_row['dest_port'], 80)
            self.assertEqual(network_row['protocol'], 'tcp')
            conn2.close()
        finally:
            os.unlink(zdb_path)
            os.unlink(edb_path)

    @unittest.mock.patch('sqlite3.connect')
    def test_import_handles_corrupt_db(self, mock_connect):
        """If sqlite3.connect fails, import_zircolite_logs must return 0 cleanly."""
        import sqlite3
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as zdb:
            zdb_path = zdb.name
        try:
            with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as edb:
                edb_path = edb.name
            try:
                mock_connect.side_effect = sqlite3.OperationalError('unable to open database file')
                count = sigma_analyzer.import_zircolite_logs(zdb_path, edb_path)
                self.assertEqual(count, 0)
            finally:
                os.unlink(edb_path)
        finally:
            os.unlink(zdb_path)


class TestValidatorsLogDetection(unittest.TestCase):
    def test_is_log_file_evtx(self):
        self.assertTrue(validators.is_log_file(b'ElfFile\x00'))

    def test_is_log_file_json(self):
        self.assertTrue(validators.is_log_file(b'{"EventID": 1}'))

    def test_is_log_file_csv(self):
        self.assertTrue(validators.is_log_file(b'timestamp,message\n2024-01-01,hello'))

    def test_is_log_file_xml(self):
        self.assertTrue(validators.is_log_file(b'<?xml version="1.0"?><root/>'))

    def test_is_log_file_not_html(self):
        self.assertFalse(validators.is_log_file(b'<!DOCTYPE html><html></html>'))

    def test_is_log_file_not_binary(self):
        self.assertFalse(validators.is_log_file(b'\x00\x01\x02\x03'))

    def test_is_log_file_by_extension(self):
        self.assertTrue(validators.is_log_file_by_extension('test.evtx'))
        self.assertTrue(validators.is_log_file_by_extension('test.json'))
        self.assertTrue(validators.is_log_file_by_extension('test.log'))
        self.assertFalse(validators.is_log_file_by_extension('test.exe'))


class TestGetSigmaRulesInfoNeverRaises(unittest.TestCase):
    def test_invalid_utf8_does_not_raise(self):
        """REGRESSION: get_sigma_rules_info()'s docstring promises it never
        raises, falling back to None fields if a cached rules file fails to
        parse - but it opened its file in plain text mode (default
        encoding), unlike get_yara_rules_info()/get_suricata_rules_info()
        which both use errors='ignore'. Invalid UTF-8 bytes in a corrupted
        cached windows.json/linux.json raised UnicodeDecodeError instead,
        which - since GET /api/rules-info has no per-handler try/except -
        broke the entire Rules-info response for all three rulesets, not
        just the corrupted one."""
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_dir = os.path.join(tmpdir, 'sigma-rules')
            os.makedirs(rules_dir, exist_ok=True)
            with open(os.path.join(rules_dir, 'windows.json'), 'wb') as f:
                f.write(b'\xff\xfe[{"bad": "utf8"')

            result = sigma_analyzer.get_sigma_rules_info(data_dir=tmpdir)

        self.assertEqual(result['windows'], {'count': None, 'updated': None, 'stale': None})

    def test_stale_field_reflects_file_age(self):
        """'stale' must be False for a just-written file and True once its
        mtime is older than config.RULES_MAX_AGE_HOURS - purely a local
        os.path.getmtime() comparison via validators.is_file_stale(), no
        network access."""
        import config
        import time
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_dir = os.path.join(tmpdir, 'sigma-rules')
            os.makedirs(rules_dir, exist_ok=True)
            rules_file = os.path.join(rules_dir, 'windows.json')
            with open(rules_file, 'w') as f:
                json.dump([{'title': 'rule1'}], f)

            fresh = sigma_analyzer.get_sigma_rules_info(data_dir=tmpdir)
            self.assertFalse(fresh['windows']['stale'], 'a just-written rules file must not be stale')

            old_time = time.time() - (config.RULES_MAX_AGE_HOURS + 1) * 3600
            os.utime(rules_file, (old_time, old_time))
            stale = sigma_analyzer.get_sigma_rules_info(data_dir=tmpdir)
            self.assertTrue(stale['windows']['stale'], 'a rules file older than RULES_MAX_AGE_HOURS must be stale')


class TestSetupSigmaRulesFreshness(unittest.TestCase):
    def _make_stale_rules(self, tmpdir):
        import time
        import config
        rules_dir = os.path.join(tmpdir, config.SIGMA_RULES_SUBDIR)
        os.makedirs(rules_dir, exist_ok=True)
        for name in ('windows', 'linux'):
            path = os.path.join(rules_dir, f'{name}.json')
            with open(path, 'w') as f:
                f.write('{"old": "rules"}')
            old_time = time.time() - (config.RULES_MAX_AGE_HOURS + 1) * 3600
            os.utime(path, (old_time, old_time))
        return rules_dir

    @unittest.mock.patch('sigma_analyzer._download_rule_file')
    @unittest.mock.patch('sigma_analyzer.is_host_reachable', return_value=True)
    def test_stale_cached_rules_are_refreshed_when_online(self, mock_reachable, mock_download):
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_stale_rules(tmpdir)
            result = sigma_analyzer.setup_sigma_rules(tmpdir)
        self.assertEqual(mock_download.call_count, 2, 'both rulesets should be refreshed')
        self.assertIn('windows', result)
        self.assertIn('linux', result)

    @unittest.mock.patch('sigma_analyzer._download_rule_file')
    @unittest.mock.patch('sigma_analyzer.is_host_reachable', return_value=False)
    def test_stale_cached_rules_kept_when_offline(self, mock_reachable, mock_download):
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_dir = self._make_stale_rules(tmpdir)
            result = sigma_analyzer.setup_sigma_rules(tmpdir)
        mock_download.assert_not_called()
        self.assertEqual(result['windows'], os.path.join(rules_dir, 'windows.json'))

    @unittest.mock.patch('sigma_analyzer._download_rule_file')
    @unittest.mock.patch('sigma_analyzer.is_host_reachable', return_value=True)
    def test_fresh_cached_rules_are_not_refreshed(self, mock_reachable, mock_download):
        with tempfile.TemporaryDirectory() as tmpdir:
            import config
            rules_dir = os.path.join(tmpdir, config.SIGMA_RULES_SUBDIR)
            os.makedirs(rules_dir, exist_ok=True)
            with open(os.path.join(rules_dir, 'windows.json'), 'w') as f:
                f.write('{"fresh": "rules"}')
            with open(os.path.join(rules_dir, 'linux.json'), 'w') as f:
                f.write('{"fresh": "rules"}')
            sigma_analyzer.setup_sigma_rules(tmpdir)
        mock_download.assert_not_called()

    @unittest.mock.patch('sigma_analyzer._download_rule_file', side_effect=OSError('network error'))
    @unittest.mock.patch('sigma_analyzer.is_host_reachable', return_value=True)
    def test_refresh_failure_falls_back_to_stale_cached_rules(self, mock_reachable, mock_download):
        """REGRESSION: a failed refresh attempt must not remove or break the
        still-usable stale copy - setup must keep returning it."""
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_dir = self._make_stale_rules(tmpdir)
            result = sigma_analyzer.setup_sigma_rules(tmpdir)
            self.assertEqual(result['windows'], os.path.join(rules_dir, 'windows.json'))
            with open(result['windows']) as f:
                self.assertEqual(f.read(), '{"old": "rules"}')

    @unittest.mock.patch('sigma_analyzer.urllib.request.urlopen')
    def test_download_rule_file_writes_atomically(self, mock_urlopen):
        """A partial/failed write must not corrupt an existing cached file
        (_download_rule_file writes to a .new temp file and renames into
        place instead of truncating dest_file directly)."""
        mock_urlopen.side_effect = OSError('connection reset')
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = os.path.join(tmpdir, 'windows.json')
            with open(dest, 'w') as f:
                f.write('{"good": "cached rules"}')
            with self.assertRaises(OSError):
                sigma_analyzer._download_rule_file('http://example.com/rules.json', dest)
            with open(dest) as f:
                self.assertEqual(f.read(), '{"good": "cached rules"}')
            self.assertFalse(os.path.exists(dest + '.new'), 'temp file must be cleaned up')

    @unittest.mock.patch('sigma_analyzer.urllib.request.urlopen')
    def test_download_rule_file_rejects_non_json_response(self, mock_urlopen):
        """REGRESSION: a transient bad response (rate-limit page, outage
        page, truncated-but-200 body) used to be written straight to disk
        and atomically swapped in over a good cached ruleset with no
        validation at all. Must be rejected before ever touching dest_file."""
        mock_urlopen.return_value.__enter__.return_value.read.return_value = b'<html>rate limited</html>'
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = os.path.join(tmpdir, 'windows.json')
            with open(dest, 'w') as f:
                f.write('{"good": "cached rules"}')
            with self.assertRaises(OSError):
                sigma_analyzer._download_rule_file('http://example.com/rules.json', dest)
            with open(dest) as f:
                self.assertEqual(f.read(), '{"good": "cached rules"}')
            self.assertFalse(os.path.exists(dest + '.new'), 'temp file must be cleaned up')


class TestNetworkAllowedFalseDoesNotClaimNoInternet(unittest.TestCase):
    """REGRESSION: with no cached copy and no baked-in file, the final
    "not available" message per ruleset used to say "No internet access
    detected" unconditionally - including when network_allowed=False
    (e.g. server startup, which never checks reachability at all by
    design). A real user on a machine WITH internet access saw this
    exact message at startup and reasonably assumed something was
    broken. The message must now distinguish "we checked and it failed"
    from "we didn't check"."""

    def test_network_allowed_false_does_not_say_no_internet(self):
        messages = []
        with tempfile.TemporaryDirectory() as tmpdir:
            sigma_analyzer.setup_sigma_rules(tmpdir, on_progress=messages.append, network_allowed=False)
        self.assertFalse(any('no internet' in m.lower() for m in messages), messages)
        self.assertIn('WARNING! No Sigma rules (windows) found', messages)
        self.assertIn('WARNING! No Sigma rules (linux) found', messages)

    def test_network_allowed_true_and_unreachable_still_says_no_internet(self):
        messages = []
        with tempfile.TemporaryDirectory() as tmpdir, \
             unittest.mock.patch('sigma_analyzer.is_host_reachable', return_value=False):
            sigma_analyzer.setup_sigma_rules(tmpdir, on_progress=messages.append, network_allowed=True)
        self.assertTrue(any('no internet' in m.lower() for m in messages), messages)


class TestRunSigmaPipelineNeverAllowsNetworkRefresh(unittest.TestCase):
    """REGRESSION: analyzing a log file must never silently phone home to
    refresh Sigma rules as a side effect of just uploading it - that's now
    an explicit, opt-in action (Rules modal, or the checkForStaleRules()
    notification), not something the analysis path triggers on its own.
    See AGENTS.md and setup_sigma_rules()'s network_allowed parameter."""

    @unittest.mock.patch('sigma_analyzer.setup_sigma_rules', return_value=None)
    @unittest.mock.patch('sigma_analyzer.is_zircolite_available', return_value=True)
    def test_run_sigma_pipeline_calls_setup_with_network_allowed_false(self, mock_available, mock_setup):
        with tempfile.TemporaryDirectory() as tmpdir:
            sigma_analyzer.run_sigma_pipeline(tmpdir, os.path.join(tmpdir, 'events.evtx'), data_dir=tmpdir)
        mock_setup.assert_called_once_with(tmpdir, network_allowed=False)


if __name__ == '__main__':
    unittest.main()
