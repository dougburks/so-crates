#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import stream_payload
from tests.pcap_fixtures import HTTP_REQUEST, HTTP_RESPONSE, write_http_pcap


def _run(cmd, max_bytes, timeout, text=False):
    """Stand-in for socrates._run_capped with the same return shape."""
    out = subprocess.run(cmd, capture_output=True, timeout=timeout).stdout
    truncated = len(out) > max_bytes
    out = out[:max_bytes]
    return 0, out.decode('utf-8', errors='replace') if text else out, truncated


class TestFollowCommand(unittest.TestCase):
    def test_ipv4_endpoints(self):
        cmd = stream_payload.follow_command('x.pcap', 'tcp', '10.0.0.1', '40000', '10.0.0.2', '80')
        self.assertEqual(cmd, ['tshark', '-r', 'x.pcap', '-q', '-z',
                               'follow,tcp,raw,10.0.0.1:40000,10.0.0.2:80'])

    def test_ipv6_endpoints_bracketed_and_compressed(self):
        """Suricata logs IPv6 fully expanded; tshark wants [addr]:port."""
        cmd = stream_payload.follow_command(
            'x.pcap', 'udp', '2001:0db8:0000:0000:0000:0000:0000:0001', '53', '2001:db8::2', '5353')
        self.assertEqual(cmd[-1], 'follow,udp,raw,[2001:db8::1]:53,[2001:db8::2]:5353')


class TestParseFollowRaw(unittest.TestCase):
    OUTPUT = ('\n===================================================================\n'
              'Follow: tcp,raw\nFilter: x\nNode 0: 10.0.0.1:40000\nNode 1: 10.0.0.2:80\n'
              '6869\n\t6f6b\n21\n\t0001ff\n'
              '===================================================================\n')

    def test_directions(self):
        p = stream_payload.parse_follow_raw
        self.assertEqual(p(self.OUTPUT, '10.0.0.1', 40000, 'src'), b'hi!')
        self.assertEqual(p(self.OUTPUT, '10.0.0.1', 40000, 'dst'), b'ok\x00\x01\xff')
        self.assertEqual(p(self.OUTPUT, '10.0.0.1', 40000, 'both'), b'hiok!\x00\x01\xff')

    def test_src_given_as_node1(self):
        """src is whatever the event row said, not necessarily whoever
        tshark saw send first."""
        p = stream_payload.parse_follow_raw
        self.assertEqual(p(self.OUTPUT, '10.0.0.2', 80, 'src'), b'ok\x00\x01\xff')
        self.assertEqual(p(self.OUTPUT, '10.0.0.2', 80, 'dst'), b'hi!')

    def test_missing_flow(self):
        out = 'Follow: tcp,raw\nFilter: x\nNode 0: :0\nNode 1: :0\n'
        for direction in stream_payload.DIRECTIONS:
            self.assertEqual(stream_payload.parse_follow_raw(out, '1.2.3.4', 1, direction), b'')

    def test_invalid_direction(self):
        with self.assertRaises(ValueError):
            stream_payload.parse_follow_raw(self.OUTPUT, '10.0.0.1', 40000, 'client')


@unittest.skipUnless(shutil.which('tshark'), 'tshark not installed')
class TestRunFollowRawAgainstTshark(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 't.pcap')
        write_http_pcap(cls.pcap)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def _follow(self, src, sport, dst, dport, direction, max_bytes=10 * 1024 * 1024):
        return stream_payload.run_follow_raw(_run, self.pcap, src, sport, dst, dport,
                                             direction, max_bytes=max_bytes, timeout=30)

    def test_exact_bytes_each_direction(self):
        self.assertEqual(self._follow('10.0.0.1', '40000', '10.0.0.2', '80', 'src'),
                         (HTTP_REQUEST, False))
        # The first response segment is retransmitted in the capture - it
        # must appear once.
        self.assertEqual(self._follow('10.0.0.1', '40000', '10.0.0.2', '80', 'dst'),
                         (HTTP_RESPONSE, False))
        self.assertEqual(self._follow('10.0.0.1', '40000', '10.0.0.2', '80', 'both'),
                         (HTTP_REQUEST + HTTP_RESPONSE, False))

    def test_ipv6(self):
        self.assertEqual(self._follow('2001:db8::2', '8080', '2001:db8::1', '40001', 'src'),
                         (HTTP_RESPONSE, False))

    def test_unknown_flow(self):
        self.assertEqual(self._follow('10.9.9.9', '1', '10.8.8.8', '2', 'both'), (b'', False))

    def test_too_large_is_refused_not_truncated(self):
        self.assertEqual(self._follow('10.0.0.1', '40000', '10.0.0.2', '80', 'dst', max_bytes=100),
                         (b'', True))


if __name__ == '__main__':
    unittest.main(verbosity=2)
