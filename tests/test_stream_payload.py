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

    def test_transcript_each_direction_without_the_retransmission(self):
        """The ASCII transcript: one line per payload packet, directions
        by source address, the retransmitted response segment once."""
        lines = stream_payload.transcript_lines(_run, self.pcap, '10.0.0.1', '40000', '10.0.0.2', '80', 'tcp',
                                                max_bytes=10 * 1024 * 1024, timeout=30)
        sent = ''.join(l['text'] for l in lines if l['direction'] == 'src')
        received = ''.join(l['text'] for l in lines if l['direction'] == 'dst')
        self.assertEqual(sent, HTTP_REQUEST.decode())
        # (the response's body is every byte value - only the printable ones survive)
        self.assertTrue(received.startswith('HTTP/1.1 200 OK\r\n\r\n'))
        self.assertEqual(received.count('HTTP/1.1 200 OK'), 1, 'the retransmitted segment must appear once')
        self.assertIn(' !"#$%&', received)

    def test_transcript_ipv6(self):
        lines = stream_payload.transcript_lines(_run, self.pcap, '2001:db8::1', '40001', '2001:db8::2', '8080', 'tcp',
                                                max_bytes=10 * 1024 * 1024, timeout=30)
        self.assertTrue(''.join(l['text'] for l in lines if l['direction'] == 'dst').startswith('HTTP/1.1 200 OK'))


class TestParseTranscript(unittest.TestCase):
    def test_unprintable_bytes_become_dots_and_whitespace_is_kept(self):
        output = '10.0.0.1\t47:45:54:00:ff:0d:0a\n10.0.0.2\t20\n10.0.0.1\t\n'
        self.assertEqual(stream_payload.parse_transcript(output, '10.0.0.1'),
                         [{'text': 'GET..\r\n', 'direction': 'src'}, {'text': ' ', 'direction': 'dst'}])

    def test_expanded_ipv6_source_matches_tsharks_compressed_form(self):
        lines = stream_payload.parse_transcript('2001:db8::1\t41\n', '2001:0db8:0000:0000:0000:0000:0000:0001')
        self.assertEqual(lines, [{'text': 'A', 'direction': 'src'}])


class TestParseHexdump(unittest.TestCase):
    @staticmethod
    def _output(n):
        return ''.join(f'12:00:0{i} IP 10.0.0.1.80 > 10.0.0.2.443: tcp 4\n\t0x0000:  4500 0028  E..(\n'
                       for i in range(n))

    def test_packets_with_their_hex_lines(self):
        packets, truncated = stream_payload.parse_hexdump(self._output(2), 10, 10000)
        self.assertEqual(packets, [{'header': '12:00:00 IP 10.0.0.1.80 > 10.0.0.2.443: tcp 4', 'lines': ['0x0000:  4500 0028  E..(']},
                                   {'header': '12:00:01 IP 10.0.0.1.80 > 10.0.0.2.443: tcp 4', 'lines': ['0x0000:  4500 0028  E..(']}])
        self.assertFalse(truncated)

    def test_stops_at_the_packet_limit_without_an_empty_extra(self):
        packets, truncated = stream_payload.parse_hexdump(self._output(3), 2, 10000)
        self.assertEqual(len(packets), 2)
        self.assertTrue(all(p['lines'] for p in packets))
        self.assertTrue(truncated)

    def test_stops_at_the_character_limit(self):
        packets, truncated = stream_payload.parse_hexdump(self._output(3), 10, 30)
        self.assertEqual(len(packets), 2)
        self.assertTrue(truncated)


if __name__ == '__main__':
    unittest.main(verbosity=2)
