"""Tests for shark_analyzer.py - tshark's part of a PCAP analysis:
grouping tshark's per-packet fields into Suricata-shaped flows and
records, the merge into events.db, the background queue and the status
API. Tests that need
real tshark output skip when tshark isn't installed."""

import json
import os
import sqlite3
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from contextlib import closing
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

import config
import db
import findings
import shark_analyzer
import socrates as server
import storage
from db import init_empty_db, query_events_sqlite
from samples import build_pcap_sample

HAS_TSHARK = bool(shutil.which('tshark'))


def _line(**fields):
    """One tshark field line (tshark_command's column order)."""
    return '\t'.join(str(fields.get(name.replace('.', '_'), '')) for name in shark_analyzer._FIELDS) + '\n'


def _tcp(t, src, sport, dst, dport, stream, protos='eth:ethertype:ip:tcp', length=60, syn='0', ack='1', cid='1:abc='):
    return _line(frame_time_epoch=t, frame_len=length, frame_protocols=protos, ip_src=src, ip_dst=dst,
                 ip_proto=6, tcp_srcport=sport, tcp_dstport=dport, tcp_stream=stream,
                 tcp_flags_syn=syn, tcp_flags_ack=ack, communityid=cid)


class TestAppProtocol(unittest.TestCase):
    def test_first_layer_above_the_transport(self):
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:tls'), 'tls')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:udp:dns'), 'dns')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:http:data-text-lines'), 'http')

    def test_carrier_layers_are_skipped(self):
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:tpkt:cotp:s7comm'), 's7comm')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:nbss:smb2'), 'smb', "Suricata's name for it")

    def test_bare_transport_and_undecoded_payload_have_none(self):
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp'), '')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:data'), '')

    def test_no_transport_uses_the_top_layer(self):
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:arp'), 'arp')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:icmp'), 'icmp')
        self.assertEqual(shark_analyzer.app_protocol(''), '')


class TestBuildFlows(unittest.TestCase):
    def test_one_flow_per_tcp_stream_counted_per_direction(self):
        lines = [
            _tcp(1.0, '10.0.0.1', 40000, '10.0.0.2', 80, 0, syn='1', ack='0', length=74),
            _tcp(1.1, '10.0.0.2', 80, '10.0.0.1', 40000, 0, syn='1', ack='1', length=74),
            _tcp(1.2, '10.0.0.1', 40000, '10.0.0.2', 80, 0, protos='eth:ethertype:ip:tcp:http', length=200),
            _tcp(1.5, '10.0.0.2', 80, '10.0.0.1', 40000, 0, protos='eth:ethertype:ip:tcp:http', length=900),
        ]
        [flow] = shark_analyzer.build_flows(lines)
        self.assertEqual((flow['src_ip'], flow['src_port'], flow['dest_ip'], flow['dest_port']),
                         ('10.0.0.1', 40000, '10.0.0.2', 80))
        self.assertEqual((flow['proto'], flow['app_proto'], flow['event_type'], flow['ip_v']), ('TCP', 'http', 'flow', 4))
        self.assertEqual(flow['flow']['pkts_toserver'], 2)
        self.assertEqual(flow['flow']['pkts_toclient'], 2)
        self.assertEqual(flow['flow']['bytes_toserver'], 274)
        self.assertEqual(flow['flow']['bytes_toclient'], 974)
        self.assertEqual(flow['flow']['start'], '1970-01-01T00:00:01.000000+0000')
        self.assertEqual(flow['flow']['end'], '1970-01-01T00:00:01.500000+0000')
        self.assertEqual(flow['timestamp'], flow['flow']['start'])
        self.assertEqual(flow['community_id'], '1:abc=')
        self.assertEqual(flow['shark'], {'protocols': {'http': 2}, 'stream': 0, 'answered': 'yes'})

    def test_syn_decides_the_client_when_the_capture_starts_mid_handshake(self):
        """A capture whose first packet is the server's SYN-ACK still names
        the SYN's sender as the client, as Suricata does."""
        lines = [
            _tcp(1.0, '10.0.0.2', 80, '10.0.0.1', 40000, 0, syn='1', ack='1'),
            _tcp(1.1, '10.0.0.1', 40000, '10.0.0.2', 80, 0, syn='1', ack='0'),
            _tcp(1.2, '10.0.0.1', 40000, '10.0.0.2', 80, 0),
        ]
        [flow] = shark_analyzer.build_flows(lines)
        self.assertEqual((flow['src_ip'], flow['dest_port']), ('10.0.0.1', 80))
        self.assertEqual((flow['flow']['pkts_toserver'], flow['flow']['pkts_toclient']), (2, 1))

    def test_without_a_syn_the_first_sender_is_the_client(self):
        lines = [_tcp(1.0, '10.0.0.2', 80, '10.0.0.1', 40000, 0), _tcp(1.1, '10.0.0.1', 40000, '10.0.0.2', 80, 0)]
        [flow] = shark_analyzer.build_flows(lines)
        self.assertEqual(flow['src_ip'], '10.0.0.2')

    def test_flows_are_ordered_by_first_packet(self):
        lines = [_tcp(5.0, '10.0.0.1', 1, '10.0.0.2', 2, 1), _tcp(1.0, '10.0.0.3', 3, '10.0.0.4', 4, 0),
                 _tcp(6.0, '10.0.0.1', 1, '10.0.0.2', 2, 1)]
        self.assertEqual([f['src_ip'] for f in shark_analyzer.build_flows(lines)], ['10.0.0.3', '10.0.0.1'])

    def test_udp_flow(self):
        lines = [
            _line(frame_time_epoch=1, frame_len=80, frame_protocols='eth:ethertype:ip:udp:dns', ip_src='10.0.0.1',
                  ip_dst='10.0.0.53', ip_proto=17, udp_srcport=5000, udp_dstport=53, udp_stream=0),
            _line(frame_time_epoch=2, frame_len=120, frame_protocols='eth:ethertype:ip:udp:dns', ip_src='10.0.0.53',
                  ip_dst='10.0.0.1', ip_proto=17, udp_srcport=53, udp_dstport=5000, udp_stream=0),
        ]
        [flow] = shark_analyzer.build_flows(lines)
        self.assertEqual((flow['proto'], flow['app_proto'], flow['src_port'], flow['dest_port']), ('UDP', 'dns', 5000, 53))
        self.assertEqual(flow['shark']['protocols'], {'dns': 2})

    def test_icmp_flows_have_no_ports_and_pair_both_directions(self):
        lines = [
            _line(frame_time_epoch=1, frame_len=98, frame_protocols='eth:ethertype:ip:icmp:data', ip_src='10.0.0.1',
                  ip_dst='10.0.0.2', ip_proto=1),
            _line(frame_time_epoch=2, frame_len=98, frame_protocols='eth:ethertype:ip:icmp:data', ip_src='10.0.0.2',
                  ip_dst='10.0.0.1', ip_proto=1),
        ]
        [flow] = shark_analyzer.build_flows(lines)
        self.assertEqual((flow['proto'], flow['app_proto']), ('ICMP', 'icmp'))
        self.assertNotIn('src_port', flow)
        self.assertNotIn('stream', flow['shark'])
        self.assertEqual((flow['flow']['pkts_toserver'], flow['flow']['pkts_toclient']), (1, 1))

    def test_ipv6_flow(self):
        line = _line(frame_time_epoch=1, frame_len=90, frame_protocols='eth:ethertype:ipv6:tcp:http',
                     ipv6_src='2001:db8::1', ipv6_dst='2001:db8::2', ipv6_nxt=6, tcp_srcport=40001,
                     tcp_dstport=8080, tcp_stream=0)
        [flow] = shark_analyzer.build_flows([line])
        self.assertEqual((flow['src_ip'], flow['ip_v'], flow['proto']),
                         ('2001:0db8:0000:0000:0000:0000:0000:0001', 6, 'TCP'), 'written out in full, like Suricata')

    def test_non_ip_traffic_is_grouped_by_mac_addresses_and_protocol(self):
        arp = dict(frame_len=42, frame_protocols='eth:ethertype:arp', eth_src='00:00:00:00:00:01', eth_dst='ff:ff:ff:ff:ff:ff')
        [flow] = shark_analyzer.build_flows([_line(frame_time_epoch=1, **arp), _line(frame_time_epoch=2, **arp)])
        self.assertEqual((flow['proto'], flow['app_proto'], flow['src_ip']), ('ARP', 'arp', '00:00:00:00:00:01'))
        self.assertNotIn('ip_v', flow)
        self.assertEqual(flow['flow']['pkts_toserver'], 2)

    def test_malformed_lines_are_skipped(self):
        good = _tcp(1.0, '10.0.0.1', 1, '10.0.0.2', 2, 0)
        self.assertEqual(len(shark_analyzer.build_flows(['', 'garbage\n', 'x\t' * 30 + '\n', good])), 1)

    def test_protocols_count_every_layer_seen_most_first(self):
        lines = [_tcp(1.0, '10.0.0.1', 1, '10.0.0.2', 21, 0, protos='eth:ethertype:ip:tcp:ftp')] + \
                [_tcp(2.0 + i, '10.0.0.1', 1, '10.0.0.2', 21, 0, protos='eth:ethertype:ip:tcp:tls') for i in range(3)]
        [flow] = shark_analyzer.build_flows(lines)
        self.assertEqual(flow['app_proto'], 'ftp', "the flow's first application protocol names it")
        self.assertEqual(list(flow['shark']['protocols'].items()), [('tls', 3), ('ftp', 1)])


class TestTsharkCommand(unittest.TestCase):
    def test_plain_fields_with_community_id(self):
        cmd = shark_analyzer.tshark_command('/x.pcap')
        self.assertEqual(cmd[:4], ['tshark', '-n', '-r', '/x.pcap'])
        self.assertIn('--enable-protocol', cmd)
        self.assertEqual(cmd[cmd.index('--enable-protocol') + 1], 'communityid')
        self.assertEqual(cmd[cmd.index('-T') + 1], 'fields')
        self.assertEqual([cmd[i + 1] for i, a in enumerate(cmd) if a == '-e'], list(shark_analyzer._FIRST_PASS_FIELDS))

    def test_shark_artifacts_are_removed_on_reanalyze(self):
        for name in shark_analyzer.SHARK_ARTIFACTS:
            self.assertIn(name, storage.PCAP_ANALYSIS_ARTIFACTS)


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestAgainstSuricata(unittest.TestCase):
    """The built-in Sample PCAP file's flows, with the values Suricata
    8.0.6 itself logged for the same capture (its eve.json flow events) -
    every field the two views share agrees."""

    SURICATA_FLOWS = {
        '1:EpYHmrPJXlZhxCKCpAtvF5gS/54=': ('10.20.4.12', 51733, '203.0.113.66', 80, 'http', 6, 4, 490, 1034),
        '1:2NztZopomhYFALQ23BcQ7v3z3E8=': ('10.20.4.12', 51791, '203.0.113.66', 50000, 'ftp-data', 5, 3, 667, 162),
    }

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'sample.pcap')
        with open(cls.pcap, 'wb') as f:
            f.write(build_pcap_sample())
        cls.flows = {f['community_id']: f for f in shark_analyzer.run_tshark(cls.pcap) if f['event_type'] == 'flow'}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_suricata_parsed_flows_match(self):
        """The three flows Suricata also parses - HTTP and the FTP control
        and data connections - carry Suricata's own community IDs. (The
        capture also opens with LLMNR/NBNS/SSDP chatter flows, which Suricata
        doesn't parse - those are the tshark view's to add, not matched here.)"""
        parsed = sorted(f['app_proto'] for f in self.flows.values()
                        if f['app_proto'] in ('ftp', 'ftp-data', 'http'))
        self.assertEqual(parsed, ['ftp', 'ftp-data', 'http'])
        for cid in self.SURICATA_FLOWS:
            self.assertIn(cid, self.flows, 'Community IDs must match Suricata\'s')

    def test_every_shared_field_matches_suricata(self):
        for cid, expected in self.SURICATA_FLOWS.items():
            f = self.flows[cid]
            got = (f['src_ip'], f['src_port'], f['dest_ip'], f['dest_port'], f['app_proto'],
                   f['flow']['pkts_toserver'], f['flow']['pkts_toclient'],
                   f['flow']['bytes_toserver'], f['flow']['bytes_toclient'])
            self.assertEqual(got, expected, cid)


class TestFieldParsing(unittest.TestCase):
    def test_unescape_undoes_tsharks_escapes(self):
        self.assertEqual(shark_analyzer._unescape(r'v=spf1 a\tb\\c'), 'v=spf1 a\tb\\c')
        self.assertEqual(shark_analyzer._unescape(r'line\nnext\r'), 'line\nnext\r')
        self.assertEqual(shark_analyzer._unescape(r'\x41\x1f'), 'A\x1f')
        self.assertEqual(shark_analyzer._unescape('plain'), 'plain')

    def test_ipv6_is_written_out_in_full_like_suricata(self):
        self.assertEqual(shark_analyzer.ipv6_exploded('2001:db8::7'), '2001:0db8:0000:0000:0000:0000:0000:0007')
        self.assertEqual(shark_analyzer.ipv6_exploded('not an address'), 'not an address')

    def test_app_proto_uses_suricatas_names(self):
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:mbtcp:modbus'), 'modbus')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:nbss:smb2'), 'smb')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:udp:kerberos'), 'krb5')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:udp:cldap'), 'ldap')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:udp:rtp:dtls'), 'dtls', 'WebRTC: RTP demultiplexing DTLS')

    def test_rpc_is_the_protocol_only_when_nothing_follows_it(self):
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:rpc:nfs'), 'nfs')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:udp:rpc:portmap'), 'portmap')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:rpc'), 'rpc')

    def test_the_osi_layers_carry_mms(self):
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:tpkt:cotp:ses:pres:mms'), 'mms')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:tpkt:cotp:ses:pres:acse:mms'), 'mms')
        self.assertEqual(shark_analyzer.app_protocol('eth:ethertype:ip:tcp:tpkt:cotp:ses'), 'ses')

    def test_command_outputs_every_occurrence_joined_by_the_aggregator(self):
        cmd = shark_analyzer.tshark_command('/x.pcap')
        self.assertIn('occurrence=a', cmd)
        self.assertIn('aggregator=\x1f', cmd)
        fields = [cmd[i + 1] for i, a in enumerate(cmd) if a == '-e']
        self.assertEqual(fields[:len(shark_analyzer._FIELDS)], list(shark_analyzer._FIELDS))
        self.assertIn('tls.handshake.type', fields, 'flow orientation reads it, though no records here do')
        self.assertNotIn('dns.response_to', fields, "a protocol's fields are the protocol pass's")
        from shark_protocols import PROTOCOLS
        cmd = shark_analyzer.tshark_command('/x.pcap', shark_analyzer._protocol_pass_fields(PROTOCOLS))
        fields = [cmd[i + 1] for i, a in enumerate(cmd) if a == '-e']
        self.assertEqual(fields[:len(shark_analyzer._FIELDS)], list(shark_analyzer._FIELDS))
        self.assertIn('dns.response_to', fields)


def _load_eve(name):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', name)
    with open(path) as f:
        return [json.loads(line) for line in f]


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestFlowsAgainstSuricata(unittest.TestCase):
    """tests/protocol_fixtures.py's capture (DNS, HTTP, TLS, Modbus, FTP):
    tshark's flows compared with what Suricata 8.0.6 logged for the same
    packets (tests/data/protocol_fixture.eve.json - regenerate it with
    Suricata if the fixture ever changes). Suricata's own records for
    these protocols are the analysis's; tshark adds none of them."""

    @classmethod
    def setUpClass(cls):
        from scripts.compare_shark_suricata import compare
        from tests.protocol_fixtures import write_protocol_pcap
        cls.tmpdir = tempfile.mkdtemp()
        pcap = os.path.join(cls.tmpdir, 'protocols.pcap')
        write_protocol_pcap(pcap)
        cls.records = shark_analyzer.run_tshark(pcap)
        cls.report = compare(_load_eve('protocol_fixture.eve.json'), cls.records)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_every_flow_matches_suricata(self):
        self.assertEqual(self.report['flow']['differences'], [])
        self.assertEqual(self.report['flow']['matched'], 13)

    def test_no_records_for_protocols_suricata_parses(self):
        self.assertEqual({r['event_type'] for r in self.records}, {'flow'})

@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestExtraCaptureAgainstSuricata(unittest.TestCase):
    """tests/protocol_fixtures.write_extra_pcap: the protocols tshark adds
    (NBNS, LLMNR, SSDP, S7comm), and the flow cases real captures turned
    up - checked against what Suricata 8.0.6 logged for the same packets
    (tests/data/extra_fixture.eve.json)."""

    @classmethod
    def setUpClass(cls):
        from scripts.compare_shark_suricata import compare
        from tests.protocol_fixtures import write_extra_pcap
        cls.tmpdir = tempfile.mkdtemp()
        pcap = os.path.join(cls.tmpdir, 'extra.pcap')
        write_extra_pcap(pcap)
        cls.records = shark_analyzer.run_tshark(pcap)
        cls.report = compare(_load_eve('extra_fixture.eve.json'), cls.records)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def _of(self, event_type):
        return [r[event_type] for r in self.records if r['event_type'] == event_type]

    def test_flows_match_suricata_except_for_protocols_it_cannot_name(self):
        """Every flow's counts and times match - including the one an ICMP
        error belongs to - and the only differences are app_proto on flows
        of protocols Suricata doesn't parse (it even calls SSDP 'sip')."""
        diffs = self.report['flow']['differences']
        self.assertTrue(diffs)
        for d in diffs:
            self.assertEqual(set(d['fields']), {'app_proto'}, d)
            self.assertIn(d['fields']['app_proto'][0], (None, 'sip'))
            self.assertIn(d['fields']['app_proto'][1], ('llmnr', 'nbns', 'ssdp', 's7comm', 'dns'))
        self.assertEqual(self.report['flow']['reoriented'], 4,
                         'the flow caught mid-conversation, and the LLMNR, NBNS and SSDP answers on flows of their own')

    def _flow(self, port):
        [flow] = [r for r in self.records if r['event_type'] == 'flow' and port in (r.get('src_port'), r.get('dest_port'))]
        return flow

    def test_a_flow_caught_mid_conversation_is_addressed_from_whoever_asked(self):
        """REGRESSION (4SICS GeekLounge): the capture opened on a DNS server's
        answer, so the server was taken for the client of the flow."""
        flow = self._flow(949)
        self.assertEqual((flow['src_ip'], flow['src_port'], flow['dest_ip'], flow['dest_port']),
                         ('10.1.0.10', 949, '10.1.0.53', 53))
        self.assertEqual((flow['flow']['pkts_toserver'], flow['flow']['pkts_toclient']), (1, 2))

    def test_an_answer_on_a_flow_of_its_own_is_addressed_from_the_asker(self):
        """A multicast or broadcast question's unicast answer is a flow of
        one packet - from the answerer, but to the client that asked."""
        [flow] = [r for r in self.records if r['event_type'] == 'flow' and '10.1.0.70' in (r['src_ip'], r['dest_ip'])]
        self.assertEqual((flow['src_ip'], flow['dest_ip'], flow['dest_port']), ('10.1.0.10', '10.1.0.70', 5355))
        self.assertEqual((flow['flow']['pkts_toserver'], flow['flow']['pkts_toclient']), (0, 1))

    def test_an_announcement_to_a_group_keeps_its_sender_as_the_client(self):
        """An mDNS response to the multicast group answers nobody - the
        group can't be a client."""
        [flow] = [r for r in self.records if r['event_type'] == 'flow' and r['src_ip'] == '10.1.0.60' and r.get('src_port') == 5353]
        self.assertEqual(flow['dest_ip'], '224.0.0.251')

    def test_icmp_error_counts_in_its_flow_in_its_own_direction(self):
        """REGRESSION: the client's port unreachable carries a copy of the
        server's response - it was counted server-to-client, and its copy
        parsed as another DNS response."""
        [flow] = [r for r in self.records if r['event_type'] == 'flow' and r.get('src_port') == 53011]
        self.assertEqual((flow['flow']['pkts_toserver'], flow['flow']['pkts_toclient']), (2, 3))

    def test_llmnr_and_only_the_protocols_suricata_lacks(self):
        """tshark decodes LLMNR (and mDNS) with its DNS dissector, and SSDP
        with its HTTP one: only LLMNR, NBNS, SSDP and S7comm become records."""
        self.assertEqual({r['event_type'] for r in self.records} - {'flow'}, {'llmnr', 'nbns', 'ssdp', 's7comm'})
        [llmnr] = self._of('llmnr')
        self.assertEqual((llmnr['type'], llmnr['answers'][0]['rdata']), ('response', '10.1.0.70'),
                         "a multicast query and its unicast answer, paired")
        self.assertEqual(llmnr['queries'], [{'rrname': 'wpad', 'rrtype': 'A'}])

    def test_ssdp(self):
        search, answer, notify = self._of('ssdp')
        self.assertEqual((search['method'], search['search_target']),
                         ('M-SEARCH', 'urn:schemas-upnp-org:device:InternetGatewayDevice:1'))
        self.assertEqual((answer['status'], answer['location'], answer['server']),
                         (200, 'http://10.1.0.60:49152/gateway.xml', 'Linux/5.4 UPnP/1.0 TestGateway/1.0'))
        self.assertEqual((notify['method'], notify['notification_type'], notify['notification_sub_type'], notify['usn']),
                         ('NOTIFY', 'upnp:rootdevice', 'ssdp:alive', 'uuid:0b1d-test::upnp:rootdevice'))

    def test_nbns(self):
        registration, query = self._of('nbns')
        self.assertEqual({k: registration[k] for k in ('opcode', 'name', 'suffix', 'service', 'address', 'transmissions')},
                         {'opcode': 'registration', 'name': 'DESKTOP-TEST01', 'suffix': '20', 'service': 'Server service',
                          'address': '10.1.0.10', 'transmissions': 3}, 'three broadcasts, one record')
        self.assertEqual((query['opcode'], query['name'], query['type'], query['address']),
                         ('query', 'FILESERVER', 'response', '10.1.0.30'), 'the broadcast query and its direct answer, paired')

    def test_s7comm(self):
        setup, read, write, userdata = self._of('s7comm')
        self.assertEqual((setup['function'], setup['response']['function']), ('Setup communication', 'Setup communication'))
        self.assertEqual(read['items'], [{'area': 'Data blocks', 'db': 1, 'address': '10.0'}])
        self.assertEqual(write['response']['error_class'], 'Error on supplies')
        self.assertEqual((userdata['type'], userdata['function_group'], userdata['subfunction']), ('userdata', 'CPU functions', 1))

@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestTelnet(unittest.TestCase):
    """tests/protocol_fixtures.write_telnet_pcap: a login, a failed login and
    a scanner's HTTP request to the Telnet port - with what Suricata 8.0.7
    logged for them (tests/data/telnet_fixture.eve.json): a 'telnet' label
    and nothing else for the two sessions, HTTP for the probe."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_telnet_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'telnet.pcap')
        write_telnet_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.by_port = {r['src_port']: r['telnet'] for r in cls.records if r['event_type'] == 'telnet'}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_a_login_rebuilt_from_its_keystrokes(self):
        """Each key its own segment, the server's echo ignored, a
        backspace applied, an arrow key no command."""
        self.assertEqual(self.by_port[41023], {'banner': 'Ubuntu 22.04.3 LTS', 'username': 'admin', 'password': 's3cret',
                                               'commands': ['ls -la', 'exit']})

    def test_a_failed_login(self):
        self.assertEqual(self.by_port[41024], {'banner': 'MOXA EtherDevice Switch EDS-508A', 'username': 'admin',
                                               'password': 'admin', 'login': 'failed'})

    def test_flows_match_suricata(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('telnet_fixture.eve.json'), self.records)['flow']
        self.assertEqual(report['matched'], 2)
        self.assertEqual([d['fields'] for d in report['differences']], [{'app_proto': ('http', 'telnet')}],
                         'only the probe: HTTP by its content to Suricata, Telnet by its port to tshark')

    def test_the_merge_adds_the_sessions_suricata_only_labelled(self):
        """Suricata recognizes Telnet but logs nothing about it: a 'telnet'
        label alone keeps nothing out. The probe it logged as HTTP stays
        Suricata's."""
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'telnet_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'telnet.pcap')))
        shark_analyzer.merge(d)
        merged = db.query_events_sqlite(events_db, 'telnet')
        self.assertEqual(sorted(e['src_port'] for e in merged), [41023, 41024])
        self.assertNotIn('conn_telnet', db.get_event_types_sqlite(events_db))


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestIEC104(unittest.TestCase):
    """tests/protocol_fixtures.write_iec104_pcap: control actions paired with
    their replies, and monitored points summarized - with what Suricata
    8.0.7 logged for the capture (tests/data/iec104_fixture.eve.json): a
    flow it gives no protocol, since it doesn't parse IEC 104."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_iec104_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'iec104.pcap')
        write_iec104_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.actions = [r['iec104'] for r in cls.records if r['event_type'] == 'iec104']
        cls.points = {p['ioa']: p for p in (r['iec104_point'] for r in cls.records if r['event_type'] == 'iec104_point')}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_control_actions_with_their_replies(self):
        self.assertEqual([(a['action'], a.get('value'), a['result']) for a in self.actions], [
            ('Interrogation', 'station', 'confirmed, terminated'),
            ('Single command', 'on', 'confirmed, terminated'),
            ('Set point (float)', 3.25, 'negative'),
            ('Interrogation', 'station', 'confirmed, terminated'),
            ('Interrogation', 'station', 'confirmed, terminated'),
            ('Clock synchronization', None, 'confirmed (request not seen)'),
        ], 'two interrogations sent before either was answered each get their own replies, in order')
        command = self.actions[1]
        self.assertEqual((command['type'], command['station'], command['ioa'], command['response']),
                         ('C_SC_NA_1', 7, 2001, {'cause': 'actcon', 'negative': False}))

    def test_points_summarize_their_updates(self):
        """Including a packet that carries two messages, split by their
        object counts."""
        self.assertEqual(sorted(self.points), [1001, 1002, 1003])
        p = self.points[1001]
        self.assertEqual((p['type'], p['updates'], p['causes'], p['last_value']),
                         ('M_ME_NC_1', 2, {'inrogen': 1, 'spont': 1}, 231.0))
        self.assertEqual((self.points[1003]['type'], self.points[1003]['last_value']), ('M_SP_NA_1', 1))

    def test_the_flow_matches_suricatas_and_the_merge_adds_both_kinds(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('iec104_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['named_by_tshark'], report['differences']), (1, 1, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'iec104_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'iec104.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual((counts.get('iec104'), counts.get('iec104_point')), (6, 3))
        self.assertNotIn('conn_iec60870_104', counts, 'records, not a connection card')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestBACnet(unittest.TestCase):
    """tests/protocol_fixtures.write_bacnet_pcap: actions paired with their
    replies, reads and value notifications summarized per object and
    property, devices from their I-Ams - with what Suricata 8.0.7 logged
    for the capture (tests/data/bacnet_fixture.eve.json): flows it gives
    no protocol, since it doesn't parse BACnet."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_bacnet_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'bacnet.pcap')
        write_bacnet_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.actions = [r['bacnet'] for r in cls.records if r['event_type'] == 'bacnet']
        cls.properties = {p['object']: p for p in (r['bacnet_property'] for r in cls.records
                                                   if r['event_type'] == 'bacnet_property')}
        cls.devices = [r['bacnet_device'] for r in cls.records if r['event_type'] == 'bacnet_device']

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_actions_with_their_replies(self):
        self.assertEqual([(a['service'], a.get('object'), a.get('value'), a.get('result')) for a in self.actions], [
            ('who-Is', None, None, None),
            ('who-Is', None, None, None),
            ('writeProperty', 'binary-output,3', 'active', 'ok'),
            ('writeProperty', 'analog-value,2', 50.0, 'ok'),
            ('reinitializeDevice', None, None, 'error: services: password-failure'),
            ('deviceCommunicationControl', None, None, 'ok'),
        ], 'a write and a read sent with the same invoke id each get their own reply, though they came in the other order')
        self.assertEqual(self.actions[1]['range'], '100-200')

    def test_the_same_discovery_question_is_one_record_counted(self):
        from tests.protocol_fixtures import bacnet_packets, _bacnet_ip, _BACNET_BROADCAST, CLIENT
        from tests.pcap_fixtures import write_pcap
        who_is = _bacnet_ip(CLIENT, _BACNET_BROADCAST, b'\x10\x08', broadcast=True)
        path = os.path.join(self.tmpdir, 'who_is.pcap')
        write_pcap(path, bacnet_packets() + [who_is] * 3)
        asked = [r['bacnet'] for r in shark_analyzer.run_tshark(path)
                 if r['event_type'] == 'bacnet' and r['bacnet']['service'] == 'who-Is']
        self.assertEqual([(a.get('range'), a['count']) for a in asked], [(None, 4), ('100-200', 1)])
        self.assertEqual(asked[0]['last_seen'][:19], '2023-11-14T22:13:41')

    def test_passwords_and_states_come_from_the_requests_bytes(self):
        """tshark shows them only as text."""
        reinit, control = self.actions[4], self.actions[5]
        self.assertEqual((reinit['state'], reinit['password']), ('warmstart', 'filister'))
        self.assertEqual((control['state'], control['duration'], control['password']), ('disable', 5, 'secret'))

    def test_reads_and_notifications_are_summarized(self):
        read = self.properties['analog-value,1']
        self.assertEqual((read['service'], read['property'], read['count'], read['errors'], read['last_value'],
                          read['last_error']),
                         ('readProperty', 'present-value', 2, 1, 72.5, 'error: property: unknown-property'))
        self.assertEqual(self.properties['analog-value,2']['last_value'], 49.0)
        cov = self.properties['analog-input,2']
        self.assertEqual((cov['service'], cov['device'], cov['last_value']),
                         ('unconfirmedCOVNotification', 'device,1047', 21.5))

    def test_devices_from_their_i_ams_with_tsharks_vendor_name(self):
        self.assertEqual([(d['device'], d['vendor_id'], d['vendor'], d['announcements']) for d in self.devices],
                         [(1047, 42, 'Acuity Brands Lighting, Inc.', 2)])

    def test_flows_match_suricatas_and_the_merge_adds_the_records(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('bacnet_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['named_by_tshark'], report['differences']), (3, 3, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'bacnet_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'bacnet.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual((counts.get('bacnet'), counts.get('bacnet_property'), counts.get('bacnet_device')), (6, 3, 1))
        self.assertNotIn('conn_bvlc', counts, 'records, not a connection card')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestOPCUA(unittest.TestCase):
    """tests/protocol_fixtures.write_opcua_pcap, read by the structured
    pass: the connection's session, and its changes with their own
    statuses - with what Suricata 8.0.7 logged for the capture
    (tests/data/opcua_fixture.eve.json): a flow it gives no protocol,
    since it doesn't parse OPC UA."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_opcua_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'opcua.pcap')
        write_opcua_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.sessions = [r['opcua'] for r in cls.records if r['event_type'] == 'opcua']
        cls.actions = [r['opcua_action'] for r in cls.records if r['event_type'] == 'opcua_action']

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_the_session(self):
        self.assertEqual(len(self.sessions), 1)
        s = self.sessions[0]
        self.assertEqual({k: s.get(k) for k in ('endpoint', 'security_policy', 'security_mode', 'client_application',
                                                'session_name', 'user_token', 'username', 'activation')},
                         {'endpoint': 'opc.tcp://10.1.0.48:4840/fixture', 'security_policy': 'None', 'security_mode': 'None',
                          'client_application': 'Fixture Client', 'session_name': 'Fixture Session',
                          'user_token': 'username', 'username': 'user1', 'activation': 'Good'})
        self.assertEqual(s['password'], 's3cret', 'a UserName token with no encryption algorithm carries it in the clear')
        self.assertEqual((s['services']['Read'], s['services']['Publish'], s['errors'], s['last_error']),
                         (1, 1, 1, 'Publish: BadNoSubscription'))

    def test_changes_with_their_own_statuses(self):
        self.assertEqual(self.actions, [
            {'service': 'Write', 'node': 'ns=1;s=the.answer', 'attribute': 'Value', 'value': '42', 'result': 'Good'},
            {'service': 'Call', 'node': 'ns=1;i=62541', 'object': 'i=85', 'arguments': ['Hello'],
             'result': 'BadNodeIdUnknown'},
        ], 'the call was refused for its one operation though the response itself was Good')

    def test_status_names_are_tsharks(self):
        from shark_protocols import _opcua_status
        self.assertEqual([_opcua_status(c) for c in ('0x00000000', '0x80340000', '0x801f0000', '0x80ff0000')],
                         ['Good', 'BadNodeIdUnknown', 'BadUserAccessDenied', '0x80ff0000'])

    def test_the_flow_matches_suricatas_and_the_merge_adds_the_records(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('opcua_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['named_by_tshark'], report['differences']), (1, 1, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'opcua_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'opcua.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual((counts.get('opcua'), counts.get('opcua_action')), (1, 2))
        self.assertNotIn('conn_opcua', counts, 'records, not a connection card')

    def test_a_loopback_capture_is_decoded_too(self):
        """The structured pass decodes only the link layers it enables;
        OPC UA test servers are often captured on loopback."""
        from tests.protocol_fixtures import opcua_packets
        path = os.path.join(self.tmpdir, 'loopback.pcap')
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 0))          # DLT_NULL
            for i, p in enumerate(opcua_packets()):
                p = struct.pack('<I', 2) + p[14:]                                      # AF_INET, not Ethernet
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)
        records = shark_analyzer.run_tshark(path)
        self.assertEqual(sum(r['event_type'] == 'opcua_action' for r in records), 2)


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestGOOSE(unittest.TestCase):
    """tests/protocol_fixtures.write_goose_pcap: one record per state
    change, repeats counted, with what Suricata 8.0.7 logged for the
    capture (tests/data/goose_fixture.eve.json) - only 'Ethertype unknown'
    decoder alerts, since it doesn't decode GOOSE."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_goose_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'goose.pcap')
        write_goose_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.states = [r['goose'] for r in cls.records if r['event_type'] == 'goose']

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_one_record_per_state_change(self):
        self.assertEqual([(s['stnum'], s['repeats'], s['values']) for s in self.states],
                         [(1, 2, [False, '40', 7]), (2, 0, [True, '40', 7]), (10, 0, [True, '40', 7]),
                          (1, 0, [False, '40', 7])])
        self.assertEqual((self.states[0]['gocb_ref'], self.states[0]['dataset'], self.states[0]['go_id']),
                         ('IED1LD0/LLN0$GO$gcb1', 'IED1LD0/LLN0$Trips', 'Trips'))
        self.assertEqual(self.states[1]['changed'], [0], 'the trip value turned true')

    def test_a_jump_or_reset_in_stnum_is_marked(self):
        self.assertNotIn('anomaly', self.states[1])
        self.assertEqual((self.states[2]['stnum_gap'], self.states[2]['anomaly']), (7, 'stNum skipped 7'))
        self.assertEqual((self.states[3]['stnum_reset_from'], self.states[3]['anomaly']), (10, 'stNum reset from 10'))

    def test_the_merge_adds_the_records(self):
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'goose_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'goose.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual(counts.get('goose'), 4)
        self.assertNotIn('conn_goose', counts, 'records, not a connection card')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestRPC(unittest.TestCase):
    """tests/protocol_fixtures.write_rpc_pcap: one record per RPC call and
    its reply - with what Suricata 8.0.7 logged for the capture
    (tests/data/rpc_fixture.eve.json): flows it gives no protocol (it
    parses NFS, not the portmapper or mountd), and a portmap-listing
    alert on the scanner's DUMP."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_rpc_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'rpc.pcap')
        write_rpc_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.calls = {r['rpc']['xid']: r['rpc'] for r in cls.records if r['event_type'] == 'rpc'}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_the_portmappers_dump_is_an_inventory(self):
        dump = self.calls['0x00000001']
        self.assertEqual((dump['program'], dump['version'], dump['procedure'], dump['reply']),
                         ('portmapper', 2, 'DUMP', 'RPC executed successfully'))
        self.assertEqual(dump['mappings'], [{'program': 'portmapper', 'version': 2, 'transport': 'udp', 'port': 111},
                                            {'program': 'mountd', 'version': 3, 'transport': 'udp', 'port': 20048},
                                            {'program': 'nfs', 'version': 3, 'transport': 'tcp', 'port': 2049}])

    def test_getport_found_and_not(self):
        found, missing = self.calls['0x00000002'], self.calls['0x00000006']
        self.assertEqual((found['query'], found['port']), ({'program': 'mountd', 'version': 3, 'transport': 'udp'}, 20048))
        self.assertEqual((missing['query']['program'], missing['reply']), ('100099', 'not registered'))

    def test_mountd_who_mounted_what_and_what_it_exports(self):
        mnt, export = self.calls['0x00000003'], self.calls['0x00000004']
        self.assertEqual({k: mnt[k] for k in ('program', 'procedure', 'path', 'auth', 'machine_name', 'uid', 'gid',
                                              'mount_status')},
                         {'program': 'mountd', 'procedure': 'MNT', 'path': '/export/home', 'auth': 'AUTH_UNIX',
                          'machine_name': 'client1', 'uid': 1000, 'gid': 1000, 'mount_status': 'OK'})
        self.assertEqual((export['exports'], export['export_clients']), (['/export/home'], ['10.1.0.0/24']),
                         "its own flow, though tshark gives every client of mountd's port one UDP stream")

    def test_a_scanners_unanswered_dump(self):
        scan = self.calls['0x00000005']
        self.assertEqual((scan['procedure'], scan['calls']), ('DUMP', 1))
        self.assertNotIn('reply', scan)

    def test_flows_match_suricatas_and_the_merge_adds_the_records(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('rpc_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['named_by_tshark'], report['differences']), (6, 6, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'rpc_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'rpc.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual(counts.get('rpc'), 6)
        self.assertFalse([t for t in counts if t.startswith('conn_')], 'records, not connection cards')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestCoAP(unittest.TestCase):
    """tests/protocol_fixtures.write_coap_pcap: one record per request and
    its response - with what Suricata 8.0.7 logged for the capture
    (tests/data/coap_fixture.eve.json): flows it gives no protocol."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_coap_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'coap.pcap')
        write_coap_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.coap = [r['coap'] for r in cls.records if r['event_type'] == 'coap']

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_discovery_lists_the_devices_resources(self):
        self.assertEqual(self.coap[0], {'method': 'GET', 'type': 'Confirmable', 'uri': '/.well-known/core',
                                        'accept': 'application/link-format', 'responses': 1,
                                        'response_code': '2.05 Content', 'response_time': 1.0,
                                        'response_content_format': 'application/link-format', 'response_length': 86,
                                        'resources': ['/sensors/temp', '/sensors/light', '/config']})

    def test_a_read_sent_twice_a_refused_put_and_a_separate_404(self):
        read, put, missing = self.coap[1:4]
        self.assertEqual({k: read[k] for k in ('uri', 'query', 'retransmissions', 'response_code', 'response_time',
                                                'response_content_format')},
                         {'uri': '/sensors/temp', 'query': 'unit=c', 'retransmissions': 1,
                          'response_code': '2.05 Content', 'response_time': 2.0,
                          'response_content_format': 'application/json'})
        self.assertEqual({k: put[k] for k in ('method', 'request_content_format', 'request_length', 'response_code')},
                         {'method': 'PUT', 'request_content_format': 'application/cbor', 'request_length': 3,
                          'response_code': '4.01 Unauthorized'})
        self.assertEqual((missing['type'], missing['response_code']), ('Non-Confirmable', '4.04 Not Found'),
                         'matched by its token, its own message ID being different')

    def test_a_ping_and_a_scanners_unanswered_discovery(self):
        ping, scan = self.coap[4:]
        self.assertEqual((ping['method'], ping['response_code']), ('ping', 'reset'))
        self.assertEqual(scan, {'method': 'GET', 'type': 'Confirmable', 'uri': '/.well-known/core'})

    def test_a_payload_past_extended_options(self):
        from shark_protocols import _coap_payload
        message = bytes([0x41, 1, 0, 1, 0xaa]) + bytes([0xbd, 7]) + b'x' * 20 + bytes([0x0e, 0, 1]) + b'y' * 270
        self.assertEqual(_coap_payload(message + b'\xffBODY'), b'BODY')
        self.assertEqual(_coap_payload(message[:12]), b'', 'cut short')

    def test_flows_match_suricatas_and_the_merge_adds_the_records(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('coap_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['named_by_tshark'], report['differences']), (2, 2, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'coap_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'coap.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual(counts.get('coap'), 6)
        self.assertFalse([t for t in counts if t.startswith('conn_')], 'records, not connection cards')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestXDMCP(unittest.TestCase):
    """tests/protocol_fixtures.write_xdmcp_pcap: one record per client and
    login manager - with what Suricata 8.0.7 logged for the capture
    (tests/data/xdmcp_fixture.eve.json): flows it gives no protocol, and
    an alert on the scanner's query, which doesn't make it Suricata's."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_xdmcp_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'xdmcp.pcap')
        write_xdmcp_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.xdmcp = {r['src_port']: r['xdmcp'] for r in cls.records if r['event_type'] == 'xdmcp'}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_a_display_given_a_login_screen(self):
        self.assertEqual(self.xdmcp[40177], {
            'version': 1, 'messages': ['Query', 'Willing', 'Request', 'Accept', 'Manage'],
            'server_host_name': 'labsrv', 'server_status': 'Linux 5.15.0-91-generic, load: 0.08',
            'authorization_names': ['MIT-MAGIC-COOKIE-1'], 'display_number': 0, 'display_addresses': ['10.1.0.40'],
            'manufacturer_display_id': 'Linux 1', 'display_class': 'MIT-unspecified', 'result': 'managed'})

    def test_the_authorization_cookie_is_never_kept(self):
        from tests.protocol_fixtures import XDMCP_COOKIE
        text = json.dumps([r for r in self.records if r['event_type'] == 'xdmcp'])
        self.assertNotIn(XDMCP_COOKIE.hex(), text)
        self.assertNotIn(XDMCP_COOKIE.hex(':'), text)

    def test_a_broadcast_answered_by_two_servers(self):
        broadcast = self.xdmcp[40178]
        self.assertEqual((broadcast['responders'], broadcast['result']), (['10.1.0.62', '10.1.0.63'], 'willing'))
        self.assertEqual(broadcast['answers'], ['10.1.0.62 willing: labsrv (Linux 5.15.0-91-generic, load: 0.08)',
                                                '10.1.0.63 unwilling: busybox (Too many sessions)'])

    def test_a_scanner_nobody_answered_and_a_declined_request(self):
        self.assertEqual(self.xdmcp[41000], {'version': 1, 'messages': ['Query'], 'result': 'no answer'})
        declined = self.xdmcp[41001]
        self.assertEqual({k: declined[k] for k in ('authentication_names', 'status', 'result')},
                         {'authentication_names': ['XDM-AUTHENTICATION-1'], 'status': 'Authentication failed',
                          'result': 'declined'})

    def test_flows_match_suricatas_and_the_merge_adds_the_records(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('xdmcp_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['differences']), (6, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'xdmcp_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'xdmcp.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual(counts.get('xdmcp'), 4)
        self.assertFalse([t for t in counts if t.startswith('conn_')], 'records, not connection cards')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestTunnels(unittest.TestCase):
    """tests/protocol_fixtures.write_tunnel_pcap: one record per tunnel,
    and its packets' flows as Suricata 8.0.7 logged them
    (tests/data/tunnel_fixture.eve.json): the inner flow from the inner
    network layer on, and - but for GRE - the outer flow too."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_tunnel_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'tunnel.pcap')
        write_tunnel_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.tunnels = {r['tunnel']['type']: r for r in cls.records if r['event_type'] == 'tunnel'}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_a_gre_tunnel_between_two_sites(self):
        gre = self.tunnels['GRE']
        self.assertEqual((gre['src_ip'], gre['dest_ip'], gre['proto']), ('192.0.2.10', '192.0.2.20', 'GRE'))
        self.assertEqual({k: gre['tunnel'][k] for k in ('packets_toserver', 'packets_toclient', 'bytes_toserver',
                                                        'bytes_toclient', 'inner_flows', 'inner_hosts', 'age')},
                         {'packets_toserver': 2, 'packets_toclient': 1, 'bytes_toserver': 156, 'bytes_toclient': 78,
                          'inner_flows': 1, 'inner_hosts': ['10.10.0.5', '10.20.0.7'], 'age': 2})

    def test_udp_tunnels_and_ip_in_ip(self):
        self.assertEqual(sorted(self.tunnels), ['6in4', 'GRE', 'IP-in-IP', 'Teredo', 'VXLAN'])
        vxlan, teredo = self.tunnels['VXLAN'], self.tunnels['Teredo']
        self.assertEqual((vxlan['proto'], vxlan['src_port'], vxlan['dest_port'], vxlan['tunnel']['inner_hosts']),
                         ('UDP', 50000, 4789, ['172.16.5.1', '172.16.5.2']))
        self.assertEqual((teredo['dest_port'], teredo['tunnel']['inner_hosts'][1], teredo['tunnel']['packets_toserver'],
                          teredo['tunnel']['inner_flows']),
                         (3544, '2001:0db8:0000:0000:0000:0000:0000:0001', 2, 1), 'the bubble counted, but no flow')
        self.assertEqual((self.tunnels['6in4']['proto'], self.tunnels['IP-in-IP']['proto']), ('IPv6', 'IP-in-IP'))

    def test_a_probe_whose_inner_packet_returns_to_its_sender(self):
        self.assertTrue(self.tunnels['IP-in-IP']['tunnel']['returns_to_sender'])
        self.assertNotIn('returns_to_sender', self.tunnels['GRE']['tunnel'])

    def test_an_icmp_error_about_a_tunneled_packet_is_its_outer_flows(self):
        """REGRESSION: an ICMP error quoting a whole tunneled packet (Linux
        quotes up to 576 bytes) landed on the flow of the packet inside -
        and for Teredo on a made-up flow, the quoted outer packet's IPv4
        addresses with the inner packet's ports. Suricata counts it on the
        tunnel's outer flow, and GRE's on none (it logs no outer flow)."""
        from scripts.compare_shark_suricata import compare
        from tests.protocol_fixtures import write_icmp_tunnel_pcap
        pcap = os.path.join(self.tmpdir, 'icmp_tunnel.pcap')
        write_icmp_tunnel_pcap(pcap)
        records = shark_analyzer.run_tshark(pcap)
        report = compare(_load_eve('icmp_tunnel_fixture.eve.json'), records)['flow']
        self.assertEqual((report['suricata'], report['shark'], report['matched'], report['differences']), (5, 5, 5, []))
        flows = {(r['src_ip'], r.get('dest_port')): r for r in records if r['event_type'] == 'flow'}
        self.assertEqual(flows[('10.1.0.70', 4789)]['shark']['answered'], 'ICMP error only')
        self.assertEqual(flows[('172.16.5.1', 53)]['flow']['pkts_toclient'], 0, 'not the VXLAN packet inside')
        self.assertEqual(flows[('10.10.0.5', 443)]['flow']['pkts_toclient'], 0, "GRE's: no flow's")

    def test_flows_match_suricatas_inner_and_outer(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('tunnel_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['suricata'], report['shark'], report['matched'], report['differences']),
                         (9, 9, 9, []), 'a Teredo bubble is its tunnel\'s, and no flow of its own')
        inner = [r for r in self.records if r['event_type'] == 'flow' and r.get('app_proto') == 'dns']
        self.assertEqual((inner[0]['src_ip'], inner[0]['flow']['bytes_toserver']), ('172.16.5.1', 40),
                         'the VXLAN packet inside, from its IP header on')

    def test_the_merge_adds_tunnels_but_no_connection_cards_for_outer_flows(self):
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'tunnel_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'tunnel.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual(counts.get('tunnel'), 5)
        self.assertNotIn('conn_vxlan', counts)
        self.assertNotIn('conn_teredo', counts)

    def test_community_id_of_a_flow_without_ports(self):
        self.assertEqual(shark_analyzer._community_id('198.51.100.19', '10.1.0.1', 4, None, None),
                         '1:gcg0H/WlbVi2i7iyVESN6ELcU3Y=')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestRIP(unittest.TestCase):
    """tests/protocol_fixtures.write_rip_pcap: one record per sender,
    destination and kind of message - with what Suricata 8.0.7 logged
    for the capture (tests/data/rip_fixture.eve.json): flows it gives no
    protocol."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_rip_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'rip.pcap')
        write_rip_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.rip = {r['src_ip']: r['rip'] for r in cls.records if r['event_type'] == 'rip'}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_a_routers_updates_withdrawing_a_route(self):
        self.assertEqual(self.rip['10.1.0.1'], {
            'version': 'RIPv2', 'command': 'response', 'messages': 2, 'authentication': 'simple password',
            'metric_changes': 1, 'route_count': 3, 'withdrawn': 1,
            'routes': ['10.2.0.0/16 metric 1', '10.3.0.0/16 metric 16 via 10.1.0.2', '0.0.0.0/0 metric 1 tag 7']})

    def test_the_password_is_never_kept(self):
        from tests.protocol_fixtures import RIP_PASSWORD
        text = json.dumps([r for r in self.records if r['event_type'] == 'rip'])
        self.assertNotIn(RIP_PASSWORD.decode(), text)
        self.assertNotIn(RIP_PASSWORD.hex(), text)

    def test_a_hosts_default_route_and_a_scanners_answered_request(self):
        self.assertEqual(self.rip['10.1.0.66']['routes'], ['0.0.0.0/0 metric 1'])
        self.assertEqual(self.rip['198.51.100.18'], {'version': 'RIPv1', 'command': 'request', 'messages': 1,
                                                     'whole_table': True, 'responses': 1, 'route_count': 2,
                                                     'routes': ['10.0.0.0 metric 1', '172.16.0.0 metric 2']})

    def test_a_ripng_update(self):
        self.assertEqual(self.rip['fe80:0000:0000:0000:0000:0000:0000:0001']['routes'],
                         ['2001:0db8:0001:0000:0000:0000:0000:0000/48 metric 1',
                          '2001:0db8:0002:0000:0000:0000:0000:0000/48 metric 3'])

    def test_flows_match_suricatas_and_the_merge_adds_the_records(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('rip_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['named_by_tshark'], report['differences']), (4, 4, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'rip_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'rip.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual(counts.get('rip'), 4)
        self.assertFalse([t for t in counts if t.startswith('conn_')], 'records, not connection cards')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestL2TP(unittest.TestCase):
    """tests/protocol_fixtures.write_l2tp_pcap: one record per control
    connection - with what Suricata 8.0.7 logged for the capture
    (tests/data/l2tp_fixture.eve.json): flows it gives no protocol."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_l2tp_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'l2tp.pcap')
        write_l2tp_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.l2tp = {r['src_ip']: r['l2tp'] for r in cls.records if r['event_type'] == 'l2tp'}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_a_vpn_tunnel_its_call_and_its_end(self):
        self.assertEqual(self.l2tp['10.1.0.39'], {
            'version': 2, 'messages': ['SCCRQ', 'SCCRP', 'SCCCN', 'ICRQ', 'ICRP', 'ICCN', 'CDN', 'StopCCN'],
            'client_host_name': 'WIN-CLIENT7', 'client_vendor': 'Microsoft', 'client_firmware': '0x0601',
            'protocol_version': '1.0', 'tunnel_authentication': True, 'server_host_name': 'vpn-gw',
            'server_vendor': 'xl2tpd', 'server_firmware': '0x0680', 'calls': 1, 'calling_number': '10.1.0.39',
            'data_messages': 2, 'call_result': 'administrative reasons',
            'stop_result': 'general request to clear control connection', 'state': 'established'})

    def test_the_tunnels_challenge_and_response_are_never_kept(self):
        from tests.protocol_fixtures import L2TP_CHALLENGE, L2TP_RESPONSE
        text = json.dumps([r for r in self.records if r['event_type'] == 'l2tp'])
        for secret in (L2TP_CHALLENGE, L2TP_CHALLENGE[::-1], L2TP_RESPONSE, L2TP_RESPONSE[::-1]):
            self.assertNotIn(secret.hex(), text)
            self.assertNotIn(secret.hex(':'), text)

    def test_a_scanner_nobody_answered_and_one_refused(self):
        self.assertEqual(self.l2tp['198.51.100.16'], {'version': 2, 'messages': ['SCCRQ'],
                                                      'client_host_name': 'masscan1', 'protocol_version': '1.0',
                                                      'state': 'no answer'})
        refused = self.l2tp['198.51.100.17']
        self.assertEqual({k: refused[k] for k in ('client_host_name', 'client_vendor', 'state', 'stop_result',
                                                  'stop_error', 'stop_message')},
                         {'client_host_name': 'l2tpscan', 'client_vendor': 'driftnet', 'state': 'refused',
                          'stop_result': 'general error', 'stop_error': 'generic vendor error',
                          'stop_message': 'not allowed'})

    def test_flows_match_suricatas_and_the_merge_adds_the_records(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('l2tp_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['named_by_tshark'], report['differences']), (3, 3, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'l2tp_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'l2tp.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual(counts.get('l2tp'), 3)
        self.assertFalse([t for t in counts if t.startswith('conn_')], 'records, not connection cards')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestIPMI(unittest.TestCase):
    """tests/protocol_fixtures.write_ipmi_pcap: one record per flow to a
    BMC, of what it said before any login - with what Suricata 8.0.7
    logged for the capture (tests/data/ipmi_fixture.eve.json): flows it
    gives no protocol."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_ipmi_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'ipmi.pcap')
        write_ipmi_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.ipmi = {r['src_port']: r['ipmi'] for r in cls.records if r['event_type'] == 'ipmi'}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_a_consoles_ping_capabilities_and_session_to_a_modern_bmc(self):
        self.assertEqual(self.ipmi[50101], {
            'requests': ['presence ping', 'channel authentication capabilities', 'open session'], 'responses': 3,
            'result': 'answered', 'ipmi_supported': True, 'requested_privilege': 'administrator', 'channel': 1,
            'auth_types': ['MD5'], 'ipmi_versions': ['1.5', '2.0'], 'anonymous_login': False,
            'null_user_names': False, 'non_null_user_names': True, 'user_level_authentication': True,
            'per_message_authentication': True, 'kg_set': False,
            'cipher_requested': {'authentication': 'RAKP-HMAC-SHA1', 'integrity': 'HMAC-SHA1-96',
                                 'confidentiality': 'AES-CBC-128'},
            'session_status': 'OK',
            'cipher_accepted': {'authentication': 'RAKP-HMAC-SHA1', 'integrity': 'HMAC-SHA1-96',
                                'confidentiality': 'AES-CBC-128'}})

    def test_the_rakp_messages_and_their_password_hash_are_never_read(self):
        from tests.protocol_fixtures import IPMI_RAKP2_HMAC
        text = json.dumps([r for r in self.records if r['event_type'] == 'ipmi'])
        self.assertNotIn('admin"', text)
        self.assertNotIn(IPMI_RAKP2_HMAC.hex(), text)
        self.assertNotIn(IPMI_RAKP2_HMAC.hex(':'), text)

    def test_an_old_bmcs_anonymous_login_and_cipher_zero(self):
        caps, cipher_zero = self.ipmi[52000], self.ipmi[52001]
        self.assertEqual({k: caps[k] for k in ('auth_types', 'ipmi_versions', 'anonymous_login', 'weaknesses')},
                         {'auth_types': ['none', 'MD5', 'straight password'], 'ipmi_versions': ['1.5'],
                          'anonymous_login': True,
                          'weaknesses': ['anonymous login', 'null user names', 'no authentication offered',
                                         'cleartext password']})
        self.assertEqual((cipher_zero['cipher_accepted']['authentication'], cipher_zero['weaknesses']),
                         ('RAKP-none', ['cipher zero accepted']))

    def test_a_ping_nobody_answered(self):
        self.assertEqual(self.ipmi[52002], {'requests': ['presence ping'], 'result': 'no answer'})

    def test_flows_match_suricatas_and_the_merge_adds_the_records(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('ipmi_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['named_by_tshark'], report['differences']), (4, 4, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'ipmi_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'ipmi.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual(counts.get('ipmi'), 4)
        self.assertFalse([t for t in counts if t.startswith('conn_')], 'records, not connection cards')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestSLP(unittest.TestCase):
    """tests/protocol_fixtures.write_slp_pcap: one record per request and
    its replies, or per advertisement - with what Suricata 8.0.7 logged
    for the capture (tests/data/slp_fixture.eve.json): flows it gives no
    protocol."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_slp_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'slp.pcap')
        write_slp_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.slp = [r for r in cls.records if r['event_type'] == 'slp']

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_a_clients_questions_to_an_esxi_host(self):
        types, service, attributes, scope = (r['slp'] for r in self.slp[:4])
        self.assertEqual(types, {'version': 2, 'function': 'Service Type Request', 'xid': 1, 'scopes': 'DEFAULT',
                                 'request_length': 29, 'responses': 1, 'response': 'Service Type Reply',
                                 'response_time': 1.0, 'status': 'OK',
                                 'service_types': ['service:VMwareInfrastructure', 'service:wbem'],
                                 'response_length': 61})
        self.assertEqual({k: service[k] for k in ('function', 'service_type', 'scopes', 'urls')},
                         {'function': 'Service Request', 'service_type': 'service:VMwareInfrastructure',
                          'scopes': 'DEFAULT', 'urls': ['service:VMwareInfrastructure://esx01.example.org']})
        self.assertEqual({k: attributes[k] for k in ('function', 'url', 'response', 'attributes')},
                         {'function': 'Attribute Request', 'url': 'service:VMwareInfrastructure://esx01.example.org',
                          'response': 'Attribute Reply',
                          'attributes': '(product="VMware ESXi 7.0.3 build-19193900"),(hostname=esx01)'})
        self.assertEqual((scope['scopes'], scope['status']), ('LAB', 'SCOPE_NOT_SUPPORTED'))

    def test_a_multicast_request_answered_by_a_host(self):
        record = self.slp[4]
        self.assertEqual(record['dest_ip'], '239.255.255.253')
        self.assertEqual({k: record['slp'][k] for k in ('multicast', 'response', 'responders', 'urls')},
                         {'multicast': True, 'response': 'DA Advertisement', 'responders': ['10.1.0.57'],
                          'urls': ['service:directory-agent://10.1.0.57']})

    def test_a_scanners_registration_and_its_unanswered_probe(self):
        registration, probe = (r['slp'] for r in self.slp[5:7])
        self.assertEqual({k: registration[k] for k in ('function', 'url', 'service_type', 'lifetime', 'fresh',
                                                       'request_length', 'response', 'status')},
                         {'function': 'Service Registration', 'url': 'service:printer:lpr://198.51.100.14',
                          'service_type': 'service:printer:lpr', 'lifetime': 65535, 'fresh': True,
                          'request_length': 134, 'response': 'Service Acknowledge', 'status': 'OK'})
        self.assertEqual(probe, {'version': 2, 'function': 'Service Type Request', 'xid': 7, 'scopes': 'DEFAULT',
                                 'request_length': 29})

    def test_an_advertisement_is_a_record_of_its_own(self):
        self.assertEqual(self.slp[7]['slp'], {'version': 2, 'function': 'SA Advertisement', 'scopes': 'DEFAULT',
                                              'urls': ['service:service-agent://10.1.0.57'], 'length': 63})

    def test_flows_match_suricatas_and_the_merge_adds_the_records(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('slp_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['named_by_tshark'], report['differences']), (6, 6, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'slp_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'slp.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual(counts.get('slp'), 8)
        self.assertFalse([t for t in counts if t.startswith('conn_')], 'records, not connection cards')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestSTUN(unittest.TestCase):
    """tests/protocol_fixtures.write_stun_pcap: one record per flow and
    method - with what Suricata 8.0.7 logged for the capture
    (tests/data/stun_fixture.eve.json): flows it gives no protocol, and
    ET INFO alerts on the Bindings, which don't make them Suricata's."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_stun_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'stun.pcap')
        write_stun_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.stun = {r['src_port']: r['stun'] for r in cls.records if r['event_type'] == 'stun'}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_bindings_on_one_flow_are_one_record_with_the_public_address(self):
        self.assertEqual(self.stun[40001], {'method': 'Binding', 'requests': 2, 'successes': 2, 'result': 'success',
                                            'mapped_addresses': ['203.0.113.50:40001'],
                                            'client_software': 'fixture-client 1.0',
                                            'server_software': 'fixture-stun 2.1'})

    def test_a_turn_allocate_refused_then_made(self):
        allocate = self.stun[40002]
        self.assertEqual({k: allocate[k] for k in ('method', 'requests', 'errors', 'successes', 'error_codes', 'result',
                                                    'relayed_addresses', 'mapped_addresses', 'username', 'realm',
                                                    'lifetime')},
                         {'method': 'Allocate', 'requests': 2, 'errors': 1, 'successes': 1,
                          'error_codes': ['401 Unauthorized'], 'result': 'success',
                          'relayed_addresses': ['192.0.2.30:50000'], 'mapped_addresses': ['203.0.113.50:40002'],
                          'username': 'turnuser', 'realm': 'example.org', 'lifetime': 600})

    def test_an_ipv6_mapped_address(self):
        self.assertEqual(self.stun[40003]['mapped_addresses'], ['[2001:0db8:ffff:0000:0000:0000:0000:0050]:40003'])

    def test_a_scanners_binding_request_nobody_answered(self):
        self.assertEqual(self.stun[41000], {'method': 'Binding', 'requests': 1})

    def test_flows_match_suricatas_and_the_merge_adds_the_records(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('stun_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['named_by_tshark'], report['differences']), (4, 4, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'stun_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'stun.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual(counts.get('stun'), 4)
        self.assertFalse([t for t in counts if t.startswith('conn_')], 'records, not connection cards')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestRADIUS(unittest.TestCase):
    """tests/protocol_fixtures.write_radius_pcap: one record per login -
    its challenges and final answer - and per accounting message, with
    what Suricata 8.0.7 logged for the capture
    (tests/data/radius_fixture.eve.json): flows it gives no protocol."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_radius_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'radius.pcap')
        write_radius_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.radius = [r['radius'] for r in cls.records if r['event_type'] == 'radius']
        cls.by_user = {(r.get('user'), r['message']): r for r in cls.radius}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_logins_from_one_nas_port_stay_apart(self):
        """A NAS sends every user's requests from one port: rounds are
        chained by the State a challenge carries and the next request
        echoes, not by flow - by flow, two logins at once merged, and a
        request nobody answered took in every later login."""
        from tests.pcap_fixtures import write_pcap
        from tests.protocol_fixtures import RADIUS_NAS, RADIUS_SERVER, _eap, _radius, _udp_packet
        ask = lambda ident, attrs: _udp_packet(RADIUS_NAS, RADIUS_SERVER, 50100, 1812, _radius(1, ident, attrs))
        answer = lambda code, ident, attrs=(): _udp_packet(RADIUS_SERVER, RADIUS_NAS, 1812, 50100, _radius(code, ident, attrs))
        packets = [
            ask(1, ((1, 'nobody'),)),                                                   # never answered
            ask(2, ((1, 'dave'), (79, _eap(2, 1, 1, b'dave')))),
            ask(3, ((1, 'erin'), (79, _eap(2, 1, 1, b'erin')))),
            answer(11, 2, ((79, _eap(1, 2, 25, b'\x20')), (24, 'state-dave'))),
            answer(11, 3, ((79, _eap(1, 2, 25, b'\x20')), (24, 'state-erin'))),
            ask(4, ((1, 'erin'), (79, _eap(2, 2, 25, b'\x00')), (24, 'state-erin'))),
            ask(5, ((1, 'dave'), (79, _eap(2, 2, 25, b'\x00')), (24, 'state-dave'))),
            answer(3, 4),
            answer(2, 5),
        ]
        pcap = os.path.join(self.tmpdir, 'one_port.pcap')
        write_pcap(pcap, packets)
        logins = {r['radius'].get('user'): r['radius'] for r in shark_analyzer.run_tshark(pcap)
                  if r['event_type'] == 'radius'}
        self.assertEqual({u: (b['requests'], b.get('challenges'), b.get('result')) for u, b in logins.items()},
                         {'nobody': (1, None, None), 'dave': (2, 1, 'accepted'), 'erin': (2, 1, 'rejected')})
        self.assertNotIn('state-', json.dumps(list(logins.values())), 'State links the rounds, and is never kept')

    def test_a_wifi_login_challenged_then_accepted_is_one_record(self):
        login = self.by_user[('alice', 'Access-Request')]
        self.assertEqual({k: login[k] for k in ('requests', 'challenges', 'result', 'eap_methods', 'reply_message',
                                                 'framed_ip', 'calling_station', 'called_station', 'nas_identifier',
                                                 'nas_ip', 'port_type', 'service_type', 'response_time')},
                         {'requests': 2, 'challenges': 1, 'result': 'accepted', 'eap_methods': ['EAP-PEAP'],
                          'reply_message': 'Welcome, alice', 'framed_ip': '10.1.5.20',
                          'calling_station': 'AA-BB-CC-DD-EE-01', 'called_station': '00-11-22-33-44-55:CorpWiFi',
                          'nas_identifier': 'wlc-1', 'nas_ip': '10.1.0.2', 'port_type': 'Wireless - IEEE 802.11',
                          'service_type': 'Framed', 'response_time': 3.0})

    def test_a_rejected_login_and_a_retransmitted_one(self):
        bob, carol = self.by_user[('bob', 'Access-Request')], self.by_user[('carol', 'Access-Request')]
        self.assertEqual((bob['result'], bob['reply_message']), ('rejected', 'Authentication failed'))
        self.assertEqual((carol['result'], carol['requests'], carol['retransmissions'], carol['response_time']),
                         ('accepted', 1, 1, 2.0))
        self.assertFalse([r for r in self.radius if 'password' in json.dumps(r).lower()])

    def test_accounting_start_and_stop(self):
        start, stop = self.by_user[('alice', 'Accounting Start')], self.by_user[('alice', 'Accounting Stop')]
        self.assertEqual((start['session_id'], start['framed_ip'], start['result']), ('sess-0001', '10.1.5.20', 'acknowledged'))
        self.assertEqual({k: stop[k] for k in ('session_time', 'bytes_in', 'bytes_out', 'terminate_cause')},
                         {'session_time': 3600, 'bytes_in': 1048576, 'bytes_out': 52428800,
                          'terminate_cause': 'User Request'})

    def test_a_scanners_request_nobody_answered(self):
        scan = self.by_user[('infragrab-0123@invalid.invalid', 'Access-Request')]
        self.assertEqual(scan, {'message': 'Access-Request', 'requests': 1, 'user': 'infragrab-0123@invalid.invalid'})

    def test_flows_match_suricatas_and_the_merge_adds_the_records(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('radius_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['named_by_tshark'], report['differences']), (5, 5, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'radius_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'radius.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual(counts.get('radius'), 6)
        self.assertFalse([t for t in counts if t.startswith('conn_')], 'records, not connection cards')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestSOCKS(unittest.TestCase):
    """tests/protocol_fixtures.write_socks_pcap: one record per connection
    through the proxy - with what Suricata 8.0.7 logged for the capture
    (tests/data/socks_fixture.eve.json): flows it gives no protocol, but
    for the SOCKS 5 one it calls dcerpc (its greeting starts 05, like a
    DCE/RPC header), backed only by a protocol-decode alert."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_socks_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'socks.pcap')
        write_socks_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.sessions = {r['src_port']: r['socks'] for r in cls.records if r['event_type'] == 'socks'}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_a_socks5_connect_by_name_and_what_went_through_it(self):
        self.assertEqual(self.sessions[42001], {
            'version': '5', 'auth_methods': ['no authentication'], 'auth_method': 'no authentication',
            'command': 'connect', 'request_name': 'files.example.net', 'request_port': 80, 'status': 'succeeded',
            'bound_host': '192.0.2.10', 'bound_port': 50123, 'tunneled': 'http'})

    def test_a_login_keeps_the_user_name_never_the_password(self):
        login = self.sessions[42002]
        self.assertEqual({k: login[k] for k in ('auth_methods', 'auth_method', 'user', 'login', 'request_host',
                                                 'request_port', 'status')},
                         {'auth_methods': ['no authentication', 'username/password'], 'auth_method': 'username/password',
                          'user': 'proxyuser', 'login': 'succeeded', 'request_host': '203.0.113.25', 'request_port': 25,
                          'status': 'connection not allowed by ruleset'})
        self.assertNotIn('hunter', json.dumps(self.records))

    def test_socks4_and_4a(self):
        self.assertEqual(self.sessions[42003], {'version': '4a', 'command': 'connect', 'request_name': 'example.org',
                                                'request_port': 80, 'user': 'bob', 'status': 'granted',
                                                'bound_host': '198.51.100.80', 'bound_port': 80})
        self.assertEqual(self.sessions[42004], {'version': '4', 'command': 'connect', 'request_host': '192.0.2.67',
                                                'request_port': 6667, 'status': 'rejected or failed'})

    def test_an_open_proxy_check_turned_away(self):
        self.assertEqual(self.sessions[51000], {'version': '5', 'auth_methods': ['username/password'],
                                                'auth_method': 'no acceptable methods',
                                                'status': 'no acceptable authentication method'})

    def test_only_a_socks_handshake_starts_a_record(self):
        """tshark calls anything on port 1080 SOCKS: a scanner's HTTP proxy
        check sent there, or a DCE/RPC connection whose client port it was,
        which starts 05 00 like a SOCKS 5 reply."""
        from tests.pcap_fixtures import write_pcap
        from tests.protocol_fixtures import _Tcp
        probe = _Tcp('198.51.100.20', '10.1.0.45', 12345, 1080)
        rpc = _Tcp('10.1.0.32', '10.1.0.33', 1080, 49188)
        pkts = (probe.open() + probe.send(True, b'GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n') + probe.close()
                + rpc.open() + rpc.send(True, bytes.fromhex('05000083100000009000100001000000'))
                + rpc.send(False, bytes.fromhex('05000203100000004000100001000000')) + rpc.close())
        pcap = os.path.join(self.tmpdir, 'not_socks.pcap')
        write_pcap(pcap, pkts)
        self.assertEqual([r for r in shark_analyzer.run_tshark(pcap) if r['event_type'] == 'socks'], [])

    def test_flows_match_suricatas_and_the_merge_adds_every_record(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('socks_fixture.eve.json'), self.records)['flow']
        self.assertEqual([d['fields'] for d in report['differences']], [{'app_proto': ('dcerpc', 'socks')}])
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'socks_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'socks.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual(counts.get('socks'), 5,
                         "the dcerpc label is backed by nothing but a protocol-decode alert, so it isn't Suricata's word")
        self.assertFalse([t for t in counts if t.startswith('conn_')], 'records, not connection cards')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestTLSFailures(unittest.TestCase):
    """tests/protocol_fixtures.write_tls_failure_pcap: a record per TCP
    connection that sent a TLS alert while it could still be read - with
    what Suricata 8.0.7 logged for the capture
    (tests/data/tls_failure_fixture.eve.json): a tls record for each
    connection that got as far as the server's certificate, and none of
    the alerts."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_tls_failure_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'tls_failure.pcap')
        write_tls_failure_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.failures = {r['dest_ip']: r for r in cls.records if r['event_type'] == 'tls_failure'}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_a_client_refusing_the_certificate_and_a_server_turning_a_client_away(self):
        from tests.protocol_fixtures import TLS_FAILURE_CLIENT, TLS_REFUSED_SERVER, TLS_UNWILLING_SERVER
        refused = self.failures[TLS_REFUSED_SERVER]
        self.assertEqual(refused['tls_failure'], {'alert': 'Unknown CA', 'sent_by': 'client',
                                                  'alerts': ['client: Unknown CA']})
        self.assertEqual((refused['src_ip'], refused['src_port'], refused['dest_port']), (TLS_FAILURE_CLIENT, 41201, 443))
        self.assertEqual(self.failures[TLS_UNWILLING_SERVER]['tls_failure'],
                         {'alert': 'Handshake Failure', 'sent_by': 'server', 'alerts': ['server: Handshake Failure']})

    def test_an_encrypted_alert_is_no_record(self):
        from tests.protocol_fixtures import TLS_GOOD_SERVER
        self.assertNotIn(TLS_GOOD_SERVER, self.failures)
        self.assertEqual(len(self.failures), 2)

    def test_an_orderly_close_is_no_failure(self):
        flow = shark_analyzer._Flow(('k',), 'TCP', 4, '10.0.0.1', '10.0.0.2', 40000, 443, 1.0, '0')
        failures = shark_analyzer._TLSFailures()
        failures.add(flow, '10.0.0.1', 40000, 1.0, ['Close Notify'])
        failures.add(flow, '10.0.0.2', 443, 2.0, ['Close Notify'])
        self.assertEqual(list(failures.records()), [])
        failures.add(flow, '10.0.0.2', 443, 3.0, ['Close Notify', 'Decrypt Error'])
        self.assertEqual([r['tls_failure'] for r in failures.records()],
                         [{'alert': 'Decrypt Error', 'sent_by': 'server', 'alerts': ['server: Decrypt Error']}])

    def test_the_merge_keeps_them_on_suricatas_tls_flows_and_names_the_certificate(self):
        from tests.protocol_fixtures import TLS_REFUSED_SERVER, TLS_UNWILLING_SERVER
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'tls_failure_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'tls_failure.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual((counts.get('tls_failure'), counts.get('tls')), (2, 2),
                         'Suricata called all three tls, but logs no alerts')
        with closing(sqlite3.connect(events_db)) as conn:
            merged = {e['dest_ip']: e['tls_failure'] for e in (json.loads(r[0]) for r in conn.execute(
                "SELECT json_data FROM events WHERE event_type = 'tls_failure'"))}
        self.assertEqual(merged[TLS_REFUSED_SERVER], {
            'sni': 'vpn.example', 'version': 'TLS 1.2', 'subject': 'C=US, O=Fixture Ltd, CN=dtls.example',
            'issuerdn': 'C=US, O=Fixture Ltd, CN=dtls.example', 'subjectaltname': ['dtls.example', 'vpn.example'],
            'serial': '12:34:AB:CD', 'fingerprint': '0b:a9:85:77:db:22:9e:e7:a6:fe:09:ca:65:2c:38:52:2b:c4:04:66',
            'notbefore': '2026-10-10T20:40:09', 'notafter': '2036-10-07T20:40:09',
            'alert': 'Unknown CA', 'sent_by': 'client', 'alerts': ['client: Unknown CA']})
        self.assertEqual(merged[TLS_UNWILLING_SERVER]['alert'], 'Handshake Failure',
                         'no certificate to name: Suricata has no tls record of a handshake that stopped at the hello')
        self.assertNotIn('sni', merged[TLS_UNWILLING_SERVER])
        found = findings.query_findings(events_db)
        self.assertEqual(sorted((r['id'], r['count']) for r in found['rules']),
                         [('tls_certificate_out_of_date', 2), ('tls_certificate_refused', 1), ('tls_name_mismatch', 1),
                          ('tls_self_signed', 2)],
                         'the certificate starts in 2026, and the capture is from 2023; it names vpn.example, '
                         'not good.example')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestDTLS(unittest.TestCase):
    """tests/protocol_fixtures.write_dtls_pcap: one record per connection's
    handshake, named like Suricata's tls records - with what Suricata
    8.0.7 logged for the capture (tests/data/dtls_fixture.eve.json):
    flows it gives no protocol, since it parses TLS over TCP only."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_dtls_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'dtls.pcap')
        write_dtls_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.handshakes = {r['src_ip']: r['dtls'] for r in cls.records if r['event_type'] == 'dtls'}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_a_completed_webrtc_handshake(self):
        from tests.protocol_fixtures import DTLS_CLIENT
        d = self.handshakes[DTLS_CLIENT]
        self.assertEqual({k: d[k] for k in ('version', 'sni', 'cipher_suite', 'client_alpns', 'server_alpns', 'srtp_profile',
                                            'cookie_exchange', 'client_hellos', 'handshake')},
                         {'version': 'DTLS 1.2', 'sni': 'dtls.example', 'cipher_suite': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                          'client_alpns': ['webrtc'], 'server_alpns': ['webrtc'], 'srtp_profile': 'SRTP_AES128_CM_HMAC_SHA1_80',
                          'cookie_exchange': True, 'client_hellos': 2, 'handshake': 'completed'},
                         'completed once both sides changed cipher spec - after SRTP, tshark calls those packets rtp:dtls')
        self.assertTrue(d['ja3']['hash'] and d['ja3s']['hash'] and d['ja4'].startswith('dd2d'))

    def test_the_certificate_as_suricata_names_it(self):
        from tests.protocol_fixtures import DTLS_CLIENT
        d = self.handshakes[DTLS_CLIENT]
        self.assertEqual({k: d[k] for k in ('subject', 'issuerdn', 'serial', 'fingerprint', 'notbefore', 'notafter', 'san')},
                         {'subject': 'C=US, O=Fixture Ltd, CN=dtls.example', 'issuerdn': 'C=US, O=Fixture Ltd, CN=dtls.example',
                          'serial': '12:34:AB:CD', 'fingerprint': '0b:a9:85:77:db:22:9e:e7:a6:fe:09:ca:65:2c:38:52:2b:c4:04:66',
                          'notbefore': '2026-10-10T20:40:09', 'notafter': '2036-10-07T20:40:09',
                          'san': ['dtls.example', 'vpn.example']}, 'as openssl x509 reads it')

    def test_a_scanners_unanswered_client_hello(self):
        from tests.protocol_fixtures import DTLS_SCANNER
        d = self.handshakes[DTLS_SCANNER]
        self.assertEqual((d['handshake'], d['version']), ('client hello only', 'DTLS 1.2'))
        self.assertNotIn('subject', d)
        self.assertTrue(d['ja4'], 'its JA4 names the tool')

    def test_an_unreadable_certificate_is_left_out(self):
        from shark_protocols import _x509
        self.assertEqual(_x509('30:82:ff'), {})

    def test_flows_match_suricatas_and_the_merge_adds_the_records(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('dtls_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['named_by_tshark'], report['differences']), (2, 2, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'dtls_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'dtls.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual(counts.get('dtls'), 2)
        self.assertNotIn('conn_dtls', counts, 'records, not a connection card')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestSyslog(unittest.TestCase):
    """tests/protocol_fixtures.write_syslog_pcap: one record per message,
    in each format - with what Suricata 8.0.7 logged for the capture
    (tests/data/syslog_fixture.eve.json): flows it gives no protocol,
    since it has no syslog parser."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_syslog_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'syslog.pcap')
        write_syslog_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.messages = [r['syslog'] for r in sorted(cls.records, key=lambda r: r.get('src_port', 0))
                        if r['event_type'] == 'syslog']

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_rfc_3164_program_and_pid_split_where_tshark_doesnt(self):
        sshd = self.messages[0]
        self.assertEqual({k: sshd[k] for k in ('facility', 'severity', 'format', 'timestamp', 'hostname', 'program', 'pid')},
                         {'facility': 'auth', 'severity': 'info', 'format': 'RFC 3164', 'timestamp': 'Oct 10 14:02:15',
                          'hostname': 'sw-core', 'program': 'sshd', 'pid': '812'})
        self.assertEqual(sshd['message'], 'Failed password for admin from 10.1.0.77 port 51122 ssh2')

    def test_a_message_with_no_timestamp_or_host_is_kept_whole(self):
        asa = self.messages[1]
        self.assertEqual((asa['facility'], asa['severity'], asa['format']), ('local7', 'info', 'RFC 3164'))
        self.assertNotIn('hostname', asa)
        self.assertTrue(asa['message'].startswith('%ASA-6-302013: Built inbound TCP connection'))

    def test_rfc_5424_with_structured_data(self):
        app = self.messages[2]
        self.assertEqual({k: app.get(k) for k in ('facility', 'severity', 'format', 'timestamp', 'hostname', 'program',
                                                  'pid', 'msgid', 'message')},
                         {'facility': 'local4', 'severity': 'notice', 'format': 'RFC 5424',
                          'timestamp': '2026-10-10T14:02:15.003Z', 'hostname': 'app1.example.com', 'program': 'evntslog',
                          'pid': None, 'msgid': 'ID47', 'message': 'An application event'})
        self.assertEqual(app['structured_data'],
                         {'exampleSDID@32473': {'iut': '3', 'eventSource': 'Application', 'eventID': '1011'}})

    def test_no_priority_and_a_long_message(self):
        self.assertEqual(self.messages[3], {'format': 'no priority', 'message': 'no priority here at all'})
        long = self.messages[4]
        self.assertEqual((len(long['message']), long['truncated']), (2048, True))

    def test_flows_match_suricatas_and_the_merge_adds_the_records(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('syslog_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['named_by_tshark'], report['differences']), (5, 5, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'syslog_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'syslog.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual(counts.get('syslog'), 5)
        self.assertNotIn('conn_syslog', counts, 'records, not a connection card')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestDHCPv6(unittest.TestCase):
    """tests/protocol_fixtures.write_dhcpv6_pcap: one record per
    transaction, the server's reply (on another flow) paired with the
    client's message - with what Suricata 8.0.7 logged for the capture
    (tests/data/dhcpv6_fixture.eve.json): flows it gives no protocol,
    since it parses DHCP for IPv4 only."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_dhcpv6_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'dhcpv6.pcap')
        write_dhcpv6_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.transactions = {r['dhcpv6']['transaction_id']: r['dhcpv6'] for r in cls.records
                            if r['event_type'] == 'dhcpv6'}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_each_message_is_paired_with_its_reply(self):
        self.assertEqual({t: (b['message'], b.get('reply')) for t, b in self.transactions.items()},
                         {'0x000101': ('Solicit', 'Advertise'), '0x000102': ('Request', 'Reply'),
                          '0x00abcd': ('Solicit', None)})

    def test_the_reply_says_what_the_client_got(self):
        reply = self.transactions['0x000102']
        self.assertEqual((reply['client_mac'], reply['assigned_addresses'], reply['dns_servers'],
                          reply['domain_search'], reply['status'], reply['status_message']),
                         ('00:1b:21:00:00:10', ['2001:0db8:0000:0000:0000:0000:0000:0010'],
                          ['2001:0db8:0000:0000:0000:0000:0000:0053'], ['example.com'], 'Success',
                          'All addresses assigned'))
        self.assertEqual(reply['server_duid'], '0001000123c34600001b21000001')

    def test_a_windows_solicit_gives_its_hostname_and_retransmissions_are_counted(self):
        laptop = self.transactions['0x00abcd']
        self.assertEqual((laptop['hostname'], laptop['vendor_class'], laptop['client_mac'], laptop['transmissions']),
                         ('LAPTOP.example.com', 'MSFT 5.0', '00:1b:21:00:00:20', 2))

    def test_flows_match_suricatas_and_the_merge_adds_the_records(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('dhcpv6_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['named_by_tshark'], report['differences']), (3, 3, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'dhcpv6_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'dhcpv6.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual(counts.get('dhcpv6'), 3)
        self.assertNotIn('conn_dhcpv6', counts, 'records, not a connection card')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestNeighbors(unittest.TestCase):
    """tests/protocol_fixtures.write_neighbor_pcap: LLDP and CDP
    announcements, one record per sending MAC, device and port - with
    what Suricata 8.0.7 logged for the capture
    (tests/data/neighbor_fixture.eve.json): only 'Ethertype unknown'
    decoder alerts, since it doesn't decode either."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_neighbor_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'neighbor.pcap')
        write_neighbor_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.lldp = {r['src_ip']: r['lldp'] for r in cls.records if r['event_type'] == 'lldp'}
        cls.cdp = [r['cdp'] for r in cls.records if r['event_type'] == 'cdp']

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_an_lldp_switch_says_what_it_is(self):
        from tests.protocol_fixtures import NEIGHBOR_SWITCH
        switch = self.lldp[NEIGHBOR_SWITCH]
        self.assertEqual((switch['count'], switch['chassis_id'], switch['port_id'], switch['system_name']),
                         (2, NEIGHBOR_SWITCH, 'Gi1/0/1', 'sw1.example'), 'the repeated announcement counted')
        self.assertEqual(switch['system_description'], 'Fixture Switch OS 1.0\nBuilt 2026-01-01')
        self.assertEqual((switch['capabilities'], switch['management_addresses'], switch['vlan']),
                         (['bridge', 'router'], ['10.1.0.1'], 10))

    def test_a_local_chassis_id_is_text_and_lldp_med_inventory_is_kept(self):
        from tests.protocol_fixtures import NEIGHBOR_PLC
        plc = self.lldp[NEIGHBOR_PLC]
        self.assertEqual((plc['chassis_id'], plc['port_id']), ('plc-1 line 2', 'port-001'))
        self.assertEqual((plc['manufacturer'], plc['model'], plc['serial_number'], plc['hardware_revision'],
                          plc['firmware_revision']), ('Fixture Automation', 'PLC-100', 'SN-0042', 'HW 3', 'FW 2.1'))
        self.assertEqual((plc['ttl'], plc['shutdowns']), (0, 1), 'its port shut down')

    def test_cdp(self):
        self.assertEqual(len(self.cdp), 1)
        sw = self.cdp[0]
        self.assertEqual((sw['device_id'], sw['port_id'], sw['platform'], sw['software_version'], sw['capabilities']),
                         ('sw1', 'GigabitEthernet1/0/1', 'cisco WS-C2960-24TT', 'Fixture IOS 15.2', ['switch', 'IGMP']))
        self.assertEqual((sw['addresses'], sw['native_vlan'], sw['vtp_domain'], sw['duplex']),
                         (['10.1.0.1'], 10, 'PLANT', 'full'))

    def test_the_merge_adds_the_records(self):
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'neighbor_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'neighbor.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual((counts.get('lldp'), counts.get('cdp')), (2, 1))
        self.assertNotIn('conn_lldp', counts, 'records, not a connection card')
        flows = [r for r in self.records if r['event_type'] == 'flow']
        self.assertTrue(flows and all('answered' not in f['shark'] for f in flows), 'nothing answers a link-layer announcement')
        self.assertNotIn('conn_cdp', counts)


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestBrowser(unittest.TestCase):
    """tests/protocol_fixtures.write_browser_pcap: Windows Browser messages,
    one record per host, name and kind of message - with what Suricata
    8.0.7 logged for the capture (tests/data/browser_fixture.eve.json):
    flows it gives no protocol, since it doesn't parse NetBIOS datagrams."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import write_browser_pcap
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcap = os.path.join(cls.tmpdir, 'browser.pcap')
        write_browser_pcap(cls.pcap)
        cls.records = shark_analyzer.run_tshark(cls.pcap)
        cls.messages = {(b['source_name'], b['message']): b for b in
                        (r['browser'] for r in cls.records if r['event_type'] == 'browser')}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_one_record_per_host_and_message(self):
        self.assertEqual(sorted(self.messages), [('DC1', 'Local Master Announcement'), ('WS1', 'Browser Election Request'),
                                                 ('WS1', 'Host Announcement'), ('WS1', 'Request Announcement')])
        self.assertEqual(self.messages[('WS1', 'Host Announcement')]['count'], 2, 'the repeated announcement counted')

    def test_announcements_say_what_the_host_is(self):
        workstation = self.messages[('WS1', 'Host Announcement')]
        self.assertEqual((workstation['destination_name'], workstation['os_version'], workstation['roles'],
                          workstation['comment']),
                         ('FIXTUREDOM', '10.0', ['workstation', 'server', 'NT workstation'], 'Accounting PC'))
        self.assertIn('domain controller', self.messages[('DC1', 'Local Master Announcement')]['roles'])
        self.assertIn('master browser', self.messages[('DC1', 'Local Master Announcement')]['roles'])

    def test_flows_match_suricatas_and_the_merge_adds_the_records(self):
        from scripts.compare_shark_suricata import compare
        report = compare(_load_eve('browser_fixture.eve.json'), self.records)['flow']
        self.assertEqual((report['matched'], report['named_by_tshark'], report['differences']), (2, 2, []))
        d = os.path.join(self.tmpdir, 'analysis')
        os.makedirs(d)
        shutil.copy(self.pcap, d)
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                    'browser_fixture.eve.json'))
        self.assertTrue(shark_analyzer.build(d, os.path.join(d, 'browser.pcap')))
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual(counts.get('browser'), 4)
        self.assertNotIn('conn_nbdgm', counts, 'records, not a connection card')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestOnePassOrTwo(unittest.TestCase):
    """A capture mostly of protocols with records here gets one pass
    asking for the fields of those the probe saw (_mostly_recorded,
    _combined_fields) - and any other's flows the protocol pass; any other
    capture, a first pass for flows and a protocol pass over just the
    packets that need it. The records are the same either way."""

    @classmethod
    def setUpClass(cls):
        from tests.protocol_fixtures import (write_bacnet_pcap, write_browser_pcap, write_extra_pcap,
                                             write_iec104_pcap, write_protocol_pcap, write_telnet_pcap)
        cls.tmpdir = tempfile.mkdtemp()
        cls.pcaps = {}
        for name, write in (('iec104', write_iec104_pcap), ('bacnet', write_bacnet_pcap), ('telnet', write_telnet_pcap),
                            ('extra', write_extra_pcap), ('browser', write_browser_pcap), ('protocols', write_protocol_pcap)):
            cls.pcaps[name] = os.path.join(cls.tmpdir, name + '.pcap')
            write(cls.pcaps[name])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    @staticmethod
    def _records(pcap, combined):
        with mock.patch.object(shark_analyzer, '_mostly_recorded', return_value=combined):
            return sorted(json.dumps(r, sort_keys=True) for r in shark_analyzer.run_tshark(pcap))

    def test_the_same_records_either_way(self):
        for name, pcap in self.pcaps.items():
            with self.subTest(capture=name):
                two = self._records(pcap, False)
                self.assertEqual(self._records(pcap, True), two)
                self.assertTrue(any('"event_type": "flow"' not in r for r in two) or name == 'protocols')

    def test_a_protocol_the_probe_missed_still_gets_its_records(self):
        """REGRESSION GUARD: the combined pass asks only for the sampled
        protocols' fields - here S7comm's, on a capture with NBNS, LLMNR
        and SSDP too, whose flows get the protocol pass instead."""
        two = self._records(self.pcaps['extra'], False)
        self.assertEqual(self._records(self.pcaps['extra'], frozenset({'s7comm'})), two)
        self.assertTrue(any('"event_type": "nbns"' in r for r in two))

    def test_the_combined_pass_asks_only_for_the_sampled_protocols_fields(self):
        from shark_protocols import DTLS, IEC104
        fields = shark_analyzer._combined_fields((IEC104,))
        self.assertTrue(set(IEC104.fields) <= set(fields))
        self.assertFalse(set(DTLS.fields) & set(fields))

    def test_the_probe_tells_one_protocols_capture_from_a_mixed_one(self):
        with mock.patch.object(shark_analyzer, '_PROBE_MIN_PACKETS', 1):
            self.assertEqual(shark_analyzer._mostly_recorded(self.pcaps['iec104']), {'iec60870_104'},
                             'the protocols it saw, for the combined pass to ask for')
            self.assertFalse(shark_analyzer._mostly_recorded(self.pcaps['protocols']), 'DNS, HTTP, TLS, Modbus, FTP')

    def test_a_small_capture_is_never_probed(self):
        with mock.patch.object(shark_analyzer.pcap_subset, 'copy_frames', side_effect=AssertionError('probed')):
            self.assertFalse(shark_analyzer._mostly_recorded(self.pcaps['iec104']))


class _NbnsFromJson:
    """A structured protocol for testing the structured pass on its own:
    NBNS names, read from each packet's JSON tree."""
    app_protos = ('nbns',)
    tshark_protocols = ('nbns',)
    layers = ('nbns',)
    display_filter = 'nbns'

    def __init__(self):
        self.seen = []

    def feed_json(self, pkt, layers):
        from shark_protocols import _flatten, _pdus
        for pdu in _pdus(layers.get('nbns')):
            self.seen.append((pkt.flow.cport, _flatten(pdu).get('nbns.name', [''])[0]))

    def finish(self):
        return []


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestStructuredPass(unittest.TestCase):
    """shark_analyzer._structured_pass: a second tshark run writing JSON
    trees, over just the flows of the protocols that need it."""

    def test_reads_only_the_flows_that_need_it_from_a_copy_of_their_packets(self):
        from tests.protocol_fixtures import extra_packets, dns_packets
        from tests.pcap_fixtures import write_pcap
        with tempfile.TemporaryDirectory() as tmp:
            pcap = os.path.join(tmp, 'padded.pcap')
            write_pcap(pcap, dns_packets() * 40 + extra_packets())     # mostly DNS, then the NBNS
            proto = _NbnsFromJson()
            calls = []
            real_copy = shark_analyzer.pcap_subset.copy_frames

            def spy(src, dst, ranges):
                calls.append(ranges)
                return real_copy(src, dst, ranges)
            # (no field protocols, so the protocol pass cuts no copy of its own)
            with mock.patch.object(shark_analyzer, 'STRUCTURED_PROTOCOLS', (lambda: proto,)), \
                    mock.patch.object(shark_analyzer, 'PROTOCOLS', ()), \
                    mock.patch.object(shark_analyzer.pcap_subset, 'copy_frames', side_effect=spy):
                shark_analyzer.run_tshark(pcap)
        [ranges] = calls
        self.assertLess(len(ranges), 5, 'a few frame ranges, not the whole capture')
        self.assertEqual(sorted({(port, name.split('<')[0]) for port, name in proto.seen}),
                         [(137, 'DESKTOP-TEST01'), (137, 'FILESERVER')], 'each packet matched to its first-pass flow')

    def test_no_flows_that_need_it_no_second_pass(self):
        from tests.protocol_fixtures import write_protocol_pcap
        with tempfile.TemporaryDirectory() as tmp:
            pcap = os.path.join(tmp, 'protocols.pcap')
            write_protocol_pcap(pcap)
            with mock.patch.object(shark_analyzer, 'STRUCTURED_PROTOCOLS', (_NbnsFromJson,)), \
                    mock.patch.object(shark_analyzer, '_structured_command', side_effect=AssertionError('ran')):
                shark_analyzer.run_tshark(pcap)

    def test_frame_ranges(self):
        flows = [mock.Mock(first_frame=a, last_frame=b) for a, b in ((10, 20), (15, 30), (40, 41), (100, 200), (0, 0))]
        self.assertEqual(shark_analyzer._frame_ranges(flows), [(10, 30), (40, 41), (100, 200)])
        self.assertEqual(shark_analyzer._merge_ranges([(10, 30), (40, 41), (100, 200)], max_ranges=2),
                         [(10, 41), (100, 200)], 'closing the smallest gap')

    def test_json_packets_one_at_a_time(self):
        lines = ['[\n', '  {\n', '    "_source": {"layers": {"nbns": {"nbns.id": "5"}}}\n', '  },\n',
                 '  {\n', '    "_source": {"layers": {"nbns": {"nbns.id": "6"}}}\n', '  }\n', ']\n']
        self.assertEqual([p['nbns']['nbns.id'] for p in shark_analyzer._json_packets(lines)], ['5', '6'])

@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestAnswered(unittest.TestCase):
    """A flow says whether its server answered: a scanner's UDP probes -
    one answered, one answered only by an ICMP port unreachable (a closed
    port), one not at all - and an announcement to a multicast group,
    whose replies would come back on another flow."""

    def test_answered_no_and_icmp_error_only(self):
        from tests.pcap_fixtures import write_pcap
        from tests.protocol_fixtures import _icmp_unreachable, _udp_packet
        coap = b'\x40\x01\x00\x01\xbb.well-known\x04core'           # a CoAP GET /.well-known/core
        probe = _udp_packet('10.9.0.1', '10.9.0.2', 40001, 5683, coap)
        packets = [_udp_packet('10.9.0.1', '10.9.0.3', 40002, 5683, coap),
                   _udp_packet('10.9.0.3', '10.9.0.1', 5683, 40002, b'\x60\x45\x00\x01'),
                   probe, _icmp_unreachable('10.9.0.2', '10.9.0.1', probe),
                   _udp_packet('10.9.0.1', '10.9.0.4', 40003, 5683, coap),
                   _udp_packet('10.9.0.1', '224.0.1.187', 40004, 5683, coap)]
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        pcap = os.path.join(tmpdir, 'probes.pcap')
        write_pcap(pcap, packets)
        flows = {r['dest_ip']: r for r in shark_analyzer.run_tshark(pcap) if r['event_type'] == 'flow'}
        self.assertEqual({ip: (f['app_proto'], f['shark'].get('answered')) for ip, f in flows.items()},
                         {'10.9.0.3': ('coap', 'yes'), '10.9.0.2': ('coap', 'ICMP error only'),
                          '10.9.0.4': ('coap', 'no'), '224.0.1.187': ('coap', None)})
        self.assertEqual(flows['10.9.0.2']['flow']['pkts_toclient'], 1, 'the ICMP error still counts as a packet back')

    def test_the_merge_gives_the_protocols_nobody_answered_one_card(self):
        """Echo was answered once, so it keeps its card; memcached's probes
        got only an ICMP error, so they're filed under Probed Only - with
        their own app_proto."""
        from tests.pcap_fixtures import write_pcap
        from tests.protocol_fixtures import _icmp_unreachable, _udp_packet
        echo = b'hello'
        memcache = b'\x00\x01\x00\x00\x00\x01\x00\x00stats\r\n'
        probe = _udp_packet('10.9.0.1', '10.9.0.2', 40005, 11211, memcache)
        packets = [_udp_packet('10.9.0.1', '10.9.0.3', 40002, 7, echo),
                   _udp_packet('10.9.0.3', '10.9.0.1', 7, 40002, echo),
                   _udp_packet('10.9.0.1', '10.9.0.4', 40003, 7, echo),
                   probe, _icmp_unreachable('10.9.0.2', '10.9.0.1', probe),
                   _udp_packet('10.9.0.1', '10.9.0.5', 40006, 11211, memcache)]
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        pcap = os.path.join(d, 'probes.pcap')
        write_pcap(pcap, packets)
        eve = os.path.join(d, 'eve.json')
        open(eve, 'w').close()
        events_db = os.path.join(d, 'events.db')
        db.create_sqlite_db(events_db, eve)
        self.assertTrue(shark_analyzer.build(d, pcap))
        self.assertEqual(shark_analyzer.probe_only_protocols(shark_analyzer.shark_db_path(d)), {'memcache'})
        shark_analyzer.merge(d)
        counts = db.get_event_types_sqlite(events_db)
        self.assertEqual((counts.get('conn_echo'), counts.get(db.PROBED_CONNECTION_TYPE)), (2, 2))
        self.assertNotIn('conn_memcache', counts)
        probed = db.query_events_sqlite(events_db, db.PROBED_CONNECTION_TYPE)
        self.assertEqual(sorted((e['app_proto'], e['shark']['answered']) for e in probed),
                         [('memcache', 'ICMP error only'), ('memcache', 'no')])


class TestFlowOrientation(unittest.TestCase):
    def _flow(self):
        return shark_analyzer._Flow(('udp', 0), 'UDP', 4, '10.0.0.53', '10.0.0.9', 53, 40000, 1.0, 0)

    def test_a_reply_first_turns_the_flow_round(self):
        flow = self._flow()
        flow.add('10.0.0.53', 53, 80, 1.0, 'dns', '', False)
        flow.orient('10.0.0.53', 53, True)
        self.assertEqual((flow.client, flow.cport, flow.server, flow.pkts_ts, flow.pkts_tc), ('10.0.0.9', 40000, '10.0.0.53', 0, 1))

    def test_only_the_first_request_or_reply_decides(self):
        flow = self._flow()
        flow.orient('10.0.0.53', 53, False)    # the first sender's request: it is the client
        flow.orient('10.0.0.53', 53, True)
        self.assertEqual(flow.client, '10.0.0.53')

    def test_a_stream_that_opens_on_a_syn_ack_is_the_other_sides(self):
        """Found in the 4SICS GeekLounge capture: a server re-sends its
        SYN-ACK after the client reset the connection, and tshark starts a
        new stream there - whose first sender is the server."""
        from tests.pcap_fixtures import _tcp_packet, write_pcap
        with tempfile.TemporaryDirectory() as tmp:
            pcap = os.path.join(tmp, 'synack.pcap')
            write_pcap(pcap, [_tcp_packet('10.0.0.80', '10.0.0.9', 80, 40000, 5000, 1001, 0x12),
                              _tcp_packet('10.0.0.9', '10.0.0.80', 40000, 80, 1001, 0, 0x04)])
            [flow] = [e for e in shark_analyzer.run_tshark(pcap) if e['event_type'] == 'flow']
        self.assertEqual((flow['src_ip'], flow['src_port'], flow['dest_port']), ('10.0.0.9', 40000, 80))
        self.assertEqual((flow['flow']['pkts_toserver'], flow['flow']['pkts_toclient']), (1, 1))

    def test_a_syn_outranks_a_message(self):
        flow = shark_analyzer._Flow(('tcp', 0), 'TCP', 4, '10.0.0.9', '10.0.0.80', 40000, 80, 1.0, 0)
        flow.add('10.0.0.9', 40000, 60, 1.0, '', '', True)
        flow.orient('10.0.0.9', 40000, True)
        self.assertEqual(flow.client, '10.0.0.9')

    def test_what_marks_a_reply(self):
        def cols(**values):
            out = [''] * len(shark_analyzer._FIRST_PASS_FIELDS)
            for name, value in values.items():
                out[shark_analyzer._COLUMN[name.replace('__', '.')]] = value
            return out
        cases = [({'dns__flags__response': 'True'}, True), ({'dns__flags__response': 'False'}, False),
                 ({'nbns__flags__response': '1'}, True), ({'http__response__code': '200'}, True),
                 ({'http__request__method': 'GET'}, False), ({'ftp__response__code': '220'}, True),
                 ({'ftp__request__command': 'USER'}, False), ({'s7comm__header__rosctr': '3'}, True),
                 ({'s7comm__header__rosctr': '1'}, False), ({'s7comm__header__rosctr': '7'}, None),
                 ({'tls__handshake__type': '2'}, True), ({'tls__handshake__type': '1\x1f16'}, False),   # the first of a packet's handshakes
                 ({'tls__handshake__type': '11'}, None), ({'ip__src': '10.0.0.1'}, None), ({}, None)]
        for values, expected in cases:
            with self.subTest(values=values):
                self.assertIs(shark_analyzer._is_reply(cols(**values)), expected)

    def test_a_255_address_that_answers_is_a_host(self):
        """In a /23 or larger, 10.1.2.255 is a host: one that answers isn't
        a broadcast address, which never does. And a broadcast is known by
        its frames' Ethernet broadcast destination, whatever its last octet."""
        def flow(server):
            return shark_analyzer._Flow(('k',), 'UDP', 4, '10.1.0.5', server, 40000, 161, 1.0, '0')
        host = flow('10.1.2.255')
        host.add('10.1.0.5', 40000, 80, 1.0, 'snmp', '', False)
        self.assertEqual(host.answered(), '', 'unanswered, it may be the broadcast address')
        host.add('10.1.2.255', 161, 120, 1.1, 'snmp', '', False)
        self.assertFalse(host.to_group())
        self.assertEqual(host.answered(), 'yes')
        subnet = flow('10.1.1.127')
        subnet.mac_broadcast = True
        subnet.add('10.1.0.5', 40000, 80, 1.0, 'snmp', '', False)
        self.assertTrue(subnet.to_group(), "a /25's broadcast, sent to ff:ff:ff:ff:ff:ff")
        self.assertEqual(subnet.answered(), '')
        limited = flow('255.255.255.255')
        limited.add('255.255.255.255', 161, 120, 1.1, 'snmp', '', False)
        self.assertTrue(limited.to_group(), '255.255.255.255 is always the broadcast')

    def test_group_addresses(self):
        self.assertEqual([shark_analyzer._is_group_address(a) for a in
                          ('224.0.0.251', '239.255.255.250', '255.255.255.255', '10.1.0.255', 'ff02::fb', '10.1.0.10', '2001:db8::1', 'aa:bb:cc:dd:ee:ff')],
                         [True, True, True, True, True, False, False, False])


class TestProtocolDetails(unittest.TestCase):
    def test_each_field_is_asked_of_tshark_once(self):
        """REGRESSION: tshark fills only one column of a field asked for
        twice - SSDP reads http.* fields that flow orientation reads too."""
        from shark_protocols import PROTOCOLS, SSDP
        for fields in (shark_analyzer._FIRST_PASS_FIELDS, shark_analyzer._protocol_pass_fields(PROTOCOLS)):
            self.assertEqual(len(fields), len(set(fields)))
        self.assertTrue(set(SSDP.fields) & set(shark_analyzer._ORIENTATION_FIELDS), 'the case this guards')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestAnalyze(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.pcap = os.path.join(self.dir, 'sample.pcap')
        with open(self.pcap, 'wb') as f:
            f.write(build_pcap_sample())
        # Server-wide, learned from a run - each test starts as a new server
        patcher = mock.patch.object(shark_analyzer, '_read_from_copy', False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_writes_a_queryable_shark_db_and_nothing_else(self):
        shark_analyzer.analyze(self.dir, self.pcap)
        db_path = shark_analyzer.shark_db_path(self.dir)
        events = query_events_sqlite(db_path, 'flow')
        self.assertEqual(len(events), 10)  # every flow tshark grouped: HTTP/DNS/TLS/IRC/FTP/FTP-data + LLMNR/NBNS/SSDP chatter
        for et in ('llmnr', 'nbns', 'ssdp'):  # the chatter Suricata doesn't parse is recorded too
            self.assertTrue(query_events_sqlite(db_path, et), et)
        self.assertFalse(os.path.exists(os.path.join(self.dir, 'shark.db.tmp')))
        self.assertFalse(os.path.exists(os.path.join(self.dir, shark_analyzer.SHARK_ERROR)))
        status = shark_analyzer.status(self.dir, self.pcap)
        self.assertIsInstance(status.pop('seconds'), int, 'how long the run took')
        self.assertEqual(status, {'status': 'ready'})

    def test_shark_db_is_stamped_and_an_older_format_is_rebuilt(self):
        """REGRESSION: shark.db existing meant 'ready' forever, so an
        analysis built before a tshark change never got it - its
        flows-only shark.db hid the protocol records added since."""
        import sqlite3
        shark_analyzer.analyze(self.dir, self.pcap)
        db_path = shark_analyzer.shark_db_path(self.dir)
        self.assertEqual(shark_analyzer.format_version(db_path), shark_analyzer.SHARK_FORMAT_VERSION)
        conn = sqlite3.connect(db_path)
        conn.execute('PRAGMA user_version = 1')
        conn.commit()
        conn.close()
        self.assertEqual(shark_analyzer.status(self.dir, self.pcap), {'status': 'not_started'})
        self.assertFalse(os.path.exists(db_path), 'the stale database is removed so it gets rebuilt')

    def test_a_failed_run_records_why_and_leaves_no_database(self):
        with open(self.pcap, 'wb') as f:
            f.write(b'not a pcap at all')
        shark_analyzer.analyze(self.dir, self.pcap)
        self.assertFalse(os.path.exists(shark_analyzer.shark_db_path(self.dir)))
        status = shark_analyzer.status(self.dir, self.pcap)
        self.assertEqual(status['status'], 'error')
        self.assertIn('tshark failed', status['message'])

    def _denying_tshark(self, deny):
        """os.environ for a tshark that, like one under AppArmor 5's profile
        for it, may not read captures under deny ('' for anywhere) - each
        refusal noted in self.denials - and a temp directory of the test's
        own (self.tmp), so what's left in it can be checked."""
        bin_dir = os.path.join(self.dir, 'bin')
        os.makedirs(bin_dir)
        script = os.path.join(bin_dir, 'tshark')
        with open(script, 'w') as f:
            f.write('#!/bin/sh\nprev=\nfor a in "$@"; do\n'
                    '  if [ "$prev" = -r ]; then case "$a" in "$DENY"/*)\n'
                    '    echo "$a" >> "$DENY_LOG"\n'
                    '    echo "tshark: You don\'t have permission to read the file \\"$a\\"." >&2; exit 2;; esac; fi\n'
                    '  prev=$a\ndone\nexec "$REAL_TSHARK" "$@"\n')
        os.chmod(script, 0o755)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.denials = os.path.join(self.tmp, 'denials')
        patcher = mock.patch.object(tempfile, 'tempdir', self.tmp)
        patcher.start()
        self.addCleanup(patcher.stop)
        return {'PATH': bin_dir + os.pathsep + os.environ['PATH'], 'DENY': deny, 'DENY_LOG': self.denials,
                'REAL_TSHARK': shutil.which('tshark'), 'TMPDIR': self.tmp}

    def _left_in_tmp(self):
        return [name for name in os.listdir(self.tmp) if name != 'denials']

    def test_a_capture_tshark_may_not_read_in_place_is_read_from_a_copy_in_tmp(self):
        """REGRESSION: on Ubuntu 26.04, AppArmor's profile for tshark kept
        it from reading the analysis's directory - every run failed with
        'You don't have permission to read the file'."""
        with mock.patch.dict(os.environ, self._denying_tshark(self.dir)):
            shark_analyzer.analyze(self.dir, self.pcap)
        with open(self.denials) as f:
            self.assertEqual(f.read().split(), [self.pcap], 'tshark was refused the capture in place, once')
        self.assertEqual(len(query_events_sqlite(shark_analyzer.shark_db_path(self.dir), 'flow')), 10)
        self.assertEqual(shark_analyzer.status(self.dir, self.pcap)['status'], 'ready')
        self.assertEqual(self._left_in_tmp(), [], 'the copy and its folder are removed')

    def test_a_capture_tshark_may_not_read_even_in_tmp_says_so(self):
        with mock.patch.dict(os.environ, self._denying_tshark('')):
            shark_analyzer.analyze(self.dir, self.pcap)
        status = shark_analyzer.status(self.dir, self.pcap)
        self.assertEqual(status['status'], 'error')
        self.assertIn('even from a copy in', status['message'])
        self.assertIn('AppArmor', status['message'])
        self.assertEqual(self._left_in_tmp(), [])

    def test_once_tshark_is_refused_in_place_later_runs_start_from_the_copy(self):
        """REGRESSION: every run tried the capture in place first, so on a
        host where AppArmor confines tshark, each one was refused - a
        DENIED line in the kernel's log - before reading the copy."""
        with mock.patch.dict(os.environ, self._denying_tshark(self.dir)):
            shark_analyzer.analyze(self.dir, self.pcap)
            self.assertTrue(shark_analyzer._read_from_copy)
            os.unlink(shark_analyzer.shark_db_path(self.dir))
            shark_analyzer.analyze(self.dir, self.pcap)
        with open(self.denials) as f:
            self.assertEqual(f.read().split(), [self.pcap], 'refused once, for the first run only')
        self.assertEqual(shark_analyzer.status(self.dir, self.pcap)['status'], 'ready')
        self.assertEqual(self._left_in_tmp(), [])

    def test_a_run_tshark_may_read_in_place_doesnt_switch_to_copies(self):
        with mock.patch.dict(os.environ, self._denying_tshark(os.path.join(self.dir, 'elsewhere'))):
            shark_analyzer.analyze(self.dir, self.pcap)
        self.assertFalse(shark_analyzer._read_from_copy)
        self.assertEqual(shark_analyzer.status(self.dir, self.pcap)['status'], 'ready')

    def test_a_killed_run_leaves_nothing_in_tmp(self):
        """REGRESSION: a run killed (a cancel, the memory watchdog) left
        its second passes' copies of frames in /tmp - the child's own
        temp folders, which only the child removed. They're in the run's
        folder now, which analyze removes however the child ends."""
        child = ['sh', '-c', 'mkdir "$TMPDIR/shark-abcd1234" && echo frames > "$TMPDIR/shark-abcd1234/subset" '
                 '&& kill -9 $$']
        with mock.patch.dict(os.environ, self._denying_tshark('')), \
                mock.patch.object(shark_analyzer, '_child_command', return_value=child):
            shark_analyzer.analyze(self.dir, self.pcap)
        self.assertEqual(self._left_in_tmp(), [])
        self.assertIn('killed', shark_analyzer.status(self.dir, self.pcap)['message'])

    def test_the_capture_is_copied_where_it_cant_be_linked_if_there_is_room(self):
        copy_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, copy_dir, True)
        copy = os.path.join(copy_dir, 'sample.pcap')
        with mock.patch.object(shark_analyzer.os, 'link', side_effect=OSError(18, 'Invalid cross-device link')):
            shark_analyzer._place_copy(self.pcap, copy)
        with open(self.pcap, 'rb') as a, open(copy, 'rb') as b:
            self.assertEqual(a.read(), b.read())
        self.assertNotEqual(os.stat(copy).st_ino, os.stat(self.pcap).st_ino, 'a copy, not a link')
        os.unlink(copy)
        with mock.patch.object(shark_analyzer.os, 'link', side_effect=OSError(18, 'Invalid cross-device link')), \
                mock.patch.object(shark_analyzer.shutil, 'disk_usage', return_value=shutil._ntuple_diskusage(10, 10, 10)):
            with self.assertRaisesRegex(RuntimeError, 'too little free space for a copy'):
                shark_analyzer._place_copy(self.pcap, copy)
        self.assertFalse(os.path.exists(copy))

    @unittest.skipIf(os.geteuid() == 0, 'root can write anywhere')
    def test_a_run_that_cannot_write_its_folder_is_an_error_not_queued_again(self):
        """REGRESSION: a folder the run couldn't write (files left by a
        run as another user) had no .shark_error either, so it read as
        never started - and each status request queued it again."""
        self.addCleanup(shark_analyzer._unwritten_errors.pop, self.dir, None)
        os.chmod(self.dir, 0o555)
        try:
            shark_analyzer.analyze(self.dir, self.pcap)
            status = shark_analyzer.status(self.dir, self.pcap)
            self.assertEqual(status['status'], 'error')
            self.assertIn("couldn't write to this analysis's folder", status['message'])
            self.assertTrue(shark_analyzer.enqueue(self.dir, self.pcap), 'Try again still queues it')
            self.assertTrue(shark_analyzer.wait_idle())
            self.assertEqual(shark_analyzer.status(self.dir, self.pcap)['status'], 'error', 'and fails the same way')
        finally:
            os.chmod(self.dir, 0o755)
        shark_analyzer.cancel(self.dir)
        self.assertEqual(shark_analyzer.status(self.dir, self.pcap)['status'], 'not_started',
                         'cancel (reanalyze, delete) forgets it')

    @unittest.skipIf(os.geteuid() == 0, 'root can write anywhere')
    def test_an_unwritable_folder_with_an_older_shark_db_is_an_error_too(self):
        """The older shark.db status() can't remove is no sign the run worked."""
        self.addCleanup(shark_analyzer._unwritten_errors.pop, self.dir, None)
        shark_analyzer.analyze(self.dir, self.pcap)
        db_path = shark_analyzer.shark_db_path(self.dir)
        conn = sqlite3.connect(db_path)
        conn.execute('PRAGMA user_version = 1')
        conn.commit()
        conn.close()
        os.chmod(self.dir, 0o555)
        try:
            self.assertEqual(shark_analyzer.status(self.dir, self.pcap), {'status': 'not_started'})
            shark_analyzer.analyze(self.dir, self.pcap)
            self.assertEqual(shark_analyzer.status(self.dir, self.pcap)['status'], 'error')
        finally:
            os.chmod(self.dir, 0o755)

    def test_timeout(self):
        with mock.patch.object(shark_analyzer, 'tshark_command', return_value=['sleep', '30']):
            start = time.monotonic()
            with self.assertRaisesRegex(RuntimeError, 'timed out after 0.3s'):
                shark_analyzer.run_tshark(self.pcap, timeout=0.3)
        self.assertLess(time.monotonic() - start, 10)

    def test_background_limit_is_a_packet_count(self):
        """tshark's memory follows packets, not bytes: the limit counts them."""
        self.assertEqual(shark_analyzer.packet_count(self.pcap), 111)
        self.assertTrue(shark_analyzer.background_eligible(self.pcap))
        with mock.patch.object(config, 'SHARK_BACKGROUND_MAX_PACKETS', 110):
            self.assertFalse(shark_analyzer.background_eligible(self.pcap))
            self.assertEqual(shark_analyzer.status(self.dir, self.pcap), {'status': 'too_large'})
        with mock.patch.object(config, 'SHARK_BACKGROUND_MAX_BYTES', 10):
            self.assertTrue(shark_analyzer.background_eligible(self.pcap), 'the file size no longer decides')
        self.assertFalse(shark_analyzer.background_eligible(os.path.join(self.dir, 'missing.pcap')))

    def test_without_capinfos_the_size_decides(self):
        real_which = shutil.which
        with mock.patch.object(shark_analyzer.shutil, 'which', side_effect=lambda n: None if n == 'capinfos' else real_which(n)):
            shark_analyzer._PACKET_COUNTS.clear()
            self.assertIsNone(shark_analyzer.packet_count(self.pcap))
            with mock.patch.object(config, 'SHARK_BACKGROUND_MAX_BYTES', 10):
                self.assertFalse(shark_analyzer.background_eligible(self.pcap))
        shark_analyzer._PACKET_COUNTS.clear()


def _row(event_type, cid='1:a', when='2026-01-01T00:00:10.000000+0000', app=None, end=None):
    e = {'event_type': event_type, 'community_id': cid, 'timestamp': when}
    if event_type == 'flow':
        e.update(app_proto=app or '', flow={'start': when, 'end': end or when})
    else:
        e[event_type] = {}
    return json.dumps(e)


class TestIsoTimes(unittest.TestCase):
    def test_iso_matches_datetimes_rounding(self):
        """_iso makes each second's text once - and rounds the
        microseconds as datetime does, half to even."""
        from datetime import datetime, timezone
        for epoch in (0.0, 1700000000.0, 1445494156.123456, 1445494156.9999995, 1445494156.0000005,
                      1445494156.0000015, 1445494156.9999999, 2 ** 31 + 0.5e-6, 1767225599.999999, -1.5):
            self.assertEqual(shark_analyzer._iso(epoch),
                             datetime.fromtimestamp(epoch, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f+0000'),
                             repr(epoch))


class TestHostileInput(unittest.TestCase):
    """What a capture's own contents mustn't be able to do: fail the whole
    run, or put secret material in a record."""

    def test_a_ripv2_keyed_digest_never_comes_out_as_routes(self):
        """An HMAC-SHA-512 trailer (RFC 4822) runs past one entry's 20
        bytes - read on past it, the digest's bytes were routes."""
        from shark_protocols import _rip_entries
        digest = bytes(range(0xa0, 0xa0 + 64))
        message = (bytes([2, 2, 0, 0])
                   + struct.pack('!HHHBBI', 0xffff, 3, 100, 1, 68, 7) + bytes(8)          # keyed authentication
                   + struct.pack('!HH', 2, 0) + socket.inet_aton('10.2.0.0') + socket.inet_aton('255.255.0.0')
                   + bytes(4) + struct.pack('!I', 1)
                   + struct.pack('!HH', 0xffff, 1) + digest)                               # the trailer
        command, version, auth, entries = _rip_entries(message)
        self.assertEqual(auth, 'keyed MD5')
        self.assertEqual([e[1] for e in entries], ['10.2.0.0/16'], 'the route, and nothing after the trailer')

    def test_an_opcua_user_management_calls_arguments_are_not_kept(self):
        """AddUser, ModifyUser, ChangePassword (OPC UA Part 18) take a
        password as an argument: the call is recorded, its arguments' values
        aren't - nor a vendor method's that's named for passwords or users."""
        from shark_protocols import _opcua_secret_method
        self.assertTrue(_opcua_secret_method('i=24301', ''))
        self.assertTrue(_opcua_secret_method('ns=2;s=Admin.ChangePassword', ''))
        self.assertTrue(_opcua_secret_method('ns=1;i=7', 'ns=3;s=UserManager'))
        self.assertFalse(_opcua_secret_method('ns=1;s=Pump.Start', 'ns=1;s=Pump'))
        self.assertFalse(_opcua_secret_method('ns=1;i=24301', 'i=85'), "another namespace's 24301 is no user management")

    def test_telnet_records_the_last_login_attempt_and_any_secret_prompt(self):
        """A failed login and then one the server took is that one's record,
        the failure counted; a secret typed at a later prompt (a PIN, an
        enable secret) is kept nowhere - nor as one of the lines typed."""
        from shark_protocols import Telnet, Packet
        telnet = Telnet()
        flow = shark_analyzer._Flow(('k',), 'TCP', 4, '10.0.0.5', '10.0.0.9', 40000, 23, 1.0, '0')
        server = lambda text: telnet.feed(Packet(1, 1.0, flow, 23, 40000), {'telnet.data': [text]})
        client = lambda text: telnet.feed(Packet(1, 1.0, flow, 40000, 23), {'telnet.data': [text]})
        server('Router\r\nlogin: '), client('admin\r'), server('Password: '), client('wrong\r')
        server('Login incorrect\r\nlogin: '), client('root\r'), server('Password: '), client('right\r')
        server('Enter PIN: '), client('1234\r'), server('# '), client('show run\r')
        body = telnet.finish()[0][3]
        self.assertEqual({k: body.get(k) for k in ('username', 'password', 'login', 'earlier_failures', 'commands')},
                         {'username': 'root', 'password': 'right', 'login': None, 'earlier_failures': 1,
                          'commands': ['show run']})
        self.assertNotIn('1234', json.dumps(body))
        # Enter alone at the prompts after a login is no attempt of its own:
        # the login typed stands (seen in the 4SICS captures)
        telnet = Telnet()
        server('login: '), client('admin\r'), server('Password: '), client('s3cret\r'), server('$ exit\r\nlogin: ')
        client('\r'), server('Password: '), client('\r')
        body = telnet.finish()[0][3]
        self.assertEqual((body.get('username'), body.get('password')), ('admin', 's3cret'))

    def test_bytes_and_escapes_that_arent_what_they_should_be_dont_fail_the_run(self):
        from shark_protocols import _dict, _hex
        self.assertEqual((_hex('41:42'), _hex('4142'), _hex(''), _hex('zz'), _hex('4')), (b'AB', b'AB', b'', b'', b''))
        self.assertEqual((_dict({'a': 1}), _dict('text'), _dict(None)), ({'a': 1}, {}, {}))
        self.assertEqual(shark_analyzer._unescape('a\\x41b\\xzz\\tc'), 'aAbxzz\tc')

    def test_a_transaction_id_reused_after_its_answer_is_a_new_transaction(self):
        """NBNS and DHCPv6, like LLMNR: a request after its transaction's
        answer is a new transaction, not a retransmission folded into the
        old one - a retransmission before the answer still is."""
        from shark_protocols import DHCPv6, NBNS, Packet
        flow = shark_analyzer._Flow(('k',), 'UDP', 4, '10.0.0.5', '10.0.0.255', 137, 137, 1.0, '0')
        nbns = NBNS()
        ask = dict({f: [] for f in NBNS.fields}, **{'nbns.id': ['0x10'], 'nbns.flags.response': ['False'],
                                                     'nbns.name': ['WPAD<00>']})
        answer = dict(ask, **{'nbns.flags.response': ['True'], 'nbns.flags.rcode': ['0']})
        asker = Packet(1, 1.0, flow, 137, 137, 'nbns', '10.0.0.5', '10.0.0.255')
        answerer = Packet(2, 1.1, flow, 137, 137, 'nbns', '10.0.0.9', '10.0.0.5')
        for packet, fields in ((asker, ask), (asker, ask), (answerer, answer), (asker, ask)):
            nbns.feed(packet, fields)
        self.assertEqual([(b['type'], b.get('transmissions')) for _, _, _, b in nbns.finish()],
                         [('response', 2), ('request', 1)])
        dhcp = DHCPv6()
        solicit = dict({f: [] for f in DHCPv6.fields}, **{'dhcpv6.msgtype': ['1'], 'dhcpv6.xid': ['0x00abcd']})
        advertise = dict(solicit, **{'dhcpv6.msgtype': ['2']})
        client = Packet(1, 1.0, flow, 546, 547, 'dhcpv6', 'fe80::5', 'ff02::1:2')
        server = Packet(2, 1.1, flow, 547, 546, 'dhcpv6', 'fe80::9', 'fe80::5')
        for packet, fields in ((client, solicit), (server, advertise), (client, solicit)):
            dhcp.feed(packet, fields)
        self.assertEqual([(b.get('message'), b.get('reply')) for _, _, _, b in dhcp.finish()],
                         [('Solicit', 'Advertise'), ('Solicit', None)])

    @unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
    def test_s7_pdus_sharing_a_packet_each_get_their_own_fields(self):
        """REGRESSION: a packet's fields were read by PDU position - but an
        ack's error class is listed only for acks, a userdata's function
        group only for userdata - so after a userdata PDU an ack_data's
        error was read from the wrong place and missed."""
        from tests.pcap_fixtures import tcp_segments, write_pcap
        from tests.protocol_fixtures import CLIENT, S7_PLC, _s7_ack, _s7_job, _tpkt_s7
        read_item = b'\x12\x0a\x10\x02\x00\x01\x00\x01\x84' + (10 << 3).to_bytes(3, 'big')
        userdata = _tpkt_s7(struct.pack('!BBHHHH', 0x32, 7, 0, 4, 8, 8) + b'\x00\x01\x12\x04\x11\x44\x01\x00'
                            + b'\xff\x09\x00\x04\x00\x11\x00\x00')
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        pcap = os.path.join(d, 's7.pcap')
        write_pcap(pcap, tcp_segments(CLIENT, S7_PLC, 41100, 102, [
            (True, _s7_job(3, b'\x05\x01' + read_item, b'\x00\x04\x00\x08\x07')),
            (False, userdata + _s7_ack(3, b'\x05\x01', b'\x0a', errcls=0x85, errcod=0x04)),
            (True, _s7_job(5, b'\x04\x01' + read_item) + userdata)]))
        records = [r['s7comm'] for r in shark_analyzer.run_tshark(pcap) if r['event_type'] == 's7comm']
        write = next(r for r in records if r.get('pdu_ref') == 3)
        self.assertEqual((write['response'].get('error_class'), write['response'].get('error_code')),
                         ('Error on supplies', 4))
        self.assertEqual([r['function_group'] for r in records if r['type'] == 'userdata'],
                         ['CPU functions', 'CPU functions'], 'a userdata second in its packet too')

    def test_bacnet_requests_awaiting_replies_are_capped(self):
        """The routed device is part of a pending request's key, so a flood
        of reads naming made-up devices grew it per packet - capped, the
        oldest dropped."""
        import shark_protocols
        bacnet = shark_protocols.BACnet()
        for i in range(shark_protocols._BACNET_MAX_PENDING + 5):
            bacnet._wait(('flow', i, 1), ('readProperty', 'read', None))
        self.assertEqual(len(bacnet.pending), shark_protocols._BACNET_MAX_PENDING)
        self.assertNotIn(('flow', 0, 1), bacnet.pending)
        self.assertIn(('flow', shark_protocols._BACNET_MAX_PENDING + 4, 1), bacnet.pending)

    def test_a_measurement_that_isnt_a_finite_number_stays_text(self):
        """A sensor's NaN or infinity - which JSON can't hold - kept as
        tshark wrote it, not stored as invalid JSON."""
        from shark_protocols import _finite
        self.assertEqual([_finite(t) for t in ('21.5', 'nan', 'inf', '-inf', 'x')], [21.5, 'nan', 'inf', '-inf', 'x'])
        self.assertEqual(json.loads(json.dumps({'v': _finite('nan')})), {'v': 'nan'})

    def test_a_timestamp_past_the_year_9999_is_clamped(self):
        for epoch, text in ((1e15, '9999-12-31T23:59:59.999999+0000'), (float('inf'), '9999-12-31T23:59:59.999999+0000'),
                            (-1e15, '0001-01-01T00:00:00.000000+0000'), (float('nan'), '0001-01-01T00:00:00.000000+0000')):
            self.assertEqual(shark_analyzer._iso(epoch), text)

    @unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
    def test_a_capture_cut_off_mid_packet_keeps_what_was_read(self):
        """tshark exits 2 at a capture's cut-off end, having read every
        packet before it - a partial upload, a capture stopped mid-write."""
        from tests.protocol_fixtures import write_extra_pcap
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        whole, cut = os.path.join(d, 'whole.pcap'), os.path.join(d, 'cut.pcap')
        write_extra_pcap(whole)
        with open(whole, 'rb') as f:
            data = f.read()
        with open(cut, 'wb') as f:
            f.write(data[:-10])
        records = shark_analyzer.run_tshark(cut)
        self.assertTrue(any(r['event_type'] == 's7comm' for r in records))
        self.assertTrue(shark_analyzer.build(d, cut))
        self.assertTrue(shark_analyzer.status(d)['damaged'], 'and the page is told the capture was cut off')
        whole_dir = os.path.join(d, 'whole')
        os.makedirs(whole_dir)
        self.assertTrue(shark_analyzer.build(whole_dir, whole))
        self.assertNotIn('damaged', shark_analyzer.status(whole_dir))
        self.assertFalse(shark_analyzer._read_to_damage(1, 'appears to have been cut short in the middle of a packet'))
        self.assertFalse(shark_analyzer._read_to_damage(2, 'tshark: Some other failure'))

    def test_llmnr_drops_an_answered_query_by_its_own_key(self):
        """Answered, a query leaves the unanswered ones - looked up by its
        key, not by rebuilding them all for each answer."""
        from shark_protocols import LLMNR, Packet
        llmnr = LLMNR()
        flow = shark_analyzer._Flow(('k',), 'UDP', 4, '10.0.0.5', '224.0.0.252', 50000, 5355, 1.0, '0')
        fields = {f: [] for f in LLMNR.fields}
        query = dict(fields, **{'dns.id': ['0x1'], 'dns.qry.name': ['wpad'], 'dns.qry.type': ['1'],
                                'dns.flags.response': ['False']})
        for port in range(50000, 50100):
            llmnr.feed(Packet(port, 1.0, flow, port, 5355, 'llmnr', '10.0.0.5', '224.0.0.252'), query)
        answer = dict(query, **{'dns.flags.response': ['True'], 'dns.flags.rcode': ['0']})
        llmnr.feed(Packet(9999, 1.1, flow, 5355, 50007, 'llmnr', '10.0.0.9', '10.0.0.5'), answer)
        self.assertEqual(len(llmnr.unanswered), 99)
        self.assertEqual(len(llmnr.unanswered_keys), 99)


class TestMergeRows(unittest.TestCase):
    """Which of a shark.db's rows join Suricata's in events.db."""
    SURICATA = {'1:http': [(1767225600.0, 1767225620.0)]}     # a flow Suricata called HTTP, 00:00:00-00:00:20

    def _kept(self, rows):
        return [(e['event_type'], e.get('app_proto')) for e in shark_analyzer.merge_rows(rows, self.SURICATA)]

    def test_records_of_protocols_suricata_lacks_and_none_of_its_own(self):
        self.assertEqual(self._kept([_row('s7comm'), _row('nbns'), _row('llmnr'), _row('ssdp'),
                                     _row('dns'), _row('http'), _row('smb'), _row('ftp_data'), _row('mdns')]),
                         [('s7comm', None), ('nbns', None), ('llmnr', None), ('ssdp', None)])

    def test_tls_failures_stay_on_flows_suricata_identified_with_its_certificate(self):
        """Suricata logs no TLS alerts, so its word on the flow doesn't
        stand in for them - and its tls record of the connection, the
        nearest in time, says which certificate."""
        rows = [_row('tls_failure', cid='1:http'), _row('tls_failure', cid='1:other')]
        asked = []

        def tls_records(cids):
            asked.append(cids)
            return {'1:http': [(1767225000.0, {'sni': 'earlier.example'}), (1767225609.0, {'sni': 'b.example'})]}
        kept = list(shark_analyzer.merge_rows(rows, self.SURICATA, tls_records=tls_records))
        self.assertEqual([e['tls_failure'] for e in kept], [{'sni': 'b.example'}, {}])
        far = lambda cids: {'1:http': [(1767225610.0 + 3600, {'sni': 'an-hour-later.example'})]}
        self.assertEqual([e['tls_failure'] for e in shark_analyzer.merge_rows(rows, self.SURICATA, tls_records=far)],
                         [{}, {}], "a tls record an hour away is the reused 5-tuple's, not this connection's")
        self.assertEqual(asked, [{'1:http', '1:other'}], 'one lookup, for all of them')
        self.assertEqual(len(list(shark_analyzer.merge_rows(rows, self.SURICATA))), 2)

    def test_flows_become_connection_rows_only_for_protocols_with_nothing_else(self):
        self.assertEqual(self._kept([_row('flow', app='openvpn'), _row('flow', app='wol'),
                                     _row('flow', app='telnet'), _row('flow', app='http'), _row('flow', app='arp'),
                                     _row('flow', app='s7comm'), _row('flow', app='syslog'), _row('flow', app='')]),
                         [('conn_openvpn', 'openvpn'), ('conn_wol', 'wol')],
                         "telnet, http and arp are Suricata's; s7comm and syslog have records; '' is no protocol")

    def test_nothing_on_a_flow_suricata_gave_a_protocol(self):
        """The 4SICS case: a scanner's HTTP request to the rsh port is HTTP
        to Suricata and rsh to tshark - Suricata's word stands."""
        self.assertEqual(self._kept([_row('flow', cid='1:http', app='rsh'), _row('nbns', cid='1:http'),
                                     _row('flow', cid='1:http', app='rsh', when='2026-01-01T01:00:00.000000+0000'),
                                     _row('flow', cid='1:other', app='rsh')]),
                         [('conn_rsh', 'rsh'), ('conn_rsh', 'rsh')],
                         'the same Community ID an hour later is another connection; another ID is too')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestMerge(unittest.TestCase):
    """shark_analyzer.merge: tshark's rows into the analysis's events.db,
    built here from Suricata's output for the extra fixture capture."""

    def setUp(self):
        from tests.protocol_fixtures import write_extra_pcap
        self.dir = tempfile.mkdtemp()
        self.pcap = os.path.join(self.dir, 'extra.pcap')
        write_extra_pcap(self.pcap)
        self.events_db = os.path.join(self.dir, 'events.db')
        db.create_sqlite_db(self.events_db, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                         'extra_fixture.eve.json'))
        self.suricata_counts = db.get_event_types_sqlite(self.events_db)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _added(self):
        after = db.get_event_types_sqlite(self.events_db)
        return {t: n - self.suricata_counts.get(t, 0) for t, n in after.items() if n != self.suricata_counts.get(t, 0)}

    def test_adds_what_suricata_lacks_once_both_are_done(self):
        self.assertIsNone(shark_analyzer.merge(self.dir), 'no shark.db yet')
        self.assertTrue(shark_analyzer.build(self.dir, self.pcap))
        with open(os.path.join(self.dir, '.phase'), 'w') as f:
            f.write('importing')
        self.assertIsNone(shark_analyzer.merge(self.dir), "Suricata isn't done")
        os.unlink(os.path.join(self.dir, '.phase'))
        self.assertEqual(shark_analyzer.merge(self.dir), 10)
        self.assertEqual(self._added(), {'s7comm': 4, 'ssdp': 3, 'nbns': 2, 'llmnr': 1},
                         "tshark's DNS, mDNS, HTTP and FTP records stay out - Suricata has those")
        self.assertTrue(shark_analyzer.merged(self.dir))
        self.assertEqual(db.tshark_types(self.events_db), ['llmnr', 'nbns', 's7comm', 'ssdp'], 'the cards marked as tshark\'s')
        self.assertIsNone(shark_analyzer.merge(self.dir), 'the same shark.db is merged once')

    def test_a_new_shark_db_replaces_the_rows_of_the_last(self):
        self.assertTrue(shark_analyzer.build(self.dir, self.pcap))
        shark_analyzer.merge(self.dir)
        time.sleep(0.01)
        self.assertTrue(shark_analyzer.build(self.dir, self.pcap))     # a retried run
        self.assertFalse(shark_analyzer.merged(self.dir))
        self.assertEqual(shark_analyzer.merge(self.dir), 10)
        self.assertEqual(self._added(), {'s7comm': 4, 'ssdp': 3, 'nbns': 2, 'llmnr': 1}, 'replaced, not added twice')
        self.assertEqual(db.get_event_types_sqlite(self.events_db, 'FILESERVER').get('nbns'), 1,
                         'search finds them (the full-text index was updated both times)')

    def test_shark_db_is_a_staging_store_without_search_indexes(self):
        """Only the merge and probe_only_protocols read shark.db - so none
        of events.db's search indexes, which cost most of the time writing
        a big capture's records took. The merge only reads the rows it can
        keep, and finds the same ones as reading them all."""
        self.assertTrue(shark_analyzer.build(self.dir, self.pcap))
        shark_db = shark_analyzer.shark_db_path(self.dir)
        with closing(sqlite3.connect(shark_db)) as conn:
            names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'index') "
                                                "AND name NOT LIKE 'sqlite_%'")}
        self.assertEqual(names, {'events', 'idx_event_type', 'shark_run'}, 'no full-text index, no address indexes')
        identified = db.suricata_identified_flows(self.events_db)
        everything = list(shark_analyzer.merge_rows(db.iter_events_json(shark_db), identified))
        prefiltered = list(shark_analyzer.merge_rows(shark_analyzer._mergeable_rows(shark_db), identified))
        self.assertEqual(prefiltered, everything)
        self.assertLess(sum(1 for _ in shark_analyzer._mergeable_rows(shark_db)),
                        sum(1 for _ in db.iter_events_json(shark_db)), 'the flows Suricata has are left unread')

    def test_a_later_pass_that_fails_fails_the_run(self):
        """The protocol pass runs alongside the writing of the flows - its
        error still reaches the caller, after the flows."""
        with mock.patch.object(shark_analyzer, '_protocol_pass', side_effect=RuntimeError('tshark (protocol pass) boom')):
            with self.assertRaisesRegex(RuntimeError, 'boom'):
                shark_analyzer.run_tshark(self.pcap)
            self.assertFalse(shark_analyzer.build(self.dir, self.pcap))
        with open(os.path.join(self.dir, shark_analyzer.SHARK_ERROR)) as f:
            self.assertIn('boom', f.read())

    def test_a_consumer_that_fails_stops_the_later_passes(self):
        """REGRESSION: a shark.db write that failed mid-flows (a full
        disk) waited out the protocol pass - up to the run's whole
        timeout - with the queue held up behind it. The passes are killed,
        and the consumer's own error is the one raised."""
        def slow_pass(*args, on_start=None, **kwargs):
            proc = subprocess.Popen(['sleep', '30'])
            on_start(proc)
            proc.wait()
            raise RuntimeError('tshark (protocol pass) exit code -9')

        def failing_consumer(records):
            for _ in records:
                raise OSError('disk full')
        started = time.monotonic()
        with mock.patch.object(shark_analyzer, '_protocol_pass', side_effect=slow_pass):
            with self.assertRaisesRegex(OSError, 'disk full'):
                shark_analyzer.run_tshark(self.pcap, consume=failing_consumer)
        self.assertLess(time.monotonic() - started, 15)

    def test_the_queue_merges_when_its_run_finishes(self):
        shark_analyzer.enqueue(self.dir, self.pcap)
        self.assertTrue(shark_analyzer.wait_idle(30))
        self.assertTrue(shark_analyzer.merged(self.dir))
        self.assertEqual(self._added().get('s7comm'), 4)

    def test_a_bare_suricata_label_doesnt_keep_tshark_out(self):
        """Suricata 8.0.6 labelled the fixture's SSDP NOTIFY flow 'sip' but
        logged no SIP: the label alone doesn't make it Suricata's flow."""
        flows = [json.loads(line) for line in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data',
                                                                'extra_fixture.eve.json')) if '"app_proto":"sip"' in line]
        self.assertEqual(len(flows), 1)
        self.assertNotIn(flows[0]['community_id'], db.suricata_identified_flows(self.events_db))

    def test_connection_rows_have_their_own_tab_but_stay_out_of_all_events(self):
        from tests.pcap_fixtures import write_pcap
        from tests.protocol_fixtures import _udp_packet
        wake = os.path.join(self.dir, 'wol.pcap')        # a Wake-on-LAN magic packet
        write_pcap(wake, [_udp_packet('10.1.0.10', '10.1.0.99', 40009, 40000, b'\xff' * 6 + bytes.fromhex('001b21000099') * 16)])
        os.replace(wake, self.pcap)
        self.assertTrue(shark_analyzer.build(self.dir, self.pcap))
        shark_analyzer.merge(self.dir)
        self.assertEqual(self._added(), {'conn_wol': 1})
        self.assertEqual([e['event_type'] for e in db.query_events_sqlite(self.events_db, 'conn_wol')], ['conn_wol'])
        self.assertNotIn('conn_wol', {e['event_type'] for e in db.query_events_sqlite(self.events_db, limit=100000)},
                         "it's a connection Suricata's own flow row already lists")
        [row] = db.query_events_sqlite(self.events_db, 'conn_wol')
        self.assertEqual(row['shark']['answered'], 'no',
                         'unanswered, as a wake-up always is - which is why it keeps its card, not Probed Only')


class TestSettingsSwitch(unittest.TestCase):
    def test_on_unless_turned_off_and_survives_a_bad_file(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertTrue(shark_analyzer.enabled(d))
            shark_analyzer.set_enabled(d, False)
            self.assertFalse(shark_analyzer.enabled(d))
            shark_analyzer.set_enabled(d, True)
            self.assertTrue(shark_analyzer.enabled(d))
            with open(os.path.join(d, shark_analyzer.SHARK_SETTINGS), 'w') as f:
                f.write('not json')
            self.assertTrue(shark_analyzer.enabled(d), 'an unreadable setting leaves it on')

    def test_suricatas_completion_queues_shar_crates_only_when_on(self):
        import inspect
        import suricata_analyzer
        src = inspect.getsource(suricata_analyzer.spawn_suricata)
        self.assertIn('shark_analyzer.enabled(data_dir) and shark_analyzer.background_eligible(pcap_path)', src)


class TestQueue(unittest.TestCase):
    def setUp(self):
        self.dirs = [tempfile.mkdtemp() for _ in range(2)]
        self.pcaps = []
        for d in self.dirs:
            p = os.path.join(d, 'x.pcap')
            open(p, 'wb').close()
            self.pcaps.append(p)

    def tearDown(self):
        for d in self.dirs:
            shark_analyzer.cancel(d)
        self.assertTrue(shark_analyzer.wait_idle(15))
        for d in self.dirs:
            shutil.rmtree(d, ignore_errors=True)

    def test_one_run_at_a_time_in_order_and_no_duplicates(self):
        gate, order = threading.Event(), []

        def fake(dir_path, pcap_path, on_start=None):
            order.append(dir_path)
            gate.wait(10)
        with mock.patch.object(shark_analyzer, 'analyze', side_effect=fake):
            self.assertTrue(shark_analyzer.enqueue(self.dirs[0], self.pcaps[0]))
            self.assertTrue(shark_analyzer.enqueue(self.dirs[1], self.pcaps[1]))
            self.assertFalse(shark_analyzer.enqueue(self.dirs[1], self.pcaps[1]), 'already queued')
            deadline = time.monotonic() + 5
            while shark_analyzer.status(self.dirs[0])['status'] != 'running' and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertEqual(shark_analyzer.status(self.dirs[0]), {'status': 'running', 'elapsed': 0})
            self.assertFalse(shark_analyzer.enqueue(self.dirs[0], self.pcaps[0]), 'already running')
            self.assertEqual(shark_analyzer.status(self.dirs[1]), {'status': 'queued', 'position': 1})
            gate.set()
            self.assertTrue(shark_analyzer.wait_idle(10))
        self.assertEqual(order, self.dirs)

    def test_a_run_reports_its_seconds_while_running_and_once_ready(self):
        gate = threading.Event()

        def fake(dir_path, pcap_path, on_start=None):
            gate.wait(10)
        with mock.patch.object(shark_analyzer, 'analyze', side_effect=fake):
            shark_analyzer.enqueue(self.dirs[0], self.pcaps[0])
            deadline = time.monotonic() + 5
            while shark_analyzer.status(self.dirs[0])['status'] != 'running' and time.monotonic() < deadline:
                time.sleep(0.02)
            with mock.patch.object(shark_analyzer.time, 'time', return_value=shark_analyzer._running_since + 42.7):
                self.assertEqual(shark_analyzer.status(self.dirs[0]), {'status': 'running', 'elapsed': 42})
            gate.set()
            self.assertTrue(shark_analyzer.wait_idle(10))

    @unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
    def test_a_built_shark_db_records_how_long_its_run_took(self):
        from tests.protocol_fixtures import write_protocol_pcap
        write_protocol_pcap(self.pcaps[0])
        # the build's start, tshark's deadline, then the build's end
        with mock.patch.object(shark_analyzer.time, 'monotonic', side_effect=[100.0, 100.0] + [117.4] * 50):
            self.assertTrue(shark_analyzer.build(self.dirs[0], self.pcaps[0]))
        self.assertEqual(shark_analyzer.status(self.dirs[0]), {'status': 'ready', 'seconds': 17})

    def test_a_shark_db_without_its_run_time_is_still_ready(self):
        """Built before runs recorded their time: no 'seconds', no error."""
        import sqlite3
        conn = sqlite3.connect(shark_analyzer.shark_db_path(self.dirs[0]))
        conn.execute(f'PRAGMA user_version = {shark_analyzer.SHARK_FORMAT_VERSION}')
        conn.close()
        self.assertEqual(shark_analyzer.status(self.dirs[0]), {'status': 'ready'})

    def test_cancel_drops_a_queued_run(self):
        gate, ran = threading.Event(), []

        def fake(dir_path, pcap_path, on_start=None):
            ran.append(dir_path)
            gate.wait(10)
        with mock.patch.object(shark_analyzer, 'analyze', side_effect=fake):
            shark_analyzer.enqueue(self.dirs[0], self.pcaps[0])
            shark_analyzer.enqueue(self.dirs[1], self.pcaps[1])
            shark_analyzer.cancel(self.dirs[1])
            self.assertEqual(shark_analyzer.status(self.dirs[1]), {'status': 'not_started'})
            gate.set()
            self.assertTrue(shark_analyzer.wait_idle(10))
        self.assertEqual(ran, [self.dirs[0]])

    def test_cancel_kills_a_running_build_and_its_tshark_without_recording_an_error(self):
        """The build runs in a child process with tshark as its own child:
        cancelling kills the whole process group, so neither outlives it."""
        marker = os.path.join(self.dirs[0], 'grandchild.pid')
        with mock.patch.object(shark_analyzer, '_child_command',
                               return_value=['sh', '-c', f'sleep 30 & echo $! > {marker}; wait']):
            shark_analyzer.enqueue(self.dirs[0], self.pcaps[0])
            deadline = time.monotonic() + 5
            while not (os.path.exists(marker) and os.path.getsize(marker)) and time.monotonic() < deadline:
                time.sleep(0.02)
            grandchild = int(open(marker).read())
            start = time.monotonic()
            shark_analyzer.cancel(self.dirs[0])
            self.assertTrue(shark_analyzer.wait_idle(10))
        self.assertLess(time.monotonic() - start, 5)
        deadline = time.monotonic() + 5
        while os.path.exists(f'/proc/{grandchild}') and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertFalse(os.path.exists(f'/proc/{grandchild}'), "the build's own child (tshark) was killed too")
        self.assertFalse(os.path.exists(os.path.join(self.dirs[0], shark_analyzer.SHARK_ERROR)))
        self.assertFalse(os.path.exists(shark_analyzer.shark_db_path(self.dirs[0])))

    def test_a_run_queued_right_after_a_cancel_still_runs(self):
        """REGRESSION: reanalyze cancels the running build and queues the
        new run at once - while the killed one was still being stopped
        (still 'running'), the new run was refused, and only a later
        status poll ever started it."""
        marker = os.path.join(self.dirs[0], 'started')
        with mock.patch.object(shark_analyzer, '_child_command',
                               return_value=['sh', '-c', f'echo x >> {marker}; sleep 30']):
            shark_analyzer.enqueue(self.dirs[0], self.pcaps[0])
            deadline = time.monotonic() + 5
            while not os.path.exists(marker) and time.monotonic() < deadline:
                time.sleep(0.02)
            shark_analyzer.cancel(self.dirs[0])
            self.assertTrue(shark_analyzer.enqueue(self.dirs[0], self.pcaps[0]), 'queued behind the cancelled run')
            self.assertFalse(shark_analyzer.enqueue(self.dirs[0], self.pcaps[0]), 'but only once')
            deadline = time.monotonic() + 10
            while open(marker).read().count('x') < 2 and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertEqual(open(marker).read().count('x'), 2, 'the new run started')
            shark_analyzer.cancel(self.dirs[0])
            self.assertTrue(shark_analyzer.wait_idle(10))

    def test_a_build_that_passes_the_memory_limit_is_stopped(self):
        """The limit covers the build and everything in its process group
        (tshark): here a child of the build is the one that grows."""
        grow = [sys.executable, '-c', 'import subprocess, sys; subprocess.run([sys.executable, "-c", '
                '"import time; x = bytearray(300 * 1024 * 1024); time.sleep(30)"])']
        with mock.patch.object(shark_analyzer, '_child_command', return_value=grow), \
                mock.patch.object(config, 'SHARK_MAX_MEMORY_BYTES', 100 * 1024 * 1024), \
                mock.patch.object(config, 'SHARK_MEMORY_CHECK_SECONDS', 0.05):
            start = time.monotonic()
            shark_analyzer.analyze(self.dirs[0], self.pcaps[0])
        self.assertLess(time.monotonic() - start, 15, 'stopped, not left to sleep')
        status = shark_analyzer.status(self.dirs[0])
        self.assertEqual(status['status'], 'error')
        self.assertIn('more than 0.0976562 GB of memory', status['message'])

    def test_a_build_that_dies_without_saying_why_is_recorded_as_an_error(self):
        """Killed (out of memory, most often) or crashed: the build never
        got to write .shark_error, so analyze does."""
        for command, expected in ((['sh', '-c', 'kill -9 $$'], 'tshark analysis stopped: killed - out of memory?'),
                                  (['sh', '-c', 'echo "MemoryError: boom" >&2; exit 1'], 'tshark analysis stopped: MemoryError: boom')):
            with self.subTest(command=command), mock.patch.object(shark_analyzer, '_child_command', return_value=command):
                shark_analyzer.analyze(self.dirs[0], self.pcaps[0])
                self.assertEqual(shark_analyzer.status(self.dirs[0]), {'status': 'error', 'message': expected})

    @unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
    def test_the_build_runs_in_its_own_lower_priority_process(self):
        from tests.protocol_fixtures import write_protocol_pcap
        write_protocol_pcap(self.pcaps[0])
        seen = {}
        real_popen = subprocess.Popen

        def spy(cmd, **kwargs):
            seen.update(cmd=cmd, kwargs=kwargs)
            return real_popen(cmd, **kwargs)
        with mock.patch.object(shark_analyzer.subprocess, 'Popen', side_effect=spy):
            shark_analyzer.analyze(self.dirs[0], self.pcaps[0])
        self.assertEqual(seen['cmd'][-4:], ['shark_analyzer', 'build', self.dirs[0], self.pcaps[0]])
        self.assertTrue(seen['kwargs']['start_new_session'])
        self.assertIs(seen['kwargs']['preexec_fn'], shark_analyzer._low_priority)
        self.assertEqual(shark_analyzer.status(self.dirs[0])['status'], 'ready')


@unittest.skipUnless(HAS_TSHARK, 'tshark not installed')
class TestSharkAPI(unittest.TestCase):
    """GET /api/shark-status, POST /api/shark-start, and view=shark on the
    read-only data endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.original_base = server.DATA_DIR
        server.DATA_DIR = cls.tmpdir
        cls.server = server.ThreadedTCPServer(('127.0.0.1', 0), server.Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        server.DATA_DIR = cls.original_base
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def setUp(self):
        self.md5 = os.urandom(16).hex()
        self.dir = os.path.join(self.tmpdir, self.md5)
        os.makedirs(self.dir)
        with open(os.path.join(self.dir, 'sample.pcap'), 'wb') as f:
            f.write(build_pcap_sample())
        init_empty_db(os.path.join(self.dir, 'events.db'))   # Suricata's view, done

    def tearDown(self):
        shark_analyzer.cancel(self.dir)
        shark_analyzer.wait_idle(15)

    def _get(self, path):
        try:
            with urllib.request.urlopen(f'http://127.0.0.1:{self.port}{path}', timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b'{}')

    def _post(self, path, body):
        req = urllib.request.Request(f'http://127.0.0.1:{self.port}{path}', data=json.dumps(body).encode(),
                                     headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b'{}')

    def _wait_ready(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            _, body = self._get(f'/api/shark-status?md5={self.md5}')
            if body['status'] not in ('queued', 'running'):
                return body
            time.sleep(0.1)
        self.fail('tshark never finished')

    def test_first_status_request_queues_it_and_it_becomes_ready_and_merged(self):
        status, body = self._get(f'/api/shark-status?md5={self.md5}')
        self.assertEqual(status, 200)
        self.assertIn(body['status'], ('queued', 'running', 'ready'))
        body = self._wait_ready()
        self.assertIsInstance(body.pop('seconds'), int)
        self.assertEqual(sorted(body.pop('types')), ['conn_irc', 'llmnr', 'nbns', 'ssdp'],
                         'what tshark added: the chatter records and the IRC connection row, which the page reloads its cards for')
        self.assertEqual(body, {'status': 'ready', 'merged': True})
        _, stats = self._get(f'/api/stats?md5={self.md5}')
        self.assertEqual(sorted(stats['tshark_types']), ['conn_irc', 'llmnr', 'nbns', 'ssdp'],
                         'the protocols here Suricata lacks - the stats say which')

    def test_waits_for_suricata(self):
        with open(os.path.join(self.dir, '.phase'), 'w') as f:
            f.write('network')
        _, body = self._get(f'/api/shark-status?md5={self.md5}')
        self.assertEqual(body, {'status': 'waiting'})

    def test_too_large_waits_to_be_asked_then_shark_start_runs_it(self):
        with mock.patch.object(config, 'SHARK_BACKGROUND_MAX_PACKETS', 1):
            _, body = self._get(f'/api/shark-status?md5={self.md5}')
            self.assertEqual(body, {'status': 'too_large'})
            status, body = self._post('/api/shark-start', {'md5': self.md5})
            self.assertEqual(status, 200)
            self.assertIn(body['status'], ('queued', 'running', 'ready'))
            self.assertEqual(self._wait_ready()['status'], 'ready')

    def test_the_settings_switch_turns_shar_crates_off_and_on(self):
        self.assertEqual(self._get('/api/shark-settings')[1], {'enabled': True}, 'on by default')
        try:
            self.assertEqual(self._post('/api/shark-settings', {'enabled': False}), (200, {'enabled': False}))
            self.assertEqual(self._get('/api/shark-settings')[1], {'enabled': False})
            self.assertEqual(self._get(f'/api/shark-status?md5={self.md5}')[1], {'status': 'disabled'})
            self.assertEqual(self._post('/api/shark-start', {'md5': self.md5})[1], {'status': 'disabled'},
                             'nothing runs while it is off, even on request')
            self.assertEqual(self._post('/api/shark-settings', {'enabled': 'no'})[0], 400)
        finally:
            self._post('/api/shark-settings', {'enabled': True})
        self.assertEqual(self._wait_ready()['status'], 'ready', 'back on: the analysis gets its run')

    def test_not_a_pcap_analysis(self):
        os.unlink(os.path.join(self.dir, 'sample.pcap'))
        with open(os.path.join(self.dir, 'notes.txt'), 'w') as f:
            f.write('hi')
        _, body = self._get(f'/api/shark-status?md5={self.md5}')
        self.assertEqual(body, {'status': 'unavailable'})

    def test_unknown_or_invalid_analysis(self):
        self.assertEqual(self._get('/api/shark-status?md5=' + 'a' * 32)[0], 404)
        self.assertEqual(self._get('/api/shark-status?md5=nope')[0], 400)
        self.assertEqual(self._post('/api/shark-start', {'md5': 'a' * 32})[0], 404)

    def test_delete_cancels_a_queued_run(self):
        with mock.patch.object(shark_analyzer, 'cancel', wraps=shark_analyzer.cancel) as cancel:
            status, _ = self._post('/api/delete-analysis', {'md5': self.md5})
        self.assertEqual(status, 200)
        cancel.assert_called_once_with(self.dir)


if __name__ == '__main__':
    unittest.main()
