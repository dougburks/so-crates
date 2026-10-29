#!/usr/bin/env python3
"""tshark's part of a PCAP analysis: the protocols Suricata doesn't parse.

Suricata stays the source of truth for every protocol it parses. Alongside
it, the same capture is queued here for tshark, which decodes far more
protocols - but packet by packet, the way Wireshark shows them. This
module turns that packet stream into Suricata-shaped records, written to
shark.db (the analysis's events.db's table, without its search indexes),
and once both are done merges into events.db what Suricata lacks (merge).

It builds one 'flow' record per conversation (tshark's tcp.stream /
udp.stream numbers, or addresses for anything without a stream), in
Suricata's own flow-event layout - addresses, ports, packet and byte
counts per direction, start and end - plus the protocols tshark found in
it and its Community ID, which matches Suricata's community_id for the
same flow. shark_protocols adds records for the protocols it describes
(see its PROTOCOLS), and this module tunnel and TLS failure records.

tshark reads the whole capture once with plain field output (-T fields) -
then again over just the packets of flows with records here, for their
protocols' fields (the protocol and structured passes): its
JSON output is several times slower and many times larger for the same
packets (measured: 532 MB pcap, 10.6s and 81 MB of fields vs 168s and
8.5 GB of full JSON). It runs at low CPU and I/O priority, one capture
at a time, under a timeout and a memory limit (config.SHARK_MAX_MEMORY_BYTES,
across the build and its tshark). tshark's memory grows with the capture's
packet count (about 930 bytes per packet measured), so captures over
config.SHARK_BACKGROUND_MAX_PACKETS only run when the user asks. The
Settings switch (enabled/set_enabled) turns tshark off altogether.

Files in the analysis directory:
    shark.db       the records, written to shark.db.tmp then renamed, so
                   a reader never sees a half-built database
    .shark_error   why the last run failed
"""

import ipaddress
import json
import math
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from contextlib import closing
from datetime import datetime, timezone

import sqlite3

import config
import pcap_subset
from db import (create_shark_db, replace_tshark_events, suricata_identified_flows,
                suricata_tls_records, tshark_merge_stamp, _iso_epoch)
from shark_protocols import PROTOCOLS, RECORDED_APP_PROTOS, STRUCTURED_PROTOCOLS, Packet

SHARK_DB = 'shark.db'
SHARK_ERROR = '.shark_error'
SHARK_ARTIFACTS = (SHARK_DB, SHARK_DB + '-wal', SHARK_DB + '-shm', SHARK_DB + '.tmp', SHARK_ERROR)
# Stamped into each shark.db (SQLite's user_version). Bump it whenever a
# change here or in shark_protocols changes what a run produces: a
# shark.db stamped with an older version is rebuilt the next time its
# status is asked for, so existing analyses pick up the change.
SHARK_FORMAT_VERSION = 38

# The fields every packet is read for, one per column of tshark's
# tab-separated output, in this order - then each of shark_protocols'
# fields. Every occurrence of a repeated field is output, joined by
# _AGGREGATOR; these base fields take the last one. A tunneled packet (IP
# in GRE, VXLAN, Teredo, IP in IP...) is split first (_split_tunnel): its
# inner flow from the inner network layer on, and its tunnel's outer flow -
# as Suricata logs them both. ip.len and ipv6.plen are for the inner
# flow's bytes, which Suricata counts from the inner IP header on.
_FIELDS = (
    'frame.time_epoch', 'frame.len', 'frame.protocols',
    'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst', 'ip.proto', 'ipv6.nxt',
    'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport',
    'tcp.stream', 'udp.stream', 'tcp.flags.syn', 'tcp.flags.ack',
    'eth.src', 'eth.dst', 'communityid', 'frame.number', 'ip.len', 'ipv6.plen',
)
(_F_TIME, _F_LEN, _F_PROTOS, _F_IP_SRC, _F_IP_DST, _F_IP6_SRC, _F_IP6_DST, _F_IP_PROTO,
 _F_IP6_NXT, _F_TCP_SPORT, _F_TCP_DPORT, _F_UDP_SPORT, _F_UDP_DPORT, _F_TCP_STREAM,
 _F_UDP_STREAM, _F_SYN, _F_ACK, _F_ETH_SRC, _F_ETH_DST, _F_CID, _F_FRAME,
 _F_IP_LEN, _F_IP6_PLEN) = range(len(_FIELDS))
# Each field once: tshark fills only one column of a field asked for twice,
# and protocols share fields (SSDP reads HTTP's) - so each protocol finds
# its fields by name (_COLUMN), not by position.
# The fields _is_reply reads to orient a flow by its first request or
# reply - requested whether or not any protocol here keeps records of them.
_ORIENTATION_FIELDS = ('dns.flags.response', 'nbns.flags.response', 'http.response.code', 'http.request.method',
                       'ftp.response.code', 'ftp.request.command', 's7comm.header.rosctr', 'tls.handshake.type')
# The alerts a TLS connection's ends sent while they could still be read
# (_TLSFailures) - TLS is most of a capture's connections, too many to
# read again in the protocol pass for one field.
_TLS_ALERT_FIELD = 'vals(tls.alert_message.desc)'
# The first pass reads every packet, for its flow - so it asks for no more
# than that: tshark's time grows with each field asked for, whether or not
# a packet has it. shark_protocols' fields are asked for by a second pass
# (_protocol_pass) over just the packets of the flows they keep records of.
_FIRST_PASS_FIELDS = _FIELDS + tuple(f for f in _ORIENTATION_FIELDS if f not in _FIELDS) + (_TLS_ALERT_FIELD,)
_COLUMN = {field: i for i, field in enumerate(_FIRST_PASS_FIELDS)}
_TLS_ALERT_COLUMN = _COLUMN[_TLS_ALERT_FIELD]
# The application protocols shark_protocols keeps records of from fields
_RECORDED_FIELD_APPS = frozenset(p for proto in PROTOCOLS for p in proto.app_protos)


def _protocol_pass_fields(protocols):
    """The protocol pass's fields: the base fields (to find each packet's
    flow), then each of these protocols' fields, each once."""
    return _FIELDS + tuple(dict.fromkeys(f for proto in protocols for f in proto.fields if f not in _FIELDS))


def _combined_fields(protocols):
    """One pass's fields, for a capture mostly of protocols with records
    here (_mostly_recorded): the first pass's, then these protocols'."""
    return _FIRST_PASS_FIELDS + tuple(dict.fromkeys(f for proto in protocols for f in proto.fields
                                                    if f not in _FIRST_PASS_FIELDS))


# The probe that picks one combined pass over two (_mostly_recorded)
_PROBE_MIN_PACKETS = 20_000
_PROBE_WINDOWS, _PROBE_WINDOW = 10, 500
_PROBE_SHARE = 0.75
# Joins a repeated field's values. tshark escapes control characters
# inside a value (a tab comes out as the two characters \t), so this can
# never appear in one.
_AGGREGATOR = '\x1f'

# IP protocol numbers Suricata names in a flow's proto field.
_IP_PROTO_NAMES = {'1': 'ICMP', '2': 'IGMP', '4': 'IP-in-IP', '6': 'TCP', '17': 'UDP', '41': 'IPv6', '47': 'GRE',
                   '50': 'ESP', '58': 'IPv6-ICMP', '89': 'OSPF', '112': 'VRRP', '132': 'SCTP'}

# tshark's names for protocols Suricata calls something else - a flow's
# app_proto uses Suricata's name, so the two views agree (its
# shark.protocols keeps tshark's own names).
SURICATA_APP_PROTO_NAMES = {'mbtcp': 'modbus', 'smb2': 'smb', 'kerberos': 'krb5', 'isakmp': 'ike',
                            'vnc': 'rfb', 'pop': 'pop3', 'bt-dht': 'bittorrent-dht', 'cldap': 'ldap',
                            'srvloc': 'slp'}

_TRANSPORT_LAYERS = {'tcp', 'udp', 'sctp'}
# Layers that only carry another protocol, or carry undecoded payload -
# never a flow's application protocol. tpkt/cotp carry S7comm and MMS,
# nbss carries SMB, and the rest are tshark's names for raw data or
# reassembly bookkeeping.
_CARRIER_LAYERS = {'tpkt', 'cotp', 'nbss', 'tcp.segments', 'data', 'data-text-lines', 'media'}
# Layers that are the application protocol unless another follows them:
# ONC RPC on its own (portmapper) is the protocol, but carries NFS; the
# OSI session, presentation and association layers carry MMS.
_WRAPPER_LAYERS = {'rpc', 'ses', 'pres', 'acse'}


def shark_db_path(dir_path):
    return os.path.join(dir_path, SHARK_DB)


def tshark_command(pcap_path, fields=_FIRST_PASS_FIELDS):
    """The tshark command that dumps these fields (the first pass's by
    default) for every packet."""
    cmd = ['tshark', '-n', '-r', pcap_path, '--enable-protocol', 'communityid',
           '-T', 'fields', '-E', 'separator=\t', '-E', 'occurrence=a', '-E', 'aggregator=' + _AGGREGATOR]
    for field in fields:
        cmd += ['-e', field]
    return cmd


def app_protocol(protocols):
    """A packet's application protocol from its frame.protocols stack
    ('eth:ethertype:ip:tcp:tls' -> 'tls'): the first layer above the
    transport that isn't a carrier ('...:tcp:tpkt:cotp:s7comm' ->
    's7comm'), or, with no TCP/UDP/SCTP layer, the topmost layer
    ('eth:ethertype:arp' -> 'arp'). '' when there's nothing above the
    transport (a bare SYN or ACK)."""
    layers = protocols.split(':') if protocols else []
    above = None
    for i, layer in enumerate(layers):
        if layer in _TRANSPORT_LAYERS:
            above = layers[i + 1:]
            break
    if above is None:
        candidates = [layer for layer in layers if layer not in _CARRIER_LAYERS and layer != 'ethertype']
        return candidates[-1] if candidates else ''
    above = [layer for layer in above if layer not in _CARRIER_LAYERS]
    # A WebRTC flow's DTLS, once its handshake agreed on SRTP, comes out
    # as rtp:dtls - tshark's RTP standing in for the demultiplexing.
    if above[:2] == ['rtp', 'dtls']:
        return 'dtls'
    for i, layer in enumerate(above):
        if layer not in _WRAPPER_LAYERS or i == len(above) - 1:
            return SURICATA_APP_PROTO_NAMES.get(layer, layer)
    return ''


_EXPLODED = {}


def ipv6_exploded(address):
    """An IPv6 address written out in full, the way Suricata logs every
    one (2001:0db8:0000:...), so filters and pivots match across both
    views. Unparseable input comes back unchanged."""
    if address not in _EXPLODED:
        if len(_EXPLODED) > 100000:
            _EXPLODED.clear()
        try:
            _EXPLODED[address] = ipaddress.IPv6Address(address).exploded
        except ValueError:
            _EXPLODED[address] = address
    return _EXPLODED[address]


_ISO_SECONDS = {}
_ISO_MAX_EPOCH = 253402300799.0      # 9999-12-31T23:59:59


def _iso(epoch):
    """Suricata's timestamp format, so both views sort and compare alike.
    A capture's millions of timestamps fall in far fewer seconds, so each
    second's text is made once (strftime was a tenth of a big capture's
    Python time); the microseconds are rounded as datetime rounds them."""
    # A time datetime can't hold - a hostile pcapng's 64-bit timestamp, past
    # the year 9999 - is clamped rather than failing the whole run
    if not 0 <= epoch < _ISO_MAX_EPOCH:
        if epoch < 0 and epoch > -_ISO_MAX_EPOCH:
            try:
                return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f+0000')
            except (ValueError, OverflowError, OSError):
                pass
        return '9999-12-31T23:59:59.999999+0000' if epoch > 0 else '0001-01-01T00:00:00.000000+0000'
    frac, whole = math.modf(epoch)
    micro = round(frac * 1e6)
    if micro >= 1_000_000:
        whole, micro = whole + 1, micro - 1_000_000
    seconds = _ISO_SECONDS.get(whole)
    if seconds is None:
        if len(_ISO_SECONDS) > 1_000_000:
            _ISO_SECONDS.clear()
        seconds = _ISO_SECONDS[whole] = datetime.fromtimestamp(whole, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
    return f'{seconds}.{micro:06d}+0000'


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _is_group_address(address):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_multicast or (ip.version == 4 and (address == '255.255.255.255' or address.endswith('.255')))


def _flag(value):
    return {'1': True, 'True': True, '0': False, 'False': False}.get(value)


def _first_value(cols, field):
    i = _COLUMN[field]
    return cols[i].split(_AGGREGATOR)[0] if i < len(cols) and cols[i] else ''


def _is_reply(cols):
    """Whether a packet is a server's reply (True), a client's request
    (False), or can't say (None), from the protocols that mark it:
    DNS/mDNS/LLMNR and NBNS's response flag, an HTTP/SSDP or FTP response
    vs request, an S7comm ack vs job, a TLS server vs client hello.
    Modbus marks neither."""
    for field in ('dns.flags.response', 'nbns.flags.response'):
        flag = _flag(_first_value(cols, field))
        if flag is not None:
            return flag
    for reply, request in (('http.response.code', 'http.request.method'),
                           ('ftp.response.code', 'ftp.request.command')):
        if _first_value(cols, reply):
            return True
        if _first_value(cols, request):
            return False
    rosctr = _first_value(cols, 's7comm.header.rosctr')
    if rosctr in ('1', '2', '3'):
        return rosctr != '1'
    return {'1': False, '2': True}.get(_first_value(cols, 'tls.handshake.type'))


class _Flow:
    __slots__ = ('key', 'proto', 'ip_v', 'client', 'server', 'cport', 'sport', 'first', 'last',
                 'pkts_ts', 'pkts_tc', 'bytes_ts', 'bytes_tc', 'protocols', 'app_proto', 'community_id',
                 'stream', 'client_set_by_syn', 'client_set_by_message', 'first_frame', 'last_frame', 'recorded',
                 'icmp_ts', 'icmp_tc', 'tunnel', 'mac_broadcast')

    def __init__(self, key, proto, ip_v, src, dst, sport, dport, when, stream):
        self.key, self.proto, self.ip_v, self.stream = key, proto, ip_v, stream
        self.client, self.server, self.cport, self.sport = src, dst, sport, dport
        self.first = self.last = when
        self.pkts_ts = self.pkts_tc = self.bytes_ts = self.bytes_tc = 0
        self.icmp_ts = self.icmp_tc = 0     # the ICMP errors among each direction's packets
        self.protocols = {}
        self.app_proto = ''
        self.community_id = ''
        self.client_set_by_syn = self.client_set_by_message = False
        self.first_frame = self.last_frame = 0     # its first and last packet's frame numbers
        self.recorded = False      # whether it carries a protocol with records (iter_records)
        self.tunnel = False        # whether it's a tunnel's outer flow (its tunnel record says more)
        self.mac_broadcast = False # whether the client sent to the Ethernet broadcast address

    def _swap(self):
        self.client, self.server = self.server, self.client
        self.cport, self.sport = self.sport, self.cport
        self.pkts_ts, self.pkts_tc = self.pkts_tc, self.pkts_ts
        self.bytes_ts, self.bytes_tc = self.bytes_tc, self.bytes_ts
        self.icmp_ts, self.icmp_tc = self.icmp_tc, self.icmp_ts

    def orient(self, src, sport, is_reply):
        """The flow's first request or reply (see _is_reply) settles which
        side is the client, unless a SYN already has: a capture that starts
        mid-conversation can open on the server's reply - whose sender
        would otherwise be taken for the client, and every record on the
        flow addressed backwards. Suricata keeps the first sender as the
        client (and then doesn't recognize the protocol), so these flows
        are the one place the two views' directions differ."""
        if self.client_set_by_syn or self.client_set_by_message:
            return
        self.client_set_by_message = True
        sent_by_client = src == self.client and sport == self.cport
        # Never make a multicast or broadcast address the client: an
        # announcement (an mDNS response to the group) is a reply nobody
        # asked for, and the group sent nothing.
        if is_reply == sent_by_client and not self.to_group():
            self._swap()

    def to_group(self):
        """Whether the server is a group - a multicast or broadcast address -
        by what the traffic says: sent to the Ethernet broadcast address
        (a subnet's broadcast, whatever its last octet), or to multicast or
        255.255.255.255. An IPv4 address ending in .255 is taken for a
        broadcast too - unless it ever answered, which a broadcast address
        never does: in a /23 or larger, 10.1.2.255 is a host."""
        if self.mac_broadcast:
            return True
        if not _is_group_address(self.server):
            return False
        return not (self.server != '255.255.255.255' and self.server.endswith('.255')
                    and self.pkts_tc > self.icmp_tc)

    def add(self, src, sport, length, when, app, community_id, syn_only, from_client=None):
        """from_client, if given, says which way the packet went instead
        of src/sport (an ICMP error about this flow - see build_records)."""
        # The client is whoever sent the SYN; failing that (a capture that
        # starts mid-connection, or UDP), whoever sent the first packet.
        if syn_only and not self.client_set_by_syn:
            if src != self.client or sport != self.cport:
                self._swap()
            self.client_set_by_syn = True
        icmp_error = from_client is not None
        if from_client is None:
            from_client = src == self.client and sport == self.cport
        if icmp_error:
            if from_client:
                self.icmp_ts += 1
            else:
                self.icmp_tc += 1
        if from_client:
            self.pkts_ts += 1
            self.bytes_ts += length
        else:
            self.pkts_tc += 1
            self.bytes_tc += length
        self.first, self.last = min(self.first, when), max(self.last, when)
        if app:
            self.protocols[app] = self.protocols.get(app, 0) + 1
            if not self.app_proto:
                self.app_proto = app
        if community_id and not self.community_id:
            self.community_id = community_id

    def record(self, when, event_type, body):
        """A transaction record on this flow, addressed client to server
        like the flow itself (Suricata addresses its transactions the same
        way)."""
        event = {'timestamp': _iso(when), 'event_type': event_type,
                 'src_ip': self.client, 'dest_ip': self.server, 'proto': self.proto, event_type: body}
        if self.ip_v:
            event['ip_v'] = self.ip_v
        if self.proto in ('TCP', 'UDP', 'SCTP'):
            event['src_port'], event['dest_port'] = self.cport, self.sport
        if self.community_id:
            event['community_id'] = self.community_id
        return event

    def event(self):
        flow = {
            'pkts_toserver': self.pkts_ts, 'pkts_toclient': self.pkts_tc,
            'bytes_toserver': self.bytes_ts, 'bytes_toclient': self.bytes_tc,
            'start': _iso(self.first), 'end': _iso(self.last),
            'age': int(self.last - self.first),
        }
        event = {
            'timestamp': _iso(self.first), 'event_type': 'flow',
            'src_ip': self.client, 'dest_ip': self.server, 'proto': self.proto,
            'app_proto': self.app_proto, 'flow': flow,
            'shark': {'protocols': dict(sorted(self.protocols.items(), key=lambda kv: -kv[1]))},
        }
        if self.ip_v:
            event['ip_v'] = self.ip_v
        if self.proto in ('TCP', 'UDP', 'SCTP'):
            event['src_port'], event['dest_port'] = self.cport, self.sport
        if self.stream is not None:
            event['shark']['stream'] = self.stream
        if self.tunnel:
            event['shark']['tunnel'] = True
        answered = self.answered()
        if answered:
            event['shark']['answered'] = answered
        if self.community_id:
            event['community_id'] = self.community_id
        return event

    def answered(self):
        """Whether the server answered: 'yes', 'no', or 'ICMP error only' -
        a probe of a closed UDP port, answered port unreachable, has
        packets back but no reply. '' for a flow to a multicast or
        broadcast address, whose replies come back on another flow, and
        for one that isn't IP (STP, LLDP...), which nothing answers."""
        if not self.ip_v or self.to_group():
            return ''
        if self.pkts_tc > self.icmp_tc:
            return 'yes'
        return 'ICMP error only' if self.icmp_tc else 'no'


# Tunnels: what carries a packet inside another - between a packet's
# outer network layer and the next one in its frame.protocols, by name
# (anything else - ESP, L2TP's PPP - isn't counted), or nothing at all
# (IP in IP, 6in4...). Zeek's tunnel.log, which Suricata has no match
# for: it decodes tunnels to inspect what's inside but logs only the
# inner flows - which is all tshark's flows here are (see _FIELDS).
_TUNNEL_LAYERS = (('vxlan', 'VXLAN'), ('geneve', 'Geneve'), ('teredo', 'Teredo'), ('ayiya', 'AYIYA'),
                  ('gtp', 'GTP-U'), ('erspan', 'ERSPAN'), ('gre', 'GRE'))
_BARE_TUNNELS = {('ip', 'ip'): 'IP-in-IP', ('ip', 'ipv6'): '6in4', ('ipv6', 'ip'): '4in6',
                 ('ipv6', 'ipv6'): 'IPv6-in-IPv6'}
_TUNNEL_OUTER_PROTO = {'IP-in-IP': 'IP-in-IP', '6in4': 'IPv6', '4in6': 'IP-in-IP', 'IPv6-in-IPv6': 'IPv6', 'GRE': 'GRE',
                       'GRE (Ethernet)': 'GRE', 'ERSPAN': 'GRE'}
_TUNNEL_MAX_HOSTS = 20


def _tunnel_type(layers):
    """A packet's tunnel and the indexes of its outer and inner network
    layers, or None."""
    nets = [i for i, layer in enumerate(layers) if layer in ('ip', 'ipv6')]
    if len(nets) < 2:
        return None
    outer, inner = nets[0], nets[1]
    between = layers[outer + 1:inner]
    if not between:
        kind = _BARE_TUNNELS[(layers[outer], layers[inner])]
    else:
        kind = next((name for layer, name in _TUNNEL_LAYERS if layer in between), None)
        if kind is None:
            return None
        if kind == 'GRE' and 'eth' in between:
            kind = 'GRE (Ethernet)'
    return kind, outer, inner


def _occurrence(cols, column, n):
    values = cols[column].split(_AGGREGATOR) if column < len(cols) and cols[column] else []
    return values[n] if n < len(values) else ''


# Each base field's layer: the frame.protocols layer whose occurrences it
# counts, to tell a tunneled packet's outer fields from its inner ones
_FIELD_LAYERS = {_F_IP_SRC: 'ip', _F_IP_DST: 'ip', _F_IP_PROTO: 'ip', _F_IP_LEN: 'ip', _F_IP6_SRC: 'ipv6',
                 _F_IP6_DST: 'ipv6', _F_IP6_NXT: 'ipv6', _F_IP6_PLEN: 'ipv6', _F_TCP_SPORT: 'tcp', _F_TCP_DPORT: 'tcp', _F_TCP_STREAM: 'tcp',
                 _F_SYN: 'tcp', _F_ACK: 'tcp', _F_UDP_SPORT: 'udp', _F_UDP_DPORT: 'udp', _F_UDP_STREAM: 'udp'}
# Suricata logs a tunnel's outer flow too - except GRE's
_NO_OUTER_FLOW = ('GRE', 'GRE (Ethernet)', 'ERSPAN')
_PROTO_NUMBERS = {'TCP': 6, 'UDP': 17, 'IP-in-IP': 4, 'IPv6': 41}


def _community_id(src, dst, proto, sport, dport):
    """Community ID v1 (seed 0) of a flow - for a tunnel's outer flow,
    which tshark's communityid (the inner one's) doesn't give."""
    import base64
    import hashlib
    family = socket.AF_INET6 if ':' in src else socket.AF_INET
    a, b = (socket.inet_pton(family, src), sport or 0), (socket.inet_pton(family, dst), dport or 0)
    if b < a:
        a, b = b, a
    # (a protocol without ports hashes them as zeros, as Suricata does)
    data = struct.pack('!H', 0) + a[0] + b[0] + struct.pack('!BBHH', proto, 0, a[1], b[1])
    return '1:' + base64.b64encode(hashlib.sha1(data).digest()).decode()


def _split_tunnel(cols):
    """A tunneled packet's two views, or None: (its tunnel's type, the
    columns of the packet inside - each base field without the outer
    layers' occurrences, frame.protocols from the inner network layer on
    - and, for a tunnel whose outer flow Suricata logs, the outer packet's
    base fields (each one's first occurrence) and app: the tunnel's
    layer, or '' for IP in IP and the like)."""
    layers = cols[_F_PROTOS].split(':')
    found = _tunnel_type(layers)
    if found is None:
        return None
    kind, outer, inner = found
    inner_cols = list(cols)
    for column, layer in _FIELD_LAYERS.items():
        values = cols[column].split(_AGGREGATOR) if cols[column] else []
        inner_cols[column] = _AGGREGATOR.join(values[layers[:inner].count(layer):])
    inner_cols[_F_PROTOS] = ':'.join(layers[inner:])
    if kind in _NO_OUTER_FLOW:
        return kind, inner_cols, None, ''
    outer_f = [_last(c) for c in cols[:len(_FIELDS)]]
    transport = layers[outer + 1] if layers[outer + 1] in ('tcp', 'udp') else ''
    for column, layer in _FIELD_LAYERS.items():
        first = cols[column].split(_AGGREGATOR)[0] if cols[column] else ''
        keep = layer == layers[outer] or layer == transport
        outer_f[column] = first if keep else ''
    outer_f[_F_PROTOS] = ':'.join(layers[:inner])
    app = next((layer for layer, _ in _TUNNEL_LAYERS if layer in layers[outer + 1:inner]), '')
    return kind, inner_cols, outer_f, app


def _icmp_quoted_tunnel(cols):
    """For an ICMP error whose copy of the packet it's about is itself
    tunneled - Linux quotes up to 576 bytes, enough for a tunnel and the
    packet inside - (the tunnel's type, the quoted outer packet's base
    fields): the error is about that outer packet, not the one inside it,
    whose addresses (and ports) the last-occurrence fields would read.
    None for any other packet."""
    layers = cols[_F_PROTOS].split(':')
    at = next((i for i, layer in enumerate(layers) if layer in ('icmp', 'icmpv6')), None)
    if at is None:
        return None
    found = _tunnel_type(layers[at + 1:])
    if found is None:
        return None
    kind, outer, _ = found
    q = at + 1 + outer                       # the quoted outer network layer
    transport = layers[q + 1] if q + 1 < len(layers) and layers[q + 1] in ('tcp', 'udp') else ''
    f = [_last(c) for c in cols[:len(_FIELDS)]]
    for column, layer in _FIELD_LAYERS.items():
        values = cols[column].split(_AGGREGATOR) if cols[column] else []
        if layer == layers[q]:
            n = layers[:q].count(layer)      # (the error's own IP header comes first)
        elif layer == transport:
            n = layers[:q + 1].count(layer)
        else:
            f[column] = ''
            continue
        f[column] = values[n] if n < len(values) else ''
    return kind, f


class _Tunnels:
    """One record per tunnel - its type and outer endpoints - with the
    inner hosts and flows it carried."""

    def __init__(self):
        self.tunnels = {}

    def add(self, cols, layers, when, length, inner_key):
        found = _tunnel_type(layers)
        if found is None:
            return
        kind, outer, inner = found

        def address(index, side):
            layer = layers[index]
            n = layers[:index].count(layer)
            if layer == 'ip':
                return _occurrence(cols, _F_IP_SRC if side == 'src' else _F_IP_DST, n)
            value = _occurrence(cols, _F_IP6_SRC if side == 'src' else _F_IP6_DST, n)
            return ipv6_exploded(value) if value else ''
        src, dst = address(outer, 'src'), address(outer, 'dst')
        sport = dport = None
        if 'udp' in layers[outer + 1:inner]:
            sport = _int(_occurrence(cols, _F_UDP_SPORT, 0))
            dport = _int(_occurrence(cols, _F_UDP_DPORT, 0))
        key = (kind,) + tuple(sorted(((src, sport or 0), (dst, dport or 0))))
        tunnel = self.tunnels.get(key)
        if tunnel is None:
            tunnel = self.tunnels[key] = {'src': src, 'dst': dst, 'sport': sport, 'dport': dport,
                                          'ip_v': 4 if layers[outer] == 'ip' else 6, 'first': when, 'last': when,
                                          'body': {'type': kind, 'packets_toserver': 0, 'packets_toclient': 0,
                                                   'bytes_toserver': 0, 'bytes_toclient': 0},
                                          'flows': set(), 'hosts': []}
        body = tunnel['body']
        side = 'toserver' if (src, sport) == (tunnel['src'], tunnel['sport']) else 'toclient'
        body[f'packets_{side}'] += 1
        body[f'bytes_{side}'] += length
        tunnel['first'], tunnel['last'] = min(tunnel['first'], when), max(tunnel['last'], when)
        if inner_key is not None:
            tunnel['flows'].add(inner_key)
        inner_src, inner_dst = address(inner, 'src'), address(inner, 'dst')
        for host in (inner_src, inner_dst):
            if host and host not in tunnel['hosts'] and len(tunnel['hosts']) < _TUNNEL_MAX_HOSTS:
                tunnel['hosts'].append(host)
        # A packet that, unwrapped, goes back to whoever sent it: a scanner
        # testing whether this end unwraps tunnels from anyone
        if inner_dst and inner_dst == src and layers[outer] == layers[inner]:
            body['returns_to_sender'] = True

    def records(self):
        for tunnel in sorted(self.tunnels.values(), key=lambda t: t['first']):
            body = tunnel['body']
            body['inner_flows'] = len(tunnel['flows'])
            body['inner_hosts'] = tunnel['hosts']
            body['start'], body['end'] = _iso(tunnel['first']), _iso(tunnel['last'])
            body['age'] = int(tunnel['last'] - tunnel['first'])
            proto = 'UDP' if tunnel['sport'] is not None else _TUNNEL_OUTER_PROTO.get(body['type'], '')
            event = {'timestamp': _iso(tunnel['first']), 'event_type': 'tunnel', 'src_ip': tunnel['src'],
                     'dest_ip': tunnel['dst'], 'proto': proto, 'ip_v': tunnel['ip_v'], 'tunnel': body}
            if tunnel['sport'] is not None:
                event['src_port'], event['dest_port'] = tunnel['sport'], tunnel['dport']
            yield event


# TLS failures: the alerts a TLS connection's ends sent before encryption
# began. tshark decodes an alert only while it's readable - in TLS 1.2 and
# earlier, the whole handshake; in TLS 1.3, whose handshake is encrypted
# after the server's hello, only until the sender has its keys (an
# OpenSSL client refusing the certificate still sends in the clear) - and
# Suricata logs a connection's handshake but none of its alerts. So this is the only record of a client refusing the server's
# certificate (Unknown CA, Certificate Expired...), Zeek's
# SSL::Invalid_Server_Cert seen from the client's side, or of a server
# turning a client away (Handshake Failure, Protocol Version). One record
# per TCP connection that sent any.
TLS_FAILURE_TYPE = 'tls_failure'
# How far from a failure Suricata's tls record of the same Community ID can
# be and still be its connection's: Suricata logs a handshake within
# seconds of its alerts, and TCP's TIME_WAIT keeps a 5-tuple from being
# reused for longer than this
_TLS_CONTEXT_SECONDS = 60
_TLS_MAX_ALERTS = 10
# An orderly close - readable only where the capture carries the session's
# keys - is no failure
_TLS_NOT_FAILURES = ('Close Notify',)


class _TLSFailures:
    def __init__(self):
        self.flows = {}     # flow -> (first alert's time, [(sender's address, port, alert)])

    def add(self, flow, src, sport, when, alerts):
        if all(alert in _TLS_NOT_FAILURES for alert in alerts):
            return
        entry = self.flows.setdefault(flow, (when, []))
        for alert in alerts:
            if alert and alert not in _TLS_NOT_FAILURES and len(entry[1]) < _TLS_MAX_ALERTS:
                entry[1].append((src, sport, alert))

    def records(self):
        for flow, (when, alerts) in sorted(self.flows.items(), key=lambda item: item[1][0]):
            if not alerts:
                continue
            sides = ['client' if (src, sport) == (flow.client, flow.cport) else 'server' for src, sport, _ in alerts]
            body = {'alert': alerts[0][2], 'sent_by': sides[0],
                    'alerts': [f'{side}: {alert}' for side, (_, _, alert) in zip(sides, alerts)]}
            yield flow.record(when, TLS_FAILURE_TYPE, body)


_ESCAPE = re.compile(r'\\(x[0-9a-fA-F]{2}|.)')
_ESCAPES = {'t': '\t', 'n': '\n', 'r': '\r', '\\': '\\'}


def _unescape(value):
    """Undo tshark's escaping of a field value: \\t, \\n, \\r, \\\\ and \\xNN."""
    if '\\' not in value:
        return value
    # (a \\x not followed by two hex digits stays the 'x' it is)
    return _ESCAPE.sub(lambda m: _ESCAPES.get(m.group(1)) or (chr(int(m.group(1)[1:], 16))
                                                            if len(m.group(1)) == 3 else m.group(1)), value)


def _last(value):
    return value.rsplit(_AGGREGATOR, 1)[-1]


def build_records(lines):
    """Turn tshark's per-packet field lines (tshark_command's output) into
    records: one flow per conversation, in order of first packet, then
    shark_protocols' transaction records."""
    return list(iter_records(lines))


def _packet_key(f, app):
    """A packet's IP version, addresses, transport, stream, ports and flow
    key, from its base fields (f: each one's last occurrence - see
    _FIELDS). A TCP flow is tshark's stream, a UDP one its stream between
    these two ends (tshark gives one stream to every client a portmapper
    or SIP told it to expect on a port, whatever port each came from); any
    other is its addresses (and, below IP, its protocol)."""
    if f[_F_IP_SRC] or f[_F_IP6_SRC]:
        ip_v = 4 if f[_F_IP_SRC] else 6
        if ip_v == 4:
            src, dst = f[_F_IP_SRC], f[_F_IP_DST]
        else:
            src, dst = ipv6_exploded(f[_F_IP6_SRC]), ipv6_exploded(f[_F_IP6_DST])
    else:
        ip_v, src, dst = 0, f[_F_ETH_SRC], f[_F_ETH_DST]
    stream = None
    if f[_F_TCP_STREAM]:
        proto, stream = 'TCP', _int(f[_F_TCP_STREAM])
        sport, dport = _int(f[_F_TCP_SPORT]), _int(f[_F_TCP_DPORT])
        key = ('tcp', stream)
    elif f[_F_UDP_STREAM]:
        proto, stream = 'UDP', _int(f[_F_UDP_STREAM])
        sport, dport = _int(f[_F_UDP_SPORT]), _int(f[_F_UDP_DPORT])
        key = ('udp', stream) + tuple(sorted(((src, sport), (dst, dport))))
    else:
        number = f[_F_IP_PROTO] or f[_F_IP6_NXT]
        proto = _IP_PROTO_NAMES.get(number, number) if ip_v else (app.upper() or 'ETH')
        sport = dport = 0
        key = (proto, app if not ip_v else '') + tuple(sorted((src, dst)))
    return ip_v, src, dst, proto, stream, sport, dport, key


def _add_outer(flows, f, app, when, length):
    """A tunneled packet to its tunnel's outer flow (_split_tunnel)."""
    ip_v, src, dst, proto, stream, sport, dport, key = _packet_key(f, app)
    flow = flows.get(key)
    if flow is None:
        flow = flows[key] = _Flow(key, proto, ip_v, src, dst, sport, dport, when, stream)
        flow.tunnel = True
    cid = _community_id(src, dst, _PROTO_NUMBERS.get(proto, _int(f[_F_IP_PROTO] or f[_F_IP6_NXT])), sport, dport) \
        if not flow.community_id else ''
    flow.add(src, sport, length, when, app, cid, False)


class _LaterPasses:
    """iter_records' protocol and structured passes, run in a thread of
    their own once the first pass is done. wait() returns the protocol
    pass's protocols, or raises what a pass raised; cancel() stops them -
    for a consumer that stopped taking records (a shark.db write that
    failed), which would otherwise wait out the passes, up to the run's
    whole timeout."""

    def __init__(self, pcap_path, flows, ranges, last_frame, deadline, combined, structured):
        self.protocols, self.error = [], None
        self.cancelled = threading.Event()
        self._procs, self._procs_lock = [], threading.Lock()

        def started(proc):
            with self._procs_lock:
                self._procs.append(proc)
            if self.cancelled.is_set():
                proc.kill()

        def run():
            try:
                if pcap_path and ranges:
                    self.protocols = _protocol_pass(pcap_path, flows, ranges, last_frame, deadline,
                                                    skip=combined or (), on_start=started)
                if structured and not self.cancelled.is_set():
                    _structured_pass(pcap_path, flows, structured, last_frame, deadline, on_start=started)
            except BaseException as e:       # re-raised in wait()
                self.error = e
            finally:
                flows.clear()
        self.thread = threading.Thread(target=run, name='shark-later-passes', daemon=True)
        self.thread.start()

    def cancel(self):
        self.cancelled.set()
        with self._procs_lock:
            for proc in self._procs:
                try:
                    proc.kill()
                except OSError:
                    pass

    def wait(self):
        self.thread.join()
        if self.error is not None and not self.cancelled.is_set():
            raise self.error
        return self.protocols


def iter_records(lines, pcap_path=None, deadline=None, combined=()):
    """build_records' records, one at a time: a flow's is built as it's
    handed out and the flow then let go, so a capture's flows - most of
    its records - never exist twice over, or all at once as records.
    Given the capture's path, shark_protocols' records too - for which
    tshark reads the packets they need again (_protocol_pass,
    _structured_pass) - except the combined protocols' (True: all of
    them), read from these same lines, which carry their fields too
    (_combined_fields, for a capture _mostly_recorded)."""
    flows = {}
    tunnels = _Tunnels()
    tls_failures = _TLSFailures()
    last_frame = 0
    feeds = None
    if combined:
        combined = PROTOCOLS if combined is True else tuple(combined)
        column = {field: i for i, field in enumerate(_combined_fields(combined))}
        feeds = [(proto(), [column[field] for field in proto.fields]) for proto in combined]
    fed_apps = frozenset(app for proto in combined or () for app in proto.app_protos)
    # The protocols the protocol pass reads packets again for: the rest
    pass_apps = _RECORDED_FIELD_APPS - fed_apps
    # The frames the protocol pass reads, as runs of consecutive frame
    # numbers: once a flow carries a protocol with records here, all of it
    # - the frames before (a span: its start, which TCP reassembly needs)
    # and every one after.
    spans, runs = [], []
    for line in lines:
        cols = line.rstrip('\n').split('\t')
        if len(cols) < len(_FIELDS):
            continue
        split = _split_tunnel(cols) if cols[_F_PROTOS].count(':ip') > 1 else None    # (ipmi, ipp...: it says)
        if split is not None:
            raw_cols, cols = cols, split[1]
        # (a field occurs more than once - joined by _AGGREGATOR - in few
        # packets but tunneled ones, so most lines need no splitting)
        f = cols[:len(_FIELDS)] if split is None and _AGGREGATOR not in line else \
            [_last(c) for c in cols[:len(_FIELDS)]]
        try:
            when = float(f[_F_TIME])
        except ValueError:
            continue
        length = _int(f[_F_LEN])
        app = app_protocol(f[_F_PROTOS])
        if split is not None:
            # Nothing inside but an IP header (a Teredo bubble, keeping a
            # NAT open) is no flow of its own - as in Suricata - only its
            # tunnel's
            bare = app in ('ip', 'ipv6')
            tunnels.add(raw_cols, raw_cols[_F_PROTOS].split(':'), when, length,
                        None if bare else _packet_key(f, '')[-1])
            if split[2] is not None:
                _add_outer(flows, split[2], split[3], when, length)
            if bare:
                continue
            # The packet inside is its flow's, as Suricata counts it: from its
            # IP header on - or, for GRE carrying Ethernet, its Ethernet header
            length = _int(f[_F_IP_LEN]) if f[_F_PROTOS].startswith('ip:') else _int(f[_F_IP6_PLEN]) + 40
            if split[0] == 'GRE (Ethernet)':
                length += 14
        # An ICMP error (port unreachable, TTL exceeded...) carries a copy
        # of the packet it's about, whose addresses and ports are what the
        # last-occurrence fields read - so it lands in that packet's flow,
        # where Suricata (almost always) counts it too. It travels the other
        # way from the copy, so its direction comes from its own (outer)
        # source, and the copy is never fed to the protocol records as a
        # real message.
        icmp_error = ':icmp:ip:' in f[_F_PROTOS] or ':icmpv6:ipv6:' in f[_F_PROTOS]
        if icmp_error:
            app = ''
            outer_src = cols[_F_IP_SRC].split(_AGGREGATOR)[0] if f[_F_IP_SRC] else \
                ipv6_exploded(cols[_F_IP6_SRC].split(_AGGREGATOR)[0])
            # About a tunneled packet: the tunnel's outer flow's - or, for
            # GRE, whose outer flow Suricata doesn't log, no flow's, as there
            quoted = _icmp_quoted_tunnel(cols) if split is None else None
            if quoted is not None:
                if quoted[0] in _NO_OUTER_FLOW:
                    continue
                f = quoted[1]
        ip_v, src, dst, proto, stream, sport, dport, key = _packet_key(f, app)
        syn_only = f[_F_SYN] in ('1', 'True') and f[_F_ACK] not in ('1', 'True')
        flow = flows.get(key)
        if flow is None:
            flow = flows[key] = _Flow(key, proto, ip_v, src, dst, sport, dport, when, stream)
        if icmp_error:
            flow.add(src, sport, length, when, '', '', False, from_client=outer_src == flow.client)
            continue
        flow.add(src, sport, length, when, app, f[_F_CID], syn_only)
        if f[_F_ETH_DST] == 'ff:ff:ff:ff:ff:ff' and src == flow.client and sport == flow.cport:
            flow.mac_broadcast = True
        if proto == 'TCP' and _TLS_ALERT_COLUMN < len(cols) and cols[_TLS_ALERT_COLUMN]:
            tls_failures.add(flow, src, sport, when, cols[_TLS_ALERT_COLUMN].split(_AGGREGATOR))
        frame = _int(f[_F_FRAME])
        flow.first_frame = flow.first_frame or frame
        flow.last_frame = last_frame = frame
        if not (flow.client_set_by_syn or flow.client_set_by_message):
            # A SYN-ACK is a reply too: a stream that opens on one (a
            # server re-sending it after the connection was reset) has
            # the server sending first.
            syn_ack = f[_F_SYN] in ('1', 'True') and f[_F_ACK] in ('1', 'True')
            is_reply = True if syn_ack else _is_reply(cols)
            if is_reply is not None:
                flow.orient(src, sport, is_reply)
        if app in fed_apps:
            _feed(cols, feeds, Packet(frame, when, flow, sport, dport, app, src, dst))
        if frame:
            if flow.recorded:
                if runs and frame <= runs[-1][1] + 1:
                    runs[-1][1] = frame
                else:
                    runs.append([frame, frame])
            elif app in pass_apps:
                flow.recorded = True
                spans.append((flow.first_frame, frame))
    protocols = [handler for handler, _ in feeds or ()]
    structured = [proto() for proto in STRUCTURED_PROTOCOLS] if pcap_path else []
    # The flows are final now - the passes below only read them - so their
    # records go out while the passes run: each pass's tshark (most of its
    # time) works alongside the writing of a capture's flows, rather than
    # before it. Their records follow the flows', as before.
    passes = _LaterPasses(pcap_path, dict(flows), spans + [tuple(r) for r in runs], last_frame, deadline,
                          combined, structured)
    del spans, runs
    ordered = sorted(flows.values(), key=lambda fl: fl.first)
    flows.clear()
    try:
        for i, flow in enumerate(ordered):
            ordered[i] = None    # the transaction records below hold the flows they need
            yield flow.event()
        del ordered
    except BaseException:
        passes.cancel()          # the consumer stopped - the passes' records have nowhere to go
        raise
    finally:
        protocols += passes.wait()
    for handler in protocols + structured:
        for flow, when, event_type, body in handler.finish():
            yield flow.record(when, event_type, body)
    yield from tunnels.records()
    yield from tls_failures.records()


# What the structured pass has to decode to reach a protocol: the link
# layers a capture can start with (Ethernet, BSD and Linux loopback/cooked
# captures, raw IP, PPP) and tunnels, then IP and the transports - all
# other dissectors are off, and a packet whose link layer is missing here
# isn't decoded at all.
_STRUCTURED_LINKS = ('eth', 'ethertype', 'vlan', 'null', 'loop', 'sll', 'raw', 'ppp', 'pppoes', 'llc', 'mpls',
                     'gre', 'vxlan')
_STRUCTURED_TRANSPORT = ('ip', 'ipv6', 'tcp', 'udp')
_STRUCTURED_BASE = _STRUCTURED_LINKS + _STRUCTURED_TRANSPORT
# editcap keeps at most 512 frame ranges - past that it warns and drops the
# rest - so a second pass's copy is cut from no more than this many
_EDITCAP_MAX_RANGES = 500


def _frame_ranges(flows):
    """The frame number ranges covering these flows - each flow whole,
    since TCP reassembly needs every segment - merged (_merge_ranges)."""
    return _merge_ranges([(fl.first_frame, fl.last_frame) for fl in flows if fl.first_frame])


def _merge_ranges(ranges, max_ranges=None):
    """Frame number ranges merged where they touch or overlap - and, given
    max_ranges, merged again across the smallest gaps until there are at
    most that many."""
    ranges = sorted(ranges)
    merged = []
    for start, end in ranges:
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    while max_ranges and len(merged) > max_ranges:
        gaps = sorted(range(len(merged) - 1), key=lambda i: merged[i + 1][0] - merged[i][1])[:len(merged) - max_ranges]
        for i in sorted(gaps, reverse=True):
            merged[i][1] = merged[i + 1][1]
            del merged[i + 1]
    return [tuple(r) for r in merged]


def _structured_command(source, handlers):
    protocols = ','.join(dict.fromkeys(_STRUCTURED_BASE + tuple(p for h in handlers for p in h.tshark_protocols)))
    layers = ' '.join(dict.fromkeys(('frame',) + _STRUCTURED_TRANSPORT + tuple(l for h in handlers for l in h.layers)))
    return ['tshark', '-n', '-r', source, '--disable-all-protocols', '--enable-protocol', protocols,
            '-Y', ' || '.join(f'({h.display_filter})' for h in handlers),
            '-T', 'json', '--no-duplicate-keys', '-J', layers]


def _json_packets(stream):
    """tshark -T json's packets, one at a time: each is an object opening
    and closing at two spaces' indent, so the whole array never has to be
    held to parse it."""
    buf = []
    for line in stream:
        if line.startswith('  {'):
            buf = [line]
        elif buf:
            if line.startswith('  }'):
                buf.append('}')
                try:
                    yield json.loads(''.join(buf))['_source']['layers']
                except (ValueError, KeyError):
                    pass
                buf = []
            else:
                buf.append(line)


def _last_layer(layers, name):
    layer = layers.get(name)
    return layer[-1] if isinstance(layer, list) and layer else layer


def _structured_flow(layers, index):
    """The first pass's flow a structured-pass packet belongs to: by its
    addresses and ports (the innermost, as the first pass reads them),
    then the flow of those that was open at the time."""
    ip, ipv6 = _last_layer(layers, 'ip'), _last_layer(layers, 'ipv6')
    if ip:
        src, dst = ip.get('ip.src'), ip.get('ip.dst')
    elif ipv6:
        src, dst = ipv6_exploded(ipv6.get('ipv6.src', '')), ipv6_exploded(ipv6.get('ipv6.dst', ''))
    else:
        return None
    for proto in ('tcp', 'udp'):
        layer = _last_layer(layers, proto)
        if layer:
            sport, dport = _int(layer.get(f'{proto}.srcport')), _int(layer.get(f'{proto}.dstport'))
            break
    else:
        return None
    candidates = index.get((proto.upper(), frozenset(((src, sport), (dst, dport)))))
    if not candidates:
        return None
    try:
        when = float(_last_layer(layers, 'frame').get('frame.time_epoch'))
    except (TypeError, ValueError, AttributeError):
        return candidates[0]
    return _open_at(candidates, when)


def _open_at(candidates, when):
    """Of the flows with a packet's addresses and ports, the one open at
    its time (or the nearest) - a second pass's tshark numbers the streams
    of its copy its own way, so they can't be matched by number."""
    open_then = [fl for fl in candidates if fl.first - 1 <= when <= fl.last + 1]
    return open_then[0] if open_then else min(candidates, key=lambda fl: abs(fl.first - when))


def _subset(pcap_path, ranges, total_frames, tmp, timeout):
    """A copy of just these frames (sorted, merged ranges) - or the capture
    itself when they're most of it, since tshark has to read every packet
    of whatever it's given. pcap_subset copies any number of ranges
    exactly; for a capture it can't read (a compressed one), editcap,
    which takes no more than _EDITCAP_MAX_RANGES - so they're merged across
    their smallest gaps first, and the copy holds more than asked for."""
    if sum(end - start + 1 for start, end in ranges) >= 0.7 * max(total_frames, 1):
        return pcap_path
    source = os.path.join(tmp, 'subset')
    if pcap_subset.copy_frames(pcap_path, source, ranges):
        return source
    if not shutil.which('editcap'):
        return pcap_path
    ranges = _merge_ranges(ranges, _EDITCAP_MAX_RANGES)
    if sum(end - start + 1 for start, end in ranges) >= 0.7 * max(total_frames, 1):
        return pcap_path
    subprocess.run(['editcap', '-r', pcap_path, source] + [f'{a}-{b}' for a, b in ranges],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=timeout)
    return source


def _structured_pass(pcap_path, flows, handlers, total_frames, deadline=None, on_start=None):
    """Feed the structured protocols (shark_protocols.STRUCTURED_PROTOCOLS)
    from a second tshark run that writes their packets as JSON trees. It
    runs only if the first pass found any of their flows, and - unless
    those flows span most of the capture - only over a copy of their
    packets (_subset: pcap_subset, or editcap - copied, not decoded),
    since tshark has to read every packet of whatever it's given."""
    relevant = [fl for fl in flows.values()
                if fl.proto in ('TCP', 'UDP') and any(p in fl.protocols for h in handlers for p in h.app_protos)]
    active = [h for h in handlers if any(p in fl.protocols for fl in relevant for p in h.app_protos)]
    if not active:
        return
    index = {}
    for fl in sorted(relevant, key=lambda fl: fl.first):
        index.setdefault((fl.proto, frozenset(((fl.client, fl.cport), (fl.server, fl.sport)))), []).append(fl)
    ranges = _frame_ranges(relevant)
    remaining = None if deadline is None else max(1.0, deadline - time.monotonic())
    with tempfile.TemporaryDirectory(prefix='shark-') as tmp:
        source = _subset(pcap_path, ranges, total_frames, tmp, remaining)
        # TZ=UTC: tshark writes absolute times (SMB's file times) in local time
        with tempfile.TemporaryFile(mode='w+', errors='replace') as stderr_file, \
                subprocess.Popen(_structured_command(source, active), stdout=subprocess.PIPE, stderr=stderr_file,
                                 text=True, errors='replace', env=dict(os.environ, TZ='UTC'),
                                 preexec_fn=_low_priority) as proc:
            if on_start:
                on_start(proc)
            killer = threading.Timer(remaining, proc.kill) if remaining else None
            if killer:
                killer.start()
            try:
                for layers in _json_packets(proc.stdout):
                    flow = _structured_flow(layers, index)
                    if flow is None:
                        continue
                    frame = _last_layer(layers, 'frame') or {}
                    try:
                        when = float(frame.get('frame.time_epoch'))
                    except (TypeError, ValueError):
                        continue
                    packet = Packet(_int(frame.get('frame.number')), when, flow, flow.cport, flow.sport)
                    for handler in active:
                        if any(name in layers for name in handler.layers):
                            handler.feed_json(packet, layers)
                proc.wait()
            finally:
                if killer:
                    killer.cancel()
            stderr_file.seek(0)
            stderr = stderr_file.read(64 * 1024)
            if proc.returncode != 0 and not _read_to_damage(proc.returncode, stderr):
                lines = stderr.strip().splitlines()
                raise RuntimeError('tshark (structured pass) ' + (lines[-1] if lines else
                                   ('timed out' if proc.returncode < 0 else f'exit code {proc.returncode}')))


def _protocol_pass(pcap_path, flows, ranges, total_frames, deadline=None, skip=(), on_start=None):
    """shark_protocols' records, from a second tshark run asking for their
    fields - over a copy of just the frames the first pass marked (each
    flow carrying one of their protocols, from its start), and asking only
    for the fields of the protocols it found. Returns the protocols, fed -
    all but skip's, which the first pass fed."""
    protocols = [proto() for proto in PROTOCOLS if proto not in skip]
    present = {app for fl in flows.values() if fl.recorded for app in fl.protocols}
    active = [p for p in protocols if present.intersection(p.app_protos)]
    if not active:
        return protocols
    fields = _protocol_pass_fields(active)
    column = {field: i for i, field in enumerate(fields)}
    feeds = [(p, [column[field] for field in p.fields]) for p in active]
    index = {}
    for fl in sorted((fl for fl in flows.values() if fl.recorded), key=lambda fl: fl.first):
        key = (fl.proto, frozenset(((fl.client, fl.cport), (fl.server, fl.sport)))) \
            if fl.proto in ('TCP', 'UDP') else fl.key
        index.setdefault(key, []).append(fl)
    ranges = _merge_ranges(ranges)
    remaining = None if deadline is None else max(1.0, deadline - time.monotonic())
    with tempfile.TemporaryDirectory(prefix='shark-') as tmp:
        source = _subset(pcap_path, ranges, total_frames, tmp, remaining)
        with tempfile.TemporaryFile(mode='w+', errors='replace') as stderr_file, \
                subprocess.Popen(tshark_command(source, fields), stdout=subprocess.PIPE, stderr=stderr_file,
                                 text=True, errors='replace', preexec_fn=_low_priority) as proc:
            if on_start:
                on_start(proc)
            killer = threading.Timer(remaining, proc.kill) if remaining else None
            if killer:
                killer.start()
            try:
                for line in proc.stdout:
                    _feed_protocols(line.rstrip('\n').split('\t'), index, feeds)
                proc.wait()
            finally:
                if killer:
                    killer.cancel()
            stderr_file.seek(0)
            stderr = stderr_file.read(64 * 1024)
            if proc.returncode != 0 and not _read_to_damage(proc.returncode, stderr):
                lines = stderr.strip().splitlines()
                raise RuntimeError('tshark (protocol pass) ' + (lines[-1] if lines else
                                   ('timed out' if proc.returncode < 0 else f'exit code {proc.returncode}')))
    return protocols


def _mostly_recorded(pcap_path):
    """Whether most of a capture's packets are in flows of protocols with
    records here - a capture of one such protocol - so that the protocol
    pass would read nearly all of it again, and one pass asking for their
    fields is quicker: the protocols with records seen, if so (an empty
    set if not). Judged from windows of packets spread across it (a
    capture's start can be one busy conversation); a capture too small for
    two passes to cost much, or one that can't be sampled, isn't."""
    count = packet_count(pcap_path)
    if not count or count < _PROBE_MIN_PACKETS:
        return frozenset()
    step = (count - _PROBE_WINDOW) // (_PROBE_WINDOWS - 1)
    windows = [(1 + i * step, i * step + _PROBE_WINDOW) for i in range(_PROBE_WINDOWS)] \
        if count > _PROBE_WINDOWS * _PROBE_WINDOW else [(1, count)]
    with tempfile.TemporaryDirectory(prefix='shark-') as tmp:
        sample = os.path.join(tmp, 'sample')
        try:
            if not pcap_subset.copy_frames(pcap_path, sample, windows):
                return frozenset()
            out = subprocess.run(['tshark', '-n', '-r', sample, '-T', 'fields', '-e', 'frame.protocols',
                                  '-e', 'tcp.stream', '-e', 'udp.stream'], capture_output=True, text=True,
                                 errors='replace', timeout=120, preexec_fn=_low_priority).stdout
        except (OSError, subprocess.SubprocessError):
            return frozenset()
    keys, recorded, apps = [], set(), set()
    for line in out.splitlines():
        protocols, tcp, udp = (line.split('\t') + ['', ''])[:3]
        app = app_protocol(protocols)
        key = ('tcp', tcp) if tcp else ('udp', udp) if udp else ('', app)
        keys.append(key)
        if app in _RECORDED_FIELD_APPS:
            recorded.add(key)
            apps.add(app)
    mostly = bool(keys) and sum(key in recorded for key in keys) >= _PROBE_SHARE * len(keys)
    return frozenset(apps) if mostly else frozenset()


def _feed_protocols(cols, index, feeds):
    """One protocol-pass packet to the protocols it's for, on the first
    pass's flow it belongs to."""
    if len(cols) < len(_FIELDS):
        return
    split = _split_tunnel(cols) if cols[_F_PROTOS].count(':ip') > 1 else None
    if split is not None:
        cols = split[1]
    f = [_last(c) for c in cols[:len(_FIELDS)]]
    try:
        when = float(f[_F_TIME])
    except ValueError:
        return
    # An ICMP error's copy of a packet is never a real message (see iter_records)
    if ':icmp:ip:' in f[_F_PROTOS] or ':icmpv6:ipv6:' in f[_F_PROTOS]:
        return
    app = app_protocol(f[_F_PROTOS])
    if app not in _RECORDED_FIELD_APPS:
        return
    _, src, dst, proto, _, sport, dport, key = _packet_key(f, app)
    candidates = index.get((proto, frozenset(((src, sport), (dst, dport))))
                           if proto in ('TCP', 'UDP') else key)
    if not candidates:
        return
    _feed(cols, feeds, Packet(_int(f[_F_FRAME]), when, _open_at(candidates, when), sport, dport, app, src, dst))


def _feed(cols, feeds, packet):
    """A packet's fields to each protocol it's for."""
    app = packet.app
    for handler, columns in feeds:
        # A protocol only sees packets of its own protocols: tshark reuses
        # one dissector's fields for others (mDNS and LLMNR carry dns.*
        # fields, SSDP http.* ones), so fields alone can't say whose packet
        # it is.
        if app not in handler.app_protos:
            continue
        values = [cols[i] if i < len(cols) else '' for i in columns]
        if not any(values):
            continue
        handler.feed(packet, {name: [_unescape(x) for x in value.split(_AGGREGATOR)] if value else []
                              for name, value in zip(handler.fields, values)})


def build_flows(lines):
    """Just build_records' flow records."""
    return [e for e in build_records(lines) if e['event_type'] == 'flow']


def _low_priority():
    """preexec_fn for tshark: lowest CPU priority, so a background run
    yields to Suricata and to the user's own work."""
    try:
        os.nice(19)
    except OSError:
        pass


# tshark's word for a capture it read up to a cut-off or damaged record -
# a capture stopped mid-write, a partial upload - before exiting 2. Every
# packet before that was read and fed as usual, as Suricata reads them.
_DAMAGED_CAPTURE = ('appears to have been cut short in the middle of a packet', 'appears to be damaged or corrupt')


# tshark's words for a capture it wasn't allowed to open. AppArmor 5
# (Ubuntu 26.04 on) has an enforcing profile for /usr/bin/tshark that lets
# it read files in /tmp and hardly anywhere else - and in a rootless
# container, which the host doesn't confine, that profile reaches the
# container's tshark too, so it can't read the analysis's directory.
_DENIED_CAPTURE = "You don't have permission to read the file"


class CaptureDenied(RuntimeError):
    """tshark wasn't allowed to open the capture (see _DENIED_CAPTURE)."""


# The folder in /tmp each run gets (analyze), and a startup sweep removes
# when a server that died left it (storage.cleanup_stale_tmp)
RUN_TMP_PREFIX = 'shark-run-'
# 5.0.1's name for it, when it held only the capture's copy. (Before
# 5.1.0, a killed run's second passes left plain shark-XXXXXXXX folders
# in /tmp, but a name that short could be anyone's.)
LEGACY_TMP_PREFIXES = ('shark-copy-',)
# In a run's folder once its build read the capture from a copy
_DENIED_MARKER = '.denied'
# Whether a build has had to: tshark's AppArmor profile (see
# _DENIED_CAPTURE) doesn't change while the server runs, so later runs go
# straight to the copy rather than each being refused - and logged by the
# kernel - once more. Set from the queue's one thread.
_read_from_copy = False


def _read_to_damage(returncode, stderr):
    """Whether a tshark run that failed only stopped at a capture's cut-off
    or damaged end, having read all it could."""
    return returncode == 2 and any(phrase in stderr for phrase in _DAMAGED_CAPTURE)


def run_tshark(pcap_path, timeout=None, on_start=None, consume=list, notes=None):
    """Run tshark over pcap_path and return consume(its records) - by
    default, the records as a list; analyze's build streams them into
    shark.db instead. Raises RuntimeError if tshark is missing, fails, is
    killed, or exceeds the timeout. on_start, if given, is called with the
    tshark process as soon as it starts."""
    if not shutil.which('tshark'):
        raise RuntimeError('tshark is not installed')
    # A capture mostly of protocols with records: one pass asking for the
    # fields of those the probe saw - any other's flows still get the
    # protocol pass, over just their packets
    seen = _mostly_recorded(pcap_path)
    combined = PROTOCOLS if seen is True else tuple(p for p in PROTOCOLS if seen and seen & set(p.app_protos))
    cmd = tshark_command(pcap_path, _combined_fields(combined) if combined else _FIRST_PASS_FIELDS)
    if shutil.which('ionice'):
        cmd = ['ionice', '-c', '3'] + cmd   # idle I/O class - allowed without privileges
    timeout = config.SHARK_RUN_TIMEOUT if timeout is None else timeout
    timed_out = threading.Event()
    # stderr goes to a file, not a pipe: it's only read once tshark exits,
    # and a pipe that filled with warnings meanwhile would stall tshark.
    with tempfile.TemporaryFile(mode='w+', errors='replace') as stderr_file, \
            subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=stderr_file, text=True,
                             errors='replace', preexec_fn=_low_priority) as proc:
        if on_start:
            on_start(proc)

        def _kill():
            timed_out.set()
            proc.kill()
        killer = threading.Timer(timeout, _kill)
        killer.start()
        try:
            events = consume(iter_records(proc.stdout, pcap_path, time.monotonic() + timeout, combined))
            proc.wait()
        finally:
            killer.cancel()
        stderr_file.seek(0)
        stderr = stderr_file.read(64 * 1024)
    if timed_out.is_set():
        raise RuntimeError(f'tshark timed out after {timeout}s')
    if proc.returncode < 0:
        raise RuntimeError('tshark was stopped')
    if proc.returncode != 0 and not _read_to_damage(proc.returncode, stderr):
        detail = stderr.strip().splitlines()[-1] if stderr.strip() else f'exit code {proc.returncode}'
        raise (CaptureDenied if _DENIED_CAPTURE in stderr else RuntimeError)(f'tshark failed: {detail}')
    if notes is not None and proc.returncode != 0:
        notes['damaged'] = True      # read up to a cut-off or damaged end
    return events


def _child_command(dir_path, pcap_path):
    cmd = [sys.executable, '-m', 'shark_analyzer', 'build', dir_path, pcap_path]
    if shutil.which('ionice'):
        cmd = ['ionice', '-c', '3'] + cmd
    return cmd


def _group_memory(pgid):
    """Bytes of memory the processes of one process group hold (resident
    set) - the build and its tshark, which runs in the build's group."""
    total = 0
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            with open(f'/proc/{pid}/stat') as f:
                fields = f.read().rsplit(')', 1)[1].split()
            if int(fields[2]) == pgid:            # field 5 of stat, the process group
                total += int(fields[21]) * _PAGE_SIZE   # field 24, resident pages
        except (OSError, ValueError, IndexError):
            continue
    return total


_PAGE_SIZE = os.sysconf('SC_PAGE_SIZE') if hasattr(os, 'sysconf') else 4096


def _watch_memory(proc, too_big):
    """Stop a build whose processes together pass SHARK_MAX_MEMORY_BYTES -
    tshark's memory grows with the capture's packet count, and a capture
    with millions of small packets could otherwise take all of it."""
    while proc.poll() is None:
        if _group_memory(proc.pid) > config.SHARK_MAX_MEMORY_BYTES:
            too_big.set()
            _kill_group(proc)
            return
        time.sleep(config.SHARK_MEMORY_CHECK_SECONDS)


def _kill_group(proc):
    """Kill a build and its tshark: the build leads its own process group."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass


def analyze(dir_path, pcap_path, on_start=None):
    """Build dir_path's shark.db from pcap_path, in a child process (build)
    at the lowest CPU and I/O priority - so building the records competes
    with neither the server's own Python nor Suricata, and the memory it
    took goes back when it exits. On failure, .shark_error says why -
    unless the run was cancelled, whose directory is being cleared or
    removed. on_start is called with the child process (the queue kills
    its process group to cancel it)."""
    error_path = os.path.join(dir_path, SHARK_ERROR)
    _remove(error_path)
    with _lock:
        _unwritten_errors.pop(dir_path, None)
    # The run's temp folder, in /tmp: the build's TMPDIR (its second
    # passes' copies of frames) and where it puts a copy of the capture if
    # tshark may not read it in place (_run_from_tmp_copy). Made here so
    # it's removed even when the build is killed (a cancel, the memory
    # watchdog), and unique, so no other run shares it
    global _read_from_copy
    run_dir = tempfile.mkdtemp(prefix=RUN_TMP_PREFIX)
    try:
        succeeded = _analyze(dir_path, pcap_path, on_start, run_dir)
        if os.path.exists(os.path.join(run_dir, _DENIED_MARKER)):
            _read_from_copy = True
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)
    if not succeeded and not os.path.exists(error_path):
        # Failed where neither the build nor _analyze could say why (an
        # unwritable folder, a full disk): without this, status() would read
        # it as never started, and each status request would queue it again
        message = ("tshark couldn't write to this analysis's folder - its files may belong to another user, "
                   'from an earlier run of SO-CRATES' if not os.access(dir_path, os.W_OK)
                   else "tshark's run failed, and why couldn't be saved in this analysis's folder - is the disk full?")
        with _lock:
            if dir_path not in _cancelled:
                _unwritten_errors[dir_path] = message


def _analyze(dir_path, pcap_path, on_start, run_dir):
    """analyze's child process and what it says when it fails. Returns
    whether the build succeeded."""
    env = dict(os.environ, SHARK_RUN_DIR=run_dir, TMPDIR=run_dir)
    if _read_from_copy:
        env['SHARK_READ_FROM_COPY'] = '1'
    with tempfile.TemporaryFile(mode='w+', errors='replace') as stderr_file:
        proc = subprocess.Popen(_child_command(dir_path, pcap_path), cwd=os.path.dirname(os.path.abspath(__file__)),
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stderr_file,
                                env=env,
                                preexec_fn=_low_priority, start_new_session=True)
        if on_start:
            on_start(proc)
        too_big, hung = threading.Event(), False
        watchdog = threading.Thread(target=_watch_memory, args=(proc, too_big), daemon=True)
        watchdog.start()
        try:
            # The build enforces tshark's own timeout; this one is for a
            # build that hangs after it
            proc.wait(timeout=config.SHARK_RUN_TIMEOUT + 600)
        except subprocess.TimeoutExpired:
            hung = True
            _kill_group(proc)
            proc.wait()
        watchdog.join()
        succeeded = not too_big.is_set() and proc.returncode == 0
        if not too_big.is_set() and (proc.returncode == 0 or _was_cancelled(dir_path)
                                     or os.path.exists(os.path.join(dir_path, SHARK_ERROR))):
            return succeeded
        stderr_file.seek(0)
        lines = stderr_file.read()[-64 * 1024:].strip().splitlines()
    if too_big.is_set():
        detail = (f'it needed more than {config.SHARK_MAX_MEMORY_BYTES / 1024 ** 3:g} GB of memory '
                  '(tshark needs about 1 KB per packet)')
    elif hung:
        detail = f'it ran past {(config.SHARK_RUN_TIMEOUT + 600) // 60} minutes'
    else:
        # It died without saying why: killed (out of memory, most often) or crashed
        detail = lines[-1] if lines else ('killed - out of memory?' if proc.returncode == -signal.SIGKILL
                                          else f'exit code {proc.returncode}')
    _remove(shark_db_path(dir_path) + '.tmp')
    try:
        with open(os.path.join(dir_path, SHARK_ERROR), 'w') as f:
            f.write(f'tshark analysis stopped: {detail}'[:500])
    except OSError:
        pass
    return False


def build(dir_path, pcap_path, copy_dir=None, from_copy=False):
    """analyze's child process: run tshark and write its records into
    shark.db as they're built, committing as it goes. On failure, writes
    the reason to .shark_error. Returns whether it succeeded. from_copy:
    read the capture from a copy in copy_dir without trying it in place
    first - an earlier run found tshark may not."""
    db_path = shark_db_path(dir_path)
    tmp_path = db_path + '.tmp'
    started = time.monotonic()
    try:
        for name in (tmp_path, tmp_path + '-wal', tmp_path + '-shm'):
            _remove(name)
        notes = {}
        denied = from_copy
        if not from_copy:
            try:
                run_tshark(pcap_path, consume=lambda records: create_shark_db(tmp_path, records), notes=notes)
            except CaptureDenied:
                denied = True
                for name in (tmp_path, tmp_path + '-wal', tmp_path + '-shm'):
                    _remove(name)
        if denied:
            # Not allowed to read it here: from a copy in /tmp, which tshark
            # may read - noted for analyze, so later runs start there
            if copy_dir:
                open(os.path.join(copy_dir, _DENIED_MARKER), 'w').close()
            _run_from_tmp_copy(copy_dir, pcap_path, tmp_path, notes)
        conn = sqlite3.connect(tmp_path)
        try:
            conn.execute(f'PRAGMA user_version = {SHARK_FORMAT_VERSION}')
            # How long the run took, tshark and building the records both,
            # and whether the capture's end was cut off or damaged
            # (status() reports both once the run is ready)
            conn.execute('CREATE TABLE shark_run (seconds REAL, damaged INTEGER)')
            conn.execute('INSERT INTO shark_run VALUES (?, ?)', (time.monotonic() - started, int(bool(notes))))
            conn.commit()
        finally:
            conn.close()
        os.replace(tmp_path, db_path)
        return True
    except Exception as e:
        _remove(tmp_path)
        try:
            with open(os.path.join(dir_path, SHARK_ERROR), 'w') as f:
                f.write(str(e)[:500])
        except OSError:
            pass
        return False


def _run_from_tmp_copy(copy_dir, pcap_path, tmp_path, notes):
    """build's run_tshark again, from the capture placed in copy_dir, a
    folder in /tmp that analyze made for this run (or one made here, for
    a build run directly) - for a tshark not allowed to read the
    analysis's directory (see _DENIED_CAPTURE). The copy is removed when
    the run ends."""
    own_dir = copy_dir is None
    if own_dir:
        copy_dir = tempfile.mkdtemp(prefix=RUN_TMP_PREFIX)
    copy = os.path.join(copy_dir, os.path.basename(pcap_path))
    try:
        _place_copy(pcap_path, copy)
        try:
            run_tshark(copy, consume=lambda records: create_shark_db(tmp_path, records), notes=notes)
        except CaptureDenied as e:
            raise RuntimeError("tshark isn't allowed to read the capture, even from a copy in "
                               f'{os.path.dirname(copy_dir)} - a security policy on this computer, most likely '
                               "AppArmor's profile for tshark, blocks it") from e
    finally:
        _remove(copy)
        if own_dir:
            shutil.rmtree(copy_dir, ignore_errors=True)


def _place_copy(pcap_path, copy):
    """Put the capture at copy: a hard link where it can be - free, and
    tshark's profile allows it by its /tmp path, but only for a file of
    this user's own (the rule is owner /tmp/**) on the same filesystem -
    else a copy, if there's room for one (/tmp is often RAM)."""
    tmp_dir = os.path.dirname(os.path.dirname(copy))
    try:
        if os.stat(pcap_path).st_uid == os.getuid():
            os.link(pcap_path, copy)
            return
    except OSError:
        pass
    try:
        src = open(pcap_path, 'rb')
    except OSError as e:
        raise RuntimeError(f"tshark couldn't read the capture, and neither could SO-CRATES: {e.strerror or e}") from e
    with src:
        size, free = os.fstat(src.fileno()).st_size, shutil.disk_usage(os.path.dirname(copy)).free
        if size > free:
            raise RuntimeError(f"tshark isn't allowed to read the capture where it is, and {tmp_dir} has too little "
                               f'free space for a copy ({size / 1024 ** 2:,.0f} MB needed, '
                               f'{free / 1024 ** 2:,.0f} MB free)')
        try:
            with open(copy, 'wb') as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
        except OSError as e:
            raise RuntimeError(f"tshark isn't allowed to read the capture where it is, and copying it to {tmp_dir} "
                               f'failed: {e.strerror or e}') from e


def _remove(path):
    try:
        os.unlink(path)
    except OSError:
        pass


# ----------------------------------------------------------------------
# The queue: one tshark run at a time, in the order they were asked for.
# ----------------------------------------------------------------------

_lock = threading.Lock()
_queue = deque()          # dir_paths waiting, each with its pcap path in _pending
_pending = {}             # dir_path -> pcap_path
_running = None           # dir_path being analyzed now, or None
_running_since = None     # when it started (time.time()), for status()'s elapsed
_running_proc = None      # its tshark process, once started
_cancelled = set()        # dir_paths whose running job was cancelled
_worker = None
_unwritten_errors = {}    # dir_path -> why its run failed, where .shark_error couldn't be written


def _was_cancelled(dir_path):
    with _lock:
        return dir_path in _cancelled


def _set_running_proc(proc):
    global _running_proc
    with _lock:
        _running_proc = proc
        if _running in _cancelled:   # cancelled before the build had started
            _kill_group(proc)


def _work():
    global _running, _running_since, _running_proc, _worker
    while True:
        with _lock:
            if not _queue:
                _running = _worker = None
                return
            dir_path = _queue.popleft()
            pcap_path = _pending.pop(dir_path)
            _running, _running_since = dir_path, time.time()
        if os.path.isfile(pcap_path):
            analyze(dir_path, pcap_path, on_start=_set_running_proc)
            if not _was_cancelled(dir_path):
                merge(dir_path)
        with _lock:
            _running = _running_since = _running_proc = None
            _cancelled.discard(dir_path)


def enqueue(dir_path, pcap_path):
    """Queue a tshark run for this analysis, unless one is already
    queued or running for it - one that was cancelled and is still being
    stopped doesn't count (reanalyze cancels, then queues the new run at
    once). Returns True if it was queued."""
    global _worker
    with _lock:
        if dir_path in _pending or (dir_path == _running and dir_path not in _cancelled):
            return False
        _unwritten_errors.pop(dir_path, None)
        _queue.append(dir_path)
        _pending[dir_path] = pcap_path
        if _worker is None:
            _worker = threading.Thread(target=_work, daemon=True)
            _worker.start()
    return True


def cancel(dir_path):
    """Stop this analysis's tshark run (reanalyze/delete): drop it
    from the queue, or kill its tshark if it's running."""
    with _lock:
        _unwritten_errors.pop(dir_path, None)
        if dir_path in _pending:
            del _pending[dir_path]
            _queue.remove(dir_path)
        elif dir_path == _running:
            _cancelled.add(dir_path)
            if _running_proc is not None:
                _kill_group(_running_proc)


_PACKET_COUNTS = {}     # (path, size, mtime) -> packet count


def packet_count(pcap_path):
    """A capture's packet count (capinfos, which reads it without decoding -
    a fraction of a second for millions of packets), or None if it can't be
    counted. Remembered per file, since status() asks on every poll."""
    try:
        st = os.stat(pcap_path)
    except OSError:
        return None
    key = (pcap_path, st.st_size, st.st_mtime)
    if key not in _PACKET_COUNTS:
        count = None
        if shutil.which('capinfos'):
            try:
                out = subprocess.run(['capinfos', '-c', '-M', '-T', '-r', pcap_path], capture_output=True,
                                     text=True, timeout=120).stdout
                count = int(out.strip().rsplit('\t', 1)[1])
            except (subprocess.SubprocessError, OSError, ValueError, IndexError):
                count = None
        if len(_PACKET_COUNTS) > 1000:
            _PACKET_COUNTS.clear()
        _PACKET_COUNTS[key] = count
    return _PACKET_COUNTS[key]


def background_eligible(pcap_path):
    """Whether a capture is small enough to analyze without being asked: by
    its packet count - what tshark's memory follows - or, when that can't
    be counted, by its size."""
    count = packet_count(pcap_path)
    if count is not None:
        return count <= config.SHARK_BACKGROUND_MAX_PACKETS
    try:
        return os.path.getsize(pcap_path) <= config.SHARK_BACKGROUND_MAX_BYTES
    except OSError:
        return False


SHARK_SETTINGS = 'shark_settings.json'


def enabled(data_dir):
    """Whether tshark runs at all - the Settings switch, kept in the
    data directory (on unless turned off)."""
    try:
        with open(os.path.join(data_dir, SHARK_SETTINGS)) as f:
            return json.load(f).get('enabled', True) is not False
    except (OSError, ValueError, AttributeError):
        return True


def set_enabled(data_dir, on):
    path = os.path.join(data_dir, SHARK_SETTINGS)
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump({'enabled': bool(on)}, f)
    os.replace(tmp, path)


def _run_info(db_path):
    """(seconds, damaged) of the run that built a shark.db - (None, False)
    for what it didn't record."""
    try:
        conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
        try:
            row = conn.execute('SELECT seconds, damaged FROM shark_run').fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return None, False
    return (row[0], bool(row[1])) if row else (None, False)


def format_version(db_path):
    """The SHARK_FORMAT_VERSION a shark.db was built with (0 if unknown)."""
    try:
        conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
        try:
            return conn.execute('PRAGMA user_version').fetchone()[0]
        finally:
            conn.close()
    except sqlite3.Error:
        return 0


# ----------------------------------------------------------------------
# Merging into the analysis's own events.db: Suricata stays the source of
# truth for every protocol it parses; tshark adds what it can't see.
# ----------------------------------------------------------------------

# Suricata 8's app-layer parsers (suricata --list-app-layer-protos), in the
# names tshark's app_proto uses, plus what it logs below the app layer
# (ICMP flows, ARP). static/socrates.js keeps the same list.
SURICATA_APP_PROTOS = frozenset((
    'http', 'ftp', 'ftp-data', 'smtp', 'tls', 'ssh', 'imap', 'smb', 'dcerpc', 'dns', 'modbus', 'enip', 'dnp3', 'nfs',
    'ntp', 'tftp', 'ike', 'krb5', 'quic', 'dhcp', 'sip', 'rfb', 'mqtt', 'pgsql', 'telnet', 'websocket', 'ldap', 'doh2',
    'rdp', 'http2', 'bittorrent-dht', 'pop3', 'mdns', 'snmp', 'icmp', 'ipv6-icmp', 'icmpv6', 'arp'))
# ... less the ones it recognizes but writes no records for - tshark's
# records of those are still the only ones there are.
SURICATA_RECORDED_APP_PROTOS = SURICATA_APP_PROTOS - {'telnet', 'imap'}

_merge_locks = {}
_merge_locks_lock = threading.Lock()


def _merge_lock(dir_path):
    with _merge_locks_lock:
        return _merge_locks.setdefault(dir_path, threading.Lock())


# Bump it whenever merge_rows changes what a merge adds from the same
# shark.db: an analysis merged by an older one is merged again.
_MERGE_VERSION = 5


def _merge_stamp(db_path):
    """Which shark.db a merge came from, and by which merge: its format
    and modification time, and _MERGE_VERSION."""
    return f'{SHARK_FORMAT_VERSION}.{_MERGE_VERSION}:{os.path.getmtime(db_path):.6f}'


# Protocols that only ever send - logs, flow exports, media streams,
# wake-up packets: an unanswered connection is how they work, not a
# probe, so they're never probe_only_protocols.
_ONE_WAY_PROTOCOLS = frozenset(('syslog', 'cflow', 'sflow', 'gelf', 'collectd', 'tzsp', 'rtp', 'rtpevent', 'rtcp',
                                'wol'))


def probe_only_protocols(shark_db):
    """The application protocols whose every connection in shark.db was
    a probe nothing answered - no reply, or only an ICMP error (_Flow.
    answered). Not one with a connection to a multicast or broadcast
    address, or one that isn't IP: neither can say whether it was
    answered. Nor a one-way protocol (_ONE_WAY_PROTOCOLS)."""
    with closing(sqlite3.connect(f'file:{shark_db}?mode=ro', uri=True)) as conn:
        rows = conn.execute(
            "SELECT json_extract(json_data, '$.app_proto') AS app, "
            "max(coalesce(json_extract(json_data, '$.shark.answered'), '') IN ('yes', '')) "
            "FROM events WHERE event_type = 'flow' AND app IS NOT NULL AND app != '' GROUP BY app").fetchall()
    return frozenset(app for app, kept in rows if not kept and app not in _ONE_WAY_PROTOCOLS)


def merge_rows(shark_rows, identified, probed=frozenset(), tls_records=None):
    """The rows of a shark.db (its stored JSON, one at a time) that belong
    in the analysis's events.db: records of protocols Suricata doesn't
    parse, and - as connection rows, CONNECTION_TYPE_PREFIX + protocol -
    flows of protocols that have neither Suricata's parsing nor records of
    their own here. Nothing on a flow Suricata identified - gave a protocol
    and backed it with records (by Community ID and time, from
    db.suricata_identified_flows): there Suricata's word stands, as on a
    scanner's HTTP request to an rsh port, which tshark, going by the port,
    calls rsh. The connections of the protocols in probed
    (probe_only_protocols) share one type, PROBED_CONNECTION_TYPE.

    The exception is TLS failures (_TLSFailures): alerts Suricata never
    logs, kept on the flows it identified too - each with what Suricata's
    tls record of its connection says (tls_records: Community IDs ->
    db.suricata_tls_records), the nearest in time and within
    _TLS_CONTEXT_SECONDS of it, so the record names the certificate
    refused."""
    from db import CONNECTION_TYPE_PREFIX, PROBED_CONNECTION_TYPE

    def suricata_knows(cid, first, last):
        return any(start - 1 <= last and first <= end + 1 for start, end in identified.get(cid, ()))
    failures = []
    for data in shark_rows:
        event = json.loads(data)
        event_type = event.get('event_type', '')
        cid = event.get('community_id')
        if event_type == 'flow':
            app = event.get('app_proto') or ''
            if not app or app in SURICATA_APP_PROTOS or app in RECORDED_APP_PROTOS or \
                    (event.get('shark') or {}).get('tunnel'):
                continue
            flow = event.get('flow') or {}
            first, last = _iso_epoch(flow.get('start')), _iso_epoch(flow.get('end'))
            if first is not None and suricata_knows(cid, first, last if last is not None else first):
                continue
            event['event_type'] = PROBED_CONNECTION_TYPE if app in probed else CONNECTION_TYPE_PREFIX + app
        elif event_type == TLS_FAILURE_TYPE:
            failures.append(event)
            continue
        else:
            if event_type.replace('_', '-') in SURICATA_RECORDED_APP_PROTOS:
                continue
            when = _iso_epoch(event.get('timestamp'))
            if when is not None and suricata_knows(cid, when, when):
                continue
        yield event
    known = tls_records({e['community_id'] for e in failures if e.get('community_id')}) \
        if failures and tls_records else {}
    for event in failures:
        candidates = known.get(event.get('community_id'))
        when = _iso_epoch(event.get('timestamp'))
        if candidates and when is not None:
            nearest = min(candidates, key=lambda c: abs(c[0] - when))
            # Only the same connection's: a 5-tuple reused later (a busy
            # NAT, a scanner) is another connection with another certificate
            if abs(nearest[0] - when) <= _TLS_CONTEXT_SECONDS:
                body = event[TLS_FAILURE_TYPE]
                event[TLS_FAILURE_TYPE] = {**nearest[1], **body}
        yield event


def _mergeable_rows(shark_db):
    """shark.db's rows, as stored, less the flows merge_rows always drops -
    no protocol, or one Suricata parses or with records here - so the
    merge doesn't parse the JSON of a capture's every flow to drop most of
    them. merge_rows still judges every row it's given."""
    dropped = sorted(SURICATA_APP_PROTOS | RECORDED_APP_PROTOS)
    placeholders = ','.join('?' * len(dropped))
    with closing(sqlite3.connect(f'file:{shark_db}?mode=ro', uri=True)) as conn:
        yield from (row[0] for row in conn.execute(
            "SELECT json_data FROM events WHERE event_type != 'flow' OR "
            f"(coalesce(app_proto, '') != '' AND app_proto NOT IN ({placeholders})) ORDER BY id", dropped))


def merge(dir_path):
    """Add tshark's rows (merge_rows) to the analysis's events.db - once
    both Suricata (its events.db imported, no .phase left) and tshark
    (a current shark.db) are done, whichever finishes last calls this. A
    later shark.db (a retried run) replaces the rows of an earlier one.
    Returns how many rows were added, or None if it wasn't time to."""
    shark_db = shark_db_path(dir_path)
    events_db = os.path.join(dir_path, 'events.db')
    with _merge_lock(dir_path):
        if not (os.path.exists(shark_db) and os.path.exists(events_db)) or \
                os.path.exists(os.path.join(dir_path, '.phase')) or format_version(shark_db) != SHARK_FORMAT_VERSION:
            return None
        stamp = _merge_stamp(shark_db)
        if tshark_merge_stamp(events_db) == stamp:
            return None
        added = replace_tshark_events(events_db, merge_rows(_mergeable_rows(shark_db),
                                                            suricata_identified_flows(events_db),
                                                            probe_only_protocols(shark_db),
                                                            lambda cids: suricata_tls_records(events_db, cids)), stamp)
    from analysis_cache import evict_analysis_cache
    evict_analysis_cache(os.path.basename(os.path.normpath(dir_path)))
    return added


_merging = set()


def merge_soon(dir_path):
    """merge() in the background, unless one is already under way for
    this analysis - a status poll that finds it unmerged asks again every
    couple of seconds."""
    with _merge_locks_lock:
        if dir_path in _merging:
            return
        _merging.add(dir_path)

    def run():
        try:
            merge(dir_path)
        except Exception:
            pass       # status() keeps reporting it unmerged; the next poll retries
        finally:
            with _merge_locks_lock:
                _merging.discard(dir_path)
    threading.Thread(target=run, daemon=True).start()


def merged(dir_path):
    """Whether the analysis's events.db has the current shark.db's rows."""
    shark_db = shark_db_path(dir_path)
    try:
        return tshark_merge_stamp(os.path.join(dir_path, 'events.db')) == _merge_stamp(shark_db)
    except OSError:
        return False


def status(dir_path, pcap_path=None):
    """This analysis's tshark state: 'ready' (with the run's
    'seconds', for a shark.db that recorded them), 'queued', 'running'
    (with 'elapsed' seconds so far), 'error' (with 'message'), 'too_large'
    (over the background limit, not yet asked for) or 'not_started'. A shark.db built by an older
    tshark (see SHARK_FORMAT_VERSION) is removed here, so the
    analysis reads as not started and gets rebuilt."""
    db_path = shark_db_path(dir_path)
    if os.path.exists(db_path):
        with _lock:
            busy = dir_path == _running or dir_path in _pending
        if busy or format_version(db_path) == SHARK_FORMAT_VERSION:
            if not busy:
                seconds, damaged = _run_info(db_path)
                ready = {'status': 'ready'} if seconds is None else {'status': 'ready', 'seconds': round(seconds)}
                if damaged:
                    ready['damaged'] = True
                return ready
        else:
            for name in (SHARK_DB, SHARK_DB + '-wal', SHARK_DB + '-shm'):
                _remove(os.path.join(dir_path, name))
    with _lock:
        if dir_path == _running:
            return {'status': 'running', 'elapsed': max(0, int(time.time() - _running_since))}
        if dir_path in _pending:
            return {'status': 'queued', 'position': list(_queue).index(dir_path) + 1}
        if dir_path in _unwritten_errors:
            return {'status': 'error', 'message': _unwritten_errors[dir_path]}
    error_path = os.path.join(dir_path, SHARK_ERROR)
    if os.path.exists(error_path):
        try:
            with open(error_path) as f:
                message = f.read().strip()
        except OSError:
            message = ''
        return {'status': 'error', 'message': message or 'tshark analysis failed'}
    if pcap_path and not background_eligible(pcap_path):
        return {'status': 'too_large'}
    return {'status': 'not_started'}


def wait_idle(timeout=60):
    """Block until the queue is empty and nothing is running (tests)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with _lock:
            if not _queue and _running is None:
                return True
        time.sleep(0.05)
    return False


if __name__ == '__main__':
    # analyze's child: python3 -m shark_analyzer build <analysis dir> <pcap>
    if len(sys.argv) == 4 and sys.argv[1] == 'build':
        sys.exit(0 if build(sys.argv[2], sys.argv[3], os.environ.get('SHARK_RUN_DIR'),
                            os.environ.get('SHARK_READ_FROM_COPY') == '1') else 1)
    sys.exit('usage: python3 -m shark_analyzer build <analysis dir> <pcap>')
