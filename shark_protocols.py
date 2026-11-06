#!/usr/bin/env python3
"""Records for protocols Suricata doesn't parse: tshark's packet-by-packet
fields turned into one record per request/response transaction, to join
Suricata's records in the analysis (shark_analyzer.merge). Suricata stays
the source of truth for everything it parses, so nothing here duplicates
one of its protocols.

Each protocol is a class listing the tshark fields it needs (appended to
shark_analyzer's single tshark run) with feed(), called for every packet
that has any of them, and finish(), which returns its records once the
capture has been read. Requests are paired with their responses as the
packets stream past - by tshark's own back-reference from a response to
its request's frame where it has one, otherwise by the flow and the
protocol's transaction ID - so tshark never needs its slower two-pass
mode. A request that never got a response is still a record.

Records come back as (flow, when, event_type, body); shark_analyzer adds
the addresses, ports and Community ID from the flow, oriented client to
server like its flow records.
"""

import math
import re
import socket
import struct


def _first(values, default=''):
    return values[0] if values else default


def _int(value, default=None):
    """tshark's decimal or 0x-prefixed hex integer, or default."""
    try:
        return int(value, 16) if str(value).lower().startswith('0x') else int(value)
    except (TypeError, ValueError):
        return default


def _hex(text):
    """tshark's bytes of a field (aa:bb:... or aabb...) - b'' for none, or
    for anything that isn't hex, instead of failing the run."""
    try:
        return bytes.fromhex(text.replace(':', '')) if text else b''
    except ValueError:
        return b''


def _finite(text):
    """A measurement as a number - or, for one that isn't a finite number
    (a sensor's NaN, or infinity, which JSON can't hold), as tshark wrote it."""
    try:
        number = float(text)
    except ValueError:
        return text
    return number if math.isfinite(number) else text


def ipv6_exploded(address):
    from shark_analyzer import ipv6_exploded as explode   # shark_analyzer imports this module
    return explode(address)


class Packet:
    """What a protocol needs to know about the packet it's fed: its frame
    number, time, flow (shark_analyzer._Flow), addresses and ports, and
    application protocol (shark_analyzer.app_protocol - 'dns', 'mdns'...)."""
    __slots__ = ('frame', 'when', 'flow', 'sport', 'dport', 'app', 'src', 'dst')

    def __init__(self, frame, when, flow, sport, dport, app='', src='', dst=''):
        self.frame, self.when, self.flow, self.sport, self.dport = frame, when, flow, sport, dport
        self.app, self.src, self.dst = app, src, dst


# ---------------------------------------------------------------- LLMNR

_DNS_TYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA',
              33: 'SRV', 35: 'NAPTR', 39: 'DNAME', 43: 'DS', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY',
              52: 'TLSA', 64: 'SVCB', 65: 'HTTPS', 99: 'SPF', 252: 'AXFR', 255: 'ANY', 257: 'CAA'}
_DNS_RCODES = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED',
               6: 'YXDOMAIN', 7: 'YXRRSET', 8: 'NXRRSET', 9: 'NOTAUTH', 10: 'NOTZONE'}
# Answer type -> the tshark field holding its data. Each list holds every
# record of that type in the message, answers first, so answers take
# values from the front.
_DNS_RDATA = {'A': 'dns.a', 'AAAA': 'dns.aaaa', 'CNAME': 'dns.cname', 'NS': 'dns.ns',
              'PTR': 'dns.ptr.domain_name', 'MX': 'dns.mx.mail_exchange', 'TXT': 'dns.txt'}


def _dns_type(value):
    number = _int(value)
    return _DNS_TYPES.get(number, f'TYPE{number}') if number is not None else ''


class LLMNR:
    """LLMNR - Windows' link-local name resolution, which tshark decodes
    with its DNS dissector (same message format, dns.* fields): a record
    per query, its response merged in, in the layout of Suricata's DNS
    records. (DNS and mDNS themselves are Suricata's.)"""
    event_type = 'llmnr'
    app_protos = ('llmnr',)      # flow app_proto values whose transactions these records are
    fields = ('dns.id', 'dns.flags.response', 'dns.qry.name', 'dns.qry.type', 'dns.flags.rcode',
              'dns.count.answers', 'dns.resp.name', 'dns.resp.type', 'dns.resp.ttl',
              'dns.response_to') + tuple(_DNS_RDATA.values())

    def __init__(self):
        self.records = []        # (flow, when, event_type, body), in request order
        self.by_frame = {}       # request frame number -> its body
        self.unanswered = {}     # (asker's address, port, id, first query) -> body, until its response
        self.unanswered_keys = {}    # id(body) -> its key in unanswered
        self.answered = {}       # the same keys, once answered -> body

    def feed(self, pkt, v):
        txid = _int(_first(v['dns.id']))
        if txid is None:
            return
        kind = 'llmnr'
        queries = [{'rrname': name, 'rrtype': _dns_type(qtype)} for name, qtype in zip(v['dns.qry.name'], v['dns.qry.type'])]
        is_response = _first(v['dns.flags.response']) in ('True', '1')
        if not is_response:
            # A retransmission - the same question, same ID, sent again while
            # still unanswered - is the same transaction. (The same ID and
            # question after an answer is a new one.)
            key = self._key(pkt.src, pkt.sport, txid, queries)
            body = self.unanswered.get(key)
            if body is None:
                body = self.unanswered[key] = {'version': 3, 'type': 'request', 'id': txid, 'queries': queries}
                self.unanswered_keys[id(body)] = key
                self.records.append((pkt.flow, pkt.when, kind, body))
            else:
                body['transmissions'] = body.get('transmissions', 1) + 1
            self.by_frame[pkt.frame] = body
            return
        answers = self._answers(v)
        # The response goes back to whoever asked. tshark links a response
        # to its query only within one conversation, and only the first
        # response - so a multicast query's unicast answer, or a repeat of
        # an answered query's response, arrives unlinked.
        key = self._key(pkt.dst, pkt.dport, txid, queries)
        body = self.by_frame.get(_int(_first(v['dns.response_to']))) or self.unanswered.get(key) \
            or self.answered.get(key)
        if body is not None and body['type'] == 'response':
            # The answer again: counted, not a new record. More than one
            # response to a query can mean an attacker racing the real server.
            body['responses'] = body.get('responses', 1) + 1
            return
        if body is None:   # a response whose request isn't in the capture
            body = {'version': 3, 'id': txid, 'queries': queries}
            self.records.append((pkt.flow, pkt.when, kind, body))
        else:
            # (by its own key - the response's can differ, and rebuilding
            # the dict for each answer was quadratic in unanswered queries)
            self.unanswered.pop(self.unanswered_keys.pop(id(body), None), None)
        self.answered[key] = body
        body['type'] = 'response'
        body['rcode'] = _DNS_RCODES.get(_int(_first(v['dns.flags.rcode']), 0), _first(v['dns.flags.rcode']))
        if answers:
            body['answers'] = answers

    @staticmethod
    def _key(asker, asker_port, txid, queries):
        return (asker, asker_port, txid, (queries[0]['rrname'], queries[0]['rrtype']) if queries else None)

    @staticmethod
    def _answers(v):
        rdata = {rtype: list(v[field]) for rtype, field in _DNS_RDATA.items()}
        count = _int(_first(v['dns.count.answers']), 0)
        answers = []
        for name, rtype, ttl in list(zip(v['dns.resp.name'], v['dns.resp.type'], v['dns.resp.ttl']))[:count]:
            rtype = _dns_type(rtype)
            answer = {'rrname': name, 'rrtype': rtype, 'ttl': _int(ttl, 0)}
            if rdata.get(rtype):
                answer['rdata'] = rdata[rtype].pop(0)
                if rtype == 'AAAA':
                    answer['rdata'] = ipv6_exploded(answer['rdata'])
            answers.append(answer)
        return answers

    def finish(self):
        return self.records


# ---------------------------------------------------------------- NBNS

_NBNS_OPCODES = {0: 'query', 5: 'registration', 6: 'release', 7: 'wack', 8: 'refresh',
                 15: 'multi-homed registration'}
_NBNS_RCODES = {0: 'NOERROR', 1: 'FMT_ERR', 2: 'SRV_ERR', 3: 'NAM_ERR', 4: 'IMP_ERR', 5: 'RFS_ERR',
                6: 'ACT_ERR', 7: 'CFT_ERR'}
# tshark writes a NetBIOS name as NAME<suffix>, and once as NAME<suffix> (service)
_NBNS_NAME = re.compile(r'^(.*)<([0-9A-Fa-f]{2})>(?: \((.*)\))?$')


class NBNS:
    """NetBIOS name service (Windows name resolution - Suricata doesn't
    parse it): a record per transaction - a query and its answer, or a
    name registration, refresh or release, usually broadcast and
    unanswered - with its retransmissions (same transaction ID, before an
    answer) folded in.
    The name is split into name, its 16th-byte suffix and the service that
    suffix means (<20> is the Server service)."""
    event_type = 'nbns'
    app_protos = ('nbns',)
    fields = ('nbns.id', 'nbns.flags.response', 'nbns.flags.opcode', 'nbns.flags.rcode', 'nbns.name',
              'nbns.addr', 'nbns.ttl')

    def __init__(self):
        self.records = []
        self.open = {}           # (asker's address, transaction id) -> body

    def feed(self, pkt, v):
        txid = _int(_first(v['nbns.id']))
        if txid is None:
            return
        # A broadcast query's answer comes back directly to the asker, on
        # another flow - so a transaction is keyed by who asked.
        is_response = _first(v['nbns.flags.response']) in ('True', '1')
        key = (pkt.dst if is_response else pkt.src, txid)
        body = self.open.get(key)
        # A request after its transaction's answer is a new one - the same
        # ID reused - not a retransmission (as LLMNR has it)
        if body is not None and not is_response and body['type'] == 'response':
            body = None
        if body is None:
            opcode = _int(_first(v['nbns.flags.opcode']), 0)
            body = self.open[key] = {'type': 'request', 'id': txid,
                                     'opcode': _NBNS_OPCODES.get(opcode, f'opcode {opcode}')}
            self.records.append((pkt.flow, pkt.when, self.event_type, body))
        for raw in v['nbns.name']:
            m = _NBNS_NAME.match(raw)
            if m:
                body.setdefault('name', m.group(1).rstrip())
                body.setdefault('suffix', m.group(2).upper())
                if m.group(3):
                    body.setdefault('service', m.group(3))
            else:
                body.setdefault('name', raw)
        if v['nbns.addr']:
            body['address'] = v['nbns.addr'][0]
        if v['nbns.ttl']:
            body['ttl'] = _int(v['nbns.ttl'][0], 0)
        if is_response:
            body['type'] = 'response'
            rcode = _int(_first(v['nbns.flags.rcode']), 0)
            body['rcode'] = _NBNS_RCODES.get(rcode, str(rcode))
        else:
            body['transmissions'] = body.get('transmissions', 0) + 1

    def finish(self):
        return self.records


# ---------------------------------------------------------------- DHCPv6
#
# Suricata parses DHCP for IPv4 only. A DHCPv6 client multicasts its
# message (Solicit, Request, Renew, Information-request...) to ff02::1:2
# and the server answers it directly (Advertise, Reply) - on another
# flow, so a transaction is keyed by the client's address and its
# transaction ID, like NBNS's. One record per transaction, its
# retransmissions counted: the client's DUID and the MAC address in it,
# the hostname it gave (the Client FQDN option - Windows always sends
# one), its vendor class, and from the reply the addresses and prefixes
# assigned, the server's DUID, DNS servers, search domains and status.
# Through a relay, the record is the relay's, with the link it serves.

_DHCPV6_MESSAGES = {1: 'Solicit', 2: 'Advertise', 3: 'Request', 4: 'Confirm', 5: 'Renew', 6: 'Rebind', 7: 'Reply',
                    8: 'Release', 9: 'Decline', 10: 'Reconfigure', 11: 'Information-request', 12: 'Relay-forw',
                    13: 'Relay-reply'}
_DHCPV6_FROM_SERVER = {2, 7, 10, 13}
_DHCPV6_STATUS = {0: 'Success', 1: 'UnspecFail', 2: 'NoAddrsAvail', 3: 'NoBinding', 4: 'NotOnLink', 5: 'UseMulticast',
                  6: 'NoPrefixAvail'}
_DHCPV6_MAX_LIST = 20


def _duid_mac(duid):
    """The Ethernet address in a link-layer DUID (types 1 and 3), or ''."""
    try:
        raw = bytes.fromhex(duid.replace(':', ''))
    except ValueError:
        return ''
    kind, hwtype = struct.unpack('!HH', raw[:4]) if len(raw) >= 4 else (0, 0)
    address = raw[8:] if kind == 1 else raw[4:] if kind == 3 else b''
    return ':'.join(f'{b:02x}' for b in address) if hwtype == 1 and len(address) == 6 else ''


class DHCPv6:
    """DHCPv6 - see the comment above."""
    event_type = 'dhcpv6'
    app_protos = ('dhcpv6',)
    fields = ('dhcpv6.msgtype', 'dhcpv6.xid', 'dhcpv6.linkaddr', 'dhcpv6.option.type', 'dhcpv6.duid.bytes',
              'dhcpv6.client_domain', 'dhcpv6.vendorclass.data', 'dhcpv6.iaaddr.ip', 'dhcpv6.iaprefix.pref_addr',
              'dhcpv6.iaprefix.pref_len',
              'dhcpv6.status_code', 'dhcpv6.status_msg', 'dhcpv6.dns_server', 'dhcpv6.search_list_entry')

    def __init__(self):
        self.records = []
        self.open = {}           # (client's or relay's address, transaction id) -> body

    def feed(self, pkt, v):
        kinds = [_int(t) for t in v['dhcpv6.msgtype']]
        txid = _int(_first(v['dhcpv6.xid']))
        if not kinds or txid is None:
            return
        outer, message = kinds[0], kinds[-1]      # a relay's message carries the client's
        from_server = outer in _DHCPV6_FROM_SERVER
        key = (pkt.dst if from_server else pkt.src, txid)
        body = self.open.get(key)
        # A client's message after the server's reply is a new exchange
        # (RFC 8415 gives each its own transaction ID; one reused is still
        # a new one), not a retransmission
        if body is not None and not from_server and 'reply' in body:
            body = None
        if body is None:
            body = self.open[key] = {'transaction_id': f'0x{txid:06x}'}
            self.records.append((pkt.flow, pkt.when, self.event_type, body))
        name = _DHCPV6_MESSAGES.get(message, f'type {message}')
        if from_server:
            body['reply'] = name
        else:
            body.setdefault('message', name)
            body['transmissions'] = body.get('transmissions', 0) + 1
        if outer in (12, 13):
            body['relayed'] = True
            if v['dhcpv6.linkaddr'] and v['dhcpv6.linkaddr'][0] != '::':
                body['link_address'] = ipv6_exploded(v['dhcpv6.linkaddr'][0])
        # Each Client ID (1) and Server ID (2) option holds one DUID, in order
        owners = [t for t in (_int(x) for x in v['dhcpv6.option.type']) if t in (1, 2)]
        for owner, duid in zip(owners, v['dhcpv6.duid.bytes']):
            duid = duid.replace(':', '')
            if owner == 1:
                body['client_duid'] = duid
                if _duid_mac(duid):
                    body['client_mac'] = _duid_mac(duid)
            else:
                body['server_duid'] = duid
        if v['dhcpv6.client_domain']:
            body['hostname'] = v['dhcpv6.client_domain'][0].rstrip('.')
        if v['dhcpv6.vendorclass.data']:
            body['vendor_class'] = v['dhcpv6.vendorclass.data'][0]
        addresses = [ipv6_exploded(a) for a in dict.fromkeys(v['dhcpv6.iaaddr.ip'])][:_DHCPV6_MAX_LIST]
        prefixes = list(dict.fromkeys(f'{ipv6_exploded(a)}/{n}' for a, n in
                                      zip(v['dhcpv6.iaprefix.pref_addr'], v['dhcpv6.iaprefix.pref_len'])))
        if from_server:
            for field, values in (('assigned_addresses', addresses), ('prefixes', prefixes),
                                 ('dns_servers', [ipv6_exploded(a) for a in dict.fromkeys(v['dhcpv6.dns_server'])]),
                                 ('domain_search', list(dict.fromkeys(e.rstrip('.') for e in
                                                                      v['dhcpv6.search_list_entry'])))):
                if values:
                    body[field] = values[:_DHCPV6_MAX_LIST]
            code = _int(_first(v['dhcpv6.status_code']))
            if code is not None:
                body['status'] = _DHCPV6_STATUS.get(code, str(code))
                if v['dhcpv6.status_msg']:
                    body['status_message'] = v['dhcpv6.status_msg'][0]
        elif addresses:
            body['requested_addresses'] = addresses

    def finish(self):
        return self.records


# ---------------------------------------------------------------- Syslog
#
# Suricata has no syslog parser. One record per message (UDP 514 - tshark
# doesn't decode syslog over TCP): its facility and severity, from the
# <PRI> that starts it, and the rest in either of the two formats - RFC
# 3164's "Mmm dd hh:mm:ss host program[pid]: text" (most devices, many
# leaving out the timestamp or host) or RFC 5424's "1 timestamp host app
# procid msgid [structured data] text". It's parsed here from the
# message's bytes: tshark reads "sshd[812]: Failed..." as program sshd and
# message "812]: Failed...".

_SYSLOG_FACILITIES = ('kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp', 'cron', 'authpriv',
                      'ftp', 'ntp', 'audit', 'alert', 'clock') + tuple(f'local{n}' for n in range(8))
_SYSLOG_SEVERITIES = ('emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug')
_SYSLOG_MAX_MESSAGE = 2048
_SYSLOG_PRI = re.compile(r'<(\d{1,3})>')
_SYSLOG_5424 = re.compile(r'1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]"\\]|\\.|"(?:[^"\\]|\\.)*")*\])+) ?(.*)', re.S)
_SYSLOG_SD_ELEMENT = re.compile(r'\[([^\s\]=]+)((?:\s+[^\s=\]]+="(?:[^"\\]|\\.)*")*)\s*\]')
_SYSLOG_SD_PARAM = re.compile(r'([^\s=\]]+)="((?:[^"\\]|\\.)*)"')
_SYSLOG_3164_TIME = re.compile(r'([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d(?:\.\d+)?(?: \d{4})?) ')
_SYSLOG_TAG = r'([A-Za-z0-9_./-]+)(?:\[(\d+)\])?: ?'
_SYSLOG_HOST_TAG = re.compile(r'([\w.:-]+) ' + _SYSLOG_TAG + r'(.*)', re.S)
_SYSLOG_TAG_ONLY = re.compile(_SYSLOG_TAG + r'(.*)', re.S)


def _syslog_nil(value):
    return '' if value == '-' else value


class Syslog:
    """Syslog - see the comment above."""
    event_type = 'syslog'
    app_protos = ('syslog',)
    fields = ('@syslog',)

    def __init__(self):
        self.records = []

    def feed(self, pkt, v):
        try:
            text = bytes.fromhex(_first(v['@syslog']).replace(':', '')).decode('utf-8', 'replace')
        except ValueError:
            return
        text = text.rstrip('\r\n\x00')
        if not text:
            return
        body = {}
        pri = _SYSLOG_PRI.match(text)
        if pri and int(pri.group(1)) < 192:
            value = int(pri.group(1))
            body['facility'] = _SYSLOG_FACILITIES[value >> 3]
            body['severity'] = _SYSLOG_SEVERITIES[value & 7]
            text = text[pri.end():]
            m = _SYSLOG_5424.match(text)
            if m:
                body['format'] = 'RFC 5424'
                for key, value in zip(('timestamp', 'hostname', 'program', 'pid', 'msgid'), m.groups()[:5]):
                    if _syslog_nil(value):
                        body[key] = value
                if m.group(6) != '-':
                    body['structured_data'] = {
                        element.group(1): {k: re.sub(r'\\(["\\\]])', r'\1', val)
                                           for k, val in _SYSLOG_SD_PARAM.findall(element.group(2))}
                        for element in _SYSLOG_SD_ELEMENT.finditer(m.group(6))}
                text = m.group(7).lstrip('\ufeff')
            else:
                body['format'] = 'RFC 3164'
                stamp = _SYSLOG_3164_TIME.match(text)
                if stamp:
                    body['timestamp'] = stamp.group(1)
                    text = text[stamp.end():]
                tagged = (_SYSLOG_HOST_TAG.match(text) if stamp else None) or _SYSLOG_TAG_ONLY.match(text)
                if tagged:
                    groups = tagged.groups()
                    if len(groups) == 4:
                        body['hostname'] = groups[0]
                        groups = groups[1:]
                    body['program'] = groups[0]
                    if groups[1]:
                        body['pid'] = groups[1]
                    text = groups[2]
        else:
            body['format'] = 'no priority'
        if len(text) > _SYSLOG_MAX_MESSAGE:
            text, body['truncated'] = text[:_SYSLOG_MAX_MESSAGE], True
        body['message'] = text
        self.records.append((pkt.flow, pkt.when, self.event_type, body))

    def finish(self):
        return self.records


# ---------------------------------------------------------------- ONC RPC
#
# Sun RPC, under NFS and the services around it - Suricata parses NFS
# itself, but not the rest: the portmapper (port 111), which tells a
# client which port each RPC program is on, the mount daemon, the lock
# and status monitors, NIS. One record per call, with its reply: the
# program, version and procedure, who the caller said it was (AUTH_UNIX's
# machine name and uid/gid), and the reply's status. The portmapper's
# replies are an inventory of the RPC services a host runs (DUMP lists
# them all; GETPORT asks for one), and the mount daemon's which exports
# it offers to whom (EXPORT) and who has them mounted (DUMP). A scanner's
# DUMP to port 111 nobody answered is still a record.

_RPC_PROGRAMS = {100000: 'portmapper', 100001: 'rstatd', 100002: 'rusersd', 100003: 'nfs', 100004: 'ypserv',
                 100005: 'mountd', 100007: 'ypbind', 100008: 'walld', 100009: 'yppasswdd', 100011: 'rquotad',
                 100012: 'sprayd', 100021: 'nlockmgr', 100024: 'status', 100026: 'bootparam', 100068: 'cmsd',
                 100069: 'ypxfrd', 100083: 'ttdbserverd', 100227: 'nfs_acl', 100232: 'sadmind', 150001: 'pcnfsd',
                 300019: 'amd'}
_RPC_PROCEDURES = {
    'portmapper': ('NULL', 'SET', 'UNSET', 'GETPORT', 'DUMP', 'CALLIT', 'GETTIME', 'UADDR2TADDR', 'TADDR2UADDR',
                   'GETVERSADDR', 'INDIRECT', 'GETADDRLIST', 'GETSTAT'),
    'mountd': ('NULL', 'MNT', 'DUMP', 'UMNT', 'UMNTALL', 'EXPORT', 'EXPORTALL', 'PATHCONF'),
    'status': ('NULL', 'STAT', 'MON', 'UNMON', 'UNMON_ALL', 'SIMU_CRASH', 'NOTIFY'),
    'nlockmgr': ('NULL', 'TEST', 'LOCK', 'CANCEL', 'UNLOCK', 'GRANTED', 'TEST_MSG', 'LOCK_MSG', 'CANCEL_MSG',
                 'UNLOCK_MSG', 'GRANTED_MSG', 'TEST_RES', 'LOCK_RES', 'CANCEL_RES', 'UNLOCK_RES', 'GRANTED_RES'),
}
# portmapper v3/v4 (rpcbind) number GETADDR where v2 has GETPORT
_RPCBIND_PROCEDURES = ('NULL', 'SET', 'UNSET', 'GETADDR', 'DUMP', 'CALLIT', 'GETTIME', 'UADDR2TADDR',
                       'TADDR2UADDR', 'GETVERSADDR', 'INDIRECT', 'GETADDRLIST', 'GETSTAT')
_RPC_TRANSPORTS = {6: 'tcp', 17: 'udp'}
_RPC_MAX_LIST = 100


def _rpc_program(number):
    return _RPC_PROGRAMS.get(number, str(number)) if number is not None else ''


class RPC:
    """ONC RPC - see the comment above."""
    event_type = 'rpc'
    app_protos = ('rpc', 'portmap', 'mount', 'nlm', 'stat', 'ypbind', 'ypserv', 'yppasswd', 'ypxfr', 'rquota',
                  'rstat', 'rwall', 'spray', 'bootparams', 'pcnfsd', 'klm', 'nfsacl', 'nfsauth', 'sadmind', 'nisplus')
    fields = ('rpc.xid', 'rpc.msgtyp', 'rpc.program', 'rpc.programversion', 'rpc.procedure',
              'vals(rpc.auth.flavor)', 'rpc.auth.machinename', 'rpc.auth.uid', 'rpc.auth.gid', 'vals(rpc.replystat)',
              'vals(rpc.state_accept)', 'portmap.prog', 'portmap.version', 'portmap.proto', 'portmap.port',
              'mount.path', 'vals(mount.status)', 'mount.export.directory', 'mount.export.group',
              'mount.dump.hostname', 'mount.dump.directory')

    def __init__(self):
        self.records = []
        self.open = {}           # (flow key, xid) -> body

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        xid, kind = _int(first('rpc.xid')), _int(first('rpc.msgtyp'))
        if xid is None or kind not in (0, 1):
            return               # tshark's RPC heuristic, matching a packet that isn't
        key = (pkt.flow.key, xid)
        body = self.open.get(key)
        if body is None:
            number = _int(first('rpc.program'))
            body = self.open[key] = {'xid': f'0x{xid:08x}', 'program': _rpc_program(number)}
            if number is not None:
                body['program_number'] = number
            version, procedure = _int(first('rpc.programversion')), _int(first('rpc.procedure'))
            if version is not None:
                body['version'] = version
            if procedure is not None:
                names = _RPCBIND_PROCEDURES if body['program'] == 'portmapper' and (version or 2) > 2 \
                    else _RPC_PROCEDURES.get(body['program'], ())
                body['procedure'] = names[procedure] if procedure < len(names) else f'procedure {procedure}'
            self.records.append((pkt.flow, pkt.when, self.event_type, body))
        if kind == 0:
            body['calls'] = body.get('calls', 0) + 1
            flavor = first('vals(rpc.auth.flavor)')
            if flavor:
                body['auth'] = flavor
            for name, field in (('machine_name', 'rpc.auth.machinename'), ('uid', 'rpc.auth.uid'),
                                ('gid', 'rpc.auth.gid')):
                if first(field):
                    body[name] = _int(first(field), first(field)) if name != 'machine_name' else first(field)
            self._call(body, v, first)
        else:
            stat, accept = first('vals(rpc.replystat)'), first('vals(rpc.state_accept)')
            body['reply'] = accept if stat == 'accepted' and accept else stat or 'reply'
            self._reply(body, v, first)

    @staticmethod
    def _call(body, v, first):
        if body['program'] == 'portmapper' and v['portmap.prog']:
            body['query'] = {'program': _rpc_program(_int(first('portmap.prog'))),
                             'version': _int(first('portmap.version')),
                             'transport': _RPC_TRANSPORTS.get(_int(first('portmap.proto')), first('portmap.proto'))}
        if first('mount.path'):
            body['path'] = first('mount.path')

    @staticmethod
    def _reply(body, v, first):
        if body['program'] == 'portmapper':
            if body.get('procedure') == 'DUMP' and v['portmap.prog']:
                body['mappings'] = [
                    {'program': _rpc_program(_int(p)), 'version': _int(ver),
                     'transport': _RPC_TRANSPORTS.get(_int(proto), proto), 'port': _int(port)}
                    for p, ver, proto, port in zip(v['portmap.prog'], v['portmap.version'], v['portmap.proto'],
                                                   v['portmap.port'])][:_RPC_MAX_LIST]
            elif v['portmap.port']:
                port = _int(first('portmap.port'))
                body['port'] = port
                if port == 0:
                    body['reply'] = 'not registered'
        if body['program'] == 'mountd':
            if first('vals(mount.status)'):
                body['mount_status'] = first('vals(mount.status)')
            if v['mount.export.directory']:
                body['exports'] = list(dict.fromkeys(v['mount.export.directory']))[:_RPC_MAX_LIST]
                if v['mount.export.group']:
                    body['export_clients'] = list(dict.fromkeys(v['mount.export.group']))[:_RPC_MAX_LIST]
            if v['mount.dump.hostname']:
                body['mounted_by'] = [f'{host}:{path}' for host, path in
                                      zip(v['mount.dump.hostname'], v['mount.dump.directory'])][:_RPC_MAX_LIST]

    def finish(self):
        return self.records


# ---------------------------------------------------------------- DTLS
#
# TLS over UDP (VPNs, WebRTC, CoAP and IoT security, CAPWAP) - Suricata
# parses TLS over TCP only. One record per connection's handshake, named
# the way Suricata's tls records are: the version agreed, the SNI and
# ALPNs the client asked for, the cipher suite the server picked, the
# JA3/JA3S/JA4 fingerprints, the server's certificate (DTLS 1.2 and
# before send it in the clear), WebRTC's SRTP profile, and how far the
# handshake got - a scanner's ClientHello nobody answered is still a
# record, its JA4 naming the tool.

_DTLS_VERSIONS = {0xfeff: 'DTLS 1.0', 0xfefd: 'DTLS 1.2', 0xfefc: 'DTLS 1.3', 0x0100: 'DTLS 1.0 (OpenSSL pre-0.9.8f)'}
_X509_NAMES = {'2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU',
               '2.5.4.5': 'serialNumber', '1.2.840.113549.1.9.1': 'emailAddress', '0.9.2342.19200300.100.1.25': 'DC'}
_X509_SAN = '2.5.29.17'
_DTLS_MAX_SANS = 20


def _dtls_version(value):
    number = _int(value)
    return _DTLS_VERSIONS.get(number, value) if number is not None else ''


def _der(data, pos):
    """A DER element at pos: (tag, start of its contents, end)."""
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7f
        length = int.from_bytes(data[pos:pos + count], 'big')
        pos += count
    if pos + length > len(data):
        raise ValueError('truncated')
    return tag, pos, pos + length


def _der_children(data, start, end):
    while start < end:
        tag, inner, start = _der(data, start)
        yield tag, inner, start


def _oid(raw):
    parts, value = [], 0
    for b in raw:
        value = value << 7 | (b & 0x7f)
        if not b & 0x80:
            parts.append(value)
            value = 0
    first = min(parts[0] // 40, 2) if parts else 0
    return '.'.join(str(n) for n in [first, parts[0] - 40 * first] + parts[1:]) if parts else ''


def _x509_name(data, start, end):
    """A Name as Suricata writes one: 'C=US, O=Example, CN=example.com'."""
    out = []
    for _, rdn, rdn_end in _der_children(data, start, end):
        for _, atv, atv_end in _der_children(data, rdn, rdn_end):
            _, oid_start, oid_end = _der(data, atv)
            _, value_start, value_end = _der(data, oid_end)
            oid = _oid(data[oid_start:oid_end])
            text = data[value_start:value_end].decode('utf-8', 'replace')
            out.append(f'{_X509_NAMES.get(oid, oid)}={text}')
    return ', '.join(out)


def _x509_time(raw):
    text = raw.decode('ascii', 'replace').rstrip('Z')
    if len(text) == 12:                  # UTCTime: YYMMDDHHMMSS
        text = ('19' if text[:2] >= '50' else '20') + text
    return f'{text[:4]}-{text[4:6]}-{text[6:8]}T{text[8:10]}:{text[10:12]}:{text[12:14]}' if len(text) >= 14 else text


def _x509(hexbytes):
    """What Suricata's tls record says about a certificate (DER, as tshark
    shows its bytes), or {} if it can't be read."""
    import hashlib
    try:
        data = bytes.fromhex(hexbytes.replace(':', ''))
        _, cert, cert_end = _der(data, 0)
        _, tbs, tbs_end = _der(data, cert)
        fields = list(_der_children(data, tbs, tbs_end))
        if fields and fields[0][0] == 0xa0:         # [0] version
            fields = fields[1:]
        (_, serial, serial_end), _, (_, issuer, issuer_end), (_, validity, validity_end), \
            (_, subject, subject_end) = fields[:5]
        times = [data[s:e] for _, s, e in _der_children(data, validity, validity_end)]
        out = {'subject': _x509_name(data, subject, subject_end), 'issuerdn': _x509_name(data, issuer, issuer_end),
               'serial': ':'.join(f'{b:02X}' for b in data[serial:serial_end].lstrip(b'\x00') or b'\x00'),
               'fingerprint': ':'.join(f'{b:02x}' for b in hashlib.sha1(data[:cert_end]).digest())}
        if len(times) == 2:
            out['notbefore'], out['notafter'] = _x509_time(times[0]), _x509_time(times[1])
        for tag, ext, ext_end in fields[5:]:
            if tag != 0xa3:                          # [3] extensions
                continue
            _, seq, seq_end = _der(data, ext)
            for _, item, item_end in _der_children(data, seq, seq_end):
                parts = list(_der_children(data, item, item_end))
                if parts and _oid(data[parts[0][1]:parts[0][2]]) == _X509_SAN:
                    _, names, names_end = _der(data, parts[-1][1])
                    sans = [data[s:e].decode('ascii', 'replace') for t, s, e in _der_children(data, names, names_end)
                            if t == 0x82]            # dNSName
                    if sans:
                        out['san'] = sans[:_DTLS_MAX_SANS]
        return out
    except (ValueError, IndexError):
        return {}


class _DTLSConnection:
    __slots__ = ('body', 'ccs', 'server_hello')

    def __init__(self, body):
        self.body, self.ccs, self.server_hello = body, set(), False


class DTLS:
    """DTLS - see the comment above."""
    event_type = 'dtls'
    app_protos = ('dtls',)
    fields = ('dtls.record.version', 'dtls.handshake.type', 'dtls.handshake.version',
              'dtls.handshake.extensions.supported_version', 'dtls.handshake.extensions_server_name',
              'dtls.handshake.extensions_alpn_str', 'vals(dtls.handshake.ciphersuite)', 'dtls.handshake.ja3',
              'dtls.handshake.ja3_full', 'dtls.handshake.ja3s', 'dtls.handshake.ja3s_full', 'dtls.handshake.ja4',
              'vals(dtls.use_srtp.protection_profile)', 'dtls.handshake.certificate', 'dtls.record.content_type',
              'vals(dtls.alert_message.desc)')

    def __init__(self):
        self.connections = {}       # flow key -> _DTLSConnection, in the order they began

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        conn = self.connections.get(pkt.flow.key)
        if conn is None:
            conn = self.connections[pkt.flow.key] = _DTLSConnection({})
            conn.body['_flow'], conn.body['_when'] = pkt.flow, pkt.when
        body = conn.body
        from_client = (pkt.src, pkt.sport) == (pkt.flow.client, pkt.flow.cport)
        types = {_int(t) for t in v['dtls.handshake.type']}
        if 1 in types:                                    # ClientHello
            body['client_hellos'] = body.get('client_hellos', 0) + 1
            body.setdefault('client_version', _dtls_version(first('dtls.handshake.version')))
            if first('dtls.handshake.extensions_server_name'):
                body['sni'] = first('dtls.handshake.extensions_server_name')
            if v['dtls.handshake.extensions_alpn_str']:
                body['client_alpns'] = list(dict.fromkeys(v['dtls.handshake.extensions_alpn_str']))
            if first('dtls.handshake.ja3'):
                body['ja3'] = {'hash': first('dtls.handshake.ja3'), 'string': first('dtls.handshake.ja3_full')}
            if first('dtls.handshake.ja4'):
                body['ja4'] = first('dtls.handshake.ja4')
            if v['vals(dtls.use_srtp.protection_profile)']:
                body['srtp_profiles'] = list(dict.fromkeys(v['vals(dtls.use_srtp.protection_profile)']))
        if 3 in types:                                    # HelloVerifyRequest
            body['cookie_exchange'] = True
        if 2 in types:                                    # ServerHello
            conn.server_hello = True
            supported = [_dtls_version(x) for x in v['dtls.handshake.extensions.supported_version']]
            body['version'] = supported[-1] if supported else _dtls_version(first('dtls.handshake.version'))
            if v['vals(dtls.handshake.ciphersuite)']:
                body['cipher_suite'] = v['vals(dtls.handshake.ciphersuite)'][-1]
            if first('dtls.handshake.ja3s'):
                body['ja3s'] = {'hash': first('dtls.handshake.ja3s'), 'string': first('dtls.handshake.ja3s_full')}
            if v['dtls.handshake.extensions_alpn_str'] and 1 not in types:
                body['server_alpns'] = list(dict.fromkeys(v['dtls.handshake.extensions_alpn_str']))
            if v['vals(dtls.use_srtp.protection_profile)'] and 1 not in types:
                body['srtp_profile'] = v['vals(dtls.use_srtp.protection_profile)'][0]
        if 11 in types and v['dtls.handshake.certificate'] and 'subject' not in body:
            body.update(_x509(v['dtls.handshake.certificate'][0]))
        if 20 in {_int(t) for t in v['dtls.record.content_type']}:     # ChangeCipherSpec
            conn.ccs.add(from_client)
        for alert in v['vals(dtls.alert_message.desc)']:
            alerts = body.setdefault('alerts', [])
            if len(alerts) < 10:
                alerts.append(f"{'client' if from_client else 'server'}: {alert}")
        if 'version' not in body and first('dtls.record.version'):
            body['record_version'] = _dtls_version(first('dtls.record.version'))

    def finish(self):
        records = []
        for conn in self.connections.values():
            body = conn.body
            flow, when = body.pop('_flow'), body.pop('_when')
            if 'version' not in body:
                body['version'] = body.pop('record_version', '') or body.get('client_version', '')
            body.pop('record_version', None)
            if conn.ccs == {True, False}:
                body['handshake'] = 'completed'
            elif conn.server_hello:
                body['handshake'] = 'server hello'
            elif body.get('cookie_exchange'):
                body['handshake'] = 'cookie exchange only'
            elif body.get('client_hellos'):
                body['handshake'] = 'client hello only'
            else:
                body['handshake'] = 'no handshake seen'
            records.append((flow, when, self.event_type, body))
        return records


# ---------------------------------------------------------------- SOCKS
#
# A SOCKS proxy (port 1080) relays a client's connection to the host it
# names - so the flow shows only the proxy, and the real destination is
# in the handshake. One record per connection, like Zeek's socks.log: the
# version, the login methods the client offered and the one the proxy
# picked, the user name (never the password), the command and the host
# (by address or name) and port asked for, the proxy's answer and the
# address it bound for the relay - and the protocol tshark saw tunneled
# through it afterwards. An open-proxy check the proxy turned away is
# still a record.

_SOCKS_AUTH_METHODS = {0: 'no authentication', 1: 'GSSAPI', 2: 'username/password', 3: 'CHAP',
                       0xff: 'no acceptable methods'}
# The proxy's answer: SOCKS 5's codes, then SOCKS 4's (tshark's vals()
# names only SOCKS 5's)
_SOCKS_RESULTS = {0: 'succeeded', 1: 'general SOCKS server failure', 2: 'connection not allowed by ruleset',
                  3: 'network unreachable', 4: 'host unreachable', 5: 'connection refused', 6: 'TTL expired',
                  7: 'command not supported', 8: 'address type not supported', 90: 'granted',
                  91: 'rejected or failed', 92: "rejected: can't reach the client's identd",
                  93: "rejected: the client's identd gave a different user"}
# Layers tshark gives a tunneled packet's bytes it can't name
_SOCKS_UNNAMED = {'data', 'tcp.segments'}


def _socks_auth_method(value):
    number = _int(value)
    return _SOCKS_AUTH_METHODS.get(number, f'method {number}') if number is not None else ''


class SOCKS:
    """SOCKS 4, 4a and 5 - see the comment above."""
    event_type = 'socks'
    app_protos = ('socks',)
    fields = ('frame.protocols', 'socks.version', 'vals(socks.command)', 'socks.results', 'socks.auth_method',
              'socks.auth_accepted_method', 'socks.auth_status', 'socks.username', 'socks.dst', 'socks.dstV6',
              'socks.remote_name', 'socks.v4a_dns_name', 'socks.dstport', 'socks.port')

    def __init__(self):
        self.records = []
        self.sessions = {}       # flow key -> body

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        layers = first('frame.protocols').split(':')
        above = layers[layers.index('socks') + 1:] if 'socks' in layers else []
        body = self.sessions.get(pkt.flow.key)
        if above:
            # The tunnel: tshark keeps adding the handshake's socks.* fields
            # to every packet relayed after it, so only the layer above counts
            if body is not None and 'tunneled' not in body:
                named = [layer for layer in above if layer not in _SOCKS_UNNAMED]
                body['tunneled'] = named[0] if named else 'unknown'
            return
        host = first('socks.dst') or (ipv6_exploded(first('socks.dstV6')) if first('socks.dstV6') else '')
        port = _int(first('socks.port') or first('socks.dstport'))
        if body is None:
            # tshark calls anything on port 1080 SOCKS - an HTTP proxy check
            # sent there, a DCE/RPC connection whose client port it was - so
            # a record starts only at a client's greeting or request
            if not (v['socks.auth_method'] or (first('vals(socks.command)') and not first('socks.results')
                                                 and (host or first('socks.remote_name')
                                                      or first('socks.v4a_dns_name')))):
                return
            body = self.sessions[pkt.flow.key] = {}
            self.records.append((pkt.flow, pkt.when, self.event_type, body))
        if v['socks.auth_method']:
            body['version'] = first('socks.version')
            body['auth_methods'] = [_socks_auth_method(m) for m in v['socks.auth_method']]
        elif first('socks.auth_accepted_method'):
            body['auth_method'] = _socks_auth_method(first('socks.auth_accepted_method'))
            if body['auth_method'] == 'no acceptable methods':
                body['status'] = 'no acceptable authentication method'
        elif first('socks.auth_status'):
            body['login'] = 'succeeded' if _int(first('socks.auth_status')) == 0 else 'failed'
            if body['login'] == 'failed':
                body['status'] = 'login failed'
        elif first('socks.results'):
            code = _int(first('socks.results'))
            body['status'] = _SOCKS_RESULTS.get(code, f'result {code}')
            if host and host not in ('0.0.0.0', '::', '0000:0000:0000:0000:0000:0000:0000:0000'):
                body['bound_host'] = host
            if port:
                body['bound_port'] = port
        elif first('vals(socks.command)'):
            version = first('socks.version')
            body['version'] = '4a' if version == '4' and first('socks.v4a_dns_name') else version
            body['command'] = first('vals(socks.command)').lower().replace('udpassociate', 'UDP associate')
            name = first('socks.remote_name') or first('socks.v4a_dns_name')
            if name:
                body['request_name'] = name
            elif host:
                body['request_host'] = host
            if port is not None:
                body['request_port'] = port
        if first('socks.username'):
            body['user'] = first('socks.username')

    def finish(self):
        return self.records


# ---------------------------------------------------------------- RADIUS
#
# How Wi-Fi (802.1X), VPNs and network devices check a login: the device
# (the NAS) asks a RADIUS server, which accepts, rejects or challenges.
# Like Zeek's radius.log, one record per login - its Access-Request, any
# rounds of challenges (an EAP method's exchange), and the final accept
# or reject: the user name (never the password, which RADIUS hides
# anyway), the device that asked and the client's MAC, the EAP method,
# the address given and the server's reply message. Accounting gets a
# record per message: a session's Start, Stop or update, with its length
# and bytes. A scanner's Access-Request nobody answered is still a record.

_RADIUS_SERVICE_TYPES = {1: 'Login', 2: 'Framed', 3: 'Callback Login', 4: 'Callback Framed', 5: 'Outbound',
                         6: 'Administrative', 7: 'NAS Prompt', 8: 'Authenticate Only', 9: 'Callback NAS Prompt',
                         10: 'Call Check', 11: 'Callback Administrative'}
_RADIUS_PORT_TYPES = {0: 'Async', 1: 'Sync', 2: 'ISDN Sync', 3: 'ISDN Async V.120', 4: 'ISDN Async V.110',
                      5: 'Virtual', 15: 'Ethernet', 16: 'xDSL', 17: 'Cable', 18: 'Wireless - Other',
                      19: 'Wireless - IEEE 802.11', 30: 'PPPoA', 31: 'PPPoEoA', 32: 'PPPoEoE', 33: 'PPPoEoVLAN',
                      34: 'PPPoEoQinQ'}
_RADIUS_ACCT_STATUS = {1: 'Start', 2: 'Stop', 3: 'Interim-Update', 7: 'Accounting-On', 8: 'Accounting-Off'}
_RADIUS_TERMINATE_CAUSES = {1: 'User Request', 2: 'Lost Carrier', 3: 'Lost Service', 4: 'Idle Timeout',
                            5: 'Session Timeout', 6: 'Admin Reset', 7: 'Admin Reboot', 8: 'Port Error',
                            9: 'NAS Error', 10: 'NAS Request', 11: 'NAS Reboot', 12: 'Port Unneeded',
                            13: 'Port Preempted', 14: 'Port Suspended', 15: 'Service Unavailable', 16: 'Callback',
                            17: 'User Error', 18: 'Host Request'}
_RADIUS_RESULTS = {'Access-Accept': 'accepted', 'Access-Reject': 'rejected', 'Accounting-Response': 'acknowledged'}
# EAP types that aren't a login method
_EAP_NOT_METHODS = {'Identity', 'Notification', 'Legacy Nak (Response Only)'}
_EAP_SHORT_NAME = re.compile(r'\((EAP-[^)]+)\)$')


def _radius_named(names, value):
    number = _int(value)
    return names.get(number, str(number)) if number is not None else ''


class RADIUS:
    """RADIUS - see the comment above."""
    event_type = 'radius'
    app_protos = ('radius',)
    fields = ('vals(radius.code)', 'radius.id', 'radius.dup', 'radius.User_Name', 'radius.NAS_IP_Address',
              'radius.NAS_IPv6_Address', 'radius.NAS_Identifier', 'radius.NAS_Port_Type', 'radius.Service_Type',
              'radius.Called_Station_Id', 'radius.Calling_Station_Id', 'radius.Framed-IP-Address',
              'radius.Framed_IP_Address', 'radius.Reply_Message', 'vals(eap.type)', 'radius.Acct_Status_Type',
              'radius.Acct_Session_Id', 'radius.Acct_Session_Time', 'radius.Acct_Input_Octets',
              'radius.Acct_Output_Octets', 'radius.Acct_Terminate_Cause', 'radius.State')

    def __init__(self):
        self.records = []
        # A login's rounds are chained by the State attribute a challenge
        # carries and the next request echoes (RFC 2865) - not by flow: a
        # NAS sends every user's requests from one port, so by flow, logins
        # going on at once merged, and one never answered took in every
        # later one. Keyed by (flow, State), State itself never kept.
        self.challenged = {}     # (flow key, State) -> the login a challenge's State continues
        self.states = {}         # id(record) -> the (flow key, State) keys it holds in challenged
        self.open = {}           # (flow key, id) -> the record its request is in
        self.started = {}        # id(record) -> its first request's time

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        code, ident = first('vals(radius.code)'), _int(first('radius.id'))
        if not code or ident is None:
            return
        key = (pkt.flow.key, ident)
        if code.endswith('-Request') or code == 'Status-Server':
            if key in self.open and first('radius.dup'):
                self.open[key]['retransmissions'] = self.open[key].get('retransmissions', 0) + 1
                return
            state = first('radius.State')
            body = self.challenged.get((pkt.flow.key, state)) if code == 'Access-Request' and state else None
            if body is None:
                body = {'message': 'Accounting-Request' if code == 'Accounting-Request' else code}
                self.records.append((pkt.flow, pkt.when, self.event_type, body))
                self.started[id(body)] = pkt.when
            body['requests'] = body.get('requests', 0) + 1
            self.open[key] = body
            self._request(body, v, first)
            return
        body = self.open.pop(key, None)
        if body is None:
            return               # a response to a request before the capture began
        body['reply'] = code
        if code == 'Access-Challenge':
            body['challenges'] = body.get('challenges', 0) + 1
            if first('radius.State'):
                held = (pkt.flow.key, first('radius.State'))
                self.challenged[held] = body
                self.states.setdefault(id(body), []).append(held)
        else:
            body['result'] = _RADIUS_RESULTS.get(code, code)
            for held in self.states.pop(id(body), ()):
                self.challenged.pop(held, None)
            # from the first request - a login's every round, like Zeek's ttl
            body['response_time'] = round(pkt.when - self.started[id(body)], 6)
        if first('radius.Reply_Message'):
            body['reply_message'] = ' '.join(v['radius.Reply_Message'])[:512]
        self._addresses(body, v, first)
        self._eap(body, v)

    def _request(self, body, v, first):
        for name, field in (('user', 'radius.User_Name'), ('nas_identifier', 'radius.NAS_Identifier'),
                            ('called_station', 'radius.Called_Station_Id'),
                            ('calling_station', 'radius.Calling_Station_Id'),
                            ('session_id', 'radius.Acct_Session_Id')):
            if first(field):
                body[name] = first(field)
        nas = first('radius.NAS_IP_Address') or (ipv6_exploded(first('radius.NAS_IPv6_Address'))
                                                 if first('radius.NAS_IPv6_Address') else '')
        if nas:
            body['nas_ip'] = nas
        if first('radius.NAS_Port_Type'):
            body['port_type'] = _radius_named(_RADIUS_PORT_TYPES, first('radius.NAS_Port_Type'))
        if first('radius.Service_Type'):
            body['service_type'] = _radius_named(_RADIUS_SERVICE_TYPES, first('radius.Service_Type'))
        if first('radius.Acct_Status_Type'):
            body['message'] = 'Accounting ' + _radius_named(_RADIUS_ACCT_STATUS, first('radius.Acct_Status_Type'))
        for name, field in (('session_time', 'radius.Acct_Session_Time'), ('bytes_in', 'radius.Acct_Input_Octets'),
                            ('bytes_out', 'radius.Acct_Output_Octets')):
            if _int(first(field)) is not None:
                body[name] = _int(first(field))
        if first('radius.Acct_Terminate_Cause'):
            body['terminate_cause'] = _radius_named(_RADIUS_TERMINATE_CAUSES, first('radius.Acct_Terminate_Cause'))
        self._addresses(body, v, first)
        self._eap(body, v)

    @staticmethod
    def _addresses(body, v, first):
        framed = first('radius.Framed-IP-Address') or first('radius.Framed_IP_Address')
        if framed:
            body['framed_ip'] = framed

    @staticmethod
    def _eap(body, v):
        for kind in v['vals(eap.type)']:
            if kind and kind not in _EAP_NOT_METHODS:
                short = _EAP_SHORT_NAME.search(kind)
                method = short.group(1) if short else kind
                if method not in body.setdefault('eap_methods', []):
                    body['eap_methods'].append(method)

    def finish(self):
        return self.records


# ---------------------------------------------------------------- STUN
#
# How a host behind NAT learns its public address (a Binding: the server
# answers with the address and port it saw the request come from), and,
# with TURN, gets a relay. WebRTC calls, VoIP and games use it - and so
# does malware, to find the address it's reachable at. Its Binding
# checks repeat every few seconds through a call, so one record per flow
# and method (Binding, Allocate...) rather than per message: the requests
# and answers counted, the errors, the public (mapped) addresses the
# server reported, a TURN relay's address, the client's and server's
# software, and the user name and realm a TURN login gave (never its
# password or integrity check). A scanner's Binding Request nobody
# answered is still a record.

_STUN_METHODS = {0x001: 'Binding', 0x002: 'Shared Secret', 0x003: 'Allocate', 0x004: 'Refresh', 0x006: 'Send',
                 0x007: 'Data', 0x008: 'CreatePermission', 0x009: 'ChannelBind', 0x00a: 'Connect',
                 0x00b: 'ConnectionBind', 0x00c: 'ConnectionAttempt'}
_STUN_REQUEST, _STUN_INDICATION, _STUN_SUCCESS, _STUN_ERROR = 0x00, 0x01, 0x10, 0x11
# Attributes holding an address, each with its family and port: what it's called in a record
_STUN_ADDRESSES = {0x0001: 'mapped', 0x0020: 'mapped', 0x8020: 'mapped', 0x0016: 'relayed', 0x0012: 'peer',
                   0x802b: 'response_origin', 0x802c: 'other', 0x0004: 'source', 0x0005: 'changed',
                   0x000b: 'reflected_from'}
_STUN_MAX_LIST = 20


class STUN:
    """STUN and TURN - see the comment above."""
    event_type = 'stun'
    app_protos = ('stun',)
    fields = ('stun.type.class', 'stun.type.method', 'stun.att.type', 'stun.att.family', 'stun.att.ipv4',
              'stun.att.ipv6', 'stun.att.port', 'stun.att.software', 'stun.att.username', 'stun.att.realm',
              'stun.att.error.class', 'stun.att.error', 'stun.att.error.reason', 'stun.att.lifetime',
              'stun.reqduplicate')

    def __init__(self):
        self.records = []
        self.flows = {}          # (flow key, method) -> body

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        kind, number = _int(first('stun.type.class')), _int(first('stun.type.method'))
        if kind is None or number is None:
            return               # TURN ChannelData: relayed bytes, not a message
        method = _STUN_METHODS.get(number, f'method 0x{number:03x}')
        key = (pkt.flow.key, method)
        body = self.flows.get(key)
        if body is None:
            body = self.flows[key] = {'method': method}
            self.records.append((pkt.flow, pkt.when, self.event_type, body))
        counter = {_STUN_REQUEST: 'requests', _STUN_INDICATION: 'indications', _STUN_SUCCESS: 'successes',
                   _STUN_ERROR: 'errors'}.get(kind, 'other')
        if counter == 'requests' and first('stun.reqduplicate'):
            counter = 'retransmissions'
        body[counter] = body.get(counter, 0) + 1
        side = 'client' if kind in (_STUN_REQUEST, _STUN_INDICATION) else 'server'
        if first('stun.att.software'):
            body.setdefault(f'{side}_software', first('stun.att.software'))
        for name, field in (('username', 'stun.att.username'), ('realm', 'stun.att.realm')):
            if first(field):
                body.setdefault(name, first(field))
        if kind == _STUN_ERROR and first('stun.att.error.class'):
            code = (_int(first('stun.att.error.class')) or 0) * 100 + (_int(first('stun.att.error')) or 0)
            error = f'{code} {first("stun.att.error.reason")}'.strip()
            codes = body.setdefault('error_codes', [])
            if error not in codes and len(codes) < _STUN_MAX_LIST:
                codes.append(error)
        if _int(first('stun.att.lifetime')) is not None:
            body['lifetime'] = _int(first('stun.att.lifetime'))
        if kind != _STUN_SUCCESS:
            return
        ipv4, ipv6, ports = iter(v['stun.att.ipv4']), iter(v['stun.att.ipv6']), iter(v['stun.att.port'])
        families = iter(v['stun.att.family'])
        for att in v['stun.att.type']:
            name = _STUN_ADDRESSES.get(_int(att))
            if name is None:
                continue
            family, port = _int(next(families, '')), next(ports, '')
            address = next(ipv6, '') if family == 2 else next(ipv4, '')
            if not address:
                continue
            if family == 2:
                address = f'[{ipv6_exploded(address)}]'
            entry = f'{address}:{port}' if port else address
            addresses = body.setdefault(f'{name}_addresses', [])
            if entry not in addresses and len(addresses) < _STUN_MAX_LIST:
                addresses.append(entry)

    def finish(self):
        for _, _, _, body in self.records:
            if body.get('successes'):
                body['result'] = 'success'
            elif body.get('error_codes'):
                body['result'] = 'error: ' + body['error_codes'][0]
        return self.records


# ---------------------------------------------------------------- CoAP
#
# HTTP for constrained devices - sensors, smart lighting and building
# gear, over UDP 5683. One record per request and its response, named
# like Suricata's http records: the method, the URI path and query, the
# response code, the content format and payload size each way, and, for
# the discovery of a device's resources (GET /.well-known/core), the
# resources it listed. Internet scanners send that discovery to find
# devices for amplification attacks - a request nobody answered is still
# a record. A CoAP ping (an empty message answered by a reset) is one too.

_COAP_MAX_RESOURCES = 50
_COAP_LINK = re.compile(r'<([^>]*)>')


def _coap_payload(raw):
    """A CoAP message's payload: what follows its options' 0xFF marker."""
    pos = 4 + (raw[0] & 0x0f) if raw else 0
    try:
        while pos < len(raw):
            if raw[pos] == 0xff:
                return raw[pos + 1:]
            delta, length = raw[pos] >> 4, raw[pos] & 0x0f
            pos += 1 + {13: 1, 14: 2}.get(delta, 0)
            if length == 13:
                length, pos = raw[pos] + 13, pos + 1
            elif length == 14:
                length, pos = int.from_bytes(raw[pos:pos + 2], 'big') + 269, pos + 2
            pos += length
    except IndexError:
        pass
    return b''


class CoAP:
    """CoAP - see the comment above."""
    event_type = 'coap'
    app_protos = ('coap',)
    fields = ('vals(coap.type)', 'vals(coap.code)', 'coap.code', 'coap.mid', 'coap.token', 'coap.retransmitted',
              'coap.opt.uri_path_recon', 'coap.opt.uri_query', 'coap.opt.uri_host', 'coap.opt.ctype',
              'coap.opt.accept', 'coap.opt.observe', 'coap.payload_length', '@coap')

    def __init__(self):
        self.records = []
        self.open = {}           # (flow key, 'token', token) / (flow key, 'mid', mid) -> body
        self.started = {}        # id(body) -> its request's time

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        kind, code, number = first('vals(coap.type)'), first('vals(coap.code)'), _int(first('coap.code'))
        mid, token = _int(first('coap.mid')), first('coap.token')
        if number is None or mid is None:
            return
        by_token = (pkt.flow.key, 'token', token) if token else None
        by_mid = (pkt.flow.key, 'mid', mid)
        if first('coap.retransmitted'):
            body = self.open.get(by_token) or self.open.get(by_mid)
            if body is not None:
                body['retransmissions'] = body.get('retransmissions', 0) + 1
            return
        request = 1 <= number < 32 or (number == 0 and kind in ('Confirmable', 'Non-Confirmable'))
        if request:
            body = {'method': code if number else 'ping', 'type': kind}
            for name, field in (('uri', 'coap.opt.uri_path_recon'), ('query', 'coap.opt.uri_query'),
                                ('host', 'coap.opt.uri_host'), ('accept', 'coap.opt.accept')):
                if first(field):
                    body[name] = '&'.join(v[field]) if name == 'query' else first(field)
            if first('coap.opt.observe'):
                body['observe'] = True
            self._payload(body, 'request', v, first)
            self.records.append((pkt.flow, pkt.when, self.event_type, body))
            self.started[id(body)] = pkt.when
            self.open[by_mid] = body
            if by_token:
                self.open[by_token] = body
            return
        if number == 0 and kind == 'Acknowledgement':
            return               # an empty ACK: the answer comes separately, by token
        body = self.open.get(by_token) if by_token else None
        if body is None:
            body = self.open.get(by_mid)
        if body is None:
            return               # an answer to a request before the capture began
        body['responses'] = body.get('responses', 0) + 1
        if 'response_code' in body:
            return               # an Observe notification after the first
        body['response_code'] = 'reset' if kind == 'Reset' else code
        body['response_time'] = round(pkt.when - self.started[id(body)], 6)
        self._payload(body, 'response', v, first)
        if body.get('uri') == '/.well-known/core' and number // 32 == 2:
            raw = _hex(first('@coap'))
            links = _COAP_LINK.findall(_coap_payload(raw).decode('utf-8', 'replace'))
            if links:
                body['resources'] = list(dict.fromkeys(links))[:_COAP_MAX_RESOURCES]

    @staticmethod
    def _payload(body, side, v, first):
        if first('coap.opt.ctype'):
            body[f'{side}_content_format'] = first('coap.opt.ctype')
        length = _int(first('coap.payload_length'))
        if length:
            body[f'{side}_length'] = length

    def finish(self):
        return self.records


# ---------------------------------------------------------------- SLP
#
# The Service Location Protocol (UDP and TCP 427): how a client finds a
# service - ESXi's vSphere service, printers, WBEM - by asking a host or
# the SLP multicast group. One record per request and its replies: the
# function, service type, scopes and URL asked about, the URLs, service
# types and attributes the reply listed, its status, and the request's
# and replies' sizes. Internet scanners send SLP to find ESXi hosts
# (the OpenSLP flaws behind the ESXiArgs ransomware) and reflectors for
# the CVE-2023-29552 amplification attack, which registers a service
# with a host so that its answers to spoofed requests grow - a
# registration from outside, or a request nobody answered, is still a
# record. A multicast request's replies come straight back from each
# host that answered, so they join the request's record, with who
# answered. An advertisement, or a reply to a request before the capture
# began, is a record of its own.

_SLP_FUNCTIONS = {1: 'Service Request', 2: 'Service Reply', 3: 'Service Registration', 4: 'Service Deregistration',
                  5: 'Service Acknowledge', 6: 'Attribute Request', 7: 'Attribute Reply', 8: 'DA Advertisement',
                  9: 'Service Type Request', 10: 'Service Type Reply', 11: 'SA Advertisement'}
_SLP_REQUESTS = {1, 3, 4, 6, 9}
_SLP_ERRORS = {0: 'OK', 1: 'LANGUAGE_NOT_SUPPORTED', 2: 'PARSE_ERROR', 3: 'INVALID_REGISTRATION',
               4: 'SCOPE_NOT_SUPPORTED', 5: 'AUTHENTICATION_UNKNOWN', 6: 'AUTHENTICATION_ABSENT',
               7: 'AUTHENTICATION_FAILED', 9: 'VER_NOT_SUPPORTED', 10: 'INTERNAL_ERROR', 11: 'DA_BUSY_NOW',
               12: 'OPTION_NOT_UNDERSTOOD', 13: 'INVALID_UPDATE', 14: 'MSG_NOT_SUPPORTED', 15: 'REFRESH_REJECTED'}
_SLP_V1_ERRORS = {**_SLP_ERRORS, 2: 'PROTOCOL_PARSE_ERROR', 5: 'CHARSET_NOT_UNDERSTOOD'}
_SLP_MAX_LIST = 50
_SLP_MAX_ATTRIBUTES = 1024
# What each request asks about: record name -> its field, by function
_SLP_ASKED = {1: (('service_type', 'srvloc.srvreq.srvtypelist'), ('scopes', 'srvloc.srvreq.scopelist'),
                  ('predicate', 'srvloc.srvreq.predicate')),
              3: (('url', 'srvloc.url.url'), ('service_type', 'srvloc.srvreq.srvtype'),
                  ('scopes', 'srvloc.srvreq.scopelist'), ('attributes', 'srvloc.srvreq.attrlist')),
              4: (('url', 'srvloc.url.url'), ('scopes', 'srvloc.srvdereq.scopelist'),
                  ('tags', 'srvloc.srvdereq.taglist')),
              6: (('url', 'srvloc.attrreq.url'), ('scopes', 'srvloc.attrreq.scopelist'),
                  ('tags', 'srvloc.attrreq.taglist')),
              9: (('naming_authority', 'srvloc.srvtypereq.nameauthlist'), ('scopes', 'srvloc.srvtypereq.scopelist'))}
# Where a reply or advertisement lists URLs and attributes
_SLP_URLS = ('srvloc.url.url', 'srvloc.daadvert.url', 'srvloc.saadvert.url')
_SLP_ATTRIBUTES = ('srvloc.attrrply.attrlist', 'srvloc.daadvert.attrlist', 'srvloc.saadvert.attrlist')
_SLP_ADVERT_SCOPES = ('srvloc.daadvert.scopelist', 'srvloc.saadvert.scopelist')


def _to_group(pkt):
    """Whether a packet went to a multicast or broadcast address - its
    flow's server's, by what the flow's traffic says (shark_analyzer._Flow
    .to_group), or else by the address."""
    if pkt.dst == pkt.flow.server:
        return pkt.flow.to_group()
    from shark_analyzer import _is_group_address   # shark_analyzer imports this module
    return _is_group_address(pkt.dst)


class SLP:
    """SLP - see the comment above."""
    event_type = 'slp'
    app_protos = ('slp',)
    fields = tuple(dict.fromkeys(
        ('srvloc.version', 'srvloc.function', 'srvloc.xid', 'srvloc.pktlen', 'srvloc.err', 'srvloc.errv2',
         'srvloc.flags_v2.fresh', 'srvloc.flags_v2.reqmulti', 'srvloc.url.lifetime', 'srvloc.srvtyperply.srvtypelist')
        + tuple(field for asked in _SLP_ASKED.values() for _, field in asked)
        + _SLP_URLS + _SLP_ATTRIBUTES + _SLP_ADVERT_SCOPES))

    def __init__(self):
        self.records = []
        self.open = {}           # (flow key, xid) / ('group', client, client port, xid) -> body
        self.started = {}        # id(body) -> its request's time and flow

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        version, number, xid = _int(first('srvloc.version')), _int(first('srvloc.function')), _int(first('srvloc.xid'))
        if version not in (1, 2) or number not in _SLP_FUNCTIONS or (version == 1 and number == 11):
            return               # something else on port 427
        function, length = _SLP_FUNCTIONS[number], _int(first('srvloc.pktlen'))
        if number in _SLP_REQUESTS:
            key = (pkt.flow.key, xid)
            body = self.open.get(key)
            if body is not None and body['function'] == function and 'response' not in body:
                body['retransmissions'] = body.get('retransmissions', 0) + 1
                return
            body = {'version': version, 'function': function, 'xid': xid}
            for name, field in _SLP_ASKED[number]:
                if first(field):
                    body[name] = first(field)
            if 'attributes' in body:
                body['attributes'] = body['attributes'][:_SLP_MAX_ATTRIBUTES]
            if number == 3:
                if _int(first('srvloc.url.lifetime')) is not None:
                    body['lifetime'] = _int(first('srvloc.url.lifetime'))
                if first('srvloc.flags_v2.fresh') in ('1', 'True'):
                    body['fresh'] = True
            if first('srvloc.flags_v2.reqmulti') in ('1', 'True'):
                body['multicast'] = True
            if length:
                body['request_length'] = length
            self.records.append((pkt.flow, pkt.when, self.event_type, body))
            self.started[id(body)] = (pkt.when, pkt.flow)
            self.open[key] = body
            if _to_group(pkt):
                self.open[('group', pkt.src, pkt.sport, xid)] = body
            return
        body = self.open.get((pkt.flow.key, xid)) or self.open.get(('group', pkt.dst, pkt.dport, xid))
        if body is None or number in (8, 11) and xid == 0:
            body = {'version': version, 'function': function}
            if xid:
                body['xid'] = xid
            for field in _SLP_ADVERT_SCOPES:
                if first(field):
                    body['scopes'] = first(field)
            self.records.append((pkt.flow, pkt.when, self.event_type, body))
            self._reply(body, v, first, version, None)
            if length:
                body['length'] = length
            return
        started, flow = self.started[id(body)]
        body['responses'] = body.get('responses', 0) + 1
        if 'response' not in body:
            body['response'] = function
            body['response_time'] = round(pkt.when - started, 6)
        if pkt.flow is not flow:
            responders = body.setdefault('responders', [])
            if pkt.src not in responders and len(responders) < _SLP_MAX_LIST:
                responders.append(pkt.src)
        self._reply(body, v, first, version, length)

    @staticmethod
    def _reply(body, v, first, version, length):
        error = _int(first('srvloc.errv2' if version == 2 else 'srvloc.err'))
        if error is not None and (error or 'status' not in body):
            body['status'] = (_SLP_ERRORS if version == 2 else _SLP_V1_ERRORS).get(error, f'error {error}')
        urls = body.get('urls', [])
        for field in _SLP_URLS:
            for url in v[field]:
                if url and url not in urls and len(urls) < _SLP_MAX_LIST:
                    urls.append(url)
        if urls:
            body['urls'] = urls
        if first('srvloc.srvtyperply.srvtypelist'):
            types = body.setdefault('service_types', [])
            for kind in first('srvloc.srvtyperply.srvtypelist').split(','):
                if kind and kind not in types and len(types) < _SLP_MAX_LIST:
                    types.append(kind)
        for field in _SLP_ATTRIBUTES:
            if first(field):
                body.setdefault('attributes', first(field)[:_SLP_MAX_ATTRIBUTES])
        if length:
            body['response_length'] = body.get('response_length', 0) + length

    def finish(self):
        return self.records


# ---------------------------------------------------------------- IPMI
#
# IPMI over RMCP (UDP 623): the out-of-band management controller (BMC)
# in a server - iDRAC, iLO, IMM, Supermicro's - which can power the
# machine on and off, reinstall it and watch its console whatever runs
# on it. What a BMC tells anyone who asks, before any login, is what's
# recorded - one record per flow: whether it answered an ASF presence
# ping, and its answer to Get Channel Authentication Capabilities (the
# IPMI versions it speaks, the login methods it offers, whether it lets
# in null user names or an anonymous login), and for an IPMI 2.0
# session, the algorithms the console asked for and the BMC accepted -
# a BMC that accepts no authentication at all (cipher zero,
# CVE-2013-4782) logs anyone in. The weaknesses those show are listed.
# Internet scanners send the capabilities request to find exposed BMCs.
# Nothing past a session's opening is read: the RAKP messages that
# follow carry a hash of the user's password (CVE-2013-4786), and
# what's inside a session is the BMC's commands.

_IPMI_PRIVILEGES = {0: 'highest available', 1: 'callback', 2: 'user', 3: 'operator', 4: 'administrator', 5: 'OEM'}
_IPMI_AUTH_TYPES = ((0x01, 'none'), (0x02, 'MD2'), (0x04, 'MD5'), (0x10, 'straight password'), (0x20, 'OEM'))
_IPMI_AUTH_ALGORITHMS = {0: 'RAKP-none', 1: 'RAKP-HMAC-SHA1', 2: 'RAKP-HMAC-MD5', 3: 'RAKP-HMAC-SHA256'}
_IPMI_INTEGRITY_ALGORITHMS = {0: 'none', 1: 'HMAC-SHA1-96', 2: 'HMAC-MD5-128', 3: 'MD5-128', 4: 'HMAC-SHA256-128'}
_IPMI_CONFIDENTIALITY_ALGORITHMS = {0: 'none', 1: 'AES-CBC-128', 2: 'xRC4-128', 3: 'xRC4-40'}
_IPMI_SESSION_STATUS = {0: 'OK', 1: 'insufficient resources', 2: 'invalid session ID', 3: 'invalid payload type',
                        4: 'invalid authentication algorithm', 5: 'invalid integrity algorithm',
                        6: 'no matching authentication payload', 7: 'no matching integrity payload',
                        9: 'invalid role', 0x0a: 'unauthorized role or privilege',
                        0x0b: 'insufficient resources for role', 0x10: 'invalid confidentiality algorithm',
                        0x11: 'no cipher suite match', 0x12: 'illegal parameter'}
_IPMI_GET_CHANNEL_AUTH = 0x38
_ASF_PING, _ASF_PONG = 0x80, 0x40
_RMCP_ASF, _RMCP_IPMI = 0x06, 0x07
_IPMI_OPEN_SESSION_REQUEST, _IPMI_OPEN_SESSION_RESPONSE = 0x10, 0x11


def _ipmi_message(session):
    """An IPMI v1.5 session's IPMB message (netfn, command, data), or None:
    the session header - its auth code there unless its type is none -
    then the message."""
    if len(session) < 10 or session[0] == 0x06:
        return None
    pos = 9 + (16 if session[0] else 0)
    if len(session) <= pos:
        return None
    message = session[pos + 1:pos + 1 + session[pos]]
    if len(message) < 7:
        return None
    return message[1] >> 2, message[5], message[6:-1]


def _ipmi_payload(session):
    """An IPMI 2.0 (RMCP+) session's payload type and payload, or None."""
    if len(session) < 12 or session[0] != 0x06:
        return None
    kind, pos = session[1] & 0x3f, 2 + (6 if session[1] & 0x3f == 0x02 else 0)
    if len(session) < pos + 10:
        return None
    length = int.from_bytes(session[pos + 8:pos + 10], 'little')
    return kind, session[pos + 10:pos + 10 + length]


def _ipmi_algorithms(payload, start):
    """An Open Session message's three algorithm payloads, from start."""
    names = (('authentication', _IPMI_AUTH_ALGORITHMS), ('integrity', _IPMI_INTEGRITY_ALGORITHMS),
             ('confidentiality', _IPMI_CONFIDENTIALITY_ALGORITHMS))
    out = {}
    for i, (name, table) in enumerate(names):
        pos = start + 8 * i
        if len(payload) >= pos + 5:
            number = payload[pos + 4] & 0x3f
            out[name] = table.get(number, f'algorithm {number}')
    return out


class IPMI:
    """IPMI over RMCP - see the comment above."""
    event_type = 'ipmi'
    app_protos = ('rmcp',)
    fields = ('rmcp.class', 'asf.type', 'data.data', '@ipmi_session')

    def __init__(self):
        self.records = []
        self.flows = {}          # flow key -> body

    def _body(self, pkt):
        body = self.flows.get(pkt.flow.key)
        if body is None:
            body = self.flows[pkt.flow.key] = {}
            self.records.append((pkt.flow, pkt.when, self.event_type, body))
        return body

    @staticmethod
    def _asked(body, what):
        if what not in body.setdefault('requests', []):
            body['requests'].append(what)

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        raw = lambda name: _hex(first(name))
        kind = _int(first('rmcp.class'))
        if kind == _RMCP_ASF:
            asf = _int(first('asf.type'))
            if asf == _ASF_PING:
                self._asked(self._body(pkt), 'presence ping')
            elif asf == _ASF_PONG:
                body, data = self._body(pkt), raw('data.data')     # the pong's body, past its ASF header
                body['responses'] = body.get('responses', 0) + 1
                if len(data) >= 9:
                    body['ipmi_supported'] = bool(data[8] & 0x80)
            return
        if kind != _RMCP_IPMI:
            return
        session = raw('@ipmi_session')
        message = _ipmi_message(session)
        if message is not None:
            netfn, command, data = message
            if command != _IPMI_GET_CHANNEL_AUTH or netfn not in (0x06, 0x07):
                return           # a command, or its answer - not read
            body = self._body(pkt)
            if netfn == 0x06:
                self._asked(body, 'channel authentication capabilities')
                if len(data) >= 2:
                    body['requested_privilege'] = _IPMI_PRIVILEGES.get(data[1] & 0x0f, str(data[1] & 0x0f))
            else:
                body['responses'] = body.get('responses', 0) + 1
                self._capabilities(body, data)
            return
        payload = _ipmi_payload(session)
        if payload is None:
            return
        kind, data = payload
        if kind == _IPMI_OPEN_SESSION_REQUEST:
            body = self._body(pkt)
            self._asked(body, 'open session')
            if len(data) >= 2:
                body['requested_privilege'] = _IPMI_PRIVILEGES.get(data[1] & 0x0f, str(data[1] & 0x0f))
            body['cipher_requested'] = _ipmi_algorithms(data, 8)
        elif kind == _IPMI_OPEN_SESSION_RESPONSE and pkt.flow.key in self.flows:
            body = self.flows[pkt.flow.key]
            body['responses'] = body.get('responses', 0) + 1
            if len(data) >= 2:
                body['session_status'] = _IPMI_SESSION_STATUS.get(data[1], f'status 0x{data[1]:02x}')
                if data[1] == 0:
                    body['cipher_accepted'] = _ipmi_algorithms(data, 12)
        # RAKP messages (0x12-0x15) and session traffic are never read - see above

    @staticmethod
    def _capabilities(body, data):
        if not data:
            return
        if data[0]:
            body['completion_code'] = f'0x{data[0]:02x}'
            return
        if len(data) < 4:
            return
        support, status = data[2], data[3]
        body['channel'] = data[1] & 0x0f
        body['auth_types'] = [name for bit, name in _IPMI_AUTH_TYPES if support & bit]
        versions = []
        if support & 0x80 and len(data) >= 5:
            versions = [version for bit, version in ((0x01, '1.5'), (0x02, '2.0')) if data[4] & bit]
        body['ipmi_versions'] = versions or ['1.5']
        body['anonymous_login'] = bool(status & 0x01)
        body['null_user_names'] = bool(status & 0x02)
        body['non_null_user_names'] = bool(status & 0x04)
        body['user_level_authentication'] = not status & 0x08
        body['per_message_authentication'] = not status & 0x10
        body['kg_set'] = bool(status & 0x20)
        if len(data) >= 8 and int.from_bytes(data[5:8], 'little'):
            body['oem_iana'] = int.from_bytes(data[5:8], 'little')

    def finish(self):
        for _, _, _, body in self.records:
            weaknesses = []
            if body.get('anonymous_login'):
                weaknesses.append('anonymous login')
            if body.get('null_user_names'):
                weaknesses.append('null user names')
            if 'none' in body.get('auth_types', ()):
                weaknesses.append('no authentication offered')
            if 'straight password' in body.get('auth_types', ()):
                weaknesses.append('cleartext password')
            if body.get('cipher_accepted', {}).get('authentication') == 'RAKP-none':
                weaknesses.append('cipher zero accepted')
            if weaknesses:
                body['weaknesses'] = weaknesses
            body['result'] = 'answered' if body.get('responses') else 'no answer'
        return self.records


# ---------------------------------------------------------------- L2TP
#
# The Layer 2 Tunneling Protocol (UDP 1701): the tunnel of L2TP/IPsec
# VPNs - Windows', routers' and phones' built-in VPN - and of ISPs'
# broadband aggregation. Seen at all, it's outside IPsec: a VPN
# endpoint answering in the clear, or a scanner looking for one. One
# record per control connection: the control messages exchanged (the
# start-control-connection request, reply and connected, calls, the
# stop), each end's host name, vendor and firmware, how it ended - the
# result and error codes and message - the calls, and how many data
# messages crossed it. Scanners name themselves in their requests
# (masscan, Censys, Xpanse...). The tunnel's authentication (a CHAP
# challenge and response, from its shared secret) is only noted, never
# kept, a LAC's proxied PPP login is never read, and neither is the PPP
# inside the tunnel - the user's own login.

_L2TP_MESSAGES = {1: 'SCCRQ', 2: 'SCCRP', 3: 'SCCCN', 4: 'StopCCN', 6: 'HELLO', 7: 'OCRQ', 8: 'OCRP', 9: 'OCCN',
                  10: 'ICRQ', 11: 'ICRP', 12: 'ICCN', 14: 'CDN', 15: 'WEN', 16: 'SLI', 20: 'ACK'}
_L2TP_STOP_RESULTS = {1: 'general request to clear control connection', 2: 'general error',
                      3: 'control channel already exists', 4: 'requester is not authorized',
                      5: 'protocol version not supported', 6: 'requester is being shut down',
                      7: 'finite state machine error'}
_L2TP_CALL_RESULTS = {1: 'lost carrier', 2: 'general error', 3: 'administrative reasons',
                      4: 'temporary lack of facilities', 5: 'permanent lack of facilities', 6: 'invalid destination',
                      7: 'no carrier', 8: 'busy', 9: 'no dial tone', 10: 'not established in time',
                      11: 'no appropriate framing'}
_L2TP_ERRORS = {1: 'no control connection exists yet', 2: 'length is wrong', 3: 'value out of range',
                4: 'insufficient resources', 5: 'invalid session ID', 6: 'generic vendor error', 7: 'try another',
                8: 'unknown mandatory AVP'}
_L2TP_CALLS = {7, 10}         # OCRQ, ICRQ
_L2TP_MAX_LIST = 20


class L2TP:
    """L2TP - see the comment above."""
    event_type = 'l2tp'
    app_protos = ('l2tp',)
    fields = ('l2tp.version', 'l2tp.type', 'l2tp.avp.message_type', 'l2tp.avp.host_name', 'l2tp.avp.vendor_name',
              'l2tp.avp.firmware_revision', 'l2tp.avp.protocol_version', 'l2tp.avp.protocol_revision',
              'l2tp.avp.hidden', 'l2tp.avp.chap_challenge', 'l2tp.result_code', 'l2tp.avp.error_code',
              'l2tp.avp.error_message', 'l2tp.avp.calling_number', 'l2tp.avp.called_number')

    def __init__(self):
        self.records = []
        self.flows = {}          # flow key -> body

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        body = self.flows.get(pkt.flow.key)
        if first('l2tp.type') in ('0', 'False'):
            if body is not None:
                body['data_messages'] = body.get('data_messages', 0) + 1
            return               # a data message: the tunnel's PPP, never read
        number = _int(first('l2tp.avp.message_type'))
        if number is None:
            return               # a zero-length acknowledgement
        if body is None:
            version = _int(first('l2tp.version'))
            body = self.flows[pkt.flow.key] = {'version': version} if version else {}
            self.records.append((pkt.flow, pkt.when, self.event_type, body))
        message = _L2TP_MESSAGES.get(number, f'message {number}')
        messages = body.setdefault('messages', [])
        if message not in messages and len(messages) < _L2TP_MAX_LIST:
            messages.append(message)
        if number in (1, 2):     # SCCRQ, SCCRP: each end saying who it is
            side = 'client' if number == 1 else 'server'
            for name, field in (('host_name', 'l2tp.avp.host_name'), ('vendor', 'l2tp.avp.vendor_name')):
                if first(field):
                    body.setdefault(f'{side}_{name}', first(field))
            if _int(first('l2tp.avp.firmware_revision')) is not None:     # e.g. Windows' version, 0x0601
                body.setdefault(f'{side}_firmware', f"0x{_int(first('l2tp.avp.firmware_revision')):04x}")
            if first('l2tp.avp.protocol_version'):
                body.setdefault('protocol_version',
                                f"{first('l2tp.avp.protocol_version')}.{first('l2tp.avp.protocol_revision') or 0}")
        if first('l2tp.avp.chap_challenge'):
            body['tunnel_authentication'] = True
        if any(h in ('1', 'True') for h in v['l2tp.avp.hidden']):
            body['hidden_avps'] = True
        if number in _L2TP_CALLS:
            body['calls'] = body.get('calls', 0) + 1
            for name, field in (('calling_number', 'l2tp.avp.calling_number'),
                                ('called_number', 'l2tp.avp.called_number')):
                if first(field):
                    body.setdefault(name, first(field))
        if number in (4, 14) and _int(first('l2tp.result_code')) is not None:
            code = _int(first('l2tp.result_code'))
            table = _L2TP_STOP_RESULTS if number == 4 else _L2TP_CALL_RESULTS
            prefix = 'stop' if number == 4 else 'call'
            body[f'{prefix}_result'] = table.get(code, f'result {code}')
            error = _int(first('l2tp.avp.error_code'))
            if error:
                body[f'{prefix}_error'] = _L2TP_ERRORS.get(error, f'error {error}')
            if first('l2tp.avp.error_message'):
                body[f'{prefix}_message'] = first('l2tp.avp.error_message')

    def finish(self):
        for _, _, _, body in self.records:
            messages = body.get('messages', ())
            if 'SCCCN' in messages:
                state = 'established'
            elif 'SCCRP' in messages:
                state = 'answered'
            elif 'StopCCN' in messages:
                state = 'refused'
            else:
                state = 'no answer'
            body['state'] = state
        return self.records


# ---------------------------------------------------------------- RIP
#
# RIP (UDP 520) and RIPng (its IPv6 version, UDP 521): routers telling
# each other the networks they reach. On a LAN its records are a map of
# the networks and the routers that reach them; a route from a host
# that isn't a router, or a metric that suddenly changes, is how routes
# are injected to put an attacker in the middle; and a request for the
# whole route table, from outside, is a scanner asking a router to give
# its networks away. One record per sender, destination and kind of
# message: the messages' count, the routes announced (each one's prefix,
# next hop, metric and tag - its last), the routes withdrawn (metric 16)
# and the metric changes between updates, and what a request asked for.
# RIPv2's authentication is only named: its simple password is sent in
# the clear, and neither that nor a keyed digest is ever kept.

_RIP_COMMANDS = {1: 'request', 2: 'response', 3: 'traceon', 4: 'traceoff', 5: 'reserved', 9: 'update request',
                 10: 'update response', 11: 'update acknowledge'}
_RIP_AUTH = {1: 'keyed MD5 trailer', 2: 'simple password', 3: 'keyed MD5'}
_RIP_INFINITY = 16
_RIP_MAX_ROUTES = 50


def _rip_entries(raw):
    """A RIP message's command, version, authentication and route entries
    (prefix, next hop, metric, tag) - never an authentication entry's
    password or digest."""
    if len(raw) < 4:
        return None
    command, version, entries, auth = raw[0], raw[1], [], None
    for pos in range(4, len(raw) - 19, 20):
        family, tag = struct.unpack('!HH', raw[pos:pos + 4])
        if family == 0xffff:
            # The keyed-authentication trailer (type 1, RFC 4822) ends the
            # message: everything after it is the digest - past one
            # entry's length for HMAC-SHA-384 and -512, so read on and its
            # bytes would come out as routes
            if tag == 1:
                break
            auth = auth or _RIP_AUTH.get(tag, f'type {tag}')
            continue
        address, mask, hop = (raw[pos + 4 + i:pos + 8 + i] for i in (0, 4, 8))
        metric = int.from_bytes(raw[pos + 16:pos + 20], 'big')
        prefix = '.'.join(map(str, address))
        if version >= 2 and (any(mask) or not any(address)):     # 0.0.0.0/0, the default route
            prefix += f'/{bin(int.from_bytes(mask, "big")).count("1")}'
        hop = '.'.join(map(str, hop)) if any(hop) else ''
        entries.append((family, prefix, hop, metric, tag if version >= 2 else 0))
    return command, version, auth, entries


def _ripng_entries(raw):
    """A RIPng message's command, version and route entries; a next-hop
    entry (metric 0xff) sets the next hop of those after it."""
    if len(raw) < 4:
        return None
    command, version, entries, hop = raw[0], raw[1], [], ''
    for pos in range(4, len(raw) - 19, 20):
        address, tag, length, metric = raw[pos:pos + 16], *struct.unpack('!HBB', raw[pos + 16:pos + 20])
        text = ipv6_exploded(socket.inet_ntop(socket.AF_INET6, address))
        if metric == 0xff:
            hop = '' if not any(address) else text
            continue
        entries.append((None, f'{text}/{length}', hop, metric, tag))
    return command, version, None, entries


class RIP:
    """RIP and RIPng - see the comment above."""
    event_type = 'rip'
    app_protos = ('rip', 'ripng')
    fields = ('@rip', '@ripng')

    def __init__(self):
        self.records = []
        self.flows = {}          # (flow key, sender, command) -> body
        self.routes = {}         # id(body) -> {prefix: (next hop, metric, tag)}

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        name = '@ripng' if pkt.app == 'ripng' else '@rip'
        raw = _hex(first(name))
        parsed = (_ripng_entries if pkt.app == 'ripng' else _rip_entries)(raw)
        if parsed is None:
            return
        command, version, auth, entries = parsed
        kind = _RIP_COMMANDS.get(command, f'command {command}')
        # A response to a request on its flow is that request's answer
        asked = self.flows.get((pkt.flow.key, 'asked'))
        if command == 2 and asked is not None and asked[0] != pkt.src:
            body = asked[1]
            body['responses'] = body.get('responses', 0) + 1
        else:
            key = (pkt.flow.key, pkt.src, kind)
            body = self.flows.get(key)
            if body is None:
                body = self.flows[key] = {'version': 'RIPng' if pkt.app == 'ripng' else f'RIPv{version}',
                                          'command': kind}
                self.records.append((pkt.flow, pkt.when, self.event_type, body))
                self.routes[id(body)] = {}
                if command in (1, 9):
                    self.flows.setdefault((pkt.flow.key, 'asked'), (pkt.src, body))
            body['messages'] = body.get('messages', 0) + 1
        if auth:
            body['authentication'] = auth
        if command in (1, 9):
            # A whole-table request: one entry, address family 0 and metric
            # 16 - which some scanners send in the wrong byte order
            if len(entries) == 1 and entries[0][0] in (0, None) and \
                    entries[0][1].split('/')[0] in ('0.0.0.0', '0000:0000:0000:0000:0000:0000:0000:0000'):
                body['whole_table'] = True
            else:
                asked = body.setdefault('requested', [])
                for _, prefix, _, _, _ in entries:
                    if prefix not in asked and len(asked) < _RIP_MAX_ROUTES:
                        asked.append(prefix)
                if not asked:
                    del body['requested']
            return
        routes = self.routes[id(body)]
        for _, prefix, hop, metric, tag in entries:
            last = routes.get(prefix)
            if last is not None and last[1] != metric:
                body['metric_changes'] = body.get('metric_changes', 0) + 1
            if last is not None or len(routes) < _RIP_MAX_ROUTES:
                routes[prefix] = (hop, metric, tag)
            elif prefix not in routes:
                body['routes_not_kept'] = body.get('routes_not_kept', 0) + 1

    def finish(self):
        for _, _, _, body in self.records:
            routes = self.routes.pop(id(body), {})
            if not routes:
                continue
            listed = []
            for prefix, (hop, metric, tag) in routes.items():
                text = f'{prefix} metric {metric}'
                if hop:
                    text += f' via {hop}'
                if tag:
                    text += f' tag {tag}'
                listed.append(text)
            body['routes'] = listed
            body['route_count'] = len(routes) + body.pop('routes_not_kept', 0)
            withdrawn = sum(1 for _, metric, _ in routes.values() if metric >= _RIP_INFINITY)
            if withdrawn:
                body['withdrawn'] = withdrawn
        return self.records


# ---------------------------------------------------------------- XDMCP
#
# XDMCP (UDP 177): how an X display finds a Unix login manager - GDM,
# LightDM, XDM, CDE - and asks it for a graphical login screen, which it
# then draws over X11 in the clear. A server that answers is offering
# that login screen to whoever asked; internet scanners look for them,
# and an old one (CDE) amplifies its answers. One record per client and
# server: the messages exchanged, the server's host name and status
# (often its OS and load), whether it was willing, the authentication
# and authorization methods named, and for a session request, the
# display, its addresses and its manufacturer's ID - and how it ended
# (accepted, declined, refused, failed). A broadcast query's answers
# come straight back from each server, so they join its record, with who
# answered. Only methods' names are read: never their data - an Accept
# carries the X authorization cookie that opens the display.

_XDMCP_OPCODES = {1: 'BroadcastQuery', 2: 'Query', 3: 'IndirectQuery', 4: 'ForwardQuery', 5: 'Willing',
                  6: 'Unwilling', 7: 'Request', 8: 'Accept', 9: 'Decline', 10: 'Manage', 11: 'Refuse',
                  12: 'Failed', 13: 'KeepAlive', 14: 'Alive'}
_XDMCP_QUERIES = {1, 2, 3, 4}
# How far an exchange got, latest last: its result
_XDMCP_RESULTS = (('Unwilling', 'unwilling'), ('Willing', 'willing'), ('Decline', 'declined'),
                  ('Refuse', 'refused'), ('Failed', 'failed'), ('Accept', 'accepted'), ('Manage', 'managed'))
_XDMCP_MAX_LIST = 20


def _xdmcp_array8(hexbytes):
    """An ARRAY8's text from tshark's bytes of it, its length first."""
    raw = _hex(hexbytes)[2:]
    return raw.decode('utf-8', 'replace')


class XDMCP:
    """XDMCP - see the comment above."""
    event_type = 'xdmcp'
    app_protos = ('xdmcp',)
    fields = ('xdmcp.version', 'xdmcp.opcode', 'xdmcp.authentication_name', 'xdmcp.authorization_name',
              'xdmcp.hostname', 'xdmcp.status', 'xdmcp.display_number', 'xdmcp.display_class',
              'xdmcp.connection_address_ipv4', 'xdmcp.connection_address_ipv6', 'xdmcp.manufacturer_display_id')

    def __init__(self):
        self.records = []
        self.flows = {}          # flow key / ('broadcast', client, client port) -> body

    @staticmethod
    def _add(body, name, values):
        listed = body.setdefault(name, [])
        for value in values:
            if value and value not in listed and len(listed) < _XDMCP_MAX_LIST:
                listed.append(value)
        if not listed:
            del body[name]

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        try:
            opcode = int(first('xdmcp.opcode'), 0)      # tshark gives it in hex: 0x0002
        except ValueError:
            return
        message = _XDMCP_OPCODES.get(opcode, f'opcode {opcode}')
        body = self.flows.get(pkt.flow.key)
        if body is None and opcode not in _XDMCP_QUERIES:
            body = self.flows.get(('broadcast', pkt.dst, pkt.dport))
            if body is not None:
                self._add(body, 'responders', [pkt.src])
                if opcode in (5, 6):         # each server's answer to the broadcast
                    answer = f"{pkt.src} {message.lower()}: {first('xdmcp.hostname')}"
                    if first('xdmcp.status'):
                        answer += f" ({first('xdmcp.status')})"
                    self._add(body, 'answers', [answer])
        if body is None:
            version = _int(first('xdmcp.version'), None)
            body = self.flows[pkt.flow.key] = {'version': version} if version is not None else {}
            self.records.append((pkt.flow, pkt.when, self.event_type, body))
            if opcode == 1 or _to_group(pkt):
                self.flows[('broadcast', pkt.src, pkt.sport)] = body
        self._add(body, 'messages', [message])
        self._add(body, 'authentication_names', v['xdmcp.authentication_name'])
        self._add(body, 'authorization_names', v['xdmcp.authorization_name'])
        if opcode in (5, 6):                 # Willing, Unwilling: who the server is
            if first('xdmcp.hostname'):
                body.setdefault('server_host_name', first('xdmcp.hostname'))
            if first('xdmcp.status'):
                body.setdefault('server_status', first('xdmcp.status'))
        elif opcode in (9, 12):              # Decline, Failed: why
            if first('xdmcp.status'):
                body['status'] = first('xdmcp.status')
        elif opcode == 7:                    # Request: the display asking for a session
            if _int(first('xdmcp.display_number'), None) is not None:
                body['display_number'] = _int(first('xdmcp.display_number'))
            self._add(body, 'display_addresses',
                      v['xdmcp.connection_address_ipv4'] +
                      [ipv6_exploded(a) for a in v['xdmcp.connection_address_ipv6'] if a])
            if first('xdmcp.manufacturer_display_id'):
                body['manufacturer_display_id'] = _xdmcp_array8(first('xdmcp.manufacturer_display_id'))
        elif opcode == 10 and first('xdmcp.display_class'):      # Manage
            body['display_class'] = _xdmcp_array8(first('xdmcp.display_class'))

    def finish(self):
        for _, _, _, body in self.records:
            messages = body.get('messages', ())
            result = 'no answer'
            for message, name in _XDMCP_RESULTS:
                if message in messages:
                    result = name
            body['result'] = result
        return self.records


# ---------------------------------------------------------------- SSDP

class SSDP:
    """SSDP (UPnP discovery - Suricata doesn't parse it): a record per
    message - an M-SEARCH looking for devices or services, a NOTIFY
    announcing one, or a search response - with its search target or
    notification type, the device's description URL (LOCATION) and server
    string, and its unique service name. tshark decodes SSDP with its HTTP
    dissector: a header is an http.request.line / http.response.line, or -
    in a NOTIFY - http.location or an http.unknown_header."""
    event_type = 'ssdp'
    app_protos = ('ssdp',)
    fields = ('http.request.method', 'http.response.code', 'http.request.line', 'http.response.line',
              'http.unknown_header', 'http.location')
    _HEADERS = {'ST': 'search_target', 'NT': 'notification_type', 'NTS': 'notification_sub_type',
                'USN': 'usn', 'MAN': 'man', 'MX': 'mx', 'LOCATION': 'location', 'SERVER': 'server',
                'USER-AGENT': 'user_agent'}

    def __init__(self):
        self.records = []

    def feed(self, pkt, v):
        if v['http.request.method']:
            body = {'type': 'request', 'method': v['http.request.method'][0]}
        elif v['http.response.code']:
            body = {'type': 'response', 'status': _int(v['http.response.code'][0], v['http.response.code'][0])}
        else:
            return
        if v['http.location']:
            body['location'] = v['http.location'][0]
        for line in v['http.request.line'] + v['http.response.line'] + v['http.unknown_header']:
            name, sep, value = line.partition(':')
            key = self._HEADERS.get(name.strip().upper())
            if sep and key and key not in body:
                # an unknown header keeps its line ending as the text \r\n
                body[key] = value.strip().removesuffix('\\r\\n').strip()
        self.records.append((pkt.flow, pkt.when, self.event_type, body))

    def finish(self):
        return self.records


# ---------------------------------------------------------------- S7comm

_S7_ROSCTR = {1: 'job', 2: 'ack', 3: 'ack_data', 7: 'userdata'}
_S7_FUNCTIONS = {0x00: 'CPU services', 0x04: 'Read Var', 0x05: 'Write Var', 0x1a: 'Request download',
                 0x1b: 'Download block', 0x1c: 'Download ended', 0x1d: 'Start upload', 0x1e: 'Upload',
                 0x1f: 'End upload', 0x28: 'PLC Control', 0x29: 'PLC Stop', 0xf0: 'Setup communication'}
_S7_AREAS = {0x03: 'System info', 0x05: 'System flags', 0x06: 'Analog inputs', 0x07: 'Analog outputs',
             0x1c: 'Counter', 0x1d: 'Timer', 0x1e: 'IEC counter', 0x1f: 'IEC timer', 0x80: 'Direct peripheral',
             0x81: 'Inputs', 0x82: 'Outputs', 0x83: 'Flags', 0x84: 'Data blocks', 0x85: 'Instance DB',
             0x86: 'Local data'}
# S7-1200/1500 symbolic addressing (syntax ID 0xb2) names its area differently
_S7_SYMBOLIC_AREAS = {0x50: 'Inputs', 0x51: 'Outputs', 0x52: 'Flags', 0x53: 'Counter', 0x54: 'Timer'}
_S7_SYMBOLIC_DB_AREA = 0x8a0e
_S7_USERDATA_GROUPS = {0x0: 'Mode transition', 0x1: 'Programmer commands', 0x2: 'Cyclic data', 0x3: 'Block functions',
                       0x4: 'CPU functions', 0x5: 'Security', 0x6: 'PBC BSEND/BRECV', 0x7: 'Time functions',
                       0xf: 'NC programming'}
_S7_ERROR_CLASSES = {0x00: 'No error', 0x81: 'Application relationship', 0x82: 'Object definition',
                     0x83: 'No resources available', 0x84: 'Error on service processing',
                     0x85: 'Error on supplies', 0x87: 'Access error'}


# Which PDU kinds (header ROSCTR) list each per-PDU field - every kind
# lists the PDU reference
_S7_ALL_KINDS = frozenset((1, 2, 3, 7))
_S7_FIELD_KINDS = {
    's7comm.param.func': frozenset((1, 3, 7)),         # a bare ack (2) has no parameters
    's7comm.header.errcls': frozenset((2, 3)), 's7comm.header.errcod': frozenset((2, 3)),
    's7comm.param.userdata.funcgroup': frozenset((7,)), 's7comm.param.userdata.subfunc': frozenset((7,)),
}


class S7comm:
    """Siemens S7 (S7comm, PLC programming and data access over ISO-on-TCP -
    Suricata doesn't parse it): a record per job - Read Var, Write Var,
    Setup communication, PLC Stop, block uploads and downloads - paired
    with its acknowledgement by PDU reference, plus a record per userdata
    message (CPU functions, block functions...). A packet can carry several
    S7 PDUs; each is its own record. The variables a read or write names
    are kept when the packet carries only that one PDU: area, data block
    and byte.bit address for classic (S7-300/400) addressing; area and data
    block for S7-1200/1500 symbolic addressing."""
    event_type = 's7comm'
    app_protos = ('s7comm',)
    fields = ('s7comm.header.rosctr', 's7comm.header.pduref', 's7comm.param.func', 's7comm.header.errcls',
              's7comm.header.errcod', 's7comm.param.itemcount', 's7comm.param.item.area', 's7comm.param.item.db',
              's7comm.param.item.address.byte', 's7comm.param.item.address.bit',
              's7comm.tiap.item.area1', 's7comm.tiap.item.area2', 's7comm.tiap.item.dbnumber',
              's7comm.param.userdata.funcgroup', 's7comm.param.userdata.subfunc')

    def __init__(self):
        self.records = []
        self.jobs = {}           # (flow key, PDU reference) -> job body awaiting its ack

    def feed(self, pkt, v):
        rosctrs = v['s7comm.header.rosctr']
        single = len(rosctrs) == 1
        # A field is listed once for each of the packet's PDUs that has it,
        # in order - and not every kind of PDU has every field (only an
        # acknowledgement's header has the error class, only userdata a
        # function group, and a bare ack no parameters) - so each is read
        # in step with the PDUs of the kinds that carry it, not by position.
        taken = {}

        def take(field, kinds, rosctr):
            if _int(rosctr) not in kinds:
                return ''
            n = taken.get(field, 0)
            taken[field] = n + 1
            values = v[field]
            return values[n] if n < len(values) else ''
        for rosctr in rosctrs:
            def at(field, _rosctr=rosctr):
                return take(field, _S7_FIELD_KINDS.get(field, _S7_ALL_KINDS), _rosctr)
            kind = _S7_ROSCTR.get(_int(rosctr), f'rosctr {rosctr}')
            pduref = _int(at('s7comm.header.pduref'))
            func = _int(at('s7comm.param.func'))
            if kind == 'userdata':
                group = _int(at('s7comm.param.userdata.funcgroup'))
                body = {'type': kind, 'pdu_ref': pduref,
                        'function_group': _S7_USERDATA_GROUPS.get(group, f'group {group}'),
                        'subfunction': _int(at('s7comm.param.userdata.subfunc'))}
                self.records.append((pkt.flow, pkt.when, self.event_type, body))
                continue
            side = {}
            if func is not None:
                side['function_raw'] = func
                side['function'] = _S7_FUNCTIONS.get(func, f'function 0x{func:02x}')
            if single and _int(_first(v['s7comm.param.itemcount'])) is not None:
                side['item_count'] = _int(_first(v['s7comm.param.itemcount']))
            if single and (v['s7comm.param.item.area'] or v['s7comm.tiap.item.area1']):
                side['items'] = ([self._item(v, n) for n in range(len(v['s7comm.param.item.area']))]
                                 + [self._symbolic_item(v, n) for n in range(len(v['s7comm.tiap.item.area1']))])
            if kind == 'job':
                body = {'type': 'job', 'pdu_ref': pduref, **side}
                self.jobs[(pkt.flow.key, pduref)] = body
                self.records.append((pkt.flow, pkt.when, self.event_type, body))
                continue
            errcls = _int(at('s7comm.header.errcls'))
            if errcls:
                side['error_class'] = _S7_ERROR_CLASSES.get(errcls, f'0x{errcls:02x}')
                side['error_code'] = _int(at('s7comm.header.errcod'), 0)
            body = self.jobs.pop((pkt.flow.key, pduref), None)
            if body is None:   # an ack whose job isn't in the capture
                body = {'type': 'job', 'pdu_ref': pduref}
                self.records.append((pkt.flow, pkt.when, self.event_type, body))
            body['response'] = side

    @staticmethod
    def _item(v, n):
        def at(field):
            values = v[field]
            return values[n] if n < len(values) else ''
        area = _int(at('s7comm.param.item.area'))
        item = {'area': _S7_AREAS.get(area, f'area 0x{area:02x}' if area is not None else '')}
        db = _int(at('s7comm.param.item.db'))
        if db:
            item['db'] = db
        byte, bit = _int(at('s7comm.param.item.address.byte')), _int(at('s7comm.param.item.address.bit'))
        if byte is not None:
            item['address'] = f'{byte}.{bit or 0}'
        return item

    @staticmethod
    def _symbolic_item(v, n):
        def at(field):
            values = v[field]
            return values[n] if n < len(values) else ''
        if _int(at('s7comm.tiap.item.area1')) == _S7_SYMBOLIC_DB_AREA:
            item = {'area': 'Data blocks'}
            if _int(at('s7comm.tiap.item.dbnumber')):
                item['db'] = _int(at('s7comm.tiap.item.dbnumber'))
            return item
        area = _int(at('s7comm.tiap.item.area2'))
        return {'area': _S7_SYMBOLIC_AREAS.get(area, f'area 0x{area:04x}' if area is not None else '')}

    def finish(self):
        return self.records


# ---------------------------------------------------------------- Telnet
#
# Suricata recognizes Telnet but logs nothing about it. One record per
# session: the server's banner, the name and password typed at its login
# prompts - the last attempt's, with how many failed before it
# (earlier_failures) - whether it said that one failed, and the lines typed
# after - rebuilt from the keystrokes (a client sends each as it's typed;
# the server echoes them, and its echo is ignored here). A secret typed at
# a prompt after the login's (a PIN, an enable secret) is kept nowhere -
# not as the password, nor as one of the lines typed.

_TELNET_ESCAPES = re.compile(r'\x1b\[[0-9;?]*[A-Za-z~]|\x1b[()][A-Za-z0-9]|\x1b.?')
_TELNET_USER_PROMPT = re.compile(r'(login|user ?name|user|account)\s*:\s*$', re.I)
_TELNET_PASSWORD_PROMPT = re.compile(r'(pass(word|code|phrase)?|pin|secret)\s*:\s*$', re.I)
_TELNET_FAILED = re.compile(r'login incorrect|access denied|authentication fail|invalid (password|login|user)|'
                            r'login fail|incorrect password|bad password', re.I)
_TELNET_MAX_SERVER_TEXT = 4096     # of the session's start, enough for its banner and login
_TELNET_MAX_COMMANDS = 100
_TELNET_MAX_LINE = 200


class _TelnetSession:
    __slots__ = ('first', 'flow', 'server_text', 'tail', 'state', 'line', 'body', 'commands', 'attempt', 'named')

    def __init__(self, flow, when):
        self.flow, self.first = flow, when
        self.server_text = ''      # the start of everything the server sent
        self.tail = ''             # the end of it, for spotting the latest prompt
        self.state = None          # what the next line typed is: 'user', 'password', or a command
        self.line = ''
        self.body = {}
        self.commands = []
        # whether the next secret typed is a login attempt's password: at the
        # start, after a user name or a failed login - not a later PIN or
        # enable secret, which is kept nowhere
        self.attempt = True
        self.named = False         # whether this attempt typed a user name


class Telnet:
    """Telnet sessions - see the comment above."""
    event_type = 'telnet'
    app_protos = ('telnet',)
    fields = ('telnet.data',)

    def __init__(self):
        self.sessions = {}        # flow key -> _TelnetSession

    def feed(self, pkt, v):
        text = ''.join(v['telnet.data'])
        if not text:
            return
        session = self.sessions.get(pkt.flow.key)
        if session is None:
            session = self.sessions[pkt.flow.key] = _TelnetSession(pkt.flow, pkt.when)
        # The server is whoever's on the Telnet port (the flow's client may
        # not be settled yet when its first data arrives)
        if pkt.sport == 23 or (pkt.dport != 23 and pkt.sport == pkt.flow.sport):
            self._from_server(session, text)
        else:
            self._from_client(session, text)

    @staticmethod
    def _from_server(session, text):
        clean = _TELNET_ESCAPES.sub('', text)
        if len(session.server_text) < _TELNET_MAX_SERVER_TEXT:
            session.server_text += clean
        session.tail = (session.tail + clean)[-200:]
        last = session.tail.rstrip(' \t')
        if _TELNET_PASSWORD_PROMPT.search(last):
            session.state = 'password'
        elif _TELNET_USER_PROMPT.search(last):
            session.state = 'user'
        if _TELNET_FAILED.search(clean):
            session.body['login'] = 'failed'
            session.attempt = True

    @staticmethod
    def _from_client(session, text):
        for ch in _TELNET_ESCAPES.sub('', text):
            if ch in '\r\n':
                line, session.line = session.line, ''
                # (each attempt's replaces the last's: a failed login and
                # then one the server took is that one's record)
                # (Enter alone at the prompts - typing nothing - is no attempt:
                # it leaves the last one's user name and password standing)
                if session.state == 'user':
                    if line:
                        session.body['username'] = line
                        session.attempt = session.named = True
                    session.state = None
                elif session.state == 'password':
                    if session.attempt and (line or session.named or 'password' not in session.body):
                        if session.body.pop('login', None) == 'failed':
                            # a new attempt after a failed one - failed only
                            # if the server says so again
                            session.body['earlier_failures'] = session.body.get('earlier_failures', 0) + 1
                        session.body['password'] = line
                        session.attempt = session.named = False
                    session.state = None
                elif line.strip() and len(session.commands) < _TELNET_MAX_COMMANDS:
                    session.commands.append(line[:_TELNET_MAX_LINE])
                session.tail = ''
            elif ch in '\x08\x7f':
                session.line = session.line[:-1]
            elif ch >= ' ' and len(session.line) < 4 * _TELNET_MAX_LINE:
                session.line += ch

    def finish(self):
        records = []
        for session in self.sessions.values():
            body = dict(session.body)
            # The banner: the first line of the server's text that reads as
            # text (option negotiation leaves stray bytes ahead of it)
            for line in session.server_text.replace('\r', '\n').split('\n'):
                line = ''.join(ch for ch in line if ch >= ' ' and ch != '\ufffd').strip()
                if sum(ch.isalnum() for ch in line) >= 3:
                    body['banner'] = line[:_TELNET_MAX_LINE]
                    break
            if session.commands:
                body['commands'] = session.commands
            if body:
                records.append((session.flow, session.first, 'telnet', body))
        return records


# ---------------------------------------------------------------- rsh, rlogin, rexec
#
# The BSD remote shells, all in the clear, which Suricata doesn't parse.
# Each opens with NUL-terminated strings from the client - rsh (514): the
# port for errors, the local and remote user names and the command;
# rexec (512): the port, the user name, the password and the command;
# rlogin (513): a NUL, the local and remote user names and the terminal -
# then a byte from the server, 0 to go ahead or 1 and why not. After
# that rsh and rexec carry the command's output, and rlogin a terminal
# session, read like Telnet's (a password prompt, the lines typed). One
# 'rsh' record per connection; a start that isn't one of these (a
# scanner's HTTP request) is kept as the probe it is, with the answer.

_RSH_SERVICES = {'rsh': 'rsh', 'rlogin': 'rlogin', 'exec': 'rexec'}
_RSH_PORTS = {512: 'rexec', 513: 'rlogin', 514: 'rsh'}
_RSH_MAX_START = 1024
_RSH_MAX_TEXT = 200


def _rsh_text(data, limit=_RSH_MAX_TEXT):
    """Bytes as one line of text - for a command's output, an error, a
    probe: line breaks and tabs as spaces (runs of them as one), other
    bytes that aren't text as dots, as a hex dump shows them."""
    text = ''.join(' ' if ch in '\t\r\n ' else ch if ch > ' ' and ch not in '\x7f\ufffd' else '.'
                   for ch in data.decode('utf-8', 'replace'))
    text = ' '.join(text.split())
    return text if len(text) <= limit else text[:limit] + '...'


def _rsh_names(fields):
    """Whether a start's strings read as user names and a command: text,
    with a user name to log in as - not a probe's bytes that happen to
    hold NULs."""
    try:
        texts = [f.decode('utf-8') for f in fields]
    except UnicodeDecodeError:
        return False
    return bool(texts[1]) and all(ch >= ' ' or ch == '\t' for t in texts for ch in t)


class _RshSession:
    __slots__ = ('flow', 'first', 'service', 'client', 'server', 'started', 'answered', 'body', 'terminal')

    def __init__(self, flow, when, service):
        self.flow, self.first, self.service = flow, when, service
        self.client = b''          # the client's bytes until its start is read
        self.server = b''          # the server's, after its answer, for output
        self.started = False
        self.answered = False
        self.body = {'service': service}
        self.terminal = None       # rlogin's session, read as Telnet's (_TelnetSession)


class RShell:
    """rsh, rlogin and rexec - see the comment above."""
    event_type = 'rsh'
    app_protos = ('rsh', 'rlogin', 'exec')
    fields = ('@rsh', '@rlogin', '@exec')

    def __init__(self):
        self.sessions = {}         # flow key -> _RshSession

    def feed(self, pkt, v):
        service = _RSH_SERVICES.get(pkt.app)
        data = _hex((v['@' + pkt.app] or [''])[0]) if service else b''
        if not data:
            return
        session = self.sessions.get(pkt.flow.key)
        if session is None:
            session = self.sessions[pkt.flow.key] = _RshSession(pkt.flow, pkt.when, service)
        # the server is whoever's on the service's port
        if _RSH_PORTS.get(pkt.sport) == service:
            self._from_server(session, data)
        else:
            self._from_client(session, data)

    def _from_client(self, session, data):
        if session.started:
            if session.terminal is not None:
                Telnet._from_client(session.terminal, data.decode('utf-8', 'replace'))
            return
        session.client = (session.client + data)[:_RSH_MAX_START]
        start = session.client
        if session.service == 'rlogin':
            if start[:1] != b'\x00':
                return
            fields = start[1:].split(b'\x00')
            if len(fields) < 4:
                return
            if not _rsh_names(fields[:3]):
                session.started = True         # not rlogin's start: a probe
                return
            local, remote, terminal = (f.decode('utf-8', 'replace') for f in fields[:3])
            session.body.update({'local_user': local, 'user': remote, 'terminal': terminal})
            session.terminal = _TelnetSession(session.flow, session.first)
            rest = b'\x00'.join(fields[3:])
        else:
            fields = start.split(b'\x00')
            if len(fields) < 5:
                return
            if not (fields[0].isdigit() or not fields[0]) or not _rsh_names(fields[1:4]):
                session.started = True         # not its start: a probe
                return
            port, first, second, command = (f.decode('utf-8', 'replace') for f in fields[:4])
            if port not in ('', '0'):
                session.body['stderr_port'] = int(port)
            if session.service == 'rexec':
                session.body.update({'user': first, 'password': second})
            else:
                session.body.update({'local_user': first, 'user': second})
            session.body['command'] = command[:4 * _RSH_MAX_TEXT]
            rest = b''
        session.started = True
        session.client = b''
        if rest and session.terminal is not None:
            Telnet._from_client(session.terminal, rest.decode('utf-8', 'replace'))

    def _from_server(self, session, data):
        if not session.answered:
            session.answered = True
            if data[:1] == b'\x00':
                session.body['result'] = 'accepted'
                data = data[1:]
            else:
                # a refusal: byte 1, then why
                session.body['result'] = 'refused'
                data = data[1:] if data[:1] == b'\x01' else data
                session.server = data
                return
        if session.body.get('result') == 'refused':
            session.server = (session.server + data)[:4 * _RSH_MAX_TEXT]
        elif session.terminal is not None:
            Telnet._from_server(session.terminal, data.decode('utf-8', 'replace'))
        elif len(session.server) < 4 * _RSH_MAX_TEXT:
            session.server += data

    def finish(self):
        records = []
        for session in self.sessions.values():
            body = dict(session.body)
            if session.client and _rsh_text(session.client):
                body['probe'] = _rsh_text(session.client)
            if body.get('result') == 'refused' and session.server.strip(b'\x00\r\n'):
                # the reason runs to the end of its line
                body['error'] = _rsh_text(session.server.split(b'\n', 1)[0])
            elif session.server:
                body['output'] = _rsh_text(session.server)
            if session.terminal is not None:
                body.update({k: v for k, v in session.terminal.body.items() if k in ('password', 'login',
                                                                                   'earlier_failures')})
                if session.terminal.commands:
                    body['commands'] = session.terminal.commands
            body.setdefault('result', 'no response')
            records.append((session.flow, session.first, 'rsh', body))
        return records


# ---------------------------------------------------------------- OpenVPN
#
# OpenVPN (UDP or TCP 1194), which Suricata doesn't parse. A client opens
# with a hard reset (each retry is another, with a new session ID), the
# server answers with its own, TLS runs inside the control channel - the
# server's certificate readable, unless tls-crypt wraps it - and then the
# tunnel's data flows, its keys renegotiated now and then. One record per
# connection: how far it got, how often the client started over, how the
# control channel is protected (tls-auth's HMAC, tls-crypt), the TLS
# handshake's certificates and cipher suite, and the data packets each
# way. tshark recognizes OpenVPN on port 1194 only.

_OPENVPN_OPCODES = {1: 'P_CONTROL_HARD_RESET_CLIENT_V1', 2: 'P_CONTROL_HARD_RESET_SERVER_V1',
                    3: 'P_CONTROL_SOFT_RESET_V1', 4: 'P_CONTROL_V1', 5: 'P_ACK_V1', 6: 'P_DATA_V1',
                    7: 'P_CONTROL_HARD_RESET_CLIENT_V2', 8: 'P_CONTROL_HARD_RESET_SERVER_V2', 9: 'P_DATA_V2',
                    10: 'P_CONTROL_HARD_RESET_CLIENT_V3', 11: 'P_CONTROL_WKC_V1'}
_OPENVPN_CLIENT_RESETS, _OPENVPN_SERVER_RESETS = {1, 7, 10}, {2, 8}
_OPENVPN_DATA = {6, 9}
_OPENVPN_STAGES = ('client reset only', 'server answered', 'TLS handshake', 'established')


class _OpenVPNSession:
    __slots__ = ('flow', 'first', 'client', 'body', 'sessions', 'keys', 'stage')

    def __init__(self, flow, when):
        self.flow, self.first = flow, when
        self.client = None         # the address that sent the hard reset
        self.body = {'client_resets': 0, 'data_to_server': 0, 'data_to_client': 0}
        self.sessions = set()      # the client's session IDs
        self.keys = set()          # key IDs the data used
        self.stage = 0


class OpenVPN:
    """OpenVPN - see the comment above."""
    event_type = 'openvpn'
    app_protos = ('openvpn',)
    fields = ('openvpn.opcode', 'openvpn.keyid', 'openvpn.sessionid', 'openvpn.hmac', 'openvpn.wkc_len',
              'openvpn.peerid', 'tls.handshake.type', 'tls.handshake.certificate', 'vals(tls.handshake.ciphersuite)',
              'tls.handshake.ja4', 'tls.handshake.extensions_server_name')

    def __init__(self):
        self.sessions = {}         # flow key -> _OpenVPNSession

    def feed(self, pkt, v):
        opcodes = [_int(x) for x in v['openvpn.opcode']]
        if not opcodes:
            return
        session = self.sessions.get(pkt.flow.key)
        if session is None:
            session = self.sessions[pkt.flow.key] = _OpenVPNSession(pkt.flow, pkt.when)
        body = session.body
        for i, opcode in enumerate(opcodes):
            if opcode in _OPENVPN_CLIENT_RESETS:
                session.client = pkt.src
                body['client_resets'] += 1
                body['version'] = 'V3 (tls-crypt-v2)' if opcode == 10 else 'V2' if opcode == 7 else 'V1'
                if i < len(v['openvpn.sessionid']):
                    session.sessions.add(v['openvpn.sessionid'][i])
            elif opcode in _OPENVPN_SERVER_RESETS:
                session.stage = max(session.stage, 1)
            elif opcode in _OPENVPN_DATA:
                to_server = session.client is None or pkt.src == session.client
                body['data_to_server' if to_server else 'data_to_client'] += 1
                if i < len(v['openvpn.keyid']):
                    session.keys.add(v['openvpn.keyid'][i])
                if body['data_to_server'] and body['data_to_client']:
                    session.stage = 3
            elif opcode == 3:
                body['soft_resets'] = body.get('soft_resets', 0) + 1
        if v['openvpn.hmac']:
            body['control_protection'] = 'tls-auth'
        if v['openvpn.wkc_len'] or body.get('version', '').startswith('V3'):
            body['control_protection'] = 'tls-crypt-v2'
        self._tls(session, pkt, v)

    @staticmethod
    def _tls(session, pkt, v):
        body = session.body
        if v['tls.handshake.type']:
            session.stage = max(session.stage, 2)
        from_client = session.client is not None and pkt.src == session.client
        for hexbytes in v['tls.handshake.certificate'][:1]:
            key = 'client_certificate' if from_client else 'certificate'
            if key not in body:
                cert = _x509(hexbytes)
                if cert:
                    body[key] = {k: cert[k] for k in ('subject', 'issuerdn', 'notbefore', 'notafter', 'serial',
                                                     'fingerprint') if k in cert}
        if v['vals(tls.handshake.ciphersuite)'] and not from_client and '2' in v['tls.handshake.type']:
            body['cipher_suite'] = v['vals(tls.handshake.ciphersuite)'][0]
        if from_client and v['tls.handshake.ja4']:
            body.setdefault('ja4', v['tls.handshake.ja4'][0])
        if from_client and v['tls.handshake.extensions_server_name']:
            body.setdefault('sni', v['tls.handshake.extensions_server_name'][0])

    def finish(self):
        records = []
        for session in self.sessions.values():
            body = dict(session.body)
            body['stage'] = _OPENVPN_STAGES[session.stage]
            if len(session.sessions) > 1:
                body['client_sessions'] = len(session.sessions)
            if len(session.keys) > 1:
                body['data_keys'] = len(session.keys)
            body.setdefault('control_protection', 'none' if session.stage >= 1 else '')
            if not body['control_protection']:
                del body['control_protection']
            records.append((session.flow, session.first, 'openvpn', body))
        return records


# ---------------------------------------------------------------- IEC 60870-5-104
#
# Telecontrol between a power grid's control centre and its substations.
# Two record types: 'iec104', one per control action - a command, set
# point, interrogation, clock sync, read, reset, parameter or file
# transfer - with its confirmation and termination paired in; and
# 'iec104_point', one per monitored point per connection (its updates
# counted, the last value kept), so a busy link's hundreds of thousands
# of measurements don't each become a record. A packet often carries
# several messages (ASDUs): each has one type, cause and station, and
# numix objects, by which the flat object and value fields split up.

_IEC104_TYPES = {
    1: 'M_SP_NA_1', 2: 'M_SP_TA_1', 3: 'M_DP_NA_1', 4: 'M_DP_TA_1', 5: 'M_ST_NA_1', 6: 'M_ST_TA_1', 7: 'M_BO_NA_1',
    8: 'M_BO_TA_1', 9: 'M_ME_NA_1', 10: 'M_ME_TA_1', 11: 'M_ME_NB_1', 12: 'M_ME_TB_1', 13: 'M_ME_NC_1', 14: 'M_ME_TC_1',
    15: 'M_IT_NA_1', 16: 'M_IT_TA_1', 17: 'M_EP_TA_1', 18: 'M_EP_TB_1', 19: 'M_EP_TC_1', 20: 'M_PS_NA_1', 21: 'M_ME_ND_1',
    30: 'M_SP_TB_1', 31: 'M_DP_TB_1', 32: 'M_ST_TB_1', 33: 'M_BO_TB_1', 34: 'M_ME_TD_1', 35: 'M_ME_TE_1', 36: 'M_ME_TF_1',
    37: 'M_IT_TB_1', 38: 'M_EP_TD_1', 39: 'M_EP_TE_1', 40: 'M_EP_TF_1', 45: 'C_SC_NA_1', 46: 'C_DC_NA_1', 47: 'C_RC_NA_1',
    48: 'C_SE_NA_1', 49: 'C_SE_NB_1', 50: 'C_SE_NC_1', 51: 'C_BO_NA_1', 58: 'C_SC_TA_1', 59: 'C_DC_TA_1', 60: 'C_RC_TA_1',
    61: 'C_SE_TA_1', 62: 'C_SE_TB_1', 63: 'C_SE_TC_1', 64: 'C_BO_TA_1', 70: 'M_EI_NA_1', 100: 'C_IC_NA_1', 101: 'C_CI_NA_1',
    102: 'C_RD_NA_1', 103: 'C_CS_NA_1', 104: 'C_TS_NA_1', 105: 'C_RP_NA_1', 106: 'C_CD_NA_1', 107: 'C_TS_TA_1',
    110: 'P_ME_NA_1', 111: 'P_ME_NB_1', 112: 'P_ME_NC_1', 113: 'P_AC_NA_1', 120: 'F_FR_NA_1', 121: 'F_SR_NA_1',
    122: 'F_SC_NA_1', 123: 'F_LS_NA_1', 124: 'F_AF_NA_1', 125: 'F_SG_NA_1', 126: 'F_DR_TA_1', 127: 'F_SC_NB_1'}
_IEC104_ACTIONS = {
    45: 'Single command', 46: 'Double command', 47: 'Regulating step command', 48: 'Set point (normalized)',
    49: 'Set point (scaled)', 50: 'Set point (float)', 51: 'Bitstring command', 58: 'Single command', 59: 'Double command',
    60: 'Regulating step command', 61: 'Set point (normalized)', 62: 'Set point (scaled)', 63: 'Set point (float)',
    64: 'Bitstring command', 70: 'End of initialization', 100: 'Interrogation', 101: 'Counter interrogation', 102: 'Read',
    103: 'Clock synchronization', 104: 'Test', 105: 'Reset process', 106: 'Delay acquisition', 107: 'Test',
    110: 'Parameter (normalized)', 111: 'Parameter (scaled)', 112: 'Parameter (float)', 113: 'Parameter activation',
    120: 'File ready', 121: 'Section ready', 122: 'Call directory/file/section', 123: 'Last section/segment',
    124: 'Acknowledge file/section', 125: 'File segment', 126: 'Directory', 127: 'Query log'}
_IEC104_CAUSES = {
    1: 'per/cyc', 2: 'back', 3: 'spont', 4: 'init', 5: 'req', 6: 'act', 7: 'actcon', 8: 'deact', 9: 'deactcon',
    10: 'actterm', 11: 'retrem', 12: 'retloc', 13: 'file', 14: 'auth', 15: 'seskey', 16: 'usrkey', 20: 'inrogen',
    37: 'reqcogen', 44: 'unknown type', 45: 'unknown cause', 46: 'unknown station', 47: 'unknown address'}
for _n in range(1, 17):
    _IEC104_CAUSES[20 + _n] = f'inro{_n}'
for _n in range(1, 5):
    _IEC104_CAUSES[37 + _n] = f'reqco{_n}'
# Each object's value: the field it's in, and how to read it, by type
_IEC104_VALUE_FIELDS = {'siq': 'iec60870_asdu.siq.spi', 'diq': 'iec60870_asdu.diq.dpi', 'vti': 'iec60870_asdu.vti.v',
                        'bits': 'iec60870_asdu.bitstring', 'norm': 'iec60870_asdu.normval', 'scal': 'iec60870_asdu.scalval',
                        'float': 'iec60870_asdu.float', 'bcr': 'iec60870_asdu.bcr.count', 'sco': 'iec60870_asdu.sco.on',
                        'dco': 'iec60870_asdu.dco.on', 'rco': 'iec60870_asdu.rco.up', 'qoi': 'iec60870_asdu.qoi',
                        'qcc': 'iec60870_asdu.qcc', 'qrp': 'iec60870_asdu.qrp'}
_IEC104_VALUE_KIND = {}
for _kind, _types in (('siq', (1, 2, 30)), ('diq', (3, 4, 31)), ('vti', (5, 6, 32)), ('bits', (7, 8, 33, 51, 64)),
                      ('norm', (9, 10, 34, 21, 48, 61)), ('scal', (11, 12, 35, 49, 62)), ('float', (13, 14, 36, 50, 63)),
                      ('bcr', (15, 16, 37)), ('sco', (45, 58)), ('dco', (46, 59)), ('rco', (47, 60)), ('qoi', (100,)),
                      ('qcc', (101,)), ('qrp', (105,))):
    for _t in _types:
        _IEC104_VALUE_KIND[_t] = _kind
_IEC104_DOUBLE_POINT = {0: 'indeterminate', 1: 'off', 2: 'on', 3: 'indeterminate'}
_IEC104_INTERROGATIONS = {20: 'station'}
for _n in range(1, 17):
    _IEC104_INTERROGATIONS[20 + _n] = f'group {_n}'


_IEC104_COMMAND_STATES = {'sco': {0: 'off', 1: 'on'}, 'dco': {1: 'off', 2: 'on'}, 'rco': {1: 'lower', 2: 'higher'}}


def _iec104_value(kind, text):
    if kind == 'siq':
        return 1 if text in ('1', 'True') else 0
    if kind in _IEC104_COMMAND_STATES:
        number = 1 if text == 'True' else 0 if text == 'False' else _int(text)
        return _IEC104_COMMAND_STATES[kind].get(number, text)
    if kind == 'diq':
        return _IEC104_DOUBLE_POINT.get(_int(text), text)
    if kind == 'qoi':
        return _IEC104_INTERROGATIONS.get(_int(text), text)
    if kind in ('norm', 'float'):
        return _finite(text)
    number = _int(text)
    return number if number is not None else text


def _iso_utc(when):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(when, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f+0000')


class _IEC104Point:
    __slots__ = ('flow', 'first', 'body')

    def __init__(self, flow, first, body):
        self.flow, self.first, self.body = flow, first, body


class IEC104:
    """IEC 60870-5-104 - see the comment above."""
    event_type = 'iec104'
    app_protos = ('iec60870_104',)
    fields = ('iec60870_asdu.typeid', 'iec60870_asdu.causetx', 'iec60870_asdu.nega', 'iec60870_asdu.test',
              'iec60870_asdu.addr', 'iec60870_asdu.numix', 'iec60870_asdu.ioa') + tuple(_IEC104_VALUE_FIELDS.values())

    # Causes that open a control action: activation, deactivation, and a
    # read's request
    _OPENS = (6, 8)

    def __init__(self):
        self.records = []
        # (flow key, type, station, first object) -> the actions waiting on
        # their replies, oldest first: a station can be sent another
        # interrogation before the last is answered, and replies in order
        self.open = {}
        self.points = {}       # (flow key, station, object, type) -> _IEC104Point

    def feed(self, pkt, v):
        values = {kind: list(v[field]) for kind, field in _IEC104_VALUE_FIELDS.items()}
        objects = list(v['iec60870_asdu.ioa'])
        for tid, cot, addr, count, negative, test in zip(
                v['iec60870_asdu.typeid'], v['iec60870_asdu.causetx'], v['iec60870_asdu.addr'], v['iec60870_asdu.numix'],
                v['iec60870_asdu.nega'] or [''] * len(v['iec60870_asdu.typeid']),
                v['iec60870_asdu.test'] or [''] * len(v['iec60870_asdu.typeid'])):
            tid, cot, addr, count = _int(tid), _int(cot, 0), _int(addr, 0), _int(count, 0)
            if tid is None:
                continue
            ioas = [_int(x, 0) for x in objects[:count]]
            del objects[:count]
            kind = _IEC104_VALUE_KIND.get(tid)
            vals = []
            if kind:
                vals = [_iec104_value(kind, x) for x in values[kind][:count]]
                del values[kind][:count]
            if tid >= 45:
                self._control(pkt, tid, cot, addr, ioas, vals, negative in ('1', 'True'), test in ('1', 'True'))
            else:
                self._points(pkt, tid, cot, addr, ioas, vals)

    def _control(self, pkt, tid, cot, addr, ioas, vals, negative, test):
        key = (pkt.flow.key, tid, addr, ioas[0] if ioas else None)
        cause = _IEC104_CAUSES.get(cot, str(cot))
        waiting = self.open.get(key, [])
        if cot in (7, 9) or 44 <= cot <= 47:
            body = next((b for b in waiting if 'response' not in b), None)
        elif cot == 10:
            body = next((b for b in waiting if 'terminated' not in b), None)
        else:
            body = None
        if cot in self._OPENS or (tid == 102 and cot == 5) or body is None:
            body = {'type_id': tid, 'type': _IEC104_TYPES.get(tid, str(tid)), 'action': _IEC104_ACTIONS.get(tid, ''),
                    'cause': cause, 'station': addr}
            if ioas:
                body['ioa'] = ioas[0]
            if vals:
                body['value'] = vals[0]
            if test:
                body['test'] = True
            opens = cot in self._OPENS or (tid == 102 and cot == 5)
            # A reply whose request the capture doesn't have (it started
            # after, or lost the packet) is still a record
            if opens:
                body['result'] = 'no confirmation'
            elif cot in (7, 9):
                body['result'] = 'negative (request not seen)' if negative else 'confirmed (request not seen)'
            elif cot == 10:
                body['result'] = 'terminated (request not seen)'
            else:
                body['result'] = cause
            self.records.append((pkt.flow, pkt.when, 'iec104', body))
            if opens:
                self.open.setdefault(key, []).append(body)
            return
        # its confirmation, termination, or an "unknown ..." refusal
        if cot in (7, 9):
            body['response'] = {'cause': cause, 'negative': negative}
            body['result'] = 'negative' if negative else 'confirmed'
        elif cot == 10:
            body['terminated'] = True
            if body['result'] == 'confirmed':
                body['result'] = 'confirmed, terminated'
            waiting.remove(body)
        elif 44 <= cot <= 47:
            body['response'] = {'cause': cause, 'negative': True}
            body['result'] = cause
            waiting.remove(body)
        # A command that needs no termination is done once confirmed; keep
        # the queue to what can still be answered
        if len(waiting) > 64:
            del waiting[:-64]

    def _points(self, pkt, tid, cot, addr, ioas, vals):
        cause = _IEC104_CAUSES.get(cot, str(cot))
        for i, ioa in enumerate(ioas):
            key = (pkt.flow.key, addr, ioa, tid)
            point = self.points.get(key)
            if point is None:
                body = {'station': addr, 'ioa': ioa, 'type_id': tid, 'type': _IEC104_TYPES.get(tid, str(tid)),
                        'updates': 0, 'causes': {}}
                point = self.points[key] = _IEC104Point(pkt.flow, pkt.when, body)
            body = point.body
            body['updates'] += 1
            body['causes'][cause] = body['causes'].get(cause, 0) + 1
            body['last_update'] = pkt.when
            if i < len(vals):
                body['last_value'] = vals[i]

    def finish(self):
        records = list(self.records)
        for point in self.points.values():
            body = point.body
            body['last_update'] = _iso_utc(body['last_update'])
            records.append((point.flow, point.first, 'iec104_point', body))
        return records


# ---------------------------------------------------------------- BACnet
#
# Building automation (HVAC, lighting, access control), over UDP 47808
# (BACnet/IP, which tshark calls bvlc) or straight over Ethernet. Three
# record types, since reads dwarf everything else: 'bacnet', one per
# action - a confirmed request other than a read (a write, a file write,
# a reinitialize or communication-control with its password, a
# subscription) paired with its reply, and each unconfirmed message
# other than I-Am and value notifications (event notifications, time
# syncs, and Who-Is/Who-Has discovery - one record per sender and question,
# counted, since a workstation can ask the same thing every few seconds
# for a day); 'bacnet_property', one per object and
# property read or reported on each connection (reads and change-of-value
# notifications counted, the last value kept); and 'bacnet_device', one
# per device announcing itself (I-Am), with its vendor. Names come from
# tshark (vals()), so its vendor and property lists stay its own. tshark
# runs a ReadPropertyMultiple reply's values together, so a value is kept
# only when a message carries exactly one.

_BACNET_READS = {'readProperty', 'readPropertyMultiple', 'readRange', 'atomicReadFile'}
_BACNET_DISCOVERY = {'who-Is', 'who-Has'}
_BACNET_VALUE_NOTIFICATIONS = {'confirmedCOVNotification', 'unconfirmedCOVNotification'}
# Messages whose first object is the device sending them, the object
# they're about following
_BACNET_FROM_DEVICE = _BACNET_VALUE_NOTIFICATIONS | {'confirmedEventNotification', 'unconfirmedEventNotification'}
_BACNET_VALUE_FIELDS = ('bacapp.present_value.real', 'bacapp.present_value.double', 'bacapp.present_value.uint',
                        'bacapp.present_value.int', 'bacapp.present_value.enum_index', 'bacapp.present_value.boolean',
                        'bacapp.present_value.char_string')
_BACNET_BINARY_OBJECTS = {'binary-input', 'binary-output', 'binary-value'}
_BACNET_REINIT_STATES = {0: 'coldstart', 1: 'warmstart', 2: 'start-backup', 3: 'end-backup', 4: 'start-restore',
                         5: 'end-restore', 6: 'abort-restore', 7: 'activate-changes'}
_BACNET_ENABLE = {0: 'enable', 1: 'disable', 2: 'disable-initiation'}
# APDU types (bacapp.type)
_BACNET_CONFIRMED, _BACNET_UNCONFIRMED, _BACNET_SIMPLE_ACK, _BACNET_COMPLEX_ACK = 0, 1, 2, 3
_BACNET_ERROR, _BACNET_REJECT, _BACNET_ABORT = 5, 6, 7


def _bacnet_tags(data, pos):
    """A BACnet APDU's tags from pos: (context tag number, value bytes),
    opening and closing tags skipped."""
    while pos < len(data):
        first = data[pos]
        pos += 1
        number, lvt = first >> 4, first & 7
        if number == 15 and pos < len(data):
            number, pos = data[pos], pos + 1
        if first & 8 and lvt in (6, 7):
            continue
        length = lvt
        if lvt == 5 and pos < len(data):
            length, pos = data[pos], pos + 1
            if length in (254, 255):
                size = 2 if length == 254 else 4
                length, pos = int.from_bytes(data[pos:pos + size], 'big'), pos + size
        yield number, data[pos:pos + length]
        pos += length


def _bacnet_string(value):
    """A character string: its character set byte, then the text."""
    if not value:
        return ''
    codec = {0: 'utf-8', 4: 'utf-16-be'}.get(value[0], 'latin-1')
    return value[1:].decode(codec, 'replace')


def _bacnet_request_details(service, hexbytes):
    """What tshark shows only as text: a reinitialize's state and
    password, a communication control's duration, enable/disable and
    password - read from the APDU's own bytes."""
    try:
        data = bytes.fromhex(hexbytes.replace(':', ''))
    except ValueError:
        return {}
    if len(data) < 4:
        return {}
    pos = 6 if data[0] & 0x08 else 4        # a segmented request's header is longer
    tags = dict(_bacnet_tags(data, pos))
    details = {}
    if service == 'reinitializeDevice':
        if 0 in tags:
            details['state'] = _BACNET_REINIT_STATES.get(int.from_bytes(tags[0], 'big'), str(int.from_bytes(tags[0], 'big')))
        if 1 in tags:
            details['password'] = _bacnet_string(tags[1])
    elif service == 'deviceCommunicationControl':
        if 0 in tags:
            details['duration'] = int.from_bytes(tags[0], 'big')
        if 1 in tags:
            details['state'] = _BACNET_ENABLE.get(int.from_bytes(tags[1], 'big'), str(int.from_bytes(tags[1], 'big')))
        if 2 in tags:
            details['password'] = _bacnet_string(tags[2])
    return details


def _bacnet_named(names, numbers):
    """tshark's names for a field's values, its numbers where it has none."""
    return [name or number for name, number in zip(names, numbers)] if len(names) == len(numbers) else list(numbers)


class _BACnetSummary:
    __slots__ = ('flow', 'first', 'body')

    def __init__(self, flow, first, body):
        self.flow, self.first, self.body = flow, first, body


# Requests awaiting their reply, across a capture's BACnet - far more than
# any real network has in flight at once
_BACNET_MAX_PENDING = 10_000


class BACnet:
    """BACnet - see the comment above."""
    event_type = 'bacnet'
    app_protos = ('bvlc', 'bacnet', 'bacapp')
    fields = ('bacapp.type', 'bacapp.invoke_id', 'bacapp.confirmed_service', 'vals(bacapp.confirmed_service)',
              'bacapp.unconfirmed_service', 'vals(bacapp.unconfirmed_service)', 'bacapp.objectType',
              'vals(bacapp.objectType)', 'bacapp.instance_number', 'bacapp.property_identifier',
              'vals(bacapp.property_identifier)', 'bacapp.vendor_identifier', 'vals(bacapp.vendor_identifier)',
              'vals(bacapp.error_class)', 'vals(bacapp.error_code)', 'vals(bacapp.reject_reason)',
              'vals(bacapp.abort_reason)', 'bacapp.who_is.low_limit', 'bacapp.who_is.high_limit',
              '@bacapp', 'bacnet.dnet', 'bacnet.dadr_mstp', 'bacnet.dadr_eth', 'bacnet.dadr_tmp', 'bacnet.snet',
              'bacnet.sadr_mstp', 'bacnet.sadr_eth', 'bacnet.sadr_tmp') + _BACNET_VALUE_FIELDS

    def __init__(self):
        self.records = []
        # (flow key, routed device, invoke id) -> [(service, 'action', body)
        # or (service, 'read', summary)], oldest first. Devices behind a
        # router share its address, and each numbers its own requests'
        # invoke ids, so the routed device - a request's destination
        # network and address, its reply's source - is part of the key;
        # and a client can reuse an invoke id before its reply comes (a
        # write and a read both [1]), so a reply naming its service takes
        # the oldest request of that service.
        self.pending = {}
        self.properties = {}   # (flow key, service, object, properties) -> _BACnetSummary
        self.devices = {}      # (flow key, device instance) -> _BACnetSummary
        self.discovery = {}    # (flow key, service, range, object) -> body

    @staticmethod
    def _service(v, kind):
        return (_bacnet_named(v[f'vals(bacapp.{kind}_service)'], v[f'bacapp.{kind}_service']) or [''])[0]

    @staticmethod
    def _objects(v):
        types = _bacnet_named(v['vals(bacapp.objectType)'], v['bacapp.objectType'])
        return [f'{t},{i}' for t, i in zip(types, v['bacapp.instance_number'])]

    @staticmethod
    def _value(v, obj):
        """The message's one value, if it carries exactly one."""
        found = [(f, x) for f in _BACNET_VALUE_FIELDS for x in v[f]]
        if len(found) != 1:
            return None
        field, text = found[0]
        if field.endswith('.enum_index') and obj and obj.split(',')[0] in _BACNET_BINARY_OBJECTS:
            return {'0': 'inactive', '1': 'active'}.get(text, text)
        if field.endswith(('.real', '.double')):
            return _finite(text)
        if field.endswith('.boolean'):
            return text in ('1', 'True')
        if field.endswith('.char_string'):
            return text
        number = _int(text)
        return number if number is not None else text

    def feed(self, pkt, v):
        apdu = _int((v['bacapp.type'] or [''])[0])
        if apdu is None:
            return
        flow = pkt.flow
        invoke = _int((v['bacapp.invoke_id'] or [''])[0])
        side = 'd' if apdu == _BACNET_CONFIRMED else 's'
        routed = tuple((v[f'bacnet.{side}{f}'] or [''])[0] for f in ('net', 'adr_mstp', 'adr_eth', 'adr_tmp'))
        pending_key = (flow.key, routed, invoke)
        objects = self._objects(v)
        props = list(dict.fromkeys(_bacnet_named(v['vals(bacapp.property_identifier)'], v['bacapp.property_identifier'])))
        if apdu == _BACNET_CONFIRMED:
            service = self._service(v, 'confirmed')
            if service in _BACNET_READS:
                obj = objects[0] if objects else ''
                if len(objects) > 1 and service == 'readPropertyMultiple':
                    obj += f' (+{len(objects) - 1} more)'
                summary = self._summary(pkt, service, obj, props)
                summary.body['count'] += 1
                self._wait(pending_key, (service, 'read', summary))
            elif service in _BACNET_VALUE_NOTIFICATIONS:
                self._notification(pkt, v, service, objects, props)
            else:
                body = self._action(pkt, v, service, 'confirmed', objects, props)
                body['result'] = 'no reply'
                self._wait(pending_key, (service, 'action', body))
        elif apdu == _BACNET_UNCONFIRMED:
            service = self._service(v, 'unconfirmed')
            if service == 'i-Am':
                self._device(pkt, v, objects)
            elif service in _BACNET_VALUE_NOTIFICATIONS:
                self._notification(pkt, v, service, objects, props)
            else:
                self._action(pkt, v, service, 'unconfirmed', objects, props)
        elif apdu in (_BACNET_SIMPLE_ACK, _BACNET_COMPLEX_ACK, _BACNET_ERROR, _BACNET_REJECT, _BACNET_ABORT):
            # A segmented reply's later segments find nothing waiting
            waiting = self.pending.get(pending_key)
            if not waiting:
                return
            service = self._service(v, 'confirmed')
            entry = next((w for w in waiting if w[0] == service), None) if service else waiting[0]
            if entry is None:
                return
            waiting.remove(entry)
            if not waiting:
                del self.pending[pending_key]
            _, kind, target = entry
            result = self._result(apdu, v)
            if kind == 'action':
                target['result'] = result
                return
            body = target.body
            if result != 'ok':
                body['errors'] += 1
                body['last_error'] = result
                return
            value = self._value(v, objects[0] if objects else '') if apdu == _BACNET_COMPLEX_ACK else None
            if value is not None:
                body['last_value'] = value
                body['last_update'] = pkt.when

    def _wait(self, key, entry):
        if key not in self.pending and len(self.pending) >= _BACNET_MAX_PENDING:
            # Nor should requests to a device never heard from: the routed
            # device is part of the key, so a flood of reads naming made-up
            # ones would otherwise grow this without end - the oldest goes
            del self.pending[next(iter(self.pending))]
        waiting = self.pending.setdefault(key, [])
        waiting.append(entry)
        # a request never answered shouldn't hold its slot forever
        if len(waiting) > 8:
            del waiting[0]

    @staticmethod
    def _result(apdu, v):
        if apdu in (_BACNET_SIMPLE_ACK, _BACNET_COMPLEX_ACK):
            return 'ok'
        if apdu == _BACNET_ERROR:
            parts = [x for x in ((v['vals(bacapp.error_class)'] or [''])[0], (v['vals(bacapp.error_code)'] or [''])[0]) if x]
            return 'error: ' + ': '.join(parts) if parts else 'error'
        if apdu == _BACNET_REJECT:
            return 'rejected: ' + ((v['vals(bacapp.reject_reason)'] or ['?'])[0])
        return 'aborted: ' + ((v['vals(bacapp.abort_reason)'] or ['?'])[0])

    def _action(self, pkt, v, service, kind, objects, props):
        body = {'service': service, 'kind': kind}
        if service in _BACNET_FROM_DEVICE and len(objects) > 1:
            body['device'], objects = objects[0], objects[1:]
        if objects:
            body['object'] = objects[0]
        if props:
            body['property'] = ', '.join(props[:5]) + (' ...' if len(props) > 5 else '')
        value = self._value(v, body.get('object'))
        if value is not None and service in ('writeProperty', 'writePropertyMultiple', 'writeGroup'):
            body['value'] = value
        if service == 'who-Is' and v['bacapp.who_is.low_limit']:
            body['range'] = f"{v['bacapp.who_is.low_limit'][0]}-{(v['bacapp.who_is.high_limit'] or ['?'])[0]}"
        if service in ('reinitializeDevice', 'deviceCommunicationControl') and v['@bacapp']:
            body.update(_bacnet_request_details(service, v['@bacapp'][0]))
        if service in _BACNET_DISCOVERY:
            key = (pkt.flow.key, service, body.get('range'), body.get('object'))
            asked = self.discovery.get(key)
            if asked is not None:
                asked['count'] += 1
                asked['last_seen'] = pkt.when
                return asked
            body['count'], body['last_seen'] = 1, pkt.when
            self.discovery[key] = body
        self.records.append((pkt.flow, pkt.when, 'bacnet', body))
        return body

    def _summary(self, pkt, service, obj, props):
        label = ', '.join(props[:5]) + (' ...' if len(props) > 5 else '')
        key = (pkt.flow.key, service, obj, label)
        summary = self.properties.get(key)
        if summary is None:
            body = {'service': service, 'object': obj, 'count': 0, 'errors': 0}
            if label:
                body['property'] = label
            summary = self.properties[key] = _BACnetSummary(pkt.flow, pkt.when, body)
        return summary

    def _notification(self, pkt, v, service, objects, props):
        """A change-of-value notification: the device sending it, then the
        object it reports on."""
        obj = objects[1] if len(objects) > 1 else (objects[0] if objects else '')
        summary = self._summary(pkt, service, obj, props)
        summary.body['count'] += 1
        if objects and len(objects) > 1:
            summary.body['device'] = objects[0]
        value = self._value(v, obj)
        if value is not None:
            summary.body['last_value'] = value
            summary.body['last_update'] = pkt.when

    def _device(self, pkt, v, objects):
        instance = _int(objects[0].split(',')[-1]) if objects else None
        key = (pkt.flow.key, instance)
        device = self.devices.get(key)
        if device is None:
            body = {'device': instance, 'announcements': 0}
            vendor_ids = v['bacapp.vendor_identifier']
            if vendor_ids:
                body['vendor_id'] = _int(vendor_ids[0])
                names = v['vals(bacapp.vendor_identifier)']
                if names and names[0] and names[0] != vendor_ids[0]:
                    body['vendor'] = names[0]
            device = self.devices[key] = _BACnetSummary(pkt.flow, pkt.when, body)
        device.body['announcements'] += 1
        device.body['last_seen'] = pkt.when

    def finish(self):
        records = list(self.records)
        for body in self.discovery.values():
            body['last_seen'] = _iso_utc(body['last_seen'])
        for summary in self.properties.values():
            if 'last_update' in summary.body:
                summary.body['last_update'] = _iso_utc(summary.body['last_update'])
            records.append((summary.flow, summary.first, 'bacnet_property', summary.body))
        for device in self.devices.values():
            device.body['last_seen'] = _iso_utc(device.body['last_seen'])
            records.append((device.flow, device.first, 'bacnet_device', device.body))
        return records


# ---------------------------------------------------------------- Windows Browser
#
# NetBIOS datagrams (UDP 138) carrying the Windows Browser protocol: each
# machine announces itself to its domain or workgroup every few minutes -
# its name, Windows version and roles (domain controller, SQL server,
# master browser...) - and the browsers hold elections and hand out backup
# lists. A passive inventory of the Windows machines on a network. The
# messages repeat, so one record per sending host, name and kind of
# message, counted; a datagram to another mailslot (NETLOGON...) is
# counted the same way under its mailslot's name.

_BROWSER_ROLES = (
    (0x1, 'workstation'), (0x2, 'server'), (0x4, 'SQL server'), (0x8, 'domain controller'),
    (0x10, 'backup controller'), (0x20, 'time source'), (0x40, 'Apple'), (0x80, 'Novell'),
    (0x100, 'domain member'), (0x200, 'print server'), (0x400, 'dial-in'), (0x800, 'Xenix'),
    (0x1000, 'NT workstation'), (0x2000, 'WfW'), (0x8000, 'NT server'), (0x10000, 'potential browser'),
    (0x20000, 'backup browser'), (0x40000, 'master browser'), (0x80000, 'domain master browser'),
    (0x100000, 'OSF'), (0x200000, 'VMS'), (0x400000, 'Windows 95+'), (0x800000, 'DFS'))


def _netbios_name(name):
    """'DUALRUNNING<1d>' -> 'DUALRUNNING'."""
    return name.split('<', 1)[0].strip() if name else ''


class Browser:
    """Windows Browser - see the comment above."""
    event_type = 'browser'
    app_protos = ('nbdgm',)
    fields = ('nbdgm.source_name', 'nbdgm.destination_name', 'mailslot.name', 'vals(browser.command)',
              'browser.server', 'browser.mb_server', 'browser.os_major', 'browser.os_minor', 'browser.server_type',
              'browser.comment', 'browser.proto_major', 'browser.proto_minor', 'browser.response_computer_name',
              'browser.backup.server', 'browser.browser_to_promote')

    def __init__(self):
        self.summaries = {}    # (source address, source name, message) -> [flow, first seen, body]

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        source = _netbios_name(first('nbdgm.source_name'))
        if not source and not first('mailslot.name'):
            return
        command = first('vals(browser.command)')
        message = command or f"mailslot {first('mailslot.name') or '?'}"
        key = (pkt.src, source, message)
        summary = self.summaries.get(key)
        if summary is None:
            body = {'message': message, 'source_name': source, 'count': 0}
            destination = _netbios_name(first('nbdgm.destination_name'))
            if destination:
                body['destination_name'] = destination
            summary = self.summaries[key] = [pkt.flow, pkt.when, body]
        body = summary[2]
        body['count'] += 1
        body['last_seen'] = pkt.when
        if command:
            self._details(body, v, first)

    @staticmethod
    def _details(body, v, first):
        """What a browser message says, kept from its latest copy."""
        if first('browser.server'):
            body['name'] = first('browser.server')
        if first('browser.os_major'):
            body['os_version'] = f"{first('browser.os_major')}.{first('browser.os_minor') or 0}"
        types = first('browser.server_type')
        if types:
            try:
                bits = int(types, 16) if types.startswith('0x') else int(types)
            except ValueError:
                bits = 0
            body['roles'] = [name for bit, name in _BROWSER_ROLES if bits & bit]
        if first('browser.comment'):
            body['comment'] = first('browser.comment')
        if first('browser.mb_server'):
            body['master_browser'] = first('browser.mb_server')
        if first('browser.proto_major'):
            body['browser_version'] = f"{first('browser.proto_major')}.{first('browser.proto_minor') or 0}"
        if first('browser.response_computer_name'):
            body['reply_to'] = first('browser.response_computer_name')
        if v['browser.backup.server']:
            body['backup_servers'] = list(dict.fromkeys(v['browser.backup.server']))[:20]
        if first('browser.browser_to_promote'):
            body['promote'] = first('browser.browser_to_promote')

    def finish(self):
        records = []
        for flow, when, body in self.summaries.values():
            body['last_seen'] = _iso_utc(body['last_seen'])
            records.append((flow, when, 'browser', body))
        return records


# ---------------------------------------------------------------- LLDP and CDP
#
# Switches, routers, phones, PLCs and some PCs announce themselves to
# their neighbor on each port every half minute or so - LLDP (the IEEE
# standard) and CDP (Cisco's) - by Ethernet multicast, never routed: so
# these records are a passive inventory of the devices on the captured
# link. One record per sending MAC, device and port, counted, with what
# its latest announcement said: the device's name, description or
# platform and software, what it is (bridge, router, phone...), its
# management addresses and VLAN, and LLDP-MED's inventory (maker, model,
# serial number). An LLDP announcement with a time to live of 0 is a
# port shutting down.

_LLDP_CAPABILITIES = ((0x1, 'other'), (0x2, 'repeater'), (0x4, 'bridge'), (0x8, 'WLAN access point'),
                      (0x10, 'router'), (0x20, 'telephone'), (0x40, 'DOCSIS cable device'), (0x80, 'station'),
                      (0x100, 'C-VLAN'), (0x200, 'S-VLAN'), (0x400, 'TPMR'))
_CDP_CAPABILITIES = ((0x1, 'router'), (0x2, 'transparent bridge'), (0x4, 'source route bridge'), (0x8, 'switch'),
                     (0x10, 'host'), (0x20, 'IGMP'), (0x40, 'repeater'), (0x80, 'phone'), (0x100, 'remotely managed'),
                     (0x200, 'CVTA'), (0x400, 'MAC relay'))
_LLDP_MAX_ADDRESSES = 20


def _capabilities(value, names):
    bits = _int(value, 0)
    return [name for bit, name in names if bits & bit]


def _lldp_id(hexbytes):
    """An LLDP chassis or port ID that tshark only shows as bytes: its
    text when it's printable (a PROFINET station name, a host name),
    otherwise its bytes, colon-separated."""
    try:
        raw = bytes.fromhex(hexbytes.replace(':', ''))
    except ValueError:
        return hexbytes
    text = raw.decode('ascii', 'replace').strip()
    if raw and text.isprintable() and '�' not in text:
        return ' '.join(text.split())     # an S7 pads its ID's parts with spaces
    return ':'.join(f'{b:02x}' for b in raw)


def _addresses(*lists):
    """Addresses, each once, without the unset 0.0.0.0 and ::."""
    seen = dict.fromkeys(a for values in lists for a in values if a and a not in ('0.0.0.0', '::'))
    return list(seen)[:_LLDP_MAX_ADDRESSES]


class _Neighbors:
    """LLDP's and CDP's shared bookkeeping: one record per sending MAC,
    device and port (see the comment above)."""

    def __init__(self):
        self.devices = {}      # (source MAC, device, port) -> [flow, first seen, body]

    def _record(self, pkt, device, port):
        key = (pkt.src, device, port)
        entry = self.devices.get(key)
        if entry is None:
            entry = self.devices[key] = [pkt.flow, pkt.when, {'count': 0}]
        body = entry[2]
        body['count'] += 1
        body['last_seen'] = pkt.when
        return body

    def finish(self):
        records = []
        for flow, when, body in self.devices.values():
            body['last_seen'] = _iso_utc(body['last_seen'])
            records.append((flow, when, self.event_type, body))
        return records


class LLDP(_Neighbors):
    """LLDP - see the comment above."""
    event_type = 'lldp'
    app_protos = ('lldp',)
    fields = ('lldp.chassis.subtype', 'lldp.chassis.id', 'lldp.chassis.id.mac', 'lldp.chassis.id.ip4',
              'lldp.chassis.id.ip6', 'lldp.port.subtype', 'lldp.port.id', 'lldp.port.id.mac', 'lldp.port.id.ip4',
              'lldp.port.id.ip6', 'lldp.port.desc', 'lldp.tlv.system.name', 'lldp.tlv.system.desc',
              'lldp.tlv.system_cap', 'lldp.tlv.enable_system_cap', 'lldp.time_to_live', 'lldp.mgn.addr.ip4',
              'lldp.mgn.addr.ip6', 'lldp.ieee.802_1.port_vlan.id', 'lldp.ieee.802_1.vlan.name',
              'lldp.media.manufacturer', 'lldp.media.model', 'lldp.media.sn', 'lldp.media.hardware',
              'lldp.media.firmware', 'lldp.media.software', 'lldp.media.asset')
    _INVENTORY = (('manufacturer', 'lldp.media.manufacturer'), ('model', 'lldp.media.model'),
                  ('serial_number', 'lldp.media.sn'), ('hardware_revision', 'lldp.media.hardware'),
                  ('firmware_revision', 'lldp.media.firmware'), ('software_revision', 'lldp.media.software'),
                  ('asset_id', 'lldp.media.asset'))

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        chassis = (first('lldp.chassis.id.mac') or first('lldp.chassis.id.ip4') or first('lldp.chassis.id.ip6')
                   or _lldp_id(first('lldp.chassis.id')))
        port = (first('lldp.port.id') or first('lldp.port.id.mac') or first('lldp.port.id.ip4')
                or first('lldp.port.id.ip6'))
        if not chassis and not port:
            return
        body = self._record(pkt, chassis, port)
        body['chassis_id'], body['port_id'] = chassis, port
        for key, field in (('port_description', 'lldp.port.desc'), ('system_name', 'lldp.tlv.system.name'),
                           ('system_description', 'lldp.tlv.system.desc')) + self._INVENTORY:
            if first(field):
                body[key] = first(field)
        enabled = first('lldp.tlv.enable_system_cap') or first('lldp.tlv.system_cap')
        if enabled:
            body['capabilities'] = _capabilities(enabled, _LLDP_CAPABILITIES)
        addresses = _addresses(v['lldp.mgn.addr.ip4'], v['lldp.mgn.addr.ip6'])
        if addresses:
            body['management_addresses'] = addresses
        vlan = _int(first('lldp.ieee.802_1.port_vlan.id'))
        if vlan:
            body['vlan'] = vlan
        if v['lldp.ieee.802_1.vlan.name']:
            body['vlan_names'] = list(dict.fromkeys(v['lldp.ieee.802_1.vlan.name']))[:_LLDP_MAX_ADDRESSES]
        ttl = _int(first('lldp.time_to_live'))
        if ttl is not None:
            body['ttl'] = ttl
            if ttl == 0:
                body['shutdowns'] = body.get('shutdowns', 0) + 1


class CDP(_Neighbors):
    """CDP - see the comment above."""
    event_type = 'cdp'
    app_protos = ('cdp',)
    fields = ('cdp.version', 'cdp.ttl', 'cdp.deviceid', 'cdp.portid', 'cdp.platform', 'cdp.software_version',
              'cdp.capabilities', 'cdp.nrgyz.ip_address', 'cdp.nrgyz.ipv6_address', 'cdp.native_vlan',
              'cdp.voice_vlan', 'cdp.vtp_management_domain', 'cdp.duplex', 'cdp.system_name', 'cdp.location',
              'cdp.model_number', 'cdp.system_serial_number')

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        device, port = first('cdp.deviceid'), first('cdp.portid')
        if not device and not port:
            return
        body = self._record(pkt, device, port)
        body['device_id'], body['port_id'] = device, port
        if v['cdp.software_version']:
            body['software_version'] = '\n'.join(v['cdp.software_version'])
        for key, field in (('platform', 'cdp.platform'), ('vtp_domain', 'cdp.vtp_management_domain'),
                           ('system_name', 'cdp.system_name'), ('location', 'cdp.location'),
                           ('model', 'cdp.model_number'), ('serial_number', 'cdp.system_serial_number')):
            if first(field):
                body[key] = first(field)
        if first('cdp.capabilities'):
            body['capabilities'] = _capabilities(first('cdp.capabilities'), _CDP_CAPABILITIES)
        addresses = _addresses(v['cdp.nrgyz.ip_address'], v['cdp.nrgyz.ipv6_address'])
        if addresses:
            body['addresses'] = addresses
        for key, field in (('native_vlan', 'cdp.native_vlan'), ('voice_vlan', 'cdp.voice_vlan'),
                           ('version', 'cdp.version'), ('ttl', 'cdp.ttl')):
            number = _int(first(field))
            if number is not None:
                body[key] = number
        if first('cdp.duplex'):
            body['duplex'] = 'full' if first('cdp.duplex') in ('1', 'True') else 'half'


# ---------------------------------------------------------------- PROFINET DCP
#
# PROFINET's Discovery and Configuration Protocol, straight over Ethernet:
# an engineering tool or IO controller finds devices (Identify - all of
# them, or one by its station name), reads their settings (Get), and
# assigns their station name and IP address (Set) - unauthenticated, so
# anyone on the segment can rename a device, readdress it, reset it to
# factory settings, or blink its LED (Signal). Two record types:
# 'pn_dcp', one per action - an Identify query, folded with its repeats,
# or a Set or Get with its result - and 'pn_device', one per device that
# described itself (an Identify or Get response, or a Hello).

_PN_DCP_SERVICES = {3: 'Get', 4: 'Set', 5: 'Identify', 6: 'Hello'}
# Control block suboptions a Set can carry (1 and 2 bracket a
# transaction, 4 is a response)
_PN_DCP_CONTROLS = {3: 'signal', 5: 'reset factory settings', 6: 'reset to factory'}
_PN_DCP_ERRORS = {1: 'option unsupported', 2: 'suboption unsupported', 3: 'suboption not set',
                  4: 'resource error', 5: 'not possible (local reasons)', 6: 'not possible (in operation)'}
_PN_DCP_ROLES = ((0x01, 'IO device'), (0x02, 'IO controller'), (0x04, 'IO multidevice'), (0x08, 'supervisor'))
_PN_DCP_MAX_WAITING = 256


def _pn_role(value):
    bits = _int(value)
    return ', '.join(name for bit, name in _PN_DCP_ROLES if bits & bit) if bits else ''


class PNDCP:
    """PROFINET DCP - see the comment above."""
    event_type = 'pn_dcp'
    app_protos = ('pn_dcp',)
    fields = ('pn_dcp.service_id', 'pn_dcp.service_type', 'pn_dcp.xid', 'pn_dcp.suboption_all',
              'pn_dcp.suboption_device_nameofstation', 'pn_dcp.suboption_device_devicevendorvalue',
              'pn_dcp.suboption_device_aliasname', 'pn_dcp.suboption_vendor_id', 'pn_dcp.suboption_device_id',
              'pn_dcp.suboption_device_role', 'pn_dcp.suboption_ip_ip', 'pn_dcp.suboption_ip_subnetmask',
              'pn_dcp.suboption_ip_standard_gateway', 'pn_dcp.block_qualifier', 'pn_dcp.suboption_control',
              'pn_dcp.suboption_dhcp', 'pn_dcp.block_error')

    def __init__(self):
        self.queries = {}      # (requester MAC, query) -> [flow, first seen, body]
        self.devices = {}      # device MAC -> [flow, first seen, body]
        self.actions = []      # (flow, when, body) of each Set and Get
        self.waiting = {}      # (requester MAC, device MAC or None, xid) -> body

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        service = _PN_DCP_SERVICES.get(_int(first('pn_dcp.service_id')))
        kind = _int(first('pn_dcp.service_type'))
        if service is None or kind is None:
            return
        xid = first('pn_dcp.xid')
        if kind == 0:
            if service == 'Hello':
                self._device(pkt, pkt.src, v)
            elif service == 'Identify':
                self._identify(pkt, v, xid)
            else:
                self._request(pkt, service, v, xid)
        else:
            self._response(pkt, service, kind, v, xid)

    def _identify(self, pkt, v, xid):
        name = (v['pn_dcp.suboption_device_nameofstation'] or [''])[0]
        alias = (v['pn_dcp.suboption_device_aliasname'] or [''])[0]
        query = 'all' if v['pn_dcp.suboption_all'] else name or alias or 'by vendor or role'
        key = (pkt.src, query)
        entry = self.queries.get(key)
        if entry is None:
            entry = self.queries[key] = [pkt.flow, pkt.when, {'service': 'Identify', 'query': query,
                                                              'count': 0, 'responses': 0}]
        entry[2]['count'] += 1
        self._wait((pkt.src, None, xid), entry[2])

    def _request(self, pkt, service, v, xid):
        body = {'service': service, 'result': 'no response'}
        if service == 'Set':
            changes = []
            if v['pn_dcp.suboption_device_nameofstation']:
                changes.append('station name')
                body['station_name'] = v['pn_dcp.suboption_device_nameofstation'][0]
            if v['pn_dcp.suboption_ip_ip']:
                changes.append('IP address')
                for key, field in (('ip', 'pn_dcp.suboption_ip_ip'), ('subnet_mask', 'pn_dcp.suboption_ip_subnetmask'),
                                   ('gateway', 'pn_dcp.suboption_ip_standard_gateway')):
                    if v[field]:
                        body[key] = v[field][0]
            if v['pn_dcp.suboption_dhcp']:
                changes.append('DHCP')
            changes += [_PN_DCP_CONTROLS[c] for c in (_int(x) for x in v['pn_dcp.suboption_control'])
                        if c in _PN_DCP_CONTROLS]
            if changes:
                body['changes'] = list(dict.fromkeys(changes))
            # a name or address set permanently (qualifier 1), or until the
            # device restarts (0)
            qualifier = _int((v['pn_dcp.block_qualifier'] or [''])[0])
            if qualifier is not None and (v['pn_dcp.suboption_device_nameofstation'] or v['pn_dcp.suboption_ip_ip']):
                body['permanent'] = bool(qualifier & 1)
        self.actions.append((pkt.flow, pkt.when, body))
        self._wait((pkt.src, pkt.dst, xid), body)

    def _wait(self, key, body):
        self.waiting[key] = body
        if len(self.waiting) > _PN_DCP_MAX_WAITING:
            self.waiting.pop(next(iter(self.waiting)))

    def _response(self, pkt, service, kind, v, xid):
        if service in ('Identify', 'Get'):
            self._device(pkt, pkt.src, v)
        body = self.waiting.get((pkt.dst, pkt.src, xid)) or self.waiting.get((pkt.dst, None, xid))
        if body is None:
            return
        if service == 'Identify':
            body['responses'] += 1
            return
        errors = [_PN_DCP_ERRORS.get(e, f'error {e}') for e in (_int(x) for x in v['pn_dcp.block_error']) if e]
        body['result'] = ', '.join(dict.fromkeys(errors)) if errors else 'ok' if kind == 1 else 'not supported'

    def _device(self, pkt, mac, v):
        def first(name):
            return (v[name] or [''])[0]
        entry = self.devices.get(mac)
        if entry is None:
            entry = self.devices[mac] = [pkt.flow, pkt.when, {'mac': mac, 'count': 0}]
        body = entry[2]
        body['count'] += 1
        body['last_seen'] = pkt.when
        for key, field in (('station_name', 'pn_dcp.suboption_device_nameofstation'),
                           ('device_type', 'pn_dcp.suboption_device_devicevendorvalue'),
                           ('alias', 'pn_dcp.suboption_device_aliasname'),
                           ('vendor_id', 'pn_dcp.suboption_vendor_id'), ('device_id', 'pn_dcp.suboption_device_id'),
                           ('ip', 'pn_dcp.suboption_ip_ip'), ('subnet_mask', 'pn_dcp.suboption_ip_subnetmask'),
                           ('gateway', 'pn_dcp.suboption_ip_standard_gateway')):
            if first(field):
                body[key] = first(field)
        role = _pn_role(first('pn_dcp.suboption_device_role'))
        if role:
            body['role'] = role

    def finish(self):
        records = [(flow, when, 'pn_dcp', body) for flow, when, body in self.queries.values()]
        records += [(flow, when, 'pn_dcp', body) for flow, when, body in self.actions]
        for flow, when, body in self.devices.values():
            body['last_seen'] = _iso_utc(body['last_seen'])
            records.append((flow, when, 'pn_device', body))
        return records


# ---------------------------------------------------------------- GOOSE
#
# IEC 61850 GOOSE: a protection relay publishes its dataset's values by
# Ethernet multicast - repeated as a heartbeat, and in a burst when one
# changes, stNum counting the changes and sqNum the repeats. Interlocks
# and trips travel this way. One record per state change of each
# publisher's control block: its values (and which changed), how often it
# was repeated, and any gap or reset in stNum.

# goose.Data's types, in the order a message lists its values
_GOOSE_VALUE_FIELDS = {3: 'goose.boolean', 4: 'goose.bit_string', 5: 'goose.integer', 6: 'goose.unsigned',
                       7: 'goose.floating_point', 9: 'goose.octet_string', 10: 'goose.visible_string',
                       17: 'goose.utc_time'}
_GOOSE_MAX_VALUES = 64


class GOOSE:
    """GOOSE - see the comment above."""
    event_type = 'goose'
    app_protos = ('goose',)
    fields = ('goose.appid', 'goose.gocbRef', 'goose.datSet', 'goose.goID', 'goose.stNum', 'goose.sqNum',
              'goose.simulation', 'goose.confRev', 'goose.ndsCom', 'goose.t', 'goose.Data') \
        + tuple(_GOOSE_VALUE_FIELDS.values())

    def __init__(self):
        self.records = []
        self.streams = {}      # (publisher, gocbRef) -> its current state's body

    @staticmethod
    def _values(v):
        """The message's values in order: goose.Data lists each one's type,
        and each type's field its values."""
        pending = {field: list(v[field]) for field in _GOOSE_VALUE_FIELDS.values()}
        values = []
        for kind in v['goose.Data']:
            field = _GOOSE_VALUE_FIELDS.get(_int(kind))
            if field is None:
                continue        # a structure or array: its members follow it
            value = pending[field].pop(0) if pending[field] else ''
            if field == 'goose.boolean':
                value = value in ('1', 'True')
            elif field in ('goose.integer', 'goose.unsigned'):
                value = _int(value, value)
            values.append(value)
        return values

    def feed(self, pkt, v):
        def first(name):
            return (v[name] or [''])[0]
        stnum = _int(first('goose.stNum'))
        if stnum is None:
            return
        key = (pkt.src, first('goose.gocbRef'))
        previous = self.streams.get(key)
        if previous is not None and previous['stnum'] == stnum:
            previous['repeats'] += 1
            return
        values = self._values(v)
        body = {'gocb_ref': first('goose.gocbRef'), 'dataset': first('goose.datSet'), 'go_id': first('goose.goID'),
                'appid': _int(first('goose.appid'), first('goose.appid')), 'stnum': stnum,
                'sqnum': _int(first('goose.sqNum')), 'conf_rev': _int(first('goose.confRev')), 'repeats': 0,
                'values': values[:_GOOSE_MAX_VALUES]}
        if first('goose.t'):
            body['event_time'] = first('goose.t')
        if first('goose.simulation') in ('1', 'True'):
            body['simulation'] = True
        if first('goose.ndsCom') in ('1', 'True'):
            body['needs_commissioning'] = True
        if previous is not None:
            changed = [i for i, (a, b) in enumerate(zip(previous['values'], body['values'])) if a != b]
            if changed:
                body['changed'] = changed
            if stnum < previous['stnum']:
                body['stnum_reset_from'] = previous['stnum']
                body['anomaly'] = f"stNum reset from {previous['stnum']}"
            elif stnum > previous['stnum'] + 1:
                body['stnum_gap'] = stnum - previous['stnum'] - 1
                body['anomaly'] = f"stNum skipped {body['stnum_gap']}"
        self.streams[key] = body
        self.records.append((pkt.flow, pkt.when, 'goose', body))

    def finish(self):
        return list(self.records)


# ---------------------------------------------------------------- OPC UA
#
# OPC UA binary (opc.tcp, port 4840), industrial automation's
# client/server protocol: a client opens a secure channel, creates and
# activates a session as some user, then reads, browses, subscribes,
# writes and calls methods on the server's nodes. Its messages nest
# deeply (even a request header carries node ids), so it's read from the
# structured pass's JSON trees. Two record types: 'opcua', one per
# connection - its endpoint, security policy and mode, the client
# application and session, the user (and the password, when the token
# isn't encrypted - with security policy None it often isn't), whether
# activation worked, and how many of each service it called; and
# 'opcua_action', one per change - a node written (with the value), a
# method called (with its arguments), a node or reference added or
# deleted - with that operation's own status. With SignAndEncrypt the
# messages after the channel opens can't be read, which the session
# record counts (encrypted_messages). tshark recognizes OPC UA on port
# 4840; on another port it's a plain TCP connection.

_OPCUA_STATUS = {
    0x0000: 'Good', 0x002d: 'GoodSubscriptionTransferred', 0x002e: 'GoodCompletesAsynchronously',
    0x002f: 'GoodOverload', 0x0030: 'GoodClamped', 0x0096: 'GoodLocalOverride', 0x00a2: 'GoodEntryInserted',
    0x00a3: 'GoodEntryReplaced', 0x00a5: 'GoodNoData', 0x00a6: 'GoodMoreData', 0x00a7: 'GoodCommunicationEvent',
    0x00a8: 'GoodShutdownEvent', 0x00a9: 'GoodCallAgain', 0x00aa: 'GoodNonCriticalTimeout',
    0x00ba: 'GoodResultsMayBeIncomplete', 0x00d9: 'GoodDataIgnored', 0x00dc: 'GoodEdited',
    0x00dd: 'GoodPostActionFailed', 0x00e0: 'GoodDependentValueChanged', 0x4000: 'Uncertain',
    0x406c: 'UncertainReferenceOutOfServer', 0x408f: 'UncertainNoCommunicationLastUsableValue',
    0x4090: 'UncertainLastUsableValue', 0x4091: 'UncertainSubstituteValue', 0x4092: 'UncertainInitialValue',
    0x4093: 'UncertainSensorNotAccurate', 0x4094: 'UncertainEngineeringUnitsExceeded', 0x4095: 'UncertainSubNormal',
    0x40a4: 'UncertainDataSubNormal', 0x40bc: 'UncertainReferenceNotDeleted',
    0x40c0: 'UncertainNotAllNodesAvailable', 0x40de: 'UncertainDominantValueChanged',
    0x40e2: 'UncertainDependentValueChanged', 0x8000: 'Bad', 0x8001: 'BadUnexpectedError',
    0x8002: 'BadInternalError', 0x8003: 'BadOutOfMemory', 0x8004: 'BadResourceUnavailable',
    0x8005: 'BadCommunicationError', 0x8006: 'BadEncodingError', 0x8007: 'BadDecodingError',
    0x8008: 'BadEncodingLimitsExceeded', 0x8009: 'BadUnknownResponse', 0x800a: 'BadTimeout',
    0x800b: 'BadServiceUnsupported', 0x800c: 'BadShutdown', 0x800d: 'BadServerNotConnected',
    0x800e: 'BadServerHalted', 0x800f: 'BadNothingToDo', 0x8010: 'BadTooManyOperations',
    0x8011: 'BadDataTypeIdUnknown', 0x8012: 'BadCertificateInvalid', 0x8013: 'BadSecurityChecksFailed',
    0x8014: 'BadCertificateTimeInvalid', 0x8015: 'BadCertificateIssuerTimeInvalid',
    0x8016: 'BadCertificateHostNameInvalid', 0x8017: 'BadCertificateUriInvalid',
    0x8018: 'BadCertificateUseNotAllowed', 0x8019: 'BadCertificateIssuerUseNotAllowed',
    0x801a: 'BadCertificateUntrusted', 0x801b: 'BadCertificateRevocationUnknown',
    0x801c: 'BadCertificateIssuerRevocationUnknown', 0x801d: 'BadCertificateRevoked',
    0x801e: 'BadCertificateIssuerRevoked', 0x801f: 'BadUserAccessDenied', 0x8020: 'BadIdentityTokenInvalid',
    0x8021: 'BadIdentityTokenRejected', 0x8022: 'BadSecureChannelIdInvalid', 0x8023: 'BadInvalidTimestamp',
    0x8024: 'BadNonceInvalid', 0x8025: 'BadSessionIdInvalid', 0x8026: 'BadSessionClosed',
    0x8027: 'BadSessionNotActivated', 0x8028: 'BadSubscriptionIdInvalid', 0x802a: 'BadRequestHeaderInvalid',
    0x802b: 'BadTimestampsToReturnInvalid', 0x802c: 'BadRequestCancelledByClient', 0x8031: 'BadNoCommunication',
    0x8032: 'BadWaitingForInitialData', 0x8033: 'BadNodeIdInvalid', 0x8034: 'BadNodeIdUnknown',
    0x8035: 'BadAttributeIdInvalid', 0x8036: 'BadIndexRangeInvalid', 0x8037: 'BadIndexRangeNoData',
    0x8038: 'BadDataEncodingInvalid', 0x8039: 'BadDataEncodingUnsupported', 0x803a: 'BadNotReadable',
    0x803b: 'BadNotWritable', 0x803c: 'BadOutOfRange', 0x803d: 'BadNotSupported', 0x803e: 'BadNotFound',
    0x803f: 'BadObjectDeleted', 0x8040: 'BadNotImplemented', 0x8041: 'BadMonitoringModeInvalid',
    0x8042: 'BadMonitoredItemIdInvalid', 0x8043: 'BadMonitoredItemFilterInvalid',
    0x8044: 'BadMonitoredItemFilterUnsupported', 0x8045: 'BadFilterNotAllowed', 0x8046: 'BadStructureMissing',
    0x8047: 'BadEventFilterInvalid', 0x8048: 'BadContentFilterInvalid', 0x8049: 'BadFilterOperandInvalid',
    0x804a: 'BadContinuationPointInvalid', 0x804b: 'BadNoContinuationPoints', 0x804c: 'BadReferenceTypeIdInvalid',
    0x804d: 'BadBrowseDirectionInvalid', 0x804e: 'BadNodeNotInView', 0x804f: 'BadServerUriInvalid',
    0x8050: 'BadServerNameMissing', 0x8051: 'BadDiscoveryUrlMissing', 0x8052: 'BadSemaphoreFileMissing',
    0x8053: 'BadRequestTypeInvalid', 0x8054: 'BadSecurityModeRejected', 0x8055: 'BadSecurityPolicyRejected',
    0x8056: 'BadTooManySessions', 0x8057: 'BadUserSignatureInvalid', 0x8058: 'BadApplicationSignatureInvalid',
    0x8059: 'BadNoValidCertificates', 0x805a: 'BadRequestCancelledByRequest', 0x805b: 'BadParentNodeIdInvalid',
    0x805c: 'BadReferenceNotAllowed', 0x805d: 'BadNodeIdRejected', 0x805e: 'BadNodeIdExists',
    0x805f: 'BadNodeClassInvalid', 0x8060: 'BadBrowseNameInvalid', 0x8061: 'BadBrowseNameDuplicated',
    0x8062: 'BadNodeAttributesInvalid', 0x8063: 'BadTypeDefinitionInvalid', 0x8064: 'BadSourceNodeIdInvalid',
    0x8065: 'BadTargetNodeIdInvalid', 0x8066: 'BadDuplicateReferenceNotAllowed', 0x8067: 'BadInvalidSelfReference',
    0x8068: 'BadReferenceLocalOnly', 0x8069: 'BadNoDeleteRights', 0x806a: 'BadServerIndexInvalid',
    0x806b: 'BadViewIdUnknown', 0x806d: 'BadTooManyMatches', 0x806e: 'BadQueryTooComplex', 0x806f: 'BadNoMatch',
    0x8070: 'BadMaxAgeInvalid', 0x8071: 'BadHistoryOperationInvalid', 0x8072: 'BadHistoryOperationUnsupported',
    0x8073: 'BadWriteNotSupported', 0x8074: 'BadTypeMismatch', 0x8075: 'BadMethodInvalid',
    0x8076: 'BadArgumentsMissing', 0x8077: 'BadTooManySubscriptions', 0x8078: 'BadTooManyPublishRequests',
    0x8079: 'BadNoSubscription', 0x807a: 'BadSequenceNumberUnknown', 0x807b: 'BadMessageNotAvailable',
    0x807c: 'BadInsufficientClientProfile', 0x807d: 'BadTcpServerTooBusy', 0x807e: 'BadTcpMessageTypeInvalid',
    0x807f: 'BadTcpSecureChannelUnknown', 0x8080: 'BadTcpMessageTooLarge', 0x8081: 'BadTcpNotEnoughResources',
    0x8082: 'BadTcpInternalError', 0x8083: 'BadTcpEndpointUrlInvalid', 0x8084: 'BadRequestInterrupted',
    0x8085: 'BadRequestTimeout', 0x8086: 'BadSecureChannelClosed', 0x8087: 'BadSecureChannelTokenUnknown',
    0x8088: 'BadSequenceNumberInvalid', 0x8089: 'BadConfigurationError', 0x808a: 'BadNotConnected',
    0x808b: 'BadDeviceFailure', 0x808c: 'BadSensorFailure', 0x808d: 'BadOutOfService',
    0x808e: 'BadDeadbandFilterInvalid', 0x8097: 'BadRefreshInProgress', 0x8098: 'BadConditionAlreadyDisabled',
    0x8099: 'BadConditionDisabled', 0x809a: 'BadEventIdUnknown', 0x809b: 'BadNoData', 0x809d: 'BadDataLost',
    0x809e: 'BadDataUnavailable', 0x809f: 'BadEntryExists', 0x80a0: 'BadNoEntryExists',
    0x80a1: 'BadTimestampNotSupported', 0x80ab: 'BadInvalidArgument', 0x80ac: 'BadConnectionRejected',
    0x80ad: 'BadDisconnect', 0x80ae: 'BadConnectionClosed', 0x80af: 'BadInvalidState', 0x80b0: 'BadEndOfStream',
    0x80b1: 'BadNoDataAvailable', 0x80b2: 'BadWaitingForResponse', 0x80b3: 'BadOperationAbandoned',
    0x80b4: 'BadExpectedStreamToBlock', 0x80b5: 'BadWouldBlock', 0x80b6: 'BadSyntaxError',
    0x80b7: 'BadMaxConnectionsReached', 0x80b8: 'BadRequestTooLarge', 0x80b9: 'BadResponseTooLarge',
    0x80bb: 'BadEventNotAcknowledgeable', 0x80bd: 'BadInvalidTimestampArgument',
    0x80be: 'BadProtocolVersionUnsupported', 0x80bf: 'BadStateNotActive', 0x80c1: 'BadFilterOperatorInvalid',
    0x80c2: 'BadFilterOperatorUnsupported', 0x80c3: 'BadFilterOperandCountMismatch',
    0x80c4: 'BadFilterElementInvalid', 0x80c5: 'BadFilterLiteralInvalid', 0x80c6: 'BadIdentityChangeNotSupported',
    0x80c8: 'BadNotTypeDefinition', 0x80c9: 'BadViewTimestampInvalid', 0x80ca: 'BadViewParameterMismatch',
    0x80cb: 'BadViewVersionInvalid', 0x80cc: 'BadConditionAlreadyEnabled', 0x80cd: 'BadDialogNotActive',
    0x80ce: 'BadDialogResponseInvalid', 0x80cf: 'BadConditionBranchAlreadyAcked',
    0x80d0: 'BadConditionBranchAlreadyConfirmed', 0x80d1: 'BadConditionAlreadyShelved',
    0x80d2: 'BadConditionNotShelved', 0x80d3: 'BadShelvingTimeOutOfRange', 0x80d4: 'BadAggregateListMismatch',
    0x80d5: 'BadAggregateNotSupported', 0x80d6: 'BadAggregateInvalidInputs', 0x80d7: 'BadBoundNotFound',
    0x80d8: 'BadBoundNotSupported', 0x80da: 'BadAggregateConfigurationRejected', 0x80db: 'BadTooManyMonitoredItems',
    0x80e1: 'BadDominantValueChanged', 0x80e3: 'BadDependentValueChanged', 0x80e4: 'BadRequestNotAllowed',
    0x80e5: 'BadTooManyArguments', 0x80e6: 'BadSecurityModeInsufficient'}
_OPCUA_SECURITY_MODES = {1: 'None', 2: 'Sign', 3: 'SignAndEncrypt'}
_OPCUA_TOKENS = {321: 'anonymous', 324: 'username', 327: 'certificate', 940: 'issued'}
_OPCUA_ATTRIBUTES = {
    1: 'NodeId', 2: 'NodeClass', 3: 'BrowseName', 4: 'DisplayName', 5: 'Description', 6: 'WriteMask',
    7: 'UserWriteMask', 8: 'IsAbstract', 9: 'Symmetric', 10: 'InverseName', 11: 'ContainsNoLoops',
    12: 'EventNotifier', 13: 'Value', 14: 'DataType', 15: 'ValueRank', 16: 'ArrayDimensions', 17: 'AccessLevel',
    18: 'UserAccessLevel', 19: 'MinimumSamplingInterval', 20: 'Historizing', 21: 'Executable',
    22: 'UserExecutable', 23: 'DataTypeDefinition', 24: 'RolePermissions', 25: 'UserRolePermissions',
    26: 'AccessRestrictions', 27: 'AccessLevelEx'}
# Requests that change the server, and the list each one's operations are in
_OPCUA_CHANGES = {'WriteRequest': 'NodesToWrite', 'CallRequest': 'MethodsToCall', 'AddNodesRequest': 'NodesToAdd',
                  'DeleteNodesRequest': 'NodesToDelete', 'AddReferencesRequest': 'ReferencesToAdd',
                  'DeleteReferencesRequest': 'ReferencesToDelete'}
_OPCUA_MAX_ACTIONS_PER_REQUEST = 100


def _opcua_hex(text):
    """An enumeration or status code tshark writes as hex ('0x0000000d')."""
    try:
        return int(text, 16) if str(text).startswith('0x') else int(text)
    except (TypeError, ValueError):
        return None


def _opcua_status(text):
    """A status code's name (tshark's), or its hex."""
    code = _opcua_hex(text)
    if code is None:
        return str(text)
    if code & 0xffff == 0 and (code >> 16) in _OPCUA_STATUS:
        return _OPCUA_STATUS[code >> 16]
    return f'0x{code:08x}'


def _dict(value):
    """A subtree that should be an object, or {} - a node tshark wrote as
    something else reads as empty instead of failing the run."""
    return value if isinstance(value, dict) else {}


def _child(tree, name):
    """A JSON subtree's child by its label's name - tshark keys a
    structure 'Name: Type'."""
    if not isinstance(tree, dict):
        return None
    for key, value in tree.items():
        if key == name or key.split(':', 1)[0] == name:
            return value
    return None


def _items(array):
    """An 'Array of X' subtree's elements, in order."""
    if not isinstance(array, dict):
        return []
    return [value for key, value in array.items() if key.startswith('[') and isinstance(value, dict)]


def _opcua_node(tree):
    """A NodeId subtree as OPC UA writes one: 'ns=1;s=the.answer', 'i=85'."""
    if not isinstance(tree, dict):
        return ''
    ns = tree.get('opcua.nodeid.nsindex') or tree.get('opcua.nodeid.nsid') or '0'
    for field, kind in (('numeric', 'i'), ('string', 's'), ('guid', 'g'), ('bytestring', 'b')):
        value = tree.get(f'opcua.nodeid.{field}')
        if value is not None:
            return (f'ns={ns};' if ns != '0' else '') + f'{kind}={value}'
    return ''


# Methods whose arguments can carry a password - OPC UA Part 18's user
# management (AddUser, ModifyUser, RemoveUser, ChangePassword: namespace
# 0's block of ids from 24264), or a vendor's method or object whose name
# says so. Their calls are recorded, but not their arguments' values.
_OPCUA_USER_MANAGEMENT_IDS = range(24264, 24331)
_OPCUA_SECRET_NAMES = re.compile(r'pass(word|wd|phrase)|credential|secret|user', re.I)


def _opcua_secret_method(*nodes):
    for node in nodes:
        if node.startswith('i='):
            number = _int(node[2:])
            if number is not None and number in _OPCUA_USER_MANAGEMENT_IDS:
                return True
        elif _OPCUA_SECRET_NAMES.search(node):
            return True
    return False


def _opcua_variant(tree):
    """A Variant subtree's value: a scalar, or the first few of an array."""
    if not isinstance(tree, dict):
        return None
    values = [v for k, v in _flatten(tree).items() if k.startswith('opcua.') and not k.startswith('opcua.variant.')
              and k not in ('opcua.ArraySize',)]
    flat = [x for v in values for x in v]
    if not flat:
        return None
    if len(flat) == 1:
        return flat[0]
    return ', '.join(str(x) for x in flat[:10]) + (' ...' if len(flat) > 10 else '')


def _opcua_password(token):
    """A UserName token's password, if it was sent in the clear."""
    password = token.get('opcua.Password')
    if password is None or token.get('opcua.EncryptionAlgorithm'):
        return None
    try:
        return bytes.fromhex(password.replace(':', '')).decode('utf-8', 'replace')
    except ValueError:
        return None


class _OPCUASession:
    __slots__ = ('flow', 'first', 'body', 'waiting')

    def __init__(self, flow, first):
        self.flow, self.first = flow, first
        self.body = {'services': {}, 'errors': 0}
        self.waiting = {}      # request id -> (service, [action bodies])


class OPCUA:
    """OPC UA - see the comment above."""
    event_type = 'opcua'
    app_protos = ('opcua',)
    tshark_protocols = ('opcua',)
    layers = ('opcua',)
    display_filter = 'opcua'

    def __init__(self):
        self.sessions = {}     # flow key -> _OPCUASession
        self.actions = []

    def feed_json(self, pkt, layers):
        session = self.sessions.get(pkt.flow.key)
        if session is None:
            session = self.sessions[pkt.flow.key] = _OPCUASession(pkt.flow, pkt.when)
        for pdu in _pdus(layers.get('opcua')):
            if isinstance(pdu, dict):
                self._message(pkt, session, pdu)

    def _message(self, pkt, session, pdu):
        body = session.body
        kind = pdu.get('opcua.transport.type')
        if kind == 'HEL' and pdu.get('opcua.transport.endpoint'):
            body.setdefault('endpoint', pdu['opcua.transport.endpoint'])
        elif kind == 'ERR':
            body['transport_error'] = _opcua_status(pdu.get('opcua.transport.error', ''))
        elif kind == 'OPN' and pdu.get('opcua.security.spu'):
            body.setdefault('security_policy', pdu['opcua.security.spu'].rsplit('#', 1)[-1])
        message = _child(pdu, 'Message')
        if not isinstance(message, dict):
            # A channel's security policy is in the clear; with one other
            # than None its mode may be SignAndEncrypt (which an encrypted
            # OPN hides), and a final chunk that doesn't decode is encrypted
            if kind == 'MSG' and pdu.get('opcua.transport.chunk') == 'F' and body.get('security_policy') not in (None, 'None'):
                body['encrypted_messages'] = body.get('encrypted_messages', 0) + 1
            return
        name = next((k.split(':', 1)[0] for k in message if not k.startswith('TypeId')), None)
        tree = message.get(name) if name in message else _child(message, name) if name else None
        if not name or not isinstance(tree, dict):
            return
        request_id = pdu.get('opcua.sequence.rqid')
        if name.endswith('Request'):
            self._request(pkt, session, name, tree, request_id)
        elif name.endswith('Response') or name == 'ServiceFault':
            self._response(session, name, tree, request_id)

    def _request(self, pkt, session, name, tree, request_id):
        body = session.body
        service = name[:-len('Request')]
        body['services'][service] = body['services'].get(service, 0) + 1
        if name == 'OpenSecureChannelRequest':
            mode = _opcua_hex(tree.get('opcua.MessageSecurityMode'))
            if mode in _OPCUA_SECURITY_MODES:
                body['security_mode'] = _OPCUA_SECURITY_MODES[mode]
        elif name == 'CreateSessionRequest':
            client = _dict(_child(tree, 'ClientDescription'))
            app_name = _dict(_child(client, 'ApplicationName')).get('opcua.loctext.Text')
            for key, value in (('client_application', app_name), ('client_uri', client.get('opcua.ApplicationUri')),
                               ('client_product', client.get('opcua.ProductUri')),
                               ('session_name', tree.get('opcua.SessionName')),
                               ('endpoint', tree.get('opcua.EndpointUrl'))):
                if value:
                    body[key] = value if key != 'endpoint' else body.get('endpoint', value)
        elif name == 'ActivateSessionRequest':
            token_tree = _dict(_child(tree, 'UserIdentityToken'))
            type_id = _int(_dict(_child(token_tree, 'TypeId')).get('opcua.nodeid.numeric'), None)
            token = next((v for k, v in token_tree.items() if k.endswith('IdentityToken') or 'IdentityToken:' in k), {})
            if type_id in _OPCUA_TOKENS:
                body['user_token'] = _OPCUA_TOKENS[type_id]
            if isinstance(token, dict):
                if token.get('opcua.PolicyId'):
                    body['user_policy'] = token['opcua.PolicyId']
                if token.get('opcua.UserName'):
                    body['username'] = token['opcua.UserName']
                password = _opcua_password(token)
                if password is not None:
                    body['password'] = password
                elif token.get('opcua.Password'):
                    body['password_encrypted'] = True
        actions = self._changes(pkt, name, tree) if name in _OPCUA_CHANGES else []
        if request_id is not None:
            session.waiting[request_id] = (service, actions)
            if len(session.waiting) > 256:
                session.waiting.pop(next(iter(session.waiting)))

    def _changes(self, pkt, name, tree):
        actions = []
        for item in _items(_child(tree, _OPCUA_CHANGES[name]))[:_OPCUA_MAX_ACTIONS_PER_REQUEST]:
            action = {'service': name[:-len('Request')]}
            if name == 'WriteRequest':
                action['node'] = _opcua_node(_child(item, 'NodeId'))
                attribute = _opcua_hex(item.get('opcua.AttributeId'))
                if attribute is not None:
                    action['attribute'] = _OPCUA_ATTRIBUTES.get(attribute, str(attribute))
                value = _opcua_variant(_child(_child(item, 'Value') or {}, 'Value'))
                if value is not None:
                    action['value'] = value
            elif name == 'CallRequest':
                action['node'] = _opcua_node(_child(item, 'MethodId'))
                action['object'] = _opcua_node(_child(item, 'ObjectId'))
                arguments = [_opcua_variant(arg) for arg in _items(_child(item, 'InputArguments'))]
                if arguments and _opcua_secret_method(action['node'], action['object']):
                    action['arguments_redacted'] = len(arguments)
                elif arguments:
                    action['arguments'] = [a for a in arguments[:10] if a is not None]
            elif name == 'AddNodesRequest':
                action['node'] = _opcua_node(_child(item, 'RequestedNewNodeId'))
                action['parent'] = _opcua_node(_child(item, 'ParentNodeId'))
                browse = _child(item, 'BrowseName') or {}
                if isinstance(browse, dict) and browse.get('opcua.qualname.Name'):
                    action['browse_name'] = browse['opcua.qualname.Name']
            elif name == 'DeleteNodesRequest':
                action['node'] = _opcua_node(_child(item, 'NodeId'))
            else:
                action['node'] = _opcua_node(_child(item, 'SourceNodeId'))
                target = _child(item, 'TargetNodeId')
                if isinstance(target, dict):
                    action['target'] = _opcua_node(target)
            action['result'] = 'no response'
            self.actions.append((pkt.flow, pkt.when, 'opcua_action', action))
            actions.append(action)
        return actions

    def _response(self, session, name, tree, request_id):
        body = session.body
        header = _child(tree, 'ResponseHeader') or {}
        result = _opcua_status(header.get('opcua.ServiceResult', '0x00000000')) if isinstance(header, dict) else 'Good'
        waiting = session.waiting.pop(request_id, None) if request_id is not None else None
        service, actions = waiting if waiting else (name[:-len('Response')], [])
        if name == 'ServiceFault' or not result.startswith('Good'):
            body['errors'] += 1
            body['last_error'] = f'{service}: {result}'
        if service == 'ActivateSession':
            body['activation'] = result
        if not actions:
            return
        results = _child(tree, 'Results')
        statuses = []
        if isinstance(results, dict):
            listed = results.get('opcua.Results')
            if listed is not None:
                statuses = listed if isinstance(listed, list) else [listed]
            else:
                statuses = [item.get('opcua.StatusCode') for item in _items(results)]
        for i, action in enumerate(actions):
            if not result.startswith('Good'):
                action['result'] = result
            elif i < len(statuses) and statuses[i] is not None:
                action['result'] = _opcua_status(statuses[i])
            else:
                action['result'] = result

    def finish(self):
        records = []
        for session in self.sessions.values():
            # a lone response, its request before the capture, says nothing
            if session.body['services'] or len(session.body) > 2:
                records.append((session.flow, session.first, 'opcua', session.body))
        return records + self.actions


# ---------------------------------------------------------------- MMS
#
# MMS (ISO 9506), the client/server protocol IEC 61850 substations use
# between SCADA and protective relays and bay controllers, over the OSI
# session and presentation layers on TCP port 102. Its messages are
# nested ASN.1, so it's read from the structured pass's JSON trees.

# ConfirmedServiceRequest/Response's choice numbers
_MMS_SERVICES = (
    'status', 'getNameList', 'identify', 'rename', 'read', 'write', 'getVariableAccessAttributes',
    'defineNamedVariable', 'defineScatteredAccess', 'getScatteredAccessAttributes', 'deleteVariableAccess',
    'defineNamedVariableList', 'getNamedVariableListAttributes', 'deleteNamedVariableList', 'defineNamedType',
    'getNamedTypeAttributes', 'deleteNamedType', 'input', 'output', 'takeControl', 'relinquishControl',
    'defineSemaphore', 'deleteSemaphore', 'reportSemaphoreStatus', 'reportPoolSemaphoreStatus',
    'reportSemaphoreEntryStatus', 'initiateDownloadSequence', 'downloadSegment', 'terminateDownloadSequence',
    'initiateUploadSequence', 'uploadSegment', 'terminateUploadSequence', 'requestDomainDownload',
    'requestDomainUpload', 'loadDomainContent', 'storeDomainContent', 'deleteDomain', 'getDomainAttributes',
    'createProgramInvocation', 'deleteProgramInvocation', 'start', 'stop', 'resume', 'reset', 'kill',
    'getProgramInvocationAttributes', 'obtainFile', 'defineEventCondition', 'deleteEventCondition',
    'getEventConditionAttributes', 'reportEventConditionStatus', 'alterEventConditionMonitoring', 'triggerEvent',
    'defineEventAction', 'deleteEventAction', 'getEventActionAttributes', 'reportEventActionStatus',
    'defineEventEnrollment', 'deleteEventEnrollment', 'alterEventEnrollment', 'reportEventEnrollmentStatus',
    'getEventEnrollmentAttributes', 'acknowledgeEventNotification', 'getAlarmSummary',
    'getAlarmEnrollmentSummary', 'readJournal', 'writeJournal', 'initializeJournal', 'reportJournalStatus',
    'createJournal', 'deleteJournal', 'getCapabilityList', 'fileOpen', 'fileRead', 'fileClose', 'fileRename',
    'fileDelete', 'fileDirectory')
_MMS_UNCONFIRMED = ('informationReport', 'unsolicitedStatus', 'eventNotification')
# Services that change the server - everything else reads or browses
_MMS_CHANGES = frozenset((
    'rename', 'write', 'defineNamedVariable', 'defineScatteredAccess', 'deleteVariableAccess',
    'defineNamedVariableList', 'deleteNamedVariableList', 'defineNamedType', 'deleteNamedType', 'output',
    'takeControl', 'relinquishControl', 'defineSemaphore', 'deleteSemaphore', 'initiateDownloadSequence',
    'terminateDownloadSequence', 'requestDomainDownload', 'loadDomainContent', 'deleteDomain',
    'createProgramInvocation', 'deleteProgramInvocation', 'start', 'stop', 'resume', 'reset', 'kill',
    'obtainFile', 'defineEventCondition', 'deleteEventCondition', 'alterEventConditionMonitoring',
    'triggerEvent', 'defineEventAction', 'deleteEventAction', 'defineEventEnrollment', 'deleteEventEnrollment',
    'alterEventEnrollment', 'acknowledgeEventNotification', 'writeJournal', 'initializeJournal',
    'createJournal', 'deleteJournal', 'fileRename', 'fileDelete'))
# ServiceError's errorClass choice numbers
_MMS_ERROR_CLASSES = ('vmd-state', 'application-reference', 'definition', 'resource', 'service', 'service-preempt',
                      'time-resolution', 'access', 'initiate', 'conclude', 'cancel', 'file', 'others')
# DataAccessError values, a read's or write's per-item failure
_MMS_ACCESS_ERRORS = ('object-invalidated', 'hardware-fault', 'temporarily-unavailable', 'object-access-denied',
                      'object-undefined', 'invalid-address', 'type-unsupported', 'type-inconsistent',
                      'object-attribute-inconsistent', 'object-access-unsupported', 'object-non-existent',
                      'object-value-invalid')


def _mms_name(table, value):
    """A choice number's name from one of the tables above, or the number."""
    number = _int(value)
    return table[number] if number is not None and 0 <= number < len(table) else str(value)


def _mms_find(tree, key):
    """Every value of a key anywhere under a subtree, in order."""
    found = []
    if isinstance(tree, dict):
        for name, value in tree.items():
            if name == key:
                found.extend(value if isinstance(value, list) else [value])
            else:
                found.extend(_mms_find(value, key))
    elif isinstance(tree, list):
        for item in tree:
            found.extend(_mms_find(item, key))
    return found


def _mms_object_names(tree):
    """The object names under a subtree, as MMS writes them: 'domain/item'
    for a domain-specific name (an IEC 61850 logical device's
    'IED1LD0/XCBR1$CO$Pos'), the bare name for a VMD-specific one."""
    names = []
    if isinstance(tree, dict):
        for name, value in tree.items():
            if name == 'mms.domain_specific_element':
                for element in value if isinstance(value, list) else [value]:
                    if isinstance(element, dict) and element.get('mms.itemId') is not None:
                        domain = element.get('mms.domainId')
                        names.append(f'{domain}/{element["mms.itemId"]}' if domain else element['mms.itemId'])
            elif name in ('mms.vmd_specific', 'mms.aa_specific'):
                names.extend(v for v in (value if isinstance(value, list) else [value]) if isinstance(v, str))
            else:
                names.extend(_mms_object_names(value))
    elif isinstance(tree, list):
        for item in tree:
            names.extend(_mms_object_names(item))
    return names


_MMS_MAX_VALUES = 10
# tshark names a value by its IEC 61850 meaning where it can guess one
# ('mms.iec61850.ctlval') - but these are a timestamp's quality flags,
# not values of their own
_MMS_TIME_QUALITY = frozenset(('mms.iec61850.timeaccuracy', 'mms.iec61850.leapsecondknown',
                               'mms.iec61850.clocknotsynchronized', 'mms.iec61850.clockfailure'))


def _mms_data(tree):
    """A Data subtree's values, flattened in order ('1, 0, 2024-...'),
    the first few of a structure or array - or None for none."""
    values = [str(v) for k, v in _flatten(tree).items() for v in v
              if k.startswith(('mms.data', 'mms.integer', 'mms.unsigned', 'mms.boolean', 'mms.floating',
                               'mms.utc_time', 'mms.binary-time', 'mms.visible', 'mms.octet', 'mms.mMSString',
                               'mms.bcd', 'mms.generalized', 'mms.iec61850.'))
              and k not in _MMS_TIME_QUALITY]
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    return ', '.join(values[:_MMS_MAX_VALUES]) + (' ...' if len(values) > _MMS_MAX_VALUES else '')


def _mms_error(tree):
    """A ServiceError subtree's class and code ('access: 2'), or None."""
    error = _child(tree, 'mms.serviceError_element') if isinstance(tree, dict) else None
    if not isinstance(error, dict):
        return None
    kind = _mms_name(_MMS_ERROR_CLASSES, error.get('mms.errorClass'))
    codes = [v for v in _dict(error.get('mms.errorClass_tree')).values() if isinstance(v, str)]
    return f'{kind}: {codes[0]}' if codes else kind


_MMS_MAX_DOMAINS = 20
_MMS_MAX_ACTIONS_PER_REQUEST = 100
# IEC 61850 control model: a write to a controllable object's Oper, SBO/SBOw
# or Cancel attribute ('LD0/XCBR1$CO$Pos$Oper') is a control command
_MMS_CONTROLS = {'Oper': 'operate', 'SBO': 'select', 'SBOw': 'select', 'Cancel': 'cancel'}
_MMS_IDENTIFIERS = ('mms.programInvocationName', 'mms.deleteProgramInvocation', 'mms.domainName', 'mms.deleteDomain',
                    'mms.FileName_item', 'mms.fileName_item')


class _MMSAssociation:
    __slots__ = ('flow', 'first', 'body', 'domains', 'waiting')

    def __init__(self, flow, first):
        self.flow, self.first = flow, first
        self.body = {'services': {}, 'errors': 0}
        self.domains = {}      # logical device -> None, in first-seen order
        self.waiting = {}      # invoke id -> (service, [action bodies])


class MMS:
    """MMS - see the comment above. One 'mms' record per connection: whether
    it was initiated, how many of each service the client called, the
    logical devices (domains) it touched, the server's vendor, model and
    revision if Identify asked, the reports the server sent, and errors."""
    event_type = 'mms'
    app_protos = ('mms',)
    tshark_protocols = ('tpkt', 'cotp', 'ses', 'pres', 'acse', 'mms')
    layers = ('mms',)
    display_filter = 'mms'

    def __init__(self):
        self.associations = {}     # flow key -> _MMSAssociation
        self.actions = []

    def feed_json(self, pkt, layers):
        association = self.associations.get(pkt.flow.key)
        if association is None:
            association = self.associations[pkt.flow.key] = _MMSAssociation(pkt.flow, pkt.when)
        for pdu in _pdus(layers.get('mms')):
            if isinstance(pdu, dict):
                for kind, tree in pdu.items():
                    self._pdu(pkt, association, kind, tree)

    def _pdu(self, pkt, association, kind, tree):
        body = association.body
        if kind == 'mms.initiate_RequestPDU_element':
            body.setdefault('initiate', 'no response')
        elif kind == 'mms.initiate_ResponsePDU_element':
            body['initiate'] = 'accepted'
        elif kind == 'mms.initiate_ErrorPDU_element':
            body['initiate'] = _mms_error({'mms.serviceError_element': tree}) or 'rejected'
            body['errors'] += 1
        elif kind == 'mms.conclude_RequestPDU_element':
            body['concluded'] = True
        elif kind == 'mms.confirmed_RequestPDU_element' and isinstance(tree, dict):
            self._request(pkt, association, tree)
        elif kind == 'mms.confirmed_ResponsePDU_element' and isinstance(tree, dict):
            self._response(association, tree)
        elif kind == 'mms.confirmed_ErrorPDU_element' and isinstance(tree, dict):
            self._failed(association, tree.get('mms.invokeID'), _mms_error(tree) or 'error')
        elif kind == 'mms.unconfirmed_PDU_element' and isinstance(tree, dict):
            service = _mms_name(_MMS_UNCONFIRMED, tree.get('mms.unconfirmedService'))
            reports = body.setdefault('reports', {})
            reports[service] = reports.get(service, 0) + 1
        elif kind in ('mms.rejectPDU_element', 'mms.reject_PDU_element'):
            body['errors'] += 1
            body['last_error'] = 'reject'

    def _domains(self, association, tree):
        for name in _mms_object_names(tree):
            if '/' in name and len(association.domains) < _MMS_MAX_DOMAINS:
                association.domains.setdefault(name.split('/', 1)[0], None)

    def _request(self, pkt, association, tree):
        body = association.body
        service = _mms_name(_MMS_SERVICES, tree.get('mms.confirmedServiceRequest'))
        body['services'][service] = body['services'].get(service, 0) + 1
        request = tree.get('mms.confirmedServiceRequest_tree')
        self._domains(association, request)
        actions = self._changes(pkt, service, request) if service in _MMS_CHANGES else []
        invoke = tree.get('mms.invokeID')
        if invoke is not None:
            association.waiting[invoke] = (service, actions)
            if len(association.waiting) > 256:
                association.waiting.pop(next(iter(association.waiting)))

    def _changes(self, pkt, service, request):
        """'mms_action' records for a request that changes the server: one
        per object it names (a write's variables, with the value written),
        or one for the request when it names none."""
        names = _mms_object_names(request)[:_MMS_MAX_ACTIONS_PER_REQUEST]
        if not names:
            # a program, domain or file is named by a plain identifier
            names = [v for key in _MMS_IDENTIFIERS for v in _mms_find(request, key) if isinstance(v, str)][:1]
        values = []
        if service == 'write':
            data = _mms_find(request, 'mms.listOfData_tree')
            items = _mms_find(data[0], 'mms.Data_tree') if data else []
            values = [_mms_data(item) for item in items]
        actions = []
        for i, name in enumerate(names or [None]):
            action = {'service': service, 'result': 'no response'}
            if name:
                action['object'] = name
                control = _MMS_CONTROLS.get(name.rsplit('$', 1)[-1]) if service == 'write' else None
                if control:
                    action['control'] = control
            if i < len(values) and values[i] is not None:
                action['value'] = values[i]
            elif len(names) == 1 and len(values) > 1:
                action['value'] = ', '.join(v for v in values if v is not None)
            self.actions.append((pkt.flow, pkt.when, 'mms_action', action))
            actions.append(action)
        return actions

    def _response(self, association, tree):
        waiting = association.waiting.pop(tree.get('mms.invokeID'), None)
        service = waiting[0] if waiting else _mms_name(_MMS_SERVICES, tree.get('mms.confirmedServiceResponse'))
        response = tree.get('mms.confirmedServiceResponse_tree')
        if waiting and waiting[1]:
            # a write's response lists each item's success or failure
            failures = []
            if service == 'write' and isinstance(response, dict):
                for item in _mms_find(response, 'mms.Write_Response_item_tree') or [response]:
                    failure = _dict(item).get('mms.failure')
                    failures.append(_mms_name(_MMS_ACCESS_ERRORS, failure) if failure is not None else None)
            for i, action in enumerate(waiting[1]):
                action['result'] = (failures[i] if i < len(failures) else None) or 'success'
        if service == 'identify':
            for key, field in (('vendor', 'mms.vendorName'), ('model', 'mms.modelName'), ('revision', 'mms.revision')):
                found = _mms_find(response, field)
                if found:
                    association.body[key] = found[0]
        if service == 'getNameList':
            self._domains(association, response)

    def _failed(self, association, invoke, error):
        body = association.body
        waiting = association.waiting.pop(invoke, None)
        for action in waiting[1] if waiting else ():
            action['result'] = error
        body['errors'] += 1
        body['last_error'] = f'{waiting[0]}: {error}' if waiting else error

    def finish(self):
        records = []
        for association in self.associations.values():
            body = association.body
            if association.domains:
                body['domains'] = list(association.domains)
            # a lone response, its request before the capture, says nothing
            if body['services'] or len(body) > 2:
                records.append((association.flow, association.first, 'mms', body))
        return records + self.actions


# ---------------------------------------------------------------- MongoDB
#
# MongoDB's wire protocol (TCP 27017), which Suricata doesn't parse: legacy
# OP_QUERY commands (what most scanners still send - isMaster, buildinfo,
# listDatabases) and their OP_REPLY, and OP_MSG, today's request and reply.
# Its messages are BSON documents nested in documents, so it's read from
# the structured pass's JSON trees.

# Opcodes tshark names
_MONGO_REPLY, _MONGO_UPDATE, _MONGO_INSERT, _MONGO_QUERY, _MONGO_DELETE = 1, 2001, 2002, 2004, 2006
_MONGO_COMPRESSED, _MONGO_MSG = 2012, 2013
# Commands that only say hello, log in or look at the connection itself
_MONGO_HANDSHAKE = frozenset((
    'hello', 'ismaster', 'isMaster', 'buildinfo', 'buildInfo', 'ping', 'getnonce', 'authenticate', 'saslStart',
    'saslContinue', 'logout', 'whatsmyuri', 'endSessions', 'getLastError', 'getlasterror', 'saslSupportedMechs'))
# Commands that change the server's data, users or state
_MONGO_CHANGES = frozenset((
    'insert', 'update', 'delete', 'findAndModify', 'findandmodify', 'drop', 'dropDatabase', 'create',
    'createIndexes', 'dropIndexes', 'renameCollection', 'collMod', 'convertToCapped', 'createUser', 'updateUser',
    'dropUser', 'dropAllUsersFromDatabase', 'grantRolesToUser', 'revokeRolesFromUser', 'createRole', 'updateRole',
    'dropRole', 'grantPrivilegesToRole', 'shutdown', 'eval', '$eval', 'setParameter', 'applyOps', 'fsync',
    'killOp', 'compact', 'repairDatabase', 'cloneCollection', 'copydb'))
# Element names whose values are never kept - a login's or user's secrets
_MONGO_SECRETS = frozenset(('pwd', 'password', 'passwd', 'key', 'nonce', 'payload', 'digestPassword'))
_MONGO_MAX_DATABASES = 50
_MONGO_PREVIEW = 200


def _mongo_elements(doc):
    """A BSON document's JSON tree as (name, value) pairs, in order: a
    value is a string or number, or a subdocument's tree (an array is a
    document too, its names '0', '1'...)."""
    els = _dict(_dict(doc).get('mongo.elements'))
    names, trees = els.get('mongo.element.name'), els.get('mongo.element.name_tree')
    if names is None:
        return []
    if not isinstance(names, list):
        names, trees = [names], [trees]
    pairs = []
    for name, tree in zip(names, trees if isinstance(trees, list) else [trees]):
        tree = _dict(tree)
        value = next((v for k, v in tree.items() if k.startswith('mongo.element.value.')
                      and k != 'mongo.element.value.length'), None)
        pairs.append((name, value if value is not None else tree.get('mongo.document')))
    return pairs


def _mongo_get(doc, name):
    return next((v for n, v in _mongo_elements(doc) if n == name), None)


def _mongo_documents(message):
    """A message's documents: an OP_QUERY's query, an OP_MSG's body and
    document sequences, an OP_REPLY's documents, a legacy write's."""
    docs = []
    for key in ('mongo.query', 'mongo.document', 'mongo.selector', 'mongo.update'):
        value = message.get(key)
        docs.extend(value if isinstance(value, list) else [value] if value is not None else [])
    for section in _pdus(message.get('mongo.msg.sections.section')):
        section = _dict(section)
        if section.get('mongo.msg.sections.section.body') is not None:
            docs.append(section['mongo.msg.sections.section.body'])
        sequence = _dict(section.get('mongo.msg.sections.section.doc_sequence'))
        docs.extend(_pdus(sequence.get('mongo.document')))
    return [d for d in docs if isinstance(d, dict)]


def _mongo_preview(doc, depth=0):
    """A document as short text ('{note: READ ME, btc: 1Ab...}'), secrets
    left out, cut at _MONGO_PREVIEW characters."""
    parts = []
    for name, value in _mongo_elements(doc):
        if name in _MONGO_SECRETS:
            continue
        shown = ('{' + _mongo_preview(value, depth + 1) + '}' if depth < 2 else '{...}') if isinstance(value, dict) else value
        parts.append(f'{name}: {shown}')
    text = ', '.join(parts)
    return text if depth or len(text) <= _MONGO_PREVIEW else text[:_MONGO_PREVIEW] + '...'


def _mongo_sasl_user(mechanism, payload):
    """The user a SASL login names - SCRAM's client-first message
    ('n,,n=alice,r=...'), or PLAIN's authentication identity (never its
    password)."""
    try:
        data = bytes.fromhex(str(payload).replace(':', ''))
    except ValueError:
        return None
    if mechanism == 'PLAIN':
        fields = data.split(b'\x00')
        return fields[1].decode('utf-8', 'replace') if len(fields) == 3 else None
    match = re.search(rb'(?:^|,)n=([^,]*)', data.split(b',,', 1)[-1])
    return match.group(1).decode('utf-8', 'replace').replace('=2C', ',').replace('=3D', '=') if match else None


class _MongoConnection:
    __slots__ = ('flow', 'first', 'body', 'databases', 'waiting', 'mechanism', 'authenticated')

    def __init__(self, flow, first):
        self.flow, self.first = flow, first
        self.body = {'commands': {}, 'errors': 0, 'answered': False}
        self.databases = {}    # database -> None, in first-seen order
        self.waiting = {}      # request id -> (command, [action bodies])
        self.mechanism = None
        self.authenticated = False


class MongoDB:
    """MongoDB - see the comment above. One 'mongodb' record per connection:
    the client's driver, application and OS (from its hello), the login
    (user and mechanism, never a password or key) and whether it worked,
    how many of each command it sent, the databases it touched, what the
    server answered (its version, the databases it listed), and errors."""
    event_type = 'mongodb'
    app_protos = ('mongo',)
    tshark_protocols = ('mongo',)
    layers = ('mongo',)
    display_filter = 'mongo'

    def __init__(self):
        self.connections = {}      # flow key -> _MongoConnection
        self.actions = []

    def feed_json(self, pkt, layers):
        connection = self.connections.get(pkt.flow.key)
        if connection is None:
            connection = self.connections[pkt.flow.key] = _MongoConnection(pkt.flow, pkt.when)
        for message in _pdus(layers.get('mongo')):
            if isinstance(message, dict):
                self._message(pkt, connection, message)

    def _message(self, pkt, connection, message):
        body = connection.body
        opcode = _int(message.get('mongo.opcode'))
        if opcode == _MONGO_COMPRESSED:
            body['compressed'] = body.get('compressed', 0) + 1
            opcode = _int(message.get('mongo.compression.original_opcode'))
        docs = _mongo_documents(message)
        reply_to = _int(message.get('mongo.response_to')) or 0
        if opcode == _MONGO_REPLY or (opcode == _MONGO_MSG and reply_to not in (0, 0xffffffff)):
            body['answered'] = True
            self._reply(connection, message.get('mongo.response_to'), docs[0] if docs else {})
            return
        namespace = message.get('mongo.full_collection_name') or ''
        database, _, collection = namespace.partition('.')
        if opcode in (_MONGO_QUERY, _MONGO_MSG) and docs and (opcode == _MONGO_MSG or collection == '$cmd'):
            command, target = (_mongo_elements(docs[0]) or [(None, None)])[0]
            database = _mongo_get(docs[0], '$db') or database
            collection = target if isinstance(target, str) else ''
        elif opcode == _MONGO_QUERY:
            command = 'find'
        else:
            command = {_MONGO_INSERT: 'insert', _MONGO_UPDATE: 'update', _MONGO_DELETE: 'delete'}.get(opcode)
        if not command:
            return
        body['commands'][command] = body['commands'].get(command, 0) + 1
        if database and len(connection.databases) < _MONGO_MAX_DATABASES:
            connection.databases.setdefault(database, None)
        if docs:
            self._login(connection, command, docs[0], database)
            if command.lower() in ('hello', 'ismaster'):
                self._client(body, _mongo_get(docs[0], 'client'))
        actions = self._change(pkt, opcode, command, database, collection, docs) if command in _MONGO_CHANGES else []
        request_id = message.get('mongo.request_id')
        if request_id is not None:
            connection.waiting[request_id] = (command, actions)
            if len(connection.waiting) > 256:
                connection.waiting.pop(next(iter(connection.waiting)))

    def _change(self, pkt, opcode, command, database, collection, docs):
        """A 'mongodb_action' record for a command that changes the server:
        its database and collection (or the user or role it's about), how
        many documents it carries, and a preview of the first - an
        attacker's ransom note is usually the one document inserted."""
        action = {'command': command, 'database': database, 'result': 'no response'}
        if command in ('createUser', 'updateUser', 'dropUser', 'grantRolesToUser', 'revokeRolesFromUser',
                       'createRole', 'updateRole', 'dropRole', 'grantPrivilegesToRole'):
            action['user' if 'User' in command else 'role'] = collection
            roles = _mongo_get(docs[0], 'roles') if docs else None
            if isinstance(roles, dict):
                action['roles'] = [r if not isinstance(r, dict) else _mongo_preview(r) for _, r in _mongo_elements(roles)][:10]
        elif collection and command not in ('dropDatabase', 'shutdown', 'fsync', 'setParameter', 'killOp'):
            action['collection'] = collection
        if opcode == _MONGO_MSG or opcode == _MONGO_QUERY:
            items = {'insert': 'documents', 'update': 'updates', 'delete': 'deletes'}.get(command)
            listed = [v for _, v in _mongo_elements(_mongo_get(docs[0], items))] if items and docs else []
            if items and not listed:
                listed = docs[1:]      # OP_MSG's document sequence
            if items:
                action['count'] = len(listed)
            if command == 'insert' and listed and isinstance(listed[0], dict):
                action['document'] = _mongo_preview(listed[0])
            elif command in ('update', 'delete') and listed and isinstance(listed[0], dict):
                action['filter'] = _mongo_preview(_mongo_get(listed[0], 'q'))
        elif opcode == _MONGO_INSERT:
            action['count'] = len(docs)
            if docs:
                action['document'] = _mongo_preview(docs[0])
        elif docs:
            action['count'] = 1
            action['filter'] = _mongo_preview(docs[0])
        self.actions.append((pkt.flow, pkt.when, 'mongodb_action', action))
        return [action]

    @staticmethod
    def _client(body, client):
        if not isinstance(client, dict):
            return
        driver, app, os_ = (_mongo_get(client, k) for k in ('driver', 'application', 'os'))
        if isinstance(driver, dict):
            body['driver'] = ' '.join(str(v) for v in (_mongo_get(driver, 'name'), _mongo_get(driver, 'version')) if v)
        if isinstance(app, dict) and _mongo_get(app, 'name'):
            body['application'] = _mongo_get(app, 'name')
        if isinstance(os_, dict):
            body['os'] = ' '.join(str(v) for v in (_mongo_get(os_, 'name') or _mongo_get(os_, 'type'),
                                                   _mongo_get(os_, 'version')) if v)
        if _mongo_get(client, 'platform'):
            body['platform'] = _mongo_get(client, 'platform')

    def _login(self, connection, command, doc, database):
        body = connection.body
        if command == 'saslStart':
            connection.mechanism = _mongo_get(doc, 'mechanism')
            user = _mongo_sasl_user(connection.mechanism, _mongo_get(doc, 'payload'))
        elif command == 'authenticate':
            connection.mechanism = _mongo_get(doc, 'mechanism') or 'MONGODB-CR'
            user = _mongo_get(doc, 'user')
        else:
            return
        if connection.mechanism:
            body['auth_mechanism'] = connection.mechanism
        if user:
            body['user'] = user
        body['auth_database'] = database
        body.setdefault('login', 'no response')

    def _reply(self, connection, request_id, doc):
        body = connection.body
        waiting = connection.waiting.pop(request_id, None)
        command, actions = waiting if waiting else ('', [])
        ok = _mongo_get(doc, 'ok')
        failed = ok is not None and str(ok) in ('0', '0.0', 'False', 'false')
        error = _mongo_get(doc, 'errmsg') or _mongo_get(doc, '$err') or _mongo_get(doc, 'codeName')
        if failed or (error and ok is None):
            body['errors'] += 1
            body['last_error'] = f'{command}: {error}' if command else str(error)
        if command in ('saslStart', 'saslContinue', 'authenticate'):
            if failed:
                body['login'] = 'failed'
            elif command == 'authenticate' or str(_mongo_get(doc, 'done')) in ('1', 'True', 'true'):
                body['login'] = 'succeeded'
                connection.authenticated = True
        elif command.lower() == 'buildinfo' and _mongo_get(doc, 'version'):
            body['server_version'] = _mongo_get(doc, 'version')
        elif command == 'listDatabases' and not failed:
            listed = _mongo_get(doc, 'databases')
            names = [_mongo_get(d, 'name') for _, d in _mongo_elements(listed) if isinstance(d, dict)]
            body['databases_listed'] = [n for n in names if n][:_MONGO_MAX_DATABASES]
        if not failed and command and command not in _MONGO_HANDSHAKE and not connection.authenticated:
            body['unauthenticated'] = True
        for action in actions:
            action['result'] = f'error: {error}' if failed else 'ok'
            if not failed and _mongo_get(doc, 'n') is not None:
                action['n'] = _int(_mongo_get(doc, 'n'), _mongo_get(doc, 'n'))

    def finish(self):
        records = []
        for connection in self.connections.values():
            body = connection.body
            if connection.databases:
                body['databases'] = list(connection.databases)
            if body['commands'] or body['answered']:
                records.append((connection.flow, connection.first, 'mongodb', body))
        return records + self.actions


# ---------------------------------------------------------------- structured protocols
#
# Protocols whose messages nest - an OPC UA write's node ids beside its
# request header's, several commands in one packet - can't be read from flat
# per-packet fields: a field present in only some of a packet's commands
# can't be told apart. These are read instead from a second tshark pass
# that writes each packet as a JSON tree (shark_analyzer's structured
# pass), run only over the flows that carry them. Each class lists the
# tshark dissectors it needs (tshark_protocols), the layers to keep
# (layers) and the packets to keep (display_filter); feed_json() gets each
# packet's layers.


def _flatten(tree, out=None):
    """A JSON subtree's fields: name -> every value under it, in order."""
    out = {} if out is None else out
    if isinstance(tree, dict):
        for name, value in tree.items():
            if isinstance(value, (dict, list)):
                if isinstance(value, list) and value and not isinstance(value[0], (dict, list)):
                    out.setdefault(name, []).extend(value)
                else:
                    _flatten(value, out)
            else:
                out.setdefault(name, []).append(value)
    elif isinstance(tree, list):
        for item in tree:
            _flatten(item, out)
    return out


def _pdus(layer):
    """A layer's messages - one, or a list of them (--no-duplicate-keys
    turns a packet's repeated layer into a list)."""
    if layer is None:
        return []
    return layer if isinstance(layer, list) else [layer]


# Every protocol with records here, from tshark's fields, in the order their
# fields follow the base fields in tshark's output.
PROTOCOLS = (LLMNR, NBNS, DHCPv6, Syslog, DTLS, RPC, SOCKS, RADIUS, STUN, CoAP, SLP, IPMI, L2TP, RIP, XDMCP, SSDP, S7comm, Telnet, IEC104, BACnet, GOOSE, Browser, LLDP, CDP, PNDCP, RShell, OpenVPN)
# ... and from the structured pass (shark_analyzer._structured_pass): for
# a protocol whose messages nest, which flat fields can't keep apart
# (several commands per packet, a token inside a command).
STRUCTURED_PROTOCOLS = (OPCUA, MMS, MongoDB)
# Flow application protocols with transaction records here - every other
# one gets a connection tab (db.CONNECTION_TYPE_PREFIX) instead.
RECORDED_APP_PROTOS = frozenset(p for proto in PROTOCOLS + STRUCTURED_PROTOCOLS for p in proto.app_protos)
