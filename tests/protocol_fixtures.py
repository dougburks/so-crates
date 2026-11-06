"""A hand-built pcap exercising what tshark's per-protocol records
have to get right - DNS, HTTP/1.1, TLS and Modbus/TCP - for checking its
output against Suricata's on the same packets (see
tests/test_shark_analyzer.py's TestProtocolRecordsAgainstSuricata, whose
expected values are what Suricata 8.0.6 logged for this capture).

Built with struct like tests/pcap_fixtures.py, deterministic, so the
expected values never drift. Keep it deterministic: changing a single byte
here means re-running Suricata over it to refresh those expectations.
"""
import socket
import functools
import struct

from tests.pcap_fixtures import _checksum, _tcp_packet, tcp_segments, write_pcap

CLIENT = '10.1.0.10'
DNS_SERVER, HTTP_SERVER, TLS_SERVER, MODBUS_SERVER = '10.1.0.53', '10.1.0.80', '10.1.0.43', '10.1.0.50'
FTP_SERVER = '10.1.0.21'


def _udp_packet(src, dst, sport, dport, payload):
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = s + d + struct.pack('!BBH', 0, 17, len(udp))
    udp = udp[:6] + struct.pack('!H', _checksum(pseudo + udp) or 0xffff) + udp[8:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, s, d)
    ip = ip[:10] + struct.pack('!H', _checksum(ip)) + ip[12:]
    return b'\x00' * 6 + b'\x11' * 6 + struct.pack('!H', 0x0800) + ip + udp


# ---------------------------------------------------------------- DNS

_TYPES = {'A': 1, 'NS': 2, 'CNAME': 5, 'PTR': 12, 'MX': 15, 'TXT': 16, 'AAAA': 28}


def _name(name):
    return b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0'


def _rdata(rtype, value):
    if rtype == 'A':
        return socket.inet_aton(value)
    if rtype == 'AAAA':
        return socket.inet_pton(socket.AF_INET6, value)
    if rtype in ('CNAME', 'NS', 'PTR'):
        return _name(value)
    if rtype == 'MX':
        return struct.pack('!H', 10) + _name(value)
    if rtype == 'TXT':
        raw = value.encode()
        return bytes([len(raw)]) + raw
    raise ValueError(rtype)


def dns_message(txid, qname, qtype, answers=(), response=False, rcode=0):
    """A DNS message: one question, and for a response its answers as
    (name, type, value) with a 300s TTL."""
    flags = 0x0100 | (0x8180 if response else 0) | rcode
    msg = struct.pack('!HHHHHH', txid, flags, 1, len(answers), 0, 0)
    msg += _name(qname) + struct.pack('!HH', _TYPES[qtype], 1)
    for name, rtype, value in answers:
        rd = _rdata(rtype, value)
        msg += _name(name) + struct.pack('!HHIH', _TYPES[rtype], 1, 300, len(rd)) + rd
    return msg


# (client port, txid, name, type, answers or None for no response, rcode)
DNS_TRANSACTIONS = [
    (53001, 0x1001, 'www.example.com', 'A', [('www.example.com', 'A', '93.184.216.34'),
                                             ('www.example.com', 'A', '93.184.216.35')], 0),
    (53002, 0x1002, 'cdn.example.net', 'A', [('cdn.example.net', 'CNAME', 'edge.example.net'),
                                             ('edge.example.net', 'A', '198.51.100.7')], 0),
    (53003, 0x1003, 'ipv6.example.org', 'AAAA', [('ipv6.example.org', 'AAAA', '2001:db8::7')], 0),
    (53004, 0x1004, 'missing.example.com', 'A', [], 3),
    (53005, 0x1005, 'lost.example.com', 'A', None, 0),
    (53006, 0x1006, 'txt.example.com', 'TXT', [('txt.example.com', 'TXT', 'v=spf1 a\tb\\c')], 0),
    (53007, 0x1007, 'mail.example.com', 'A', [('mail.example.com', 'A', '192.0.2.25')], 0),
    (53007, 0x1008, 'example.com', 'MX', [('example.com', 'MX', 'mail.example.com')], 0),
]


def dns_packets():
    pkts = []
    for port, txid, name, qtype, answers, rcode in DNS_TRANSACTIONS:
        pkts.append(_udp_packet(CLIENT, DNS_SERVER, port, 53, dns_message(txid, name, qtype)))
        if answers is not None:
            pkts.append(_udp_packet(DNS_SERVER, CLIENT, 53, port,
                                    dns_message(txid, name, qtype, answers, response=True, rcode=rcode)))
    return pkts


# ---------------------------------------------------------------- HTTP

def _http_response(status, reason, body, content_type='text/html'):
    return (f'HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n'
            f'Content-Length: {len(body)}\r\n\r\n').encode() + body


HTTP_POST_BODY = b'name=report.pdf&size=1024'


def http_packets():
    """Three requests on one keep-alive connection: a 200, a 404, and a
    POST whose body arrives in a second segment."""
    ua = 'Mozilla/5.0 (X11; Linux x86_64) SO-CRATES-test'
    post_head = (f'POST /upload HTTP/1.1\r\nHost: files.example.com\r\nUser-Agent: {ua}\r\n'
                 f'Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(HTTP_POST_BODY)}\r\n\r\n').encode()
    return tcp_segments(CLIENT, HTTP_SERVER, 41000, 80, [
        (True, f'GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: {ua}\r\n\r\n'.encode()),
        (False, _http_response(200, 'OK', b'<h1>Hello</h1>')),
        (True, f'GET /missing HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: {ua}\r\nReferer: http://www.example.com/index.html\r\n\r\n'.encode()),
        (False, _http_response(404, 'Not Found', b'nope')),
        (True, post_head),
        (True, HTTP_POST_BODY),
        (False, _http_response(201, 'Created', b'{"ok":true}', 'application/json')),
    ])


# ---------------------------------------------------------------- TLS

TLS_SNI = 'secure.example.com'


def _ext(ext_type, data):
    return struct.pack('!HH', ext_type, len(data)) + data


def client_hello():
    sni = TLS_SNI.encode()
    exts = (
        _ext(0x0000, struct.pack('!HBH', len(sni) + 3, 0, len(sni)) + sni)                  # server_name
        + _ext(0x000a, struct.pack('!H', 4) + struct.pack('!HH', 0x001d, 0x0017))          # supported_groups
        + _ext(0x000b, b'\x01\x00')                                                         # ec_point_formats
        + _ext(0x000d, struct.pack('!H', 4) + struct.pack('!HH', 0x0403, 0x0804))          # signature_algorithms
        + _ext(0x0010, struct.pack('!H', 12) + b'\x02h2' + b'\x08http/1.1')                # ALPN
        + _ext(0x002b, b'\x04' + struct.pack('!HH', 0x0304, 0x0303))                       # supported_versions
        + _ext(0x0033, struct.pack('!HHH', 36, 0x001d, 32) + bytes(range(32)))             # key_share
    )
    suites = struct.pack('!HHHH', 0x1301, 0x1302, 0xc02f, 0xc030)
    body = (struct.pack('!H', 0x0303) + bytes(32) + b'\x20' + bytes(range(32, 64))
            + struct.pack('!H', len(suites)) + suites + b'\x01\x00' + struct.pack('!H', len(exts)) + exts)
    hs = b'\x01' + struct.pack('!I', len(body))[1:] + body
    return b'\x16\x03\x01' + struct.pack('!H', len(hs)) + hs


def server_hello():
    exts = _ext(0x002b, struct.pack('!H', 0x0304)) + _ext(0x0033, struct.pack('!HH', 0x001d, 32) + bytes(32))
    body = (struct.pack('!H', 0x0303) + bytes(range(100, 132)) + b'\x20' + bytes(range(32, 64))
            + struct.pack('!H', 0x1301) + b'\x00' + struct.pack('!H', len(exts)) + exts)
    hs = b'\x02' + struct.pack('!I', len(body))[1:] + body
    record = b'\x16\x03\x03' + struct.pack('!H', len(hs)) + hs
    ccs = b'\x14\x03\x03\x00\x01\x01'
    appdata = b'\x17\x03\x03\x00\x20' + bytes(32)
    return record + ccs + appdata


def tls_packets():
    return tcp_segments(CLIENT, TLS_SERVER, 41001, 443, [
        (True, client_hello()),
        (False, server_hello()),
        (True, b'\x14\x03\x03\x00\x01\x01' + b'\x17\x03\x03\x00\x20' + bytes(32)),
    ])


# ---------------------------------------------------------------- Modbus/TCP

def _mbap(txid, unit, pdu):
    return struct.pack('!HHHB', txid, 0, len(pdu) + 1, unit) + pdu


# (txid, unit, request PDU, response PDU)
MODBUS_TRANSACTIONS = [
    (1, 1, struct.pack('!BHH', 3, 100, 2), struct.pack('!BBHH', 3, 4, 1, 2)),   # read holding registers 100-101
    (2, 1, struct.pack('!BHH', 6, 200, 7), struct.pack('!BHH', 6, 200, 7)),     # write single register 200 = 7
    (3, 1, struct.pack('!BHH', 1, 0, 8), struct.pack('!BB', 0x81, 2)),          # read coils -> illegal data address
]


def modbus_packets():
    segments = []
    for txid, unit, req, resp in MODBUS_TRANSACTIONS:
        segments += [(True, _mbap(txid, unit, req)), (False, _mbap(txid, unit, resp))]
    return tcp_segments(CLIENT, MODBUS_SERVER, 41002, 502, segments)


# ---------------------------------------------------------------- FTP

class _Tcp:
    """One TCP connection built a step at a time, so two connections'
    packets can be interleaved (an FTP data connection between its
    command's 150 and 226 replies)."""

    def __init__(self, client, server, cport, sport):
        self.c, self.s, self.cp, self.sp = client, server, cport, sport
        self.cs, self.ss = 1000, 5000

    def open(self):
        pkts = [_tcp_packet(self.c, self.s, self.cp, self.sp, self.cs, 0, 0x02)]
        self.cs += 1
        pkts.append(_tcp_packet(self.s, self.c, self.sp, self.cp, self.ss, self.cs, 0x12))
        self.ss += 1
        pkts.append(_tcp_packet(self.c, self.s, self.cp, self.sp, self.cs, self.ss, 0x10))
        return pkts

    def send(self, from_client, payload):
        if from_client:
            pkt = _tcp_packet(self.c, self.s, self.cp, self.sp, self.cs, self.ss, 0x18, payload)
            self.cs += len(payload)
        else:
            pkt = _tcp_packet(self.s, self.c, self.sp, self.cp, self.ss, self.cs, 0x18, payload)
            self.ss += len(payload)
        return [pkt]

    def close(self):
        return [_tcp_packet(self.c, self.s, self.cp, self.sp, self.cs, self.ss, 0x11),
                _tcp_packet(self.s, self.c, self.sp, self.cp, self.ss, self.cs + 1, 0x11)]


FTP_GREETING = b'220-Welcome to the test FTP server\r\n220-Second greeting line\r\n220 Ready.\r\n'


def ftp_packets():
    """A control connection with a three-line greeting, login, an OPTS
    command the server rejects, a passive RETR and an active PORT + STOR,
    each data connection running between its command's 150 and 226."""
    ctl = _Tcp(CLIENT, FTP_SERVER, 41003, 21)
    pkts = ctl.open() + ctl.send(False, FTP_GREETING)
    for command, reply in ((b'USER alice', b'331 Password required'), (b'PASS s3cret', b'230 Logged in.'),
                           (b'OPTS utf8 on', b'504 Unknown command'),
                           (b'PASV', b'227 Entering Passive Mode (10,1,0,21,195,81)'),
                           (b'RETR report.pdf', b'150 Opening data connection')):
        pkts += ctl.send(True, command + b'\r\n') + ctl.send(False, reply + b'\r\n')
    passive = _Tcp(CLIENT, FTP_SERVER, 41004, 50001)
    pkts += passive.open() + passive.send(False, b'%PDF-1.4 test report\n') + passive.close()
    pkts += ctl.send(False, b'226 Transfer complete\r\n')
    for command, reply in ((b'PORT 10,1,0,10,160,5', b'200 PORT command successful'),
                           (b'STOR upload.txt', b'150 Ok to send data')):
        pkts += ctl.send(True, command + b'\r\n') + ctl.send(False, reply + b'\r\n')
    active = _Tcp(FTP_SERVER, CLIENT, 20, 40965)   # PORT ...,160,5 = 160 * 256 + 5
    pkts += active.open() + active.send(False, b'uploaded contents\n') + active.close()
    pkts += ctl.send(False, b'226 Transfer complete\r\n')
    pkts += ctl.send(True, b'QUIT\r\n') + ctl.send(False, b'221 Goodbye.\r\n') + ctl.close()
    return pkts


def write_protocol_pcap(path):
    write_pcap(path, dns_packets() + http_packets() + tls_packets() + modbus_packets() + ftp_packets())


# ---------------------------------------------------------------- the second capture
#
# write_extra_pcap: protocols tshark records that Suricata doesn't
# (NBNS, LLMNR, SSDP, S7comm), and the cases real captures turned up that
# the first capture lacked - checked against Suricata's output where
# Suricata parses them too (tests/data/extra_fixture.eve.json).

def _udp_dns(src, dst, sport, dport, payload):
    return _udp_packet(src, dst, sport, dport, payload)


def _icmp_unreachable(src, dst, about):
    """An ICMP port unreachable from src to dst, carrying the IP header and
    first 8 bytes of the packet `about` (a whole Ethernet frame)."""
    inner = about[14:14 + 20 + 8]
    icmp = struct.pack('!BBHI', 3, 3, 0, 0) + inner
    icmp = icmp[:2] + struct.pack('!H', _checksum(icmp)) + icmp[4:]
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(icmp), 1, 0, 64, 1, 0, s, d)
    ip = ip[:10] + struct.pack('!H', _checksum(ip)) + ip[12:]
    return b'\x00' * 6 + b'\x11' * 6 + struct.pack('!H', 0x0800) + ip + icmp


def _nbns_name(name, suffix):
    raw = name.upper().ljust(15)[:15].encode() + bytes([suffix])
    encoded = b''.join(bytes([0x41 + (c >> 4), 0x41 + (c & 0xf)]) for c in raw)
    return b'\x20' + encoded + b'\x00'


def _nbns(txid, flags, name, suffix, answer_addr=None, additional_addr=None, ttl=300000):
    rr = lambda addr: b'\xc0\x0c' + struct.pack('!HHIH', 0x20, 1, ttl, 6) + b'\x00\x00' + socket.inet_aton(addr)
    an = rr(answer_addr) if answer_addr else b''
    ar = rr(additional_addr) if additional_addr else b''
    is_response = flags & 0x8000
    question = b'' if is_response else _nbns_name(name, suffix) + struct.pack('!HH', 0x20, 1)
    head = struct.pack('!HHHHHH', txid, flags, 0 if is_response else 1, 1 if an else 0, 0, 1 if ar else 0)
    if is_response:
        an = _nbns_name(name, suffix) + an[2:]
    return head + question + an + ar


def _tpkt_s7(s7):
    cotp = b'\x02\xf0\x80'
    return struct.pack('!BBH', 3, 0, 4 + len(cotp) + len(s7)) + cotp + s7


def _s7_job(pduref, params, data=b''):
    return _tpkt_s7(struct.pack('!BBHHHH', 0x32, 1, 0, pduref, len(params), len(data)) + params + data)


def _s7_ack(pduref, params, data=b'', errcls=0, errcod=0):
    return _tpkt_s7(struct.pack('!BBHHHHBB', 0x32, 3, 0, pduref, len(params), len(data), errcls, errcod) + params + data)


S7_PLC = '10.1.0.102'
SSDP_DEVICE = '10.1.0.60'
LLMNR_RESPONDER = '10.1.0.70'


def extra_packets():
    pkts = []
    # DNS: a query sent twice before its one answer; a query answered three times
    q = dns_message(0x3001, 'slow.example.com', 'A')
    a = dns_message(0x3001, 'slow.example.com', 'A', [('slow.example.com', 'A', '192.0.2.80')], response=True)
    pkts += [_udp_packet(CLIENT, DNS_SERVER, 53010, 53, q), _udp_packet(CLIENT, DNS_SERVER, 53010, 53, q),
             _udp_packet(DNS_SERVER, CLIENT, 53, 53010, a)]
    q = dns_message(0x3002, 'echo.example.com', 'A')
    a = dns_message(0x3002, 'echo.example.com', 'A', [('echo.example.com', 'A', '192.0.2.81')], response=True)
    response = _udp_packet(DNS_SERVER, CLIENT, 53, 53011, a)
    # ... and the client, having closed the port, answers the third with an ICMP port unreachable
    pkts += [_udp_packet(CLIENT, DNS_SERVER, 53011, 53, q), response, response, response,
             _icmp_unreachable(CLIENT, DNS_SERVER, response)]
    # mDNS: a query, its multicast answer, and an empty probe
    pkts += [_udp_packet(CLIENT, '224.0.0.251', 5353, 5353, dns_message(0, '_ipp._tcp.local', 'PTR')),
             _udp_packet(SSDP_DEVICE, '224.0.0.251', 5353, 5353,
                         dns_message(0, '_ipp._tcp.local', 'PTR', [('_ipp._tcp.local', 'PTR', 'printer._ipp._tcp.local')],
                                     response=True)),
             _udp_packet(CLIENT, '224.0.0.251', 5353, 5353, b'\x00' * 12)]
    # LLMNR: who has wpad?
    pkts += [_udp_packet(CLIENT, '224.0.0.252', 53020, 5355, dns_message(0x4001, 'wpad', 'A')),
             _udp_packet(LLMNR_RESPONDER, CLIENT, 5355, 53020,
                         dns_message(0x4001, 'wpad', 'A', [('wpad', 'A', LLMNR_RESPONDER)], response=True))]
    # NBNS: a registration broadcast three times, then a query and its answer
    reg = _nbns(0x5001, 0x2910, 'DESKTOP-TEST01', 0x20, additional_addr=CLIENT)
    pkts += [_udp_packet(CLIENT, '10.1.0.255', 137, 137, reg)] * 3
    pkts += [_udp_packet(CLIENT, '10.1.0.255', 137, 137, _nbns(0x5002, 0x0110, 'FILESERVER', 0x20)),
             _udp_packet('10.1.0.30', CLIENT, 137, 137, _nbns(0x5002, 0x8500, 'FILESERVER', 0x20, answer_addr='10.1.0.30'))]
    # SSDP: an M-SEARCH, a device's answer, and a NOTIFY
    pkts += [_udp_packet(CLIENT, '239.255.255.250', 53030, 1900,
                         b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\n'
                         b'ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n'),
             _udp_packet(SSDP_DEVICE, CLIENT, 1900, 53030,
                         b'HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://10.1.0.60:49152/gateway.xml\r\n'
                         b'SERVER: Linux/5.4 UPnP/1.0 TestGateway/1.0\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n'
                         b'USN: uuid:0b1d-test::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n'),
             _udp_packet(SSDP_DEVICE, '239.255.255.250', 1900, 1900,
                         b'NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\n'
                         b'LOCATION: http://10.1.0.60:49152/gateway.xml\r\nUSN: uuid:0b1d-test::upnp:rootdevice\r\n\r\n')]
    # HTTP: Host with a port, and a Content-Type with parameters
    pkts += tcp_segments(CLIENT, HTTP_SERVER, 41010, 8080, [
        (True, b'GET /status HTTP/1.1\r\nHost: www.example.com:8080\r\nUser-Agent: test\r\n\r\n'),
        (False, b'HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 2\r\n\r\nok'),
    ])
    # FTP: a failed login the server answers, then hangs up on
    pkts += tcp_segments(CLIENT, FTP_SERVER, 41011, 21, [
        (False, b'220 Ready.\r\n'), (True, b'USER bob\r\n'), (False, b'331 Password required\r\n'),
        # The client's ACK of the 530, as a real client sends one, before the 221
        (True, b'PASS wrong\r\n'), (False, b'530 Login incorrect.\r\n'), (True, b''), (False, b'221 Goodbye.\r\n'),
    ])
    # S7comm (ISO-on-TCP, port 102): setup, a read of DB1 byte 10, a write
    # the PLC refuses, and a CPU-functions userdata request
    read_item = b'\x12\x0a\x10\x02\x00\x01\x00\x01\x84' + (10 << 3).to_bytes(3, 'big')
    pkts += tcp_segments(CLIENT, S7_PLC, 41012, 102, [
        (True, _s7_job(1, b'\xf0\x00\x00\x01\x00\x01\x01\xe0')),
        (False, _s7_ack(1, b'\xf0\x00\x00\x01\x00\x01\x01\xe0')),
        (True, _s7_job(2, b'\x04\x01' + read_item)),
        (False, _s7_ack(2, b'\x04\x01', b'\xff\x04\x00\x08\x2a')),
        (True, _s7_job(3, b'\x05\x01' + read_item, b'\x00\x04\x00\x08\x07')),
        (False, _s7_ack(3, b'\x05\x01', b'\x0a', errcls=0x85, errcod=0x00)),
        (True, _tpkt_s7(struct.pack('!BBHHHH', 0x32, 7, 0, 4, 8, 8) + b'\x00\x01\x12\x04\x11\x44\x01\x00'
                        + b'\xff\x09\x00\x04\x00\x11\x00\x00')),
    ])
    # DNS caught mid-conversation (the 4SICS GeekLounge capture opens this
    # way): the answer to a query sent before recording began, then the
    # client's next query and its answer. Suricata takes the server for the
    # client, doesn't recognize the flow as DNS, and logs no DNS for it.
    old = dns_message(0x6001, 'time.example.com', 'A', rcode=5, response=True)
    new_q = dns_message(0x6002, 'time.example.com', 'A')
    new_a = dns_message(0x6002, 'time.example.com', 'A', rcode=5, response=True)
    pkts += [_udp_packet(DNS_SERVER, CLIENT, 53, 949, old), _udp_packet(CLIENT, DNS_SERVER, 949, 53, new_q),
             _udp_packet(DNS_SERVER, CLIENT, 53, 949, new_a)]
    return pkts


def write_extra_pcap(path):
    write_pcap(path, extra_packets())


# ---------------------------------------------------------------- Telnet
#
# Three sessions to TELNET_SERVER:23 - a login (option negotiation, a
# banner, a name typed a key at a time and echoed back, a password with a
# backspace in it, commands, an arrow key), a failed login at a MOXA-style
# "Account:" prompt, and a scanner's HTTP request to the Telnet port,
# which Suricata takes for HTTP.

TELNET_SERVER = '10.1.0.23'


def _keystrokes(text, echo=True):
    """Each character typed as its own segment, echoed back unless a
    password."""
    out = []
    for ch in text:
        out.append((True, ch.encode()))
        if echo and ch not in '\r\x7f':
            out.append((False, ch.encode()))
    return out


def telnet_packets():
    iac_do_ttype, iac_will_ttype = b'\xff\xfd\x18', b'\xff\xfb\x18'
    login = ([(False, iac_do_ttype), (True, iac_will_ttype),
              (False, b'\r\nUbuntu 22.04.3 LTS\r\nrouter1 login: ')]
             + _keystrokes('admin\r') + [(False, b'\r\nPassword: ')]
             + _keystrokes('s3crx\x7fet\r', echo=False)
             + [(False, b'\r\nLast login: Mon Oct  9 10:00:00 2026\r\nadmin@router1:~$ ')]
             + _keystrokes('ls -la\r') + [(False, b'\r\ntotal 0\r\nadmin@router1:~$ ')]
             + [(True, b'\x1b[A'), (False, b'ls -la'), (True, b'\x7f' * 6), (True, b'\r'), (False, b'\r\nadmin@router1:~$ ')]
             + _keystrokes('exit\r') + [(False, b'\r\nlogout\r\n')])
    failed = ([(False, iac_do_ttype), (True, iac_will_ttype),
               (False, b'\r\nMOXA EtherDevice Switch EDS-508A\r\nAccount: ')]
              + _keystrokes('admin\r') + [(False, b'\r\nPassword: ')] + _keystrokes('admin\r', echo=False)
              + [(False, b'\r\nLogin incorrect\r\n')])
    probe = [(True, b'GET / HTTP/1.0\r\n\r\n'), (False, iac_do_ttype + b'\r\nrouter2 login: ')]
    return (tcp_segments(CLIENT, TELNET_SERVER, 41023, 23, login)
            + tcp_segments(CLIENT, TELNET_SERVER, 41024, 23, failed)
            + tcp_segments(CLIENT, TELNET_SERVER, 41025, 23, probe))


def write_telnet_pcap(path):
    write_pcap(path, telnet_packets())


# ---------------------------------------------------------------- IEC 60870-5-104
#
# A controlling station (CLIENT) and a substation (IEC104_RTU:2404, common
# address 7): STARTDT, a station interrogation answered by two float
# points and terminated, a single command (on) confirmed and terminated,
# a float set point refused (negative confirmation), a packet carrying
# two messages, two interrogations sent back to back, and a confirmation
# whose request isn't in the capture.

IEC104_RTU = '10.1.0.104'
_IEC104_STATION = 7


def _apci_i(asdu, tx, rx):
    return bytes([0x68, 4 + len(asdu)]) + struct.pack('<HH', tx << 1, rx << 1) + asdu


def _apci_u(control):
    return bytes([0x68, 4, control, 0, 0, 0])


def _asdu(typeid, cause, objects, negative=False, sq=False):
    """objects: (ioa, element bytes) - each with its address unless sq."""
    vsq = len(objects) | (0x80 if sq else 0)
    cot = cause | (0x40 if negative else 0)
    body = b''
    for i, (ioa, element) in enumerate(objects):
        if not sq or i == 0:
            body += ioa.to_bytes(3, 'little')
        body += element
    return bytes([typeid, vsq, cot, 0]) + struct.pack('<H', _IEC104_STATION) + body


def iec104_packets():
    float_point = lambda value: struct.pack('<f', value) + b'\x00'          # value, quality
    interrogation = lambda cause: _asdu(100, cause, [(0, b'\x14')])         # QOI 20: station
    segments = [
        (True, _apci_u(0x07)), (False, _apci_u(0x0b)),                         # STARTDT act / con
        (True, _apci_i(interrogation(6), 0, 0)),
        (False, _apci_i(interrogation(7), 0, 1)),
        (False, _apci_i(_asdu(13, 20, [(1001, float_point(230.5)), (1002, float_point(49.98))]), 1, 1)),
        (False, _apci_i(interrogation(10), 2, 1)),
        (True, _apci_i(_asdu(45, 6, [(2001, b'\x01')]), 1, 3)),                 # single command: on
        (False, _apci_i(_asdu(45, 7, [(2001, b'\x01')]), 3, 2)),
        (False, _apci_i(_asdu(45, 10, [(2001, b'\x01')]), 4, 2)),
        (True, _apci_i(_asdu(50, 6, [(3001, struct.pack('<f', 3.25) + b'\x00')]), 2, 5)),   # set point
        (False, _apci_i(_asdu(50, 7, [(3001, struct.pack('<f', 3.25) + b'\x00')], negative=True), 5, 3)),
        # one packet, two messages: a float and a single point, spontaneous
        (False, _apci_i(_asdu(13, 3, [(1001, float_point(231.0))]), 6, 3)
                + _apci_i(_asdu(1, 3, [(1003, b'\x01')]), 7, 3)),
        # two interrogations before either is answered; replies in order
        (True, _apci_i(interrogation(6), 3, 8)), (True, _apci_i(interrogation(6), 4, 8)),
        (False, _apci_i(interrogation(7), 8, 5)), (False, _apci_i(interrogation(10), 9, 5)),
        (False, _apci_i(interrogation(7), 10, 5)), (False, _apci_i(interrogation(10), 11, 5)),
        # a clock sync confirmation whose activation the capture missed
        (False, _apci_i(_asdu(103, 7, [(0, b'\x00' * 7)]), 12, 5)),
    ]
    return tcp_segments(CLIENT, IEC104_RTU, 42404, 2404, segments)


def write_iec104_pcap(path):
    write_pcap(path, iec104_packets())


# ---------------------------------------------------------------- BACnet/IP
#
# A workstation (CLIENT:47808) and a controller (BACNET_DEVICE:47808,
# device 1047, vendor 42): Who-Is broadcasts (one with a range), the
# device's I-Am twice, a present-value read answered with 72.5 and then
# refused (unknown-property), a write of a binary output to active, a
# write and a read both sent as invoke id 4 before either reply - the
# replies in the other order, as a real client and router did - a
# reinitialize with a wrong password (password-failure), a communication
# control disabling the device for 5 minutes with its password, and a
# change-of-value notification of an analog input.

BACNET_DEVICE = '10.1.0.47'
_BACNET_BROADCAST = '10.1.255.255'
_BACNET_PORT = 47808
_ANALOG_INPUT, _ANALOG_VALUE, _BINARY_OUTPUT, _DEVICE = 0, 2, 4, 8
_PRESENT_VALUE, _STATUS_FLAGS = 85, 111


def _bacnet_ip(src, dst, apdu, expecting_reply=False, broadcast=False):
    npdu = bytes([0x01, 0x04 if expecting_reply else 0x00]) + apdu
    bvlc = bytes([0x81, 0x0b if broadcast else 0x0a]) + struct.pack('!H', 4 + len(npdu))
    return _udp_packet(src, dst, _BACNET_PORT, _BACNET_PORT, bvlc + npdu)


def _bacnet_object(obj_type, instance):
    return struct.pack('!I', (obj_type << 22) | instance)


def _ctx(number, value):
    """A context tag with a short value."""
    if len(value) <= 4:
        return bytes([(number << 4) | 0x08 | len(value)]) + value
    return bytes([(number << 4) | 0x08 | 5, len(value)]) + value


def _bacnet_string(text):
    return b'\x00' + text.encode()      # character set 0: UTF-8


def _bacnet_real(value):
    return b'\x44' + struct.pack('!f', value)


def _confirmed(invoke, service, body):
    return bytes([0x00, 0x05, invoke, service]) + body


def _read_property(invoke, obj_type, instance, prop=_PRESENT_VALUE):
    return _confirmed(invoke, 12, _ctx(0, _bacnet_object(obj_type, instance)) + _ctx(1, bytes([prop])))


def _read_property_ack(invoke, obj_type, instance, value, prop=_PRESENT_VALUE):
    return bytes([0x30, invoke, 12]) + _ctx(0, _bacnet_object(obj_type, instance)) + _ctx(1, bytes([prop])) \
        + b'\x3e' + value + b'\x3f'


def _write_property(invoke, obj_type, instance, value):
    return _confirmed(invoke, 15, _ctx(0, _bacnet_object(obj_type, instance)) + _ctx(1, bytes([_PRESENT_VALUE]))
                      + b'\x3e' + value + b'\x3f' + _ctx(4, b'\x08'))


def _bacnet_error(invoke, service, error_class, error_code):
    return bytes([0x50, invoke, service, 0x91, error_class, 0x91, error_code])


def bacnet_packets():
    device = _bacnet_object(_DEVICE, 1047)
    i_am = b'\x10\x00' + b'\xc4' + device + b'\x22\x05\xc4' + b'\x91\x00' + b'\x21\x2a'
    to_device = lambda apdu: _bacnet_ip(CLIENT, BACNET_DEVICE, apdu, expecting_reply=apdu[0] == 0x00)
    from_device = lambda apdu: _bacnet_ip(BACNET_DEVICE, CLIENT, apdu)
    cov = (b'\x10\x02' + _ctx(0, b'\x01') + _ctx(1, device) + _ctx(2, _bacnet_object(_ANALOG_INPUT, 2)) + _ctx(3, b'\x00')
           + b'\x4e' + _ctx(0, bytes([_PRESENT_VALUE])) + b'\x2e' + _bacnet_real(21.5) + b'\x2f'
           + _ctx(0, bytes([_STATUS_FLAGS])) + b'\x2e' + b'\x82\x04\x00' + b'\x2f' + b'\x4f')
    return [
        _bacnet_ip(CLIENT, _BACNET_BROADCAST, b'\x10\x08', broadcast=True),
        _bacnet_ip(CLIENT, _BACNET_BROADCAST, b'\x10\x08' + _ctx(0, b'\x64') + _ctx(1, b'\xc8'), broadcast=True),
        _bacnet_ip(BACNET_DEVICE, _BACNET_BROADCAST, i_am, broadcast=True),
        to_device(_read_property(1, _ANALOG_VALUE, 1)),
        from_device(_read_property_ack(1, _ANALOG_VALUE, 1, _bacnet_real(72.5))),
        to_device(_read_property(2, _ANALOG_VALUE, 1)),
        from_device(_bacnet_error(2, 12, 2, 32)),                                # property: unknown-property
        to_device(_write_property(3, _BINARY_OUTPUT, 3, b'\x91\x01')),          # active
        from_device(bytes([0x20, 3, 15])),
        to_device(_write_property(4, _ANALOG_VALUE, 2, _bacnet_real(50.0))),
        to_device(_read_property(4, _ANALOG_VALUE, 2)),
        from_device(_read_property_ack(4, _ANALOG_VALUE, 2, _bacnet_real(49.0))),
        from_device(bytes([0x20, 4, 15])),
        to_device(_confirmed(5, 20, _ctx(0, b'\x01') + _ctx(1, _bacnet_string('filister')))),   # warmstart
        from_device(_bacnet_error(5, 20, 5, 26)),                               # services: password-failure
        to_device(_confirmed(6, 17, _ctx(0, b'\x05') + _ctx(1, b'\x01') + _ctx(2, _bacnet_string('secret')))),
        from_device(bytes([0x20, 6, 17])),
        _bacnet_ip(BACNET_DEVICE, _BACNET_BROADCAST, i_am, broadcast=True),
        from_device(cov),
    ]


def write_bacnet_pcap(path):
    write_pcap(path, bacnet_packets())


# ---------------------------------------------------------------- OPC UA
#
# A client (CLIENT:48400) and a server (OPCUA_SERVER:4840) over one
# connection, security policy None: hello, open secure channel (mode None),
# create a session as "Fixture Client", activate it as user1 with the
# password sent in the clear, a write of 42 to ns=1;s=the.answer (Good), a
# method call refused for its one operation (BadNodeIdUnknown), a read, a
# publish answered with a ServiceFault (BadNoSubscription), and close.

OPCUA_SERVER = '10.1.0.48'
_OPCUA_ENDPOINT = 'opc.tcp://10.1.0.48:4840/fixture'


def _ua_string(text):
    if text is None:
        return struct.pack('<i', -1)
    data = text.encode() if isinstance(text, str) else text
    return struct.pack('<i', len(data)) + data


def _ua_node(ns, ident):
    if isinstance(ident, str):
        return struct.pack('<BH', 0x03, ns) + _ua_string(ident)
    if ns == 0 and ident < 256:
        return struct.pack('<BB', 0x00, ident)
    return struct.pack('<BBH', 0x01, ns, ident)


_UA_NULL_EXTOBJ = b'\x00\x00\x00'


def _ua_request_header(handle):
    return _ua_node(0, 0) + struct.pack('<qII', 0, handle, 0) + _ua_string(None) + struct.pack('<I', 0) + _UA_NULL_EXTOBJ


def _ua_response_header(handle, result=0):
    return struct.pack('<qII', 0, handle, result) + b'\x00' + struct.pack('<i', -1) + _UA_NULL_EXTOBJ


def _ua_message(kind, header, body):
    return kind + b'F' + struct.pack('<I', 8 + len(header) + len(body)) + header + body


def _ua_msg(service, request_id, body):
    header = struct.pack('<IIII', 7, 1, request_id + 1, request_id)
    return _ua_message(b'MSG', header, struct.pack('<BBH', 0x01, 0, service) + body)


def opcua_packets():
    hello = _ua_message(b'HEL', b'', struct.pack('<IIIII', 0, 65536, 65536, 0, 0) + _ua_string(_OPCUA_ENDPOINT))
    ack = _ua_message(b'ACK', b'', struct.pack('<IIIII', 0, 65536, 65536, 0, 0))
    opn_header = struct.pack('<I', 0) + _ua_string('http://opcfoundation.org/UA/SecurityPolicy#None') \
        + _ua_string(None) + _ua_string(None) + struct.pack('<II', 1, 1)
    open_request = _ua_message(b'OPN', opn_header, struct.pack('<BBH', 0x01, 0, 446) + _ua_request_header(1)
                               + struct.pack('<III', 0, 0, 1) + _ua_string(b'') + struct.pack('<I', 3600000))
    open_response = _ua_message(b'OPN', opn_header, struct.pack('<BBH', 0x01, 0, 449) + _ua_response_header(1)
                                + struct.pack('<IIIqI', 0, 7, 1, 0, 3600000) + _ua_string(b''))
    client = (_ua_string('urn:fixture:client') + _ua_string('urn:fixture') + b'\x02' + _ua_string('Fixture Client')
              + struct.pack('<I', 1) + _ua_string(None) + _ua_string(None) + struct.pack('<i', 0))
    create = _ua_msg(461, 2, _ua_request_header(2) + client + _ua_string(None) + _ua_string(_OPCUA_ENDPOINT)
                     + _ua_string('Fixture Session') + _ua_string(None) + _ua_string(None) + struct.pack('<dI', 60000.0, 0))
    create_response = _ua_msg(464, 2, _ua_response_header(2) + _ua_node(1, 1001) + _ua_node(1, 1002)
                              + struct.pack('<d', 60000.0) + _ua_string(None) + _ua_string(None)
                              + struct.pack('<ii', 0, 0) + _ua_string(None) + _ua_string(None) + struct.pack('<I', 0))
    token = _ua_string('username-policy') + _ua_string('user1') + _ua_string(b's3cret') + _ua_string(None)
    activate = _ua_msg(467, 3, _ua_request_header(3) + _ua_string(None) + _ua_string(None) + struct.pack('<ii', 0, 0)
                       + _ua_node(0, 324) + b'\x01' + struct.pack('<i', len(token)) + token
                       + _ua_string(None) + _ua_string(None))
    activate_response = _ua_msg(470, 3, _ua_response_header(3) + _ua_string(None) + struct.pack('<ii', 0, 0))
    write = _ua_msg(673, 4, _ua_request_header(4) + struct.pack('<i', 1) + _ua_node(1, 'the.answer')
                    + struct.pack('<I', 13) + _ua_string(None) + b'\x01' + b'\x06' + struct.pack('<i', 42))
    write_response = _ua_msg(676, 4, _ua_response_header(4) + struct.pack('<iI', 1, 0) + struct.pack('<i', 0))
    call = _ua_msg(712, 5, _ua_request_header(5) + struct.pack('<i', 1) + _ua_node(0, 85) + _ua_node(1, 62541)
                   + struct.pack('<i', 1) + b'\x0c' + _ua_string('Hello'))
    call_response = _ua_msg(715, 5, _ua_response_header(5) + struct.pack('<i', 1) + struct.pack('<I', 0x80340000)
                            + struct.pack('<iii', -1, -1, -1) + struct.pack('<i', -1))
    read = _ua_msg(631, 6, _ua_request_header(6) + struct.pack('<dI', 0.0, 0) + struct.pack('<i', 1)
                   + _ua_node(1, 'the.answer') + struct.pack('<I', 13) + _ua_string(None) + struct.pack('<H', 0)
                   + _ua_string(None))
    read_response = _ua_msg(634, 6, _ua_response_header(6) + struct.pack('<i', 1) + b'\x01' + b'\x06'
                            + struct.pack('<i', 42) + struct.pack('<i', 0))
    publish = _ua_msg(826, 7, _ua_request_header(7) + struct.pack('<i', 0))
    fault = _ua_msg(397, 7, _ua_response_header(7, 0x80790000))
    close = _ua_msg(473, 8, _ua_request_header(8) + b'\x01')
    close_response = _ua_msg(476, 8, _ua_response_header(8))
    segments = [(True, hello), (False, ack), (True, open_request), (False, open_response), (True, create),
                (False, create_response), (True, activate), (False, activate_response), (True, write),
                (False, write_response), (True, call), (False, call_response), (True, read), (False, read_response),
                (True, publish), (False, fault), (True, close), (False, close_response)]
    return tcp_segments(CLIENT, OPCUA_SERVER, 48400, 4840, segments)


def write_opcua_pcap(path):
    write_pcap(path, opcua_packets())


# ---------------------------------------------------------------- MMS
#
# A SCADA client (CLIENT:49152) and a relay (MMS_SERVER:102). The OSI
# connection (COTP connect, session connect carrying the presentation and
# ACSE association with MMS initiate, and its accept) is a real ICCP
# client's and server's, from ITI's IEC 61850 samples - tshark decodes MMS
# only after seeing which presentation context carries it. Then: a read of
# IED1LD0/LLN0$ST$Mod$stVal (1), Identify (Fixture Vendor, Fixture Relay,
# 1.2), a write to XCBR1$CO$Pos$Oper (an operate, success), a write to
# XCBR1$CO$Pos$SBOw (a select, refused object-access-denied), a stop of
# program Fixture_App refused (vmd-state: 2), an information report, and
# conclude.

MMS_SERVER = '10.1.0.102'


def _ber_tlv(tag, value):
    """BER: a tag (one byte, or bytes for a high tag number) and length."""
    n = len(value)
    length = bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return (tag if isinstance(tag, bytes) else bytes([tag])) + length + value


def _mms_tpkt(mms):
    """An MMS PDU in a COTP data TPDU, session give-tokens and data SPDUs,
    and presentation user data (context 3, MMS)."""
    pdv = _ber_tlv(0x61, _ber_tlv(0x30, b'\x02\x01\x03' + _ber_tlv(0xa0, mms)))
    payload = b'\x02\xf0\x80' + b'\x01\x00\x01\x00' + pdv
    return struct.pack('!BBH', 3, 0, 4 + len(payload)) + payload


def _mms_name(domain, item):
    return _ber_tlv(0xa1, _ber_tlv(0x1a, domain.encode()) + _ber_tlv(0x1a, item.encode()))


def _mms_variable(domain, item):
    return _ber_tlv(0xa0, _ber_tlv(0x30, _ber_tlv(0xa0, _mms_name(domain, item))))


def _mms_request(invoke, service):
    return _ber_tlv(0xa0, b'\x02\x01' + bytes([invoke]) + service)


def _mms_response(invoke, service):
    return _ber_tlv(0xa1, b'\x02\x01' + bytes([invoke]) + service)


def mms_packets():
    cr = bytes.fromhex('0300001611e00000b00100c0010ac1020001c2020002')
    cc = bytes.fromhex('0300000e09d0b001180200c0010a')
    associate = bytes.fromhex(
        '030000c502f0800dbc0506130100160102140200023302000134020002c1a63181a3a003800101a2819b800207808104000000018204'
        '00000002a423300f0201010604520100013004060251013010020103060528ca220201300406025101880206006160305e020101a059'
        '605780020780a107060528ca220101a20406022902a303020102a60406022901a703020101be32283006025101020103a027a8258002'
        '7d00810114820114830104a416800101810305fb00820c036e1d000000000064000198')
    accept = bytes.fromhex(
        '0300009e02f0800e95050613010016010214020002c187318184a003800101a27d80020780830400000002a512300780010081025101'
        '300780010081025101615d305b020101a056615480020780a107060528ca220101a203020100a305a103020100a40406022902a50302'
        '0102be2e282c020103a027a92580027d00810114820114830104a416800101810305fb00820c036e1d000000000064000198')
    read = _mms_request(1, _ber_tlv(0xa4, _ber_tlv(0xa1, _mms_variable('IED1LD0', 'LLN0$ST$Mod$stVal'))))
    read_response = _mms_response(1, _ber_tlv(0xa4, _ber_tlv(0xa1, b'\x85\x01\x01')))
    identify = _mms_request(2, b'\x82\x00')
    identify_response = _mms_response(2, _ber_tlv(0xa2, _ber_tlv(0x80, b'Fixture Vendor') + _ber_tlv(0x81, b'Fixture Relay')
                                                  + _ber_tlv(0x82, b'1.2')))
    operate_value = _ber_tlv(0xa0, _ber_tlv(0xa2, b'\x83\x01\xff' + b'\x85\x01\x00'))
    operate = _mms_request(3, _ber_tlv(0xa5, _mms_variable('IED1LD0', 'XCBR1$CO$Pos$Oper') + operate_value))
    operate_response = _mms_response(3, _ber_tlv(0xa5, b'\x81\x00'))
    select = _mms_request(4, _ber_tlv(0xa5, _mms_variable('IED1LD0', 'XCBR1$CO$Pos$SBOw') + operate_value))
    select_response = _mms_response(4, _ber_tlv(0xa5, b'\x80\x01\x03'))
    stop = _mms_request(5, _ber_tlv(b'\xbf\x29', _ber_tlv(0x80, b'Fixture_App')))
    stop_error = _ber_tlv(0xa2, b'\x80\x01\x05' + _ber_tlv(0xa2, _ber_tlv(0xa0, b'\x80\x01\x02')))
    report = _ber_tlv(0xa3, _ber_tlv(0xa0, _ber_tlv(0xa1, _mms_name('IED1LD0', 'LLN0$dsTrips'))
                                     + _ber_tlv(0xa0, b'\x85\x01\x07')))
    segments = [(True, cr), (False, cc), (True, associate), (False, accept)] + [
        (client, _mms_tpkt(pdu)) for client, pdu in (
            (True, read), (False, read_response), (True, identify), (False, identify_response),
            (True, operate), (False, operate_response), (True, select), (False, select_response),
            (True, stop), (False, stop_error), (False, report), (True, b'\x8b\x00'), (False, b'\x8c\x00'))]
    return tcp_segments(CLIENT, MMS_SERVER, 49152, 102, segments)


def write_mms_pcap(path):
    write_pcap(path, mms_packets())


# ---------------------------------------------------------------- GOOSE
#
# One relay (GOOSE_PUBLISHER) publishing control block LD0/LLN0$GO$gcb1:
# state 1 sent three times (heartbeat), state 2 with its trip value turned
# true, then stNum jumping to 10 and falling back to 1 - what a forged
# publisher looks like next to the real one.

GOOSE_PUBLISHER = '00:30:a7:00:00:01'
_GOOSE_DEST = bytes.fromhex('010ccd010001')


def _ber(tag, value):
    return bytes([tag, len(value)]) + value


def _goose(stnum, sqnum, trip):
    data = _ber(0x83, b'\x01' if trip else b'\x00') + _ber(0x84, b'\x06\x40') + _ber(0x85, b'\x07')
    pdu = (_ber(0x80, b'IED1LD0/LLN0$GO$gcb1') + _ber(0x81, b'\x07\xd0') + _ber(0x82, b'IED1LD0/LLN0$Trips')
           + _ber(0x83, b'Trips') + _ber(0x84, b'\x65\x53\xf1\x00\x00\x00\x00\x0a')
           + _ber(0x85, bytes([stnum])) + _ber(0x86, bytes([sqnum])) + _ber(0x87, b'\x00')
           + _ber(0x88, b'\x01') + _ber(0x89, b'\x00') + _ber(0x8a, b'\x03') + _ber(0xab, data))
    apdu = _ber(0x61, pdu)
    header = struct.pack('!HHHH', 0x0001, 8 + len(apdu), 0, 0)
    return _GOOSE_DEST + bytes.fromhex(GOOSE_PUBLISHER.replace(':', '')) + struct.pack('!H', 0x88b8) + header + apdu


def goose_packets():
    return [_goose(1, 0, False), _goose(1, 1, False), _goose(1, 2, False), _goose(2, 0, True),
            _goose(10, 0, True), _goose(1, 0, False)]


def write_goose_pcap(path):
    write_pcap(path, goose_packets())


# ---------------------------------------------------------------- MongoDB
#
# An open MongoDB server (MONGO_SERVER:27017). One client (CLIENT:50000,
# PyMongo) says isMaster by OP_QUERY, then by OP_MSG asks the version
# (6.0.5), lists the databases (admin, shop), drops shop, and inserts a
# ransom note into READ_ME_TO_RECOVER_YOUR_DATA.README - all answered ok,
# with no login. Another (CLIENT:50001) tries SCRAM-SHA-256 as alice
# (refused), then createUser backdoor with role root (refused, unauthorized).

MONGO_SERVER = '10.1.0.27'


def _bson(*elements):
    body = b''
    for name, value in elements:
        key = name.encode() + b'\x00'
        if isinstance(value, bool):
            body += b'\x08' + key + (b'\x01' if value else b'\x00')
        elif isinstance(value, int):
            body += b'\x10' + key + struct.pack('<i', value)
        elif isinstance(value, float):
            body += b'\x01' + key + struct.pack('<d', value)
        elif isinstance(value, str):
            data = value.encode() + b'\x00'
            body += b'\x02' + key + struct.pack('<i', len(data)) + data
        elif isinstance(value, bytes):
            body += b'\x05' + key + struct.pack('<iB', len(value), 0) + value
        elif isinstance(value, list):
            body += b'\x04' + key + _bson(*[(str(i), v) for i, v in enumerate(value)])
        else:                          # a subdocument, as a tuple of pairs
            body += b'\x03' + key + _bson(*value)
    return struct.pack('<i', 4 + len(body) + 1) + body + b'\x00'


def _mongo_message(opcode, request_id, response_to, payload):
    return struct.pack('<iiii', 16 + len(payload), request_id, response_to, opcode) + payload


def _mongo_query(request_id, namespace, doc):
    return _mongo_message(2004, request_id, 0, struct.pack('<i', 0) + namespace.encode() + b'\x00'
                          + struct.pack('<ii', 0, -1) + doc)


def _mongo_reply(request_id, doc):
    return _mongo_message(1, 1000 + request_id, request_id, struct.pack('<iqii', 0, 0, 0, 1) + doc)


def _mongo_msg(request_id, response_to, doc, sequence=None):
    sections = b'\x00' + doc
    if sequence:
        identifier, docs = sequence
        data = identifier.encode() + b'\x00' + b''.join(docs)
        sections += b'\x01' + struct.pack('<i', 4 + len(data)) + data
    return _mongo_message(2013, request_id, response_to, struct.pack('<I', 0) + sections)


def mongodb_packets():
    ok = ('ok', 1.0)
    client = (('driver', (('name', 'PyMongo'), ('version', '4.6.3'))),
              ('os', (('type', 'Linux'), ('name', 'Linux'), ('version', '6.1.0'))), ('platform', 'CPython 3.11.2'))
    note = _bson(('content', 'All your data is backed up. Send 0.01 BTC to 1AbcFixture to recover it.'),
                 ('email', 'recover@example.net'))
    attacker = [
        (True, _mongo_query(1, 'admin.$cmd', _bson(('isMaster', 1), ('client', client)))),
        (False, _mongo_reply(1, _bson(('ismaster', True), ('maxWireVersion', 17), ok))),
        (True, _mongo_msg(2, 0, _bson(('buildInfo', 1), ('$db', 'admin')))),
        (False, _mongo_msg(1002, 2, _bson(('version', '6.0.5'), ok))),
        (True, _mongo_msg(3, 0, _bson(('listDatabases', 1), ('$db', 'admin')))),
        (False, _mongo_msg(1003, 3, _bson(('databases', [(('name', 'admin'), ('sizeOnDisk', 40960)),
                                                          (('name', 'shop'), ('sizeOnDisk', 81920))]), ok))),
        (True, _mongo_msg(4, 0, _bson(('dropDatabase', 1), ('$db', 'shop')))),
        (False, _mongo_msg(1004, 4, _bson(('dropped', 'shop'), ok))),
        (True, _mongo_msg(5, 0, _bson(('insert', 'README'), ('$db', 'READ_ME_TO_RECOVER_YOUR_DATA')),
                          sequence=('documents', [note]))),
        (False, _mongo_msg(1005, 5, _bson(('n', 1), ok))),
    ]
    refused = ('ok', 0.0)
    login = [
        (True, _mongo_msg(6, 0, _bson(('saslStart', 1), ('mechanism', 'SCRAM-SHA-256'),
                                      ('payload', b'n,,n=alice,r=fixturenonce'), ('$db', 'admin')))),
        (False, _mongo_msg(1006, 6, _bson(('conversationId', 1), ('done', False), ('payload', b'r=fixturenonce1,s=c2FsdA==,i=15000'), ok))),
        (True, _mongo_msg(7, 0, _bson(('saslContinue', 1), ('conversationId', 1), ('payload', b'c=biws,r=fixturenonce1,p=proof'),
                                      ('$db', 'admin')))),
        (False, _mongo_msg(1007, 7, _bson(refused, ('errmsg', 'Authentication failed.'), ('code', 18),
                                          ('codeName', 'AuthenticationFailed')))),
        (True, _mongo_msg(8, 0, _bson(('createUser', 'backdoor'), ('pwd', 'hunter2'),
                                      ('roles', [(('role', 'root'), ('db', 'admin'))]), ('$db', 'admin')))),
        (False, _mongo_msg(1008, 8, _bson(refused, ('errmsg', 'command createUser requires authentication'), ('code', 13),
                                          ('codeName', 'Unauthorized')))),
    ]
    return (tcp_segments(CLIENT, MONGO_SERVER, 50000, 27017, attacker)
            + tcp_segments(CLIENT, MONGO_SERVER, 50001, 27017, login))


def write_mongodb_pcap(path):
    write_pcap(path, mongodb_packets())


# ---------------------------------------------------------------- rsh, rlogin, rexec
#
# One host (RSH_SERVER) running all three. alice runs `id; uname -a` as
# root over rsh (accepted, with its output); operator's rexec of a reboot
# is refused (Login incorrect); bob logs in over rlogin, types his password
# at the prompt, then ls and exit; and a scanner sends rsh an HTTP request,
# which it answers with an error.

RSH_SERVER = '10.1.0.51'


def rsh_packets():
    rsh = [(True, b'0\x00alice\x00root\x00id; uname -a\x00'), (False, b'\x00'),
           (False, b'uid=0(root) gid=0(root) groups=0(root)\nLinux plc 5.10.0\n')]
    rexec = [(True, b'0\x00operator\x00s3cret\x00shutdown -r now\x00'), (False, b'\x01Login incorrect.\n')]
    rlogin = [(True, b'\x00bob\x00bob\x00xterm/38400\x00'), (False, b'\x00'), (False, b'Password: '),
              (True, b'hunter2\r'), (False, b'\r\nLast login: Mon Nov  2 09:00\r\n$ '), (True, b'ls\r'),
              (False, b'ls\r\nnotes.txt\r\n$ '), (True, b'exit\r')]
    probe = [(True, b'GET / HTTP/1.0\r\n\r\n'), (False, b'\x01Can not make pipe\n')]
    return (tcp_segments(CLIENT, RSH_SERVER, 1022, 514, rsh) + tcp_segments(CLIENT, RSH_SERVER, 1023, 512, rexec)
            + tcp_segments(CLIENT, RSH_SERVER, 1021, 513, rlogin) + tcp_segments(CLIENT, RSH_SERVER, 40000, 514, probe))


def write_rsh_pcap(path):
    write_pcap(path, rsh_packets())


# ---------------------------------------------------------------- Omron FINS
#
# FINS_STATION (node 10) and FINS_PLC (node 1), over UDP 9600: a Controller
# Data Read (a CJ2M-CPU31, version 02.01), a DM read, a DM write, a switch
# to MONITOR mode, a Stop the PLC refuses, and a Program Area Protect
# Clear with the wrong password. Over FINS/TCP, CLIENT:41900 exchanges
# node addresses and forces a CIO word. FINS_SCANNER's Controller Data
# Read (source node 99, as internet scanners send it) gets no answer.

FINS_STATION, FINS_PLC, FINS_SCANNER = '10.1.0.83', '10.1.0.84', '10.1.0.85'


def _fins(command, sid, data=b'', response=None, dst=1, src=10):
    if response is None:
        header = bytes([0x80, 0, 2, 0, dst, 0, 0, src, 0, sid])
        return header + struct.pack('!H', command) + data
    return bytes([0xc0, 0, 2, 0, src, 0, 0, dst, 0, sid]) + struct.pack('!HH', command, response) + data


def _fins_tcp(command, data):
    return b'FINS' + struct.pack('!III', 8 + len(data), command, 0) + data


def fins_packets():
    model = b'CJ2M-CPU31'.ljust(20) + b'02.01'.ljust(20) + b'\x00' * 40 + bytes(12)
    udp = [(_fins(0x0501, 1), _fins(0x0501, 1, model, 0)),
           (_fins(0x0101, 2, b'\x82\x00\x64\x00\x00\x02'), _fins(0x0101, 2, b'\x12\x34\x56\x78', 0)),
           (_fins(0x0102, 3, b'\x82\x00\x64\x00\x00\x02\xff\xff\x00\x01'), _fins(0x0102, 3, b'', 0)),
           (_fins(0x0401, 4, b'\xff\xff\x02'), _fins(0x0401, 4, b'', 0)),
           (_fins(0x0402, 5, b'\xff\xff'), _fins(0x0402, 5, b'', 0x2201)),
           (_fins(0x0305, 6, b'\xff\xff\x00\x00\x00\x00\x00\xff\xff\xff\xff' + b'1234'), _fins(0x0305, 6, b'', 0x2602))]
    packets = []
    for request, reply in udp:
        packets += [_udp_packet(FINS_STATION, FINS_PLC, 9600, 9600, request), _udp_packet(FINS_PLC, FINS_STATION, 9600, 9600, reply)]
    packets.append(_udp_packet(FINS_SCANNER, FINS_PLC, 41950, 9600, _fins(0x0501, 0, src=99, dst=0)))
    tcp = [(True, _fins_tcp(0, b'\x00\x00\x00\x00')), (False, _fins_tcp(1, b'\x00\x00\x00\x0b\x00\x00\x00\x01')),
           (True, _fins_tcp(2, _fins(0x2301, 7, b'\x00\x01\x00\x01\xb0\x00\x0a\x00', src=11))),
           (False, _fins_tcp(2, _fins(0x2301, 7, b'', 0, src=11)))]
    return packets + tcp_segments(CLIENT, FINS_PLC, 41900, 9600, tcp)


def write_fins_pcap(path):
    write_pcap(path, fins_packets())


# ---------------------------------------------------------------- HART-IP
#
# HART_HOST:41960 opens a TCP session with HART_GATEWAY as a primary
# master and asks its device for its identity (by polling address 0: a
# Rosemount-made type 0x264e, ID 0000d2), its tag (PT-101) and its PV;
# writes its tag (to PT-1O1), puts its loop current at a fixed 20 mA and
# asks for a device reset, which the device refuses (access restricted).
# HART_SCANNER's UDP Session Initiate gets no answer, nor does a scanner's
# text template that tshark takes for HART-IP.

HART_HOST, HART_GATEWAY, HART_SCANNER = '10.1.0.86', '10.1.0.87', '10.1.0.88'
_HART_LONG = bytes.fromhex('a64e0000d2')        # (the primary master bit set)


def _hart_ip(kind, message, seq, body=b'', status=0):
    return struct.pack('!BBBBHH', 1, kind, message, status, seq, 8 + len(body)) + body


def _hart_frame(delimiter, address, command, data):
    frame = bytes([delimiter]) + address + bytes([command, len(data)]) + data
    return frame + bytes([functools.reduce(lambda a, b: a ^ b, frame)])


def _hart_packed(text, length):
    bits = ''.join(format(ord(c) & 0x3f, '06b') for c in text.ljust(length * 4 // 3))
    return int(bits, 2).to_bytes(length, 'big')


def hart_ip_packets():
    identity = (b'\xfe\x26\x4e\x05\x07\x04\x01\x0e\x0c\x00\x00\xd2\x05\x02\x00\x02\xd0\x00\x26\x00\x26\x84')
    request = lambda seq, command, data=b'', short=False: _hart_ip(0, 3, seq, _hart_frame(
        0x02 if short else 0x82, b'\x80' if short else _HART_LONG, command, data))
    reply = lambda seq, command, data=b'', code=0, short=False: _hart_ip(1, 3, seq, _hart_frame(
        0x06 if short else 0x86, b'\x80' if short else _HART_LONG, command, bytes([code, 0]) + data))
    tag = _hart_packed('PT-101', 6) + _hart_packed('PRESSURE', 12) + b'\x01\x0b\x7e'
    session = [(True, _hart_ip(0, 0, 1, b'\x01\x00\x00\xea\x60')), (False, _hart_ip(1, 0, 1, b'\x01\x00\x00\xea\x60')),
               (True, request(2, 0, short=True)), (False, reply(2, 0, identity, short=True)),
               (True, request(3, 13)), (False, reply(3, 13, tag)),
               (True, request(4, 1)), (False, reply(4, 1, b'\x0c' + struct.pack('!f', 4.25))),
               (True, request(5, 18, _hart_packed('PT-1O1', 6) + _hart_packed('PRESSURE', 12) + b'\x01\x0b\x7e')),
               (False, reply(5, 18, _hart_packed('PT-1O1', 6) + _hart_packed('PRESSURE', 12) + b'\x01\x0b\x7e')),
               (True, request(6, 40, struct.pack('!f', 20.0))), (False, reply(6, 40, struct.pack('!f', 20.0))),
               (True, request(7, 42)), (False, reply(7, 42, code=16)),
               (True, _hart_ip(0, 1, 8)), (False, _hart_ip(1, 1, 8))]
    return (tcp_segments(HART_HOST, HART_GATEWAY, 41960, 5094, session)
            + [_udp_packet(HART_SCANNER, HART_GATEWAY, 41970, 5094, _hart_ip(0, 0, 1, b'\x01\x00\x00\xea\x60')),
               _udp_packet(HART_SCANNER, HART_GATEWAY, 23318, 5094,
                           bytes.fromhex('7b01001631333931313131313131327b7b2e69707d7d7b7b2e706f72747d7d7b'))])


def write_hart_ip_pcap(path):
    write_pcap(path, hart_ip_packets())


# ---------------------------------------------------------------- memcached
#
# Shaped on a capture of memcached 1.6.38. CLIENT:41600 uses the text
# protocol: version, a session stored, read and deleted, a counter, a
# command memcached doesn't know, and flush_all. CLIENT:41601 stores a
# 3000-byte value whose lines look like commands. CLIENT:41602 asks for
# stats over TCP, CLIENT:41603 speaks the binary protocol. Over UDP,
# MEMCACHE_VICTIM:41700 (a forged source, as an attack's would be) asks
# for stats and gets three datagrams back; a scanner's stats items gets
# nothing, another sends random bytes to the port, and one random-byte
# packet comes from port 11211 itself.

MEMCACHE_SERVER, MEMCACHE_VICTIM, MEMCACHE_SCANNER = '198.51.100.97', '10.1.0.81', '10.1.0.82'


def _memcache_udp(request_id, seq, total, payload):
    return struct.pack('!HHHH', request_id, seq, total, 0) + payload


def _memcache_binary(magic, opcode, key=b'', extras=b'', value=b'', status=0, opaque=0):
    return struct.pack('!BBHBBHIIQ', magic, opcode, len(key), len(extras), 0, status,
                       len(key) + len(extras) + len(value), opaque, 0) + extras + key + value


def memcache_packets():
    text = [(True, b'version\r\n'), (False, b'VERSION 1.6.38\r\n'),
            (True, b'set session:4711 0 3600 16\r\n{"user":"alice"}\r\n'), (False, b'STORED\r\n'),
            (True, b'get session:4711\r\n'), (False, b'VALUE session:4711 0 16\r\n{"user":"alice"}\r\nEND\r\n'),
            (True, b'incr hits 1\r\n'), (False, b'NOT_FOUND\r\n'), (True, b'add hits 0 0 1\r\n5\r\n'),
            (False, b'STORED\r\n'), (True, b'incr hits 3\r\n'), (False, b'8\r\n'),
            (True, b'delete session:4711\r\n'), (False, b'DELETED\r\n'), (True, b'bogus\r\n'), (False, b'ERROR\r\n'),
            (True, b'flush_all\r\n'), (False, b'OK\r\n')]
    value = (b'flush_all\r\nshutdown\r\n' * 150)[:3000]
    blob = [(True, b'set blob 0 0 3000\r\n' + value + b'\r\n'), (False, b'STORED\r\n')]
    stats_reply = b''.join(b'STAT %s %s\r\n' % (k, v) for k, v in (
        (b'pid', b'1'), (b'uptime', b'86400'), (b'version', b'1.6.38'), (b'curr_connections', b'12'),
        (b'curr_items', b'52310'), (b'total_items', b'913204'), (b'bytes', b'48211904'))) + b'END\r\n'
    stats = [(True, b'stats\r\n'), (False, stats_reply)]
    binary = [(True, _memcache_binary(0x80, 0x0b, opaque=1)), (False, _memcache_binary(0x81, 0x0b, value=b'1.6.38', opaque=1)),
              (True, _memcache_binary(0x80, 0x01, b'bin:key', struct.pack('!II', 0, 0), b'binary value', opaque=2)),
              (False, _memcache_binary(0x81, 0x01, opaque=2)),
              (True, _memcache_binary(0x80, 0x00, b'nope', opaque=3)),
              (False, _memcache_binary(0x81, 0x00, value=b'Not found', status=1, opaque=3))]
    big = b''.join(b'STAT items:%d:number %d\r\n' % (i, i * 7) for i in range(1, 400)) + b'END\r\n'
    parts = [big[i:i + 1400] for i in range(0, len(big), 1400)]
    out = (tcp_segments(CLIENT, MEMCACHE_SERVER, 41600, 11211, text) + tcp_segments(CLIENT, MEMCACHE_SERVER, 41601, 11211, blob)
           + tcp_segments(CLIENT, MEMCACHE_SERVER, 41602, 11211, stats) + tcp_segments(CLIENT, MEMCACHE_SERVER, 41603, 11211, binary))
    udp = [(MEMCACHE_VICTIM, MEMCACHE_SERVER, 41700, 11211, _memcache_udp(0x1234, 0, 1, b'stats items\r\n'))]
    udp += [(MEMCACHE_SERVER, MEMCACHE_VICTIM, 11211, 41700, _memcache_udp(0x1234, i, len(parts), part))
            for i, part in enumerate(parts)]
    udp += [(MEMCACHE_SCANNER, MEMCACHE_SERVER, 41800, 11211, _memcache_udp(0, 0, 1, b'stats items\r\n')),
            (MEMCACHE_SCANNER, MEMCACHE_SERVER, 41801, 11211, bytes.fromhex('392e3419365d673a1a1d6d75570211')),
            (MEMCACHE_SCANNER, MEMCACHE_SERVER, 11211, 8081, bytes.fromhex('5c2e50616a0e557f330a1f13acef'))]
    return out + [_udp_packet(*p) for p in udp]


def write_memcache_pcap(path):
    write_pcap(path, memcache_packets())


# ---------------------------------------------------------------- Oracle TNS
#
# CLIENT:41500 connects to TNS_SERVER's listener for service FIXDB and logs
# in as sys from sqlplus on host attacker (OS user mallory), then creates
# a user (its password S3cret!), grants it DBA, reads payroll twice, runs
# a long query sent in chunks that fails (ORA-00942), drops a table and
# inserts a row. CLIENT:41501 logs in as system and is refused (ORA-01017).
# CLIENT:41502 asks for SID ORCLX, which the listener doesn't know
# (ERR=12505), CLIENT:41503 sends the listener a version command, and
# CLIENT:41504 is redirected to another port.

TNS_SERVER = '198.51.100.96'
TNS_LONG_QUERY = ('SELECT owner, table_name, num_rows FROM dba_tables WHERE owner NOT IN '
                  "('SYS', 'SYSTEM', 'OUTLN', 'DBSNMP') AND num_rows > 1000 ORDER BY num_rows DESC")


def _tns(kind, body):
    return struct.pack('!HHBBH', 8 + len(body), 0, kind, 0, 0) + body


def _tns_connect(descriptor):
    data = descriptor.encode()
    return _tns(1, struct.pack('!HHHHHHHHHHIBB', 314, 300, 0x0c41, 8192, 32767, 0x7f08, 0, 0x0100, len(data), 34,
                               2048, 0x41, 0x41) + data)


def _tns_data(payload):
    return _tns(6, b'\x00\x00' + payload)


def _tns_kv(name, value=''):
    out = struct.pack('<I', len(name)) + bytes([len(name)]) + name.encode()
    out += struct.pack('<I', len(value)) + bytes([len(value)]) + value.encode() if value else b'\x00' * 4
    return out + b'\x00' * 4


def _tns_login(function, user, pairs):
    return _tns_data(bytes([3, function, 2, 1, 1, 0, 0, 0, 1, 1, 1, 1]) + bytes([len(user)]) + user.encode()
                     + b''.join(_tns_kv(*pair) for pair in pairs))


def _tns_sql_call(sql, chunked=False):
    text = sql.encode()
    if chunked:
        string = b'\xfe' + b''.join(bytes([len(text[i:i + 64])]) + text[i:i + 64] for i in range(0, len(text), 64)) + b'\x00'
    else:
        string = bytes([len(text)]) + text
    return _tns_data(b'\x03\x5e\x05\x61\x80\x00\x00\x00\x00\x00\x00\x01' + string + b'\x01\x00\x00\x00\x00')


def _tns_reply(error=None):
    return _tns_data(b'\x04\x01\x00\x00\x00\x00\x00\x00' + (error.encode() + b'\n' if error else b''))


def _tns_session(user, final):
    keys = [('AUTH_TERMINAL', 'pts/1'), ('AUTH_PROGRAM_NM', 'sqlplus@attacker (TNS V1-V3)'),
            ('AUTH_MACHINE', 'attacker'), ('AUTH_PID', '4242'), ('AUTH_SID', 'mallory')]
    return [(True, _tns_login(0x76, user, keys)),
            (False, _tns_data(b'\x08\x02' + _tns_kv('AUTH_SESSKEY', 'AB' * 32) + _tns_kv('AUTH_VFR_DATA'))),
            (True, _tns_login(0x73, user, [('AUTH_SESSKEY', 'CD' * 32), ('AUTH_PASSWORD', 'EF' * 32)] + keys)),
            (False, final)]


def tns_packets():
    descriptor = ('(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=198.51.100.96)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=FIXDB)'
                  '(CID=(PROGRAM=sqlplus@attacker)(HOST=attacker)(USER=mallory))))')
    accept = _tns(2, struct.pack('!HHHHHHHBB', 314, 0x0c01, 8192, 32767, 0x0100, 0, 24, 0x41, 0x41))
    welcome = _tns_data(b'\x08\x05' + _tns_kv('AUTH_VERSION_STRING', '- Production') + _tns_kv('AUTH_SESSION_ID', '42')
                        + _tns_kv('AUTH_DBNAME', 'FIXDB') + _tns_kv('AUTH_INSTANCENAME', 'fixdb1')
                        + _tns_kv('AUTH_SC_SERVER_HOST', 'dbhost'))
    session = [(True, _tns_connect(descriptor)), (False, accept)] + _tns_session('sys', welcome)
    for sql, chunked, error in (('create user backdoor identified by S3cret!', False, None),
                                ('grant dba to backdoor', False, None), ('SELECT * FROM payroll', False, None),
                                ('SELECT * FROM payroll', False, 'ORA-01403: no data found'),
                                (TNS_LONG_QUERY, True, 'ORA-00942: table or view does not exist'),
                                ('drop table audit_log', False, None), ('insert into payroll values (1, 99000)', False, None)):
        session += [(True, _tns_sql_call(sql, chunked)), (False, _tns_reply(error))]
    refused_login = [(True, _tns_connect(descriptor)), (False, accept)] + _tns_session(
        'system', _tns_reply('ORA-01017: invalid username/password; logon denied'))
    unknown = [(True, _tns_connect('(DESCRIPTION=(CONNECT_DATA=(SID=ORCLX)(CID=(PROGRAM=odat)(HOST=attacker)(USER=mallory)))'
                                   '(ADDRESS=(PROTOCOL=TCP)(HOST=198.51.100.96)(PORT=1521)))')),
               (False, _tns(4, b'\x22\x00' + struct.pack('!H', 56) + b'(DESCRIPTION=(TMP=)(VSNNUM=153092352)(ERR=12505))'))]
    command = [(True, _tns_connect('(CONNECT_DATA=(COMMAND=version))')),
               (False, _tns(4, b'\x22\x00' + struct.pack('!H', 62)
                            + b'(DESCRIPTION=(TMP=)(VSNNUM=318767104)(ERR=0)(ALIAS=LISTENER))'))]
    redirect = b'(ADDRESS=(PROTOCOL=tcp)(HOST=198.51.100.96)(PORT=40123))'
    redirected = [(True, _tns_connect(descriptor)), (False, _tns(5, struct.pack('!H', len(redirect)) + redirect))]
    return (tcp_segments(CLIENT, TNS_SERVER, 41500, 1521, session) + tcp_segments(CLIENT, TNS_SERVER, 41501, 1521, refused_login)
            + tcp_segments(CLIENT, TNS_SERVER, 41502, 1521, unknown) + tcp_segments(CLIENT, TNS_SERVER, 41503, 1521, command)
            + tcp_segments(CLIENT, TNS_SERVER, 41504, 1521, redirected))


def write_tns_pcap(path):
    write_pcap(path, tns_packets())


# ---------------------------------------------------------------- OpenVPN
#
# A client (CLIENT:40500) opens an OpenVPN session over UDP with
# OPENVPN_SERVER: the hard resets, a TLS 1.2 handshake inside the control
# channel (the server's certificate is the fixtures' self-signed
# DTLS_CERTIFICATE), then data both ways, the last under a renegotiated
# key. Another host (OPENVPN_RETRIER:40600) sends three hard resets, with
# new session IDs, that nothing answers.

OPENVPN_SERVER, OPENVPN_RETRIER = '198.51.100.94', '10.1.0.77'


def _openvpn_control(opcode, session, packet_id, payload=b'', acks=(), remote=b''):
    ack = bytes([len(acks)]) + b''.join(struct.pack('!I', a) for a in acks) + (remote if acks else b'')
    return bytes([opcode << 3]) + session + ack + struct.pack('!I', packet_id) + payload


def openvpn_packets():
    client, server = bytes.fromhex('1122334455667788'), bytes.fromhex('a1a2a3a4a5a6a7a8')
    out = [
        (CLIENT, OPENVPN_SERVER, 40500, 1194, _openvpn_control(7, client, 0)),
        (OPENVPN_SERVER, CLIENT, 1194, 40500, _openvpn_control(8, server, 0, acks=(0,), remote=client)),
        (CLIENT, OPENVPN_SERVER, 40500, 1194, _openvpn_control(4, client, 1, _tls12_client_hello('vpn.example'),
                                                               acks=(0,), remote=server)),
        (OPENVPN_SERVER, CLIENT, 1194, 40500, _openvpn_control(4, server, 1, _tls12_server_flight(), acks=(1,),
                                                               remote=client)),
    ]
    data = lambda key, n: bytes([9 << 3 | key]) + b'\x00\x00\x01' + bytes(range(n))
    out += [(CLIENT, OPENVPN_SERVER, 40500, 1194, data(0, 60)), (OPENVPN_SERVER, CLIENT, 1194, 40500, data(0, 80)),
            (CLIENT, OPENVPN_SERVER, 40500, 1194, data(1, 60)), (OPENVPN_SERVER, CLIENT, 1194, 40500, data(1, 80))]
    out += [(OPENVPN_RETRIER, OPENVPN_SERVER, 40600, 1194, _openvpn_control(7, bytes([i]) * 8, 0)) for i in range(1, 4)]
    return [_udp_packet(*p) for p in out]


def write_openvpn_pcap(path):
    write_pcap(path, openvpn_packets())


# ---------------------------------------------------------------- WireGuard
#
# CLIENT:40700 and WG_SERVER:51820 complete a handshake, send data each
# way (a keepalive among it) and rekey - the server initiating this time.
# WG_RETRIER:40800 sends three initiations that nothing answers. WG_MID's
# tunnel was up before the capture started: data only, two packets each
# way, each side to one receiver index. And WG_STRAY sends one packet that
# merely has data's shape.

WG_SERVER, WG_RETRIER, WG_MID, WG_STRAY = '198.51.100.95', '10.1.0.78', '10.1.0.79', '10.1.0.80'


def _wg_initiation(sender):
    return b'\x01\x00\x00\x00' + struct.pack('<I', sender) + bytes(range(32)) + b'\x11' * 48 + b'\x22' * 28 + \
        b'\x33' * 16 + b'\x00' * 16


def _wg_response(sender, receiver):
    return b'\x02\x00\x00\x00' + struct.pack('<II', sender, receiver) + bytes(range(32, 64)) + b'\x44' * 16 + \
        b'\x55' * 16 + b'\x00' * 16


def _wg_data(receiver, counter, blocks=4):
    return b'\x04\x00\x00\x00' + struct.pack('<IQ', receiver, counter) + b'\x66' * (16 * blocks)


def wireguard_packets():
    out = [(CLIENT, WG_SERVER, 40700, 51820, _wg_initiation(0x1111)),
           (WG_SERVER, CLIENT, 51820, 40700, _wg_response(0x2222, 0x1111)),
           (CLIENT, WG_SERVER, 40700, 51820, _wg_data(0x2222, 0)),
           (WG_SERVER, CLIENT, 51820, 40700, _wg_data(0x1111, 0)),
           (CLIENT, WG_SERVER, 40700, 51820, _wg_data(0x2222, 1, blocks=1)),      # a keepalive
           (WG_SERVER, CLIENT, 51820, 40700, _wg_initiation(0x3333)),
           (CLIENT, WG_SERVER, 40700, 51820, _wg_response(0x4444, 0x3333)),
           (WG_SERVER, CLIENT, 51820, 40700, _wg_data(0x4444, 0))]
    out += [(WG_RETRIER, WG_SERVER, 40800, 51820, _wg_initiation(0x5550 + i)) for i in range(3)]
    for i in range(2):
        out += [(WG_MID, WG_SERVER, 40900, 51820, _wg_data(0x6666, 100 + i)),
                (WG_SERVER, WG_MID, 51820, 40900, _wg_data(0x7777, 200 + i))]
    out.append((WG_STRAY, WG_SERVER, 41000, 44450, _wg_data(0x8888, 959158, blocks=8)))
    return [_udp_packet(*p) for p in out]


def write_wireguard_pcap(path):
    write_pcap(path, wireguard_packets())


# ---------------------------------------------------------------- PROFINET DCP
#
# An engineering station (PN_ENGINEERING) asks every PROFINET device to
# identify itself, and one PLC (PN_DEVICE) answers: plc-line1, an S7-1500
# (Siemens, vendor 0x002a), an IO controller at 192.168.0.20. The station
# then readdresses it permanently to 10.9.9.9 (ok), and tells it to reset
# to factory (refused - in operation). Another controller (PN_CONTROLLER)
# looks for plc-line2 twice, unanswered.

PN_ENGINEERING, PN_DEVICE, PN_CONTROLLER = '00:1b:1b:00:00:01', '00:0e:8c:00:00:02', '00:1b:1b:00:00:03'
_PN_MULTICAST = '01:0e:cf:00:00:00'


def _pn_block(option, suboption, data):
    block = struct.pack('!BBH', option, suboption, len(data)) + data
    return block + (b'\x00' if len(data) % 2 else b'')


def _pn_dcp(src, dst, frame_id, service, kind, xid, blocks, delay=0):
    data = b''.join(blocks)
    dcp = struct.pack('!HBBIHH', frame_id, service, kind, xid, delay, len(data)) + data
    frame = bytes.fromhex(dst.replace(':', '')) + bytes.fromhex(src.replace(':', '')) + b'\x88\x92' + dcp
    return frame + b'\x00' * max(0, 60 - len(frame))


def pn_dcp_packets():
    ip = lambda info, addresses: _pn_block(1, 2, struct.pack('!H', info) + b''.join(socket.inet_aton(a) for a in addresses))
    identify = _pn_dcp(PN_ENGINEERING, _PN_MULTICAST, 0xfefe, 5, 0, 1, [_pn_block(0xff, 0xff, b'')], delay=1)
    answer = _pn_dcp(PN_DEVICE, PN_ENGINEERING, 0xfeff, 5, 1, 1, [
        _pn_block(2, 2, b'\x00\x00plc-line1'), _pn_block(2, 1, b'\x00\x00S7-1500'),
        _pn_block(2, 3, b'\x00\x00' + struct.pack('!HH', 0x002a, 0x010e)), _pn_block(2, 4, b'\x00\x00\x02\x00'),
        ip(1, ('192.168.0.20', '255.255.255.0', '192.168.0.1'))])
    readdress = _pn_dcp(PN_ENGINEERING, PN_DEVICE, 0xfefd, 4, 0, 2, [ip(1, ('10.9.9.9', '255.255.255.0', '10.9.9.1'))])
    readdressed = _pn_dcp(PN_DEVICE, PN_ENGINEERING, 0xfefd, 4, 1, 2, [_pn_block(5, 4, b'\x01\x02\x00')])
    reset = _pn_dcp(PN_ENGINEERING, PN_DEVICE, 0xfefd, 4, 0, 3, [_pn_block(5, 6, b'\x00\x02')])
    refused = _pn_dcp(PN_DEVICE, PN_ENGINEERING, 0xfefd, 4, 1, 3, [_pn_block(5, 4, b'\x05\x06\x06')])
    lookup = [_pn_dcp(PN_CONTROLLER, _PN_MULTICAST, 0xfefe, 5, 0, 0x100 + i, [_pn_block(2, 2, b'plc-line2')], delay=1)
              for i in range(2)]
    return [identify, answer, readdress, readdressed, reset, refused] + lookup


def write_pn_dcp_pcap(path):
    write_pcap(path, pn_dcp_packets())


# ---------------------------------------------------------------- Windows Browser
#
# NetBIOS datagrams to UDP 138 in workgroup/domain FIXTUREDOM: a workstation
# (BROWSER_WORKSTATION, WS1) announcing itself twice, a domain controller
# (BROWSER_DC, DC1) as local master browser, WS1 calling an election, and
# WS1 asking for announcements.

BROWSER_WORKSTATION, BROWSER_DC = '10.1.0.31', '10.1.0.32'
_BROWSER_BROADCAST = '10.1.255.255'


def _browser_datagram(src, source_name, payload, dgram_id):
    name = b'\\MAILSLOT\\BROWSE\x00'
    data_offset = 32 + 1 + 34 + 2 + len(name)
    words = struct.pack('<HHHHBBHIHHHHHBB', 0, len(payload), 0, 0, 0, 0, 0, 0, 0, 0, 0, len(payload), data_offset,
                        3, 0) + struct.pack('<HHH', 1, 1, 2)
    smb = b'\xffSMB\x25' + b'\x00' * 27 + bytes([len(words) // 2]) + words \
        + struct.pack('<H', len(name) + len(payload)) + name + payload
    body = _nbns_name(source_name, 0x00) + _nbns_name('FIXTUREDOM', 0x1d) + smb
    header = struct.pack('!BBH4sHHH', 0x11, 0x02, dgram_id, socket.inet_aton(src), 138, len(body), 0)
    return _udp_packet(src, _BROWSER_BROADCAST, 138, 138, header + body)


def _announcement(command, name, server_type, comment):
    return (bytes([command, 1]) + struct.pack('<I', 720000) + name.encode().ljust(16, b'\x00')
            + bytes([10, 0]) + struct.pack('<I', server_type) + bytes([15, 1]) + struct.pack('<H', 0xaa55)
            + comment.encode() + b'\x00')


def browser_packets():
    workstation = _announcement(0x01, 'WS1', 0x1003, 'Accounting PC')            # workstation, server, NT workstation
    master = _announcement(0x0f, 'DC1', 0x4802b, '')                            # ... domain controller, master browser
    election = bytes([0x08, 1]) + struct.pack('<III', 0x20010f03, 60000, 0) + b'WS1\x00'
    request = bytes([0x02, 0]) + b'WS1\x00'
    return [_browser_datagram(BROWSER_WORKSTATION, 'WS1', workstation, 1),
            _browser_datagram(BROWSER_WORKSTATION, 'WS1', workstation, 2),
            _browser_datagram(BROWSER_DC, 'DC1', master, 3),
            _browser_datagram(BROWSER_WORKSTATION, 'WS1', election, 4),
            _browser_datagram(BROWSER_WORKSTATION, 'WS1', request, 5)]


def write_browser_pcap(path):
    write_pcap(path, browser_packets())


# ---------------------------------------------------------------- LLDP and CDP
#
# A switch (NEIGHBOR_SWITCH) announcing its port Gi1/0/1 by LLDP twice and
# by CDP once, and a PLC (NEIGHBOR_PLC) announcing itself by LLDP - with
# a locally assigned chassis ID (its station name) and LLDP-MED inventory
# - then shutting its port down (time to live 0).

NEIGHBOR_SWITCH, NEIGHBOR_PLC = '00:1b:21:00:00:01', '00:1b:21:00:00:02'


def _mac(text):
    return bytes.fromhex(text.replace(':', ''))


def _lldp_tlv(kind, value):
    return struct.pack('!H', kind << 9 | len(value)) + value


def _lldp(src, tlvs):
    return _mac('01:80:c2:00:00:0e') + _mac(src) + struct.pack('!H', 0x88cc) + b''.join(tlvs) + _lldp_tlv(0, b'')


def _lldp_switch():
    return _lldp(NEIGHBOR_SWITCH, [
        _lldp_tlv(1, b'\x04' + _mac(NEIGHBOR_SWITCH)), _lldp_tlv(2, b'\x05Gi1/0/1'), _lldp_tlv(3, b'\x00\x78'),
        _lldp_tlv(4, b'Uplink to plant floor'), _lldp_tlv(5, b'sw1.example'),
        _lldp_tlv(6, b'Fixture Switch OS 1.0\nBuilt 2026-01-01'),
        _lldp_tlv(7, struct.pack('!HH', 0x14, 0x14)),                                 # bridge, router
        _lldp_tlv(8, b'\x05\x01' + socket.inet_aton('10.1.0.1') + b'\x02\x00\x00\x00\x01\x00'),
        _lldp_tlv(127, b'\x00\x80\xc2\x01' + struct.pack('!H', 10))])                 # port VLAN 10


def _lldp_plc(ttl):
    med = [_lldp_tlv(127, b'\x00\x12\xbb' + bytes([subtype]) + text) for subtype, text in
           ((5, b'HW 3'), (6, b'FW 2.1'), (8, b'SN-0042'), (9, b'Fixture Automation'), (10, b'PLC-100'))]
    return _lldp(NEIGHBOR_PLC, [
        _lldp_tlv(1, b'\x07plc-1   line 2'), _lldp_tlv(2, b'\x07port-001'), _lldp_tlv(3, struct.pack('!H', ttl)),
        _lldp_tlv(7, struct.pack('!HH', 0x80, 0x80))] + med)                          # station only


def _cdp_tlv(kind, value):
    return struct.pack('!HH', kind, 4 + len(value)) + value


def _cdp_switch():
    address = struct.pack('!I', 1) + b'\x01\x01\xcc' + struct.pack('!H', 4) + socket.inet_aton('10.1.0.1')
    tlvs = (_cdp_tlv(1, b'sw1') + _cdp_tlv(5, b'Fixture IOS 15.2') + _cdp_tlv(6, b'cisco WS-C2960-24TT')
            + _cdp_tlv(2, address) + _cdp_tlv(3, b'GigabitEthernet1/0/1') + _cdp_tlv(4, struct.pack('!I', 0x28))
            + _cdp_tlv(9, b'PLANT') + _cdp_tlv(0x0a, struct.pack('!H', 10)) + _cdp_tlv(0x0b, b'\x01'))
    header = bytes([2, 180]) + b'\x00\x00' + tlvs
    cdp = header[:2] + struct.pack('!H', _checksum(header)) + header[4:]
    llc = b'\xaa\xaa\x03\x00\x00\x0c\x20\x00' + cdp
    return _mac('01:00:0c:cc:cc:cc') + _mac(NEIGHBOR_SWITCH) + struct.pack('!H', len(llc)) + llc


def neighbor_packets():
    return [_lldp_switch(), _lldp_plc(20), _cdp_switch(), _lldp_switch(), _lldp_plc(0)]


def write_neighbor_pcap(path):
    write_pcap(path, neighbor_packets())


# ---------------------------------------------------------------- DHCPv6
#
# A client (DHCPV6_CLIENT, MAC 00:1b:21:00:00:10) getting an address from
# DHCPV6_SERVER: Solicit, Advertise, Request, Reply - and a Windows
# laptop (DHCPV6_LAPTOP) soliciting twice with the same transaction ID,
# its hostname and vendor class given, and nobody answering.

DHCPV6_CLIENT, DHCPV6_SERVER, DHCPV6_LAPTOP = 'fe80::21b:21ff:fe00:10', 'fe80::1', 'fe80::21b:21ff:fe00:20'
_DHCPV6_ALL_SERVERS = 'ff02::1:2'


def _udp6_packet(src, dst, sport, dport, payload):
    s, d = socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst)
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = s + d + struct.pack('!I3xB', len(udp), 17)
    udp = udp[:6] + struct.pack('!H', _checksum(pseudo + udp) or 0xffff) + udp[8:]
    ip = struct.pack('!IHBB', 0x60000000, len(udp), 17, 64) + s + d
    return b'\x33\x33\x00\x01\x00\x02' + b'\x11' * 6 + struct.pack('!H', 0x86dd) + ip + udp


def _dhcpv6_option(code, value):
    return struct.pack('!HH', code, len(value)) + value


def _duid(mac):
    return struct.pack('!HHI', 1, 1, 600000000) + bytes.fromhex(mac.replace(':', ''))      # DUID-LLT, Ethernet


def _dhcpv6(src, dst, kind, xid, options):
    sport, dport = (546, 547) if dst == _DHCPV6_ALL_SERVERS else (547, 546)
    return _udp6_packet(src, dst, sport, dport, bytes([kind]) + xid.to_bytes(3, 'big') + b''.join(options))


def dhcpv6_packets():
    client_id = _dhcpv6_option(1, _duid('00:1b:21:00:00:10'))
    server_id = _dhcpv6_option(2, _duid('00:1b:21:00:00:01'))
    address = _dhcpv6_option(5, socket.inet_pton(socket.AF_INET6, '2001:db8::10') + struct.pack('!II', 3600, 7200))
    ia_na = _dhcpv6_option(3, struct.pack('!III', 1, 1800, 2880) + address)
    dns = _dhcpv6_option(23, socket.inet_pton(socket.AF_INET6, '2001:db8::53'))
    search = _dhcpv6_option(24, b'\x07example\x03com\x00')
    success = _dhcpv6_option(13, struct.pack('!H', 0) + b'All addresses assigned')
    laptop = [_dhcpv6_option(1, _duid('00:1b:21:00:00:20')), _dhcpv6_option(3, struct.pack('!III', 2, 0, 0)),
              _dhcpv6_option(39, b'\x00\x06LAPTOP\x07example\x03com\x00'),
              _dhcpv6_option(16, struct.pack('!IH', 311, 8) + b'MSFT 5.0')]
    return [_dhcpv6(DHCPV6_CLIENT, _DHCPV6_ALL_SERVERS, 1, 0x000101, [client_id, ia_na]),
            _dhcpv6(DHCPV6_SERVER, DHCPV6_CLIENT, 2, 0x000101, [client_id, server_id, ia_na, dns, search]),
            _dhcpv6(DHCPV6_CLIENT, _DHCPV6_ALL_SERVERS, 3, 0x000102, [client_id, server_id, ia_na]),
            _dhcpv6(DHCPV6_SERVER, DHCPV6_CLIENT, 7, 0x000102, [client_id, server_id, ia_na, dns, search, success]),
            _dhcpv6(DHCPV6_LAPTOP, _DHCPV6_ALL_SERVERS, 1, 0x00abcd, laptop),
            _dhcpv6(DHCPV6_LAPTOP, _DHCPV6_ALL_SERVERS, 1, 0x00abcd, laptop)]


def write_dhcpv6_pcap(path):
    write_pcap(path, dhcpv6_packets())


# ---------------------------------------------------------------- Syslog
#
# Messages to a collector (SYSLOG_COLLECTOR) on UDP 514 in each form: RFC
# 3164 with a program[pid] tag, RFC 3164 with no timestamp or host (a
# Cisco ASA's), RFC 5424 with structured data, one with no <PRI>, and one
# too long to keep whole.

SYSLOG_SWITCH, SYSLOG_FIREWALL, SYSLOG_SERVER, SYSLOG_COLLECTOR = '10.1.0.2', '10.1.0.1', '10.1.0.3', '10.1.0.50'


def syslog_packets():
    messages = [
        (SYSLOG_SWITCH, b'<38>Oct 10 14:02:15 sw-core sshd[812]: Failed password for admin from 10.1.0.77 port 51122 ssh2'),
        (SYSLOG_FIREWALL, b'<190>%ASA-6-302013: Built inbound TCP connection 1 for outside:198.51.100.7/5 to inside:10.1.0.20/80'),
        (SYSLOG_SERVER, b'<165>1 2026-10-10T14:02:15.003Z app1.example.com evntslog - ID47 '
                        b'[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] \xef\xbb\xbfAn application event'),
        (SYSLOG_SERVER, b'no priority here at all'),
        (SYSLOG_SWITCH, b'<14>Oct 10 14:03:00 sw-core logger: ' + b'x' * 3000),
    ]
    return [_udp_packet(src, SYSLOG_COLLECTOR, 51400 + i, 514, message) for i, (src, message) in enumerate(messages)]


def write_syslog_pcap(path):
    write_pcap(path, syslog_packets())


# ---------------------------------------------------------------- DTLS
#
# A WebRTC-style DTLS 1.2 handshake (DTLS_CLIENT to DTLS_SERVER, port
# 4433): ClientHello with SNI dtls.example, ALPN webrtc and two SRTP
# profiles; the server's cookie challenge; the ClientHello again with the
# cookie; ServerHello (ECDHE-ECDSA AES-128-GCM, one SRTP profile), the
# certificate below and ServerHelloDone; then both sides' ChangeCipherSpec
# and encrypted Finished. And a scanner's ClientHello nobody answered.

DTLS_CLIENT, DTLS_SERVER, DTLS_SCANNER = '10.1.0.30', '10.1.0.40', '198.51.100.7'
# Self-signed, C=US, O=Fixture Ltd, CN=dtls.example, serial 1234ABCD, SANs
# dtls.example and vpn.example (openssl req -x509, prime256v1)
DTLS_CERTIFICATE = bytes.fromhex(
    '308201df30820185a00302010202041234abcd300a06082a8648ce3d040302303a310b300906035504061302555331143012'
    '060355040a0c0b46697874757265204c74643115301306035504030c0c64746c732e6578616d706c65301e170d3236313031'
    '303230343030395a170d3336313030373230343030395a303a310b300906035504061302555331143012060355040a0c0b46'
    '697874757265204c74643115301306035504030c0c64746c732e6578616d706c653059301306072a8648ce3d020106082a86'
    '48ce3d03010703420004f96f4b948da619acb865e5ee2880723128ebdd0e92ae2481d5ba52d0f46f7bc0af3c7c5e46973e3b'
    '0e4741806201562644cfe6e37ac4ddda5d77092ce87aac63a3793077301d0603551d0e041604147bbe8a66bb3c46c5d27bfc'
    'eae8dc43d7edb8cf9f301f0603551d230418301680147bbe8a66bb3c46c5d27bfceae8dc43d7edb8cf9f300f0603551d1301'
    '01ff040530030101ff30240603551d11041d301b820c64746c732e6578616d706c65820b76706e2e6578616d706c65300a06'
    '082a8648ce3d0403020348003045022079292eecf5aff6a3fca1b6e016f0802a72600585c00abf4af5c940fbea6d63300221'
    '00e53ec5406887ca9133d90f82166b0d8570a9b59fc564f78d6062815aae1aacac')
_DTLS_COOKIE = bytes(range(16))


def _dtls_record(content_type, payload, epoch=0, seq=0):
    return struct.pack('!BHH', content_type, 0xfefd, epoch) + seq.to_bytes(6, 'big') + struct.pack('!H', len(payload)) + payload


def _dtls_handshake(kind, body, message_seq):
    length = len(body).to_bytes(3, 'big')
    return bytes([kind]) + length + struct.pack('!H', message_seq) + b'\x00\x00\x00' + length + body


def _tls_extension(kind, data):
    return struct.pack('!HH', kind, len(data)) + data


def _client_hello(cookie=b''):
    name = b'dtls.example'
    sni = _tls_extension(0, struct.pack('!HBH', len(name) + 3, 0, len(name)) + name)
    alpn = _tls_extension(16, struct.pack('!H', 7) + b'\x06webrtc')
    srtp = _tls_extension(14, struct.pack('!HHH', 4, 0x0001, 0x0007) + b'\x00')
    groups = _tls_extension(10, struct.pack('!HH', 2, 0x0017)) + _tls_extension(11, b'\x01\x00')
    extensions = sni + alpn + srtp + groups
    return (struct.pack('!H', 0xfefd) + b'\x11' * 32 + b'\x00' + bytes([len(cookie)]) + cookie
            + struct.pack('!HHBB', 2, 0xc02b, 1, 0) + struct.pack('!H', len(extensions)) + extensions)


def dtls_packets():
    srtp = _tls_extension(14, struct.pack('!HH', 2, 0x0001) + b'\x00')
    alpn = _tls_extension(16, struct.pack('!H', 7) + b'\x06webrtc')
    server_hello = (struct.pack('!H', 0xfefd) + b'\x22' * 32 + b'\x00' + struct.pack('!HB', 0xc02b, 0)
                    + struct.pack('!H', len(srtp + alpn)) + srtp + alpn)
    certificate = (len(DTLS_CERTIFICATE) + 3).to_bytes(3, 'big') + len(DTLS_CERTIFICATE).to_bytes(3, 'big') + DTLS_CERTIFICATE
    flight = (_dtls_record(22, _dtls_handshake(2, server_hello, 1), seq=1)
              + _dtls_record(22, _dtls_handshake(11, certificate, 2), seq=2)
              + _dtls_record(22, _dtls_handshake(14, b'', 3), seq=3))
    finished = b'\x33' * 40

    def client(payload):
        return _udp_packet(DTLS_CLIENT, DTLS_SERVER, 50000, 4433, payload)

    def server(payload):
        return _udp_packet(DTLS_SERVER, DTLS_CLIENT, 4433, 50000, payload)
    return [client(_dtls_record(22, _dtls_handshake(1, _client_hello(), 0))),
            server(_dtls_record(22, _dtls_handshake(3, struct.pack('!HB', 0xfefd, 16) + _DTLS_COOKIE, 0))),
            client(_dtls_record(22, _dtls_handshake(1, _client_hello(_DTLS_COOKIE), 1), seq=1)),
            server(flight),
            client(_dtls_record(20, b'\x01', seq=2) + _dtls_record(22, finished, epoch=1)),
            server(_dtls_record(20, b'\x01', seq=4) + _dtls_record(22, finished, epoch=1)),
            _udp_packet(DTLS_SCANNER, DTLS_SERVER, 41000, 4433, _dtls_record(22, _dtls_handshake(1, _client_hello(), 0)))]


def write_dtls_pcap(path):
    write_pcap(path, dtls_packets())


# ---------------------------------------------------------------- ONC RPC
#
# A client (RPC_CLIENT) and an NFS server (RPC_SERVER), over UDP: the
# portmapper's DUMP (three programs registered) and GETPORT for mountd,
# mountd's MNT of /export/home as AUTH_UNIX client1 (uid 1000) and its
# EXPORT list, a GETPORT for a program not registered - and a scanner's
# DUMP nobody answered.

RPC_CLIENT, RPC_SERVER, RPC_SCANNER = '10.1.0.30', '10.1.0.40', '198.51.100.7'


def _xdr(*values):
    return b''.join(struct.pack('!I', v) for v in values)


def _xdr_string(text):
    raw = text.encode()
    return _xdr(len(raw)) + raw + b'\x00' * (-len(raw) % 4)


def _rpc_call(xid, program, version, procedure, args=b'', cred=_xdr(0, 0)):
    return _xdr(xid, 0, 2, program, version, procedure) + cred + _xdr(0, 0) + args


def _rpc_reply(xid, results=b''):
    return _xdr(xid, 1, 0, 0, 0, 0) + results          # accepted, AUTH_NULL verifier, SUCCESS


def rpc_packets():
    unix = _xdr(0) + _xdr_string('client1') + _xdr(1000, 1000, 1, 1000)
    cred = _xdr(1, len(unix)) + unix
    mappings = _xdr(1, 100000, 2, 17, 111, 1, 100005, 3, 17, 20048, 1, 100003, 3, 6, 2049, 0)
    exports = _xdr(1) + _xdr_string('/export/home') + _xdr(1) + _xdr_string('10.1.0.0/24') + _xdr(0, 0)

    def exchange(port, server_port, call, reply):
        return [_udp_packet(RPC_CLIENT, RPC_SERVER, port, server_port, call),
                _udp_packet(RPC_SERVER, RPC_CLIENT, server_port, port, reply)]
    return (exchange(700, 111, _rpc_call(1, 100000, 2, 4), _rpc_reply(1, mappings))
            + exchange(701, 111, _rpc_call(2, 100000, 2, 3, _xdr(100005, 3, 17, 0)), _rpc_reply(2, _xdr(20048)))
            + exchange(702, 20048, _rpc_call(3, 100005, 3, 1, _xdr_string('/export/home'), cred),
                       _rpc_reply(3, _xdr(0) + _xdr_string('ABCDEFGH') + _xdr(1, 1)))
            + exchange(703, 20048, _rpc_call(4, 100005, 3, 5), _rpc_reply(4, exports))
            + exchange(704, 111, _rpc_call(6, 100000, 2, 3, _xdr(100099, 1, 17, 0)), _rpc_reply(6, _xdr(0)))
            + [_udp_packet(RPC_SCANNER, RPC_SERVER, 40000, 111, _rpc_call(5, 100000, 2, 4))])


def write_rpc_pcap(path):
    write_pcap(path, rpc_packets())


# ---------------------------------------------------------------- SOCKS
#
# Clients through a SOCKS proxy (SOCKS_PROXY, port 1080): a SOCKS5
# CONNECT by name with no login, then an HTTP request through the tunnel;
# a SOCKS5 login and a CONNECT the proxy's ruleset refuses; a SOCKS4a
# CONNECT by name and a SOCKS4 one by address, refused; and an open-proxy
# check that offers no method the proxy accepts.

SOCKS_CLIENT, SOCKS_PROXY, SOCKS_SCANNER = '10.1.0.31', '10.1.0.45', '198.51.100.9'


def socks_packets():
    def session(client, cport, exchanges):
        tcp = _Tcp(client, SOCKS_PROXY, cport, 1080)
        pkts = tcp.open()
        for request, reply in exchanges:
            pkts += tcp.send(True, request)
            if reply:
                pkts += tcp.send(False, reply)
        return pkts + tcp.close()

    name = b'files.example.net'
    return (session(SOCKS_CLIENT, 42001, [
                (b'\x05\x01\x00', b'\x05\x00'),
                (b'\x05\x01\x00\x03' + bytes([len(name)]) + name + struct.pack('!H', 80),
                 b'\x05\x00\x00\x01' + socket.inet_aton('192.0.2.10') + struct.pack('!H', 50123)),
                (b'GET /update.bin HTTP/1.1\r\nHost: files.example.net\r\n\r\n',
                 b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')])
            + session(SOCKS_CLIENT, 42002, [
                (b'\x05\x02\x00\x02', b'\x05\x02'),
                (b'\x01\x09proxyuser\x06hunter', b'\x01\x00'),
                (b'\x05\x01\x00\x01' + socket.inet_aton('203.0.113.25') + struct.pack('!H', 25),
                 b'\x05\x02\x00\x01' + b'\x00' * 6)])
            + session(SOCKS_CLIENT, 42003, [
                (b'\x04\x01' + struct.pack('!H', 80) + b'\x00\x00\x00\x01' + b'bob\x00' + b'example.org\x00',
                 b'\x00\x5a' + struct.pack('!H', 80) + socket.inet_aton('198.51.100.80'))])
            + session(SOCKS_CLIENT, 42004, [
                (b'\x04\x01' + struct.pack('!H', 6667) + socket.inet_aton('192.0.2.67') + b'\x00',
                 b'\x00\x5b' + b'\x00' * 6)])
            + session(SOCKS_SCANNER, 51000, [(b'\x05\x01\x02', b'\x05\xff')]))


def write_socks_pcap(path):
    write_pcap(path, socks_packets())


# ---------------------------------------------------------------- RADIUS
#
# A Wi-Fi controller (RADIUS_NAS) asking its RADIUS server: alice's PEAP
# login, challenged then accepted; bob's PAP login, rejected with a reply
# message; carol's request sent twice before it was accepted; alice's
# accounting Start and Stop - and a scanner's Access-Request nobody
# answered.

RADIUS_NAS, RADIUS_SERVER, RADIUS_SCANNER = '10.1.0.2', '10.1.0.12', '198.51.100.11'


def _radius_attr(kind, value):
    if isinstance(value, int):
        value = struct.pack('!I', value)
    elif isinstance(value, str):
        value = value.encode()
    return struct.pack('!BB', kind, len(value) + 2) + value


def _radius(code, ident, attrs=()):
    body = b''.join(_radius_attr(k, v) for k, v in attrs)
    return struct.pack('!BBH', code, ident, 20 + len(body)) + bytes(range(16)) + body


def _eap(code, ident, kind=None, data=b''):
    body = (bytes([kind]) + data) if kind is not None else b''
    return struct.pack('!BBH', code, ident, 4 + len(body)) + body


def radius_packets():
    wifi = ((4, socket.inet_aton(RADIUS_NAS)), (32, 'wlc-1'), (30, '00-11-22-33-44-55:CorpWiFi'), (61, 19), (6, 2))

    def exchange(sport, dport, request, reply=None, client=RADIUS_NAS):
        pkts = [_udp_packet(client, RADIUS_SERVER, sport, dport, request)]
        if reply:
            pkts.append(_udp_packet(RADIUS_SERVER, client, dport, sport, reply))
        return pkts
    peap = 25
    return (exchange(50001, 1812, _radius(1, 1, ((1, 'alice'), (31, 'AA-BB-CC-DD-EE-01')) + wifi
                                          + ((79, _eap(2, 1, 1, b'alice')),)),
                     _radius(11, 1, ((79, _eap(1, 2, peap, b'\x20')), (24, 'state1'))))
            + exchange(50001, 1812, _radius(1, 2, ((1, 'alice'), (31, 'AA-BB-CC-DD-EE-01')) + wifi
                                            + ((79, _eap(2, 2, peap, b'\x00')), (24, 'state1'))),
                       _radius(2, 2, ((79, _eap(3, 2)), (18, 'Welcome, alice'), (8, socket.inet_aton('10.1.5.20')))))
            + exchange(50002, 1812, _radius(1, 3, ((1, 'bob'), (2, bytes(16)), (31, 'AA-BB-CC-DD-EE-02')) + wifi),
                       _radius(3, 3, ((18, 'Authentication failed'),)))
            + exchange(50003, 1812, _radius(1, 4, ((1, 'carol'), (2, bytes(16)), (31, 'AA-BB-CC-DD-EE-03')) + wifi))
            + exchange(50003, 1812, _radius(1, 4, ((1, 'carol'), (2, bytes(16)), (31, 'AA-BB-CC-DD-EE-03')) + wifi),
                       _radius(2, 4))
            + exchange(50004, 1813, _radius(4, 5, ((40, 1), (1, 'alice'), (44, 'sess-0001'),
                                                   (8, socket.inet_aton('10.1.5.20')), (31, 'AA-BB-CC-DD-EE-01')) + wifi),
                       _radius(5, 5))
            + exchange(50004, 1813, _radius(4, 6, ((40, 2), (1, 'alice'), (44, 'sess-0001'), (46, 3600),
                                                   (42, 1048576), (43, 52428800), (49, 1),
                                                   (31, 'AA-BB-CC-DD-EE-01')) + wifi),
                       _radius(5, 6))
            + exchange(40001, 1812, _radius(1, 181, ((1, 'infragrab-0123@invalid.invalid'),)), client=RADIUS_SCANNER))


def write_radius_pcap(path):
    write_pcap(path, radius_packets())


# ---------------------------------------------------------------- STUN
#
# A client (STUN_CLIENT) asking a STUN server (STUN_SERVER, port 3478) its
# public address twice; a TURN Allocate refused for want of a login, then
# made with one (a relayed address, and the mapped one); a Binding over
# IPv6; and a scanner's Binding Request nobody answered.

STUN_CLIENT, STUN_SERVER, STUN_SCANNER = '10.1.0.34', '192.0.2.30', '198.51.100.12'
STUN_CLIENT6, STUN_SERVER6 = '2001:db8::34', '2001:db8::30'
_STUN_COOKIE = 0x2112A442


def _stun_attr(kind, value):
    return struct.pack('!HH', kind, len(value)) + value + b'\x00' * (-len(value) % 4)


def _stun_xor_address(address, port, txid):
    if ':' in address:
        raw = socket.inet_pton(socket.AF_INET6, address)
        key = struct.pack('!I', _STUN_COOKIE) + txid
        return struct.pack('!BBH', 0, 2, port ^ 0x2112) + bytes(a ^ b for a, b in zip(raw, key))
    raw = struct.unpack('!I', socket.inet_aton(address))[0]
    return struct.pack('!BBHI', 0, 1, port ^ 0x2112, raw ^ _STUN_COOKIE)


def _stun(kind, txid, attrs=()):
    body = b''.join(_stun_attr(k, v) for k, v in attrs)
    return struct.pack('!HHI', kind, len(body), _STUN_COOKIE) + txid + body


def _stun_error(code, reason):
    return struct.pack('!HBB', 0, code // 100, code % 100) + reason.encode()


def stun_packets():
    software, server_software = (0x8022, b'fixture-client 1.0'), (0x8022, b'fixture-stun 2.1')

    def exchange(client, server, sport, request, reply=None, udp=_udp_packet):
        pkts = [udp(client, server, sport, 3478, request)]
        if reply:
            pkts.append(udp(server, client, 3478, sport, reply))
        return pkts
    pkts = []
    for n in (1, 2):
        txid = bytes([n]) * 12
        pkts += exchange(STUN_CLIENT, STUN_SERVER, 40001, _stun(0x0001, txid, (software,)),
                         _stun(0x0101, txid, ((0x0020, _stun_xor_address('203.0.113.50', 40001, txid)),
                                              server_software)))
    refused, allowed = b'\x03' * 12, b'\x04' * 12
    transport = (0x0019, bytes([17, 0, 0, 0]))
    pkts += exchange(STUN_CLIENT, STUN_SERVER, 40002, _stun(0x0003, refused, (transport, software)),
                     _stun(0x0113, refused, ((0x0009, _stun_error(401, 'Unauthorized')), (0x0014, b'example.org'),
                                             (0x0015, b'nonce-1'), server_software)))
    pkts += exchange(STUN_CLIENT, STUN_SERVER, 40002,
                     _stun(0x0003, allowed, (transport, (0x0006, b'turnuser'), (0x0014, b'example.org'),
                                             (0x0015, b'nonce-1'), (0x0008, bytes(20)), software)),
                     _stun(0x0103, allowed, ((0x0016, _stun_xor_address('192.0.2.30', 50000, allowed)),
                                             (0x0020, _stun_xor_address('203.0.113.50', 40002, allowed)),
                                             (0x000d, struct.pack('!I', 600)), (0x0008, bytes(20)), server_software)))
    six = b'\x05' * 12
    pkts += exchange(STUN_CLIENT6, STUN_SERVER6, 40003, _stun(0x0001, six),
                     _stun(0x0101, six, ((0x0020, _stun_xor_address('2001:db8:ffff::50', 40003, six)),)),
                     udp=_udp6_packet)
    pkts += exchange(STUN_SCANNER, STUN_SERVER, 41000, _stun(0x0001, b'\x06' * 12))
    return pkts


def write_stun_pcap(path):
    write_pcap(path, stun_packets())


# ---------------------------------------------------------------- CoAP
#
# A client (COAP_CLIENT) and a sensor (COAP_DEVICE, port 5683): discovery
# of its resources (/.well-known/core); a temperature read, sent twice
# before its answer; a PUT the device refused; a non-confirmable GET
# answered by a separate non-confirmable 4.04; a CoAP ping - and a
# scanner's discovery nobody answered.

COAP_CLIENT, COAP_DEVICE, COAP_SCANNER = '10.1.0.36', '10.1.0.56', '198.51.100.13'
COAP_RESOURCES = b'</sensors/temp>;rt="temperature";if="sensor",</sensors/light>;rt="light-lux",</config>'


def _coap(kind, code, mid, token=b'', options=(), payload=b''):
    out, last = bytearray([0x40 | kind << 4 | len(token), code]) + struct.pack('!H', mid) + token, 0
    for number, value in sorted(options, key=lambda o: o[0]):
        if isinstance(value, int):
            value = value.to_bytes((value.bit_length() + 7) // 8, 'big')
        elif isinstance(value, str):
            value = value.encode()
        delta, length = number - last, len(value)
        out += bytes([min(delta, 13) << 4 | min(length, 13)])
        out += bytes([delta - 13]) if delta >= 13 else b''
        out += bytes([length - 13]) if length >= 13 else b''
        out += value
        last = number
    return bytes(out) + (b'\xff' + payload if payload else b'')


def coap_packets():
    con, non, ack, rst = 0, 1, 2, 3
    get, put = 1, 3

    def request(client, sport, message):
        return _udp_packet(client, COAP_DEVICE, sport, 5683, message)

    def answer(sport, message):
        return _udp_packet(COAP_DEVICE, COAP_CLIENT, 5683, sport, message)
    path = lambda *parts: tuple((11, p) for p in parts)
    temp = _coap(con, get, 2, b'\x02', path('sensors', 'temp') + ((15, 'unit=c'),))
    return [request(COAP_CLIENT, 45001, _coap(con, get, 1, b'\x01', path('.well-known', 'core') + ((17, 40),))),
            answer(45001, _coap(ack, 69, 1, b'\x01', ((12, 40),), COAP_RESOURCES)),
            request(COAP_CLIENT, 45001, temp), request(COAP_CLIENT, 45001, temp),
            answer(45001, _coap(ack, 69, 2, b'\x02', ((12, 50),), b'{"t":21.5}')),
            request(COAP_CLIENT, 45001, _coap(con, put, 3, b'\x03', path('config') + ((12, 60),), b'\xa1\x01\x02')),
            answer(45001, _coap(ack, 129, 3, b'\x03')),
            request(COAP_CLIENT, 45001, _coap(non, get, 4, b'\x04', path('missing'))),
            answer(45001, _coap(non, 132, 900, b'\x04')),
            request(COAP_CLIENT, 45001, _coap(con, 0, 5)),
            answer(45001, _coap(rst, 0, 5)),
            request(COAP_SCANNER, 46000, _coap(con, get, 7, b'\x07', path('.well-known', 'core')))]


def write_coap_pcap(path):
    write_pcap(path, coap_packets())


# ---------------------------------------------------------------- SLP

# A client (SLP_CLIENT) asking an ESXi host (SLP_HOST, port 427) for its
# service types, then for its vSphere service and that service's
# attributes, and for a scope it doesn't serve; the client asking on the
# SLP multicast group, answered by the host directly; a scanner
# (SLP_SCANNER) registering a service with the host, and asking for its
# service types without an answer - the amplification probe; and the
# host announcing itself as a directory agent.
SLP_CLIENT, SLP_HOST, SLP_SCANNER, SLP_MULTICAST = '10.1.0.37', '10.1.0.57', '198.51.100.14', '239.255.255.253'
SLP_URL = 'service:VMwareInfrastructure://esx01.example.org'
SLP_ATTRIBUTES = '(product="VMware ESXi 7.0.3 build-19193900"),(hostname=esx01)'


def _slp_string(value):
    raw = value.encode()
    return struct.pack('!H', len(raw)) + raw


def _slp_url(url, lifetime=10800):
    return b'\0' + struct.pack('!H', lifetime) + _slp_string(url) + b'\0'


def _slp(function, xid, body, flags=0):
    """An SLPv2 message (RFC 2608): the header, language 'en', then body."""
    lang = _slp_string('en')
    length = 14 + len(lang) - 2 + len(body)
    return (bytes([2, function]) + length.to_bytes(3, 'big') + struct.pack('!H', flags) + b'\0\0\0' +
            struct.pack('!H', xid) + lang + body)


def slp_packets():
    def ask(src, sport, dst, message):
        return _udp_packet(src, dst, sport, 427, message)

    def answer(dport, message):
        return _udp_packet(SLP_HOST, SLP_CLIENT, 427, dport, message)
    s = _slp_string
    service_request = lambda xid, kind, scope, flags=0: _slp(1, xid, s('') + s(kind) + s(scope) + s('') + s(''), flags)
    type_request = lambda xid: _slp(9, xid, s('') + b'\xff\xff' + s('DEFAULT'))
    return [ask(SLP_CLIENT, 50001, SLP_HOST, type_request(1)),
            answer(50001, _slp(10, 1, b'\0\0' + s('service:VMwareInfrastructure,service:wbem'))),
            ask(SLP_CLIENT, 50001, SLP_HOST, service_request(2, 'service:VMwareInfrastructure', 'DEFAULT')),
            answer(50001, _slp(2, 2, b'\0\0\0\1' + _slp_url(SLP_URL))),
            ask(SLP_CLIENT, 50001, SLP_HOST, _slp(6, 3, s('') + s(SLP_URL) + s('DEFAULT') + s('') + s(''))),
            answer(50001, _slp(7, 3, b'\0\0' + s(SLP_ATTRIBUTES) + b'\0')),
            ask(SLP_CLIENT, 50001, SLP_HOST, service_request(4, 'service:wbem', 'LAB')),
            answer(50001, _slp(2, 4, b'\0\4\0\0')),
            ask(SLP_CLIENT, 50002, SLP_MULTICAST, service_request(5, 'service:directory-agent', 'DEFAULT', 0x2000)),
            answer(50002, _slp(8, 5, b'\0\0' + struct.pack('!I', 1700000000) + s('service:directory-agent://10.1.0.57') +
                               s('DEFAULT') + s('') + s('') + b'\0')),
            ask(SLP_SCANNER, 51000, SLP_HOST, _slp(3, 6, _slp_url('service:printer:lpr://198.51.100.14', 65535) +
                                                   s('service:printer:lpr') + s('DEFAULT') + s('(x=' + 'A' * 40 + ')') +
                                                   b'\0', flags=0x4000)),
            _udp_packet(SLP_HOST, SLP_SCANNER, 427, 51000, _slp(5, 6, b'\0\0')),
            ask(SLP_SCANNER, 51001, SLP_HOST, type_request(7)),
            _udp_packet(SLP_HOST, '255.255.255.255', 427, 427,
                        _slp(11, 0, s('service:service-agent://10.1.0.57') + s('DEFAULT') + s('') + b'\0'))]


def write_slp_pcap(path):
    write_pcap(path, slp_packets())


# ---------------------------------------------------------------- IPMI

# An admin console (IPMI_CONSOLE) pinging a server's BMC (IPMI_BMC, port
# 623), asking its authentication capabilities and opening an IPMI 2.0
# session - its RAKP messages, one with the BMC's password hash, follow
# and must never be read; a scanner (IPMI_SCANNER) asking an older BMC
# (IPMI_OLD_BMC) that lets in anonymous logins and accepts cipher zero,
# and pinging an address with no BMC.
IPMI_CONSOLE, IPMI_BMC, IPMI_OLD_BMC, IPMI_SCANNER = '10.1.0.38', '10.1.0.58', '10.1.0.59', '198.51.100.15'
IPMI_NOBODY = '10.1.0.60'
IPMI_RAKP2_HMAC = bytes(range(0x40, 0x54))


def _ipmb(netfn, command, data, request):
    """An IPMB message: requests from the console's software ID (0x81) to
    the BMC (0x20), responses back, with their checksums."""
    target, source = (0x20, 0x81) if request else (0x81, 0x20)
    head = bytes([target, netfn << 2])
    body = bytes([source, 0, command]) + data
    check = lambda b: (-sum(b)) & 0xff
    return head + bytes([check(head)]) + body + bytes([check(body)])


def _ipmi15(message):
    return b'\x06\x00\xff\x07' + b'\x00' + b'\0' * 8 + bytes([len(message)]) + message


def _ipmi20(kind, payload):
    return b'\x06\x00\xff\x07' + bytes([0x06, kind]) + b'\0' * 8 + struct.pack('<H', len(payload)) + payload


def _ipmi_algorithms(auth, integrity, confidentiality):
    return b''.join(bytes([i, 0, 0, 8, alg, 0, 0, 0]) for i, alg in enumerate((auth, integrity, confidentiality)))


def ipmi_packets():
    ping = b'\x06\x00\xff\x06' + b'\x00\x00\x11\xbe\x80\x01\x00\x00'
    pong = b'\x06\x00\xff\x06' + b'\x00\x00\x11\xbe\x40\x01\x00\x10' + b'\x00\x00\x11\xbe' + b'\0' * 4 + b'\x81\x00' + b'\0' * 6
    caps_request = _ipmi15(_ipmb(0x06, 0x38, b'\x8e\x04', True))
    modern = _ipmi15(_ipmb(0x07, 0x38, b'\x00\x01\x84\x04\x03\x00\x00\x00\x00', False))
    old = _ipmi15(_ipmb(0x07, 0x38, b'\x00\x01\x15\x07\x00\x00\x00\x00\x00', False))
    open_request = lambda algs: _ipmi20(0x10, b'\x01\x04\x00\x00' + b'\xa0\xa1\xa2\xa3' + _ipmi_algorithms(*algs))
    open_response = lambda algs: _ipmi20(0x11, b'\x01\x00\x04\x00' + b'\xa0\xa1\xa2\xa3' + b'\x10\x20\x30\x40' +
                                         _ipmi_algorithms(*algs))
    rakp1 = _ipmi20(0x12, b'\x02\x00\x00\x00\x10\x20\x30\x40' + b'\x55' * 16 + b'\x14\x00\x00' + bytes([5]) + b'admin')
    rakp2 = _ipmi20(0x13, b'\x02\x00\x00\x00\xa0\xa1\xa2\xa3' + b'\x66' * 16 + b'\x77' * 16 + IPMI_RAKP2_HMAC)

    def ask(src, sport, dst, message):
        return _udp_packet(src, dst, sport, 623, message)

    def answer(src, dst, dport, message):
        return _udp_packet(src, dst, 623, dport, message)
    return [ask(IPMI_CONSOLE, 50101, IPMI_BMC, ping), answer(IPMI_BMC, IPMI_CONSOLE, 50101, pong),
            ask(IPMI_CONSOLE, 50101, IPMI_BMC, caps_request), answer(IPMI_BMC, IPMI_CONSOLE, 50101, modern),
            ask(IPMI_CONSOLE, 50101, IPMI_BMC, open_request((1, 1, 1))),
            answer(IPMI_BMC, IPMI_CONSOLE, 50101, open_response((1, 1, 1))),
            ask(IPMI_CONSOLE, 50101, IPMI_BMC, rakp1), answer(IPMI_BMC, IPMI_CONSOLE, 50101, rakp2),
            ask(IPMI_SCANNER, 52000, IPMI_OLD_BMC, caps_request), answer(IPMI_OLD_BMC, IPMI_SCANNER, 52000, old),
            ask(IPMI_SCANNER, 52001, IPMI_OLD_BMC, open_request((0, 0, 0))),
            answer(IPMI_OLD_BMC, IPMI_SCANNER, 52001, open_response((0, 0, 0))),
            ask(IPMI_SCANNER, 52002, IPMI_NOBODY, ping)]


def write_ipmi_pcap(path):
    write_pcap(path, ipmi_packets())


# ---------------------------------------------------------------- L2TP

# A Windows client (L2TP_CLIENT) opening an authenticated control
# connection to a VPN server (L2TP_SERVER, port 1701), placing a call
# whose PPP crosses the tunnel, then clearing the call and the tunnel; a
# scanner (L2TP_SCANNER) nobody answered; and another the server refused.
# The tunnel's challenge and response, and the PPP, must never be kept.
L2TP_CLIENT, L2TP_SERVER, L2TP_SCANNER, L2TP_REFUSED = '10.1.0.39', '10.1.0.61', '198.51.100.16', '198.51.100.17'
L2TP_CHALLENGE = bytes(range(0x30, 0x40))
L2TP_RESPONSE = bytes(range(0x60, 0x70))


def _l2tp_avp(kind, value, hidden=False):
    if isinstance(value, str):
        value = value.encode()
    return struct.pack('!HHH', 0x8000 | (0x4000 if hidden else 0) | (6 + len(value)), 0, kind) + value


def _l2tp_control(tunnel, session, ns, nr, avps=()):
    body = b''.join(avps)
    return struct.pack('!HHHHHH', 0xc802, 12 + len(body), tunnel, session, ns, nr) + body


def l2tp_packets():
    u16, u32 = (lambda n: struct.pack('!H', n)), (lambda n: struct.pack('!I', n))
    message = lambda n: _l2tp_avp(0, u16(n))

    def sccrq(host, vendor=None, firmware=None, challenge=None):
        avps = [message(1), _l2tp_avp(2, b'\x01\x00'), _l2tp_avp(3, u32(3)), _l2tp_avp(4, u32(0)),
                _l2tp_avp(7, host), _l2tp_avp(9, u16(1)), _l2tp_avp(10, u16(8))]
        if firmware is not None:
            avps.append(_l2tp_avp(6, u16(firmware)))
        if vendor:
            avps.append(_l2tp_avp(8, vendor))
        if challenge:
            avps.append(_l2tp_avp(11, challenge))
        return _l2tp_control(0, 0, 0, 0, avps)

    def up(message_bytes, sport=1701):
        return _udp_packet(L2TP_CLIENT, L2TP_SERVER, sport, 1701, message_bytes)

    def down(message_bytes, dst=L2TP_CLIENT, dport=1701):
        return _udp_packet(L2TP_SERVER, dst, 1701, dport, message_bytes)
    ppp = lambda tunnel, session: struct.pack('!HHH', 0x0002, tunnel, session) + b'\xff\x03\xc0\x21\x01\x01\x00\x04'
    return [up(sccrq('WIN-CLIENT7', 'Microsoft', 0x0601, L2TP_CHALLENGE)),
            down(_l2tp_control(1, 0, 0, 1, [message(2), _l2tp_avp(2, b'\x01\x00'), _l2tp_avp(3, u32(3)),
                                            _l2tp_avp(7, 'vpn-gw'), _l2tp_avp(8, 'xl2tpd'), _l2tp_avp(6, u16(0x0680)),
                                            _l2tp_avp(9, u16(7)), _l2tp_avp(11, L2TP_CHALLENGE[::-1]),
                                            _l2tp_avp(13, L2TP_RESPONSE)])),
            up(_l2tp_control(7, 0, 1, 1, [message(3), _l2tp_avp(13, L2TP_RESPONSE[::-1])])),
            down(_l2tp_control(1, 0, 1, 2)),
            up(_l2tp_control(7, 0, 2, 1, [message(10), _l2tp_avp(14, u16(3)), _l2tp_avp(15, u32(1)),
                                          _l2tp_avp(18, u32(0)), _l2tp_avp(22, '10.1.0.39')])),
            down(_l2tp_control(1, 3, 1, 3, [message(11), _l2tp_avp(14, u16(9))])),
            up(_l2tp_control(7, 9, 3, 2, [message(12), _l2tp_avp(24, u32(100000000)), _l2tp_avp(19, u32(1))])),
            up(ppp(7, 9)), down(ppp(1, 3)),
            up(_l2tp_control(7, 9, 4, 2, [message(14), _l2tp_avp(1, u16(3)), _l2tp_avp(14, u16(3))])),
            up(_l2tp_control(7, 0, 5, 2, [message(4), _l2tp_avp(1, u16(1)), _l2tp_avp(9, u16(1))])),
            _udp_packet(L2TP_SCANNER, L2TP_SERVER, 40000, 1701, sccrq('masscan1')),
            _udp_packet(L2TP_REFUSED, L2TP_SERVER, 40001, 1701, sccrq('l2tpscan', 'driftnet', 0x0123)),
            down(_l2tp_control(0, 0, 0, 1, [message(4), _l2tp_avp(1, u16(2) + u16(6) + b'not allowed'),
                                            _l2tp_avp(9, u16(2))]), L2TP_REFUSED, 40001)]


def write_l2tp_pcap(path):
    write_pcap(path, l2tp_packets())


# ---------------------------------------------------------------- RIP

# A router (RIP_ROUTER) multicasting two RIPv2 updates, authenticated
# with a simple password, the second withdrawing a route; a host
# (RIP_ROGUE) announcing a default route - an injection; a scanner
# (RIP_SCANNER) asking the router for its whole table and answered; and
# a RIPng router's update. The password must never be kept.
RIP_ROUTER, RIP_ROGUE, RIP_SCANNER, RIP_GROUP = '10.1.0.1', '10.1.0.66', '198.51.100.18', '224.0.0.9'
RIPNG_ROUTER, RIPNG_GROUP = 'fe80::1', 'ff02::9'
RIP_PASSWORD = b'r0uterPw'


def _rip(command, version, entries, password=None):
    out = bytes([command, version, 0, 0])
    if password:
        out += struct.pack('!HH', 0xffff, 2) + password.ljust(16, b'\0')
    for family, address, mask, hop, metric, tag in entries:
        out += struct.pack('!HH', family, tag) + socket.inet_aton(address) + socket.inet_aton(mask)
        out += socket.inet_aton(hop) + struct.pack('!I', metric)
    return out


def rip_packets():
    route = lambda address, mask, metric, hop='0.0.0.0', tag=0: (2, address, mask, hop, metric, tag)
    update = lambda metric: _rip(2, 2, [route('10.2.0.0', '255.255.0.0', 1),
                                        route('10.3.0.0', '255.255.0.0', metric, '10.1.0.2'),
                                        route('0.0.0.0', '0.0.0.0', 1, tag=7)], RIP_PASSWORD)
    ripng = (bytes([2, 1, 0, 0]) + socket.inet_pton(socket.AF_INET6, '2001:db8:1::') + struct.pack('!HBB', 0, 48, 1) +
             socket.inet_pton(socket.AF_INET6, '2001:db8:2::') + struct.pack('!HBB', 0, 48, 3))
    return [_udp_packet(RIP_ROUTER, RIP_GROUP, 520, 520, update(2)),
            _udp_packet(RIP_ROGUE, RIP_GROUP, 520, 520, _rip(2, 2, [route('0.0.0.0', '0.0.0.0', 1)])),
            _udp_packet(RIP_ROUTER, RIP_GROUP, 520, 520, update(16)),
            _udp_packet(RIP_SCANNER, RIP_ROUTER, 40520, 520, _rip(1, 1, [(0, '0.0.0.0', '0.0.0.0', '0.0.0.0', 16, 0)])),
            _udp_packet(RIP_ROUTER, RIP_SCANNER, 520, 40520,
                        _rip(2, 1, [(2, '10.0.0.0', '0.0.0.0', '0.0.0.0', 1, 0), (2, '172.16.0.0', '0.0.0.0', '0.0.0.0', 2, 0)])),
            _udp6_packet(RIPNG_ROUTER, RIPNG_GROUP, 521, 521, ripng)]


def write_rip_pcap(path):
    write_pcap(path, rip_packets())


# ---------------------------------------------------------------- Tunnels

# Two sites (TUNNEL_SITE_A, TUNNEL_SITE_B) joined by GRE, a TCP connection
# between their LANs crossing it both ways; a VXLAN overlay between two
# hosts; a Teredo client reaching its relay; a scanner's IP-in-IP probe
# whose inner packet goes back to the scanner; and a 6in4 packet.
TUNNEL_SITE_A, TUNNEL_SITE_B = '192.0.2.10', '192.0.2.20'
VXLAN_A, VXLAN_B, TEREDO_CLIENT, TEREDO_RELAY = '10.1.0.70', '10.1.0.71', '10.1.0.72', '198.51.100.30'
TUNNEL_SCANNER, TUNNEL_TARGET, SIXIN4_SENDER = '198.51.100.19', '10.1.0.1', '198.51.100.20'


def _ipv4_wrap(src, dst, proto, payload):
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    ip = ip[:10] + struct.pack('!H', _checksum(ip)) + ip[12:]
    return b'\x00' * 6 + b'\x11' * 6 + struct.pack('!H', 0x0800) + ip + payload


def _teredo_bubble():
    """A Teredo bubble: an IPv6 header with no next header (59) and nothing after it."""
    s, d = socket.inet_pton(socket.AF_INET6, '2001:0:c633:641e::1'), socket.inet_pton(socket.AF_INET6, '2001:db8::1')
    return struct.pack('!IHBB', 6 << 28, 0, 59, 64) + s + d


def tunnel_packets():
    inner = lambda packet: packet[14:]          # an Ethernet frame's IP packet
    gre = lambda packet: _ipv4_wrap(*packet[0], 47, b'\x00\x00\x08\x00' + inner(packet[1]))
    syn = _tcp_packet('10.10.0.5', '10.20.0.7', 51000, 443, 1, 0, 0x02)
    syn_ack = _tcp_packet('10.20.0.7', '10.10.0.5', 443, 51000, 1, 2, 0x12)
    ack = _tcp_packet('10.10.0.5', '10.20.0.7', 51000, 443, 2, 2, 0x10)
    vxlan_frame = _udp_packet('172.16.5.1', '172.16.5.2', 40000, 53, b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00')
    teredo = _udp6_packet('2001:0:c633:641e::1', '2001:db8::1', 40001, 7, b'ping')
    return [gre(((TUNNEL_SITE_A, TUNNEL_SITE_B), syn)), gre(((TUNNEL_SITE_B, TUNNEL_SITE_A), syn_ack)),
            gre(((TUNNEL_SITE_A, TUNNEL_SITE_B), ack)),
            _udp_packet(VXLAN_A, VXLAN_B, 50000, 4789, b'\x08\x00\x00\x00\x00\x13\x88\x00' + vxlan_frame),
            _udp_packet(TEREDO_CLIENT, TEREDO_RELAY, 50444, 3544, inner(teredo)),
            _udp_packet(TEREDO_CLIENT, TEREDO_RELAY, 50444, 3544, _teredo_bubble()),
            _ipv4_wrap(TUNNEL_SCANNER, TUNNEL_TARGET, 4,
                       inner(_udp_packet(TUNNEL_TARGET, TUNNEL_SCANNER, 33000, 33001, b'probe'))),
            _ipv4_wrap(SIXIN4_SENDER, TUNNEL_TARGET, 41, inner(_udp6_packet('2002:c633:6414::1', '2001:db8::2',
                                                                            40002, 7, b'6in4')))]


def write_tunnel_pcap(path):
    write_pcap(path, tunnel_packets())


# An ICMP port unreachable about each of a VXLAN, a Teredo and a GRE packet,
# quoting the whole of it as Linux does (up to 576 bytes) - the tunnel and
# the packet inside both. Each is about the outer packet: Suricata counts
# the first two on the tunnel's outer flow, and GRE's (no outer flow) on
# none (tests/data/icmp_tunnel_fixture.eve.json, Suricata 8.0.7).

def _icmp_unreachable_quoting(src, dst, about, quote=548):
    inner = about[14:14 + quote]
    icmp = struct.pack('!BBHI', 3, 3, 0, 0) + inner
    icmp = icmp[:2] + struct.pack('!H', _checksum(icmp)) + icmp[4:]
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(icmp), 1, 0, 64, 1, 0, s, d)
    ip = ip[:10] + struct.pack('!H', _checksum(ip)) + ip[12:]
    return b'\x00' * 6 + b'\x11' * 6 + struct.pack('!H', 0x0800) + ip + icmp


def icmp_tunnel_packets():
    vxlan_frame = _udp_packet('172.16.5.1', '172.16.5.2', 40000, 53, b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00')
    vxlan = _udp_packet(VXLAN_A, VXLAN_B, 50000, 4789, b'\x08\x00\x00\x00\x00\x13\x88\x00' + vxlan_frame)
    teredo = _udp_packet(TEREDO_CLIENT, TEREDO_RELAY, 50444, 3544,
                         _udp6_packet('2001:0:c633:641e::1', '2001:db8::1', 40001, 7, b'ping')[14:])
    syn = _tcp_packet('10.10.0.5', '10.20.0.7', 51000, 443, 1, 0, 0x02)
    gre = _ipv4_wrap(TUNNEL_SITE_A, TUNNEL_SITE_B, 47, b'\x00\x00\x08\x00' + syn[14:])
    return [vxlan, _icmp_unreachable_quoting(VXLAN_B, VXLAN_A, vxlan),
            teredo, _icmp_unreachable_quoting(TEREDO_RELAY, TEREDO_CLIENT, teredo),
            gre, _icmp_unreachable_quoting(TUNNEL_SITE_B, TUNNEL_SITE_A, gre)]


def write_icmp_tunnel_pcap(path):
    write_pcap(path, icmp_tunnel_packets())


# ---------------------------------------------------------------- XDMCP

# A client (XDMCP_CLIENT) asking a login manager (XDMCP_SERVER, port
# 177), which is willing, then requesting a session - the X authorization
# cookie in the Accept must never be kept; a scanner (XDMCP_SCANNER) nobody
# answered; a broadcast query answered by one server willing and one not;
# and a request declined.
XDMCP_CLIENT, XDMCP_SERVER, XDMCP_BUSY, XDMCP_SCANNER = '10.1.0.40', '10.1.0.62', '10.1.0.63', '198.51.100.21'
XDMCP_PROBER, XDMCP_BROADCAST = '198.51.100.22', '10.1.0.255'
XDMCP_COOKIE = bytes(range(0xa0, 0xb0))


def _array8(value):
    value = value.encode() if isinstance(value, str) else value
    return struct.pack('!H', len(value)) + value


def _arrays8(values):
    return bytes([len(values)]) + b''.join(_array8(v) for v in values)


def _xdmcp(opcode, body):
    return struct.pack('!HHH', 1, opcode, len(body)) + body


def xdmcp_packets():
    query = lambda names=(): _xdmcp(2, _arrays8(names))
    willing = lambda host, status: _xdmcp(5, _array8('') + _array8(host) + _array8(status))
    request = lambda auth: _xdmcp(7, struct.pack('!H', 0) + b'\x01' + struct.pack('!H', 0) +
                                  _arrays8([socket.inet_aton(XDMCP_CLIENT)]) + _array8(auth) + _array8('') +
                                  _arrays8(['MIT-MAGIC-COOKIE-1']) + _array8('Linux 1'))
    accept = _xdmcp(8, struct.pack('!I', 0x1234) + _array8('') + _array8('') + _array8('MIT-MAGIC-COOKIE-1') +
                    _array8(XDMCP_COOKIE))
    manage = _xdmcp(10, struct.pack('!IH', 0x1234, 0) + _array8('MIT-unspecified'))
    decline = _xdmcp(9, _array8('Authentication failed') + _array8('XDM-AUTHENTICATION-1') + _array8(''))

    def ask(src, sport, dst, message):
        return _udp_packet(src, dst, sport, 177, message)

    def answer(src, dst, dport, message):
        return _udp_packet(src, dst, 177, dport, message)
    return [ask(XDMCP_CLIENT, 40177, XDMCP_SERVER, query()),
            answer(XDMCP_SERVER, XDMCP_CLIENT, 40177, willing('labsrv', 'Linux 5.15.0-91-generic, load: 0.08')),
            ask(XDMCP_CLIENT, 40177, XDMCP_SERVER, request('')),
            answer(XDMCP_SERVER, XDMCP_CLIENT, 40177, accept),
            ask(XDMCP_CLIENT, 40177, XDMCP_SERVER, manage),
            ask(XDMCP_SCANNER, 41000, XDMCP_SERVER, query()),
            ask(XDMCP_CLIENT, 40178, XDMCP_BROADCAST, _xdmcp(1, _arrays8([]))),
            answer(XDMCP_SERVER, XDMCP_CLIENT, 40178, willing('labsrv', 'Linux 5.15.0-91-generic, load: 0.08')),
            answer(XDMCP_BUSY, XDMCP_CLIENT, 40178, _xdmcp(6, _array8('busybox') + _array8('Too many sessions'))),
            ask(XDMCP_PROBER, 41001, XDMCP_SERVER, query(['XDM-AUTHENTICATION-1'])),
            answer(XDMCP_SERVER, XDMCP_PROBER, 41001, willing('labsrv', 'Willing to manage')),
            ask(XDMCP_PROBER, 41001, XDMCP_SERVER, request('XDM-AUTHENTICATION-1')),
            answer(XDMCP_SERVER, XDMCP_PROBER, 41001, decline)]


def write_xdmcp_pcap(path):
    write_pcap(path, xdmcp_packets())


# ---------------------------------------------------------------- TLS failures
#
# TLS 1.2 over TCP, where the handshake's alerts are readable: a client
# refusing the server's self-signed certificate (DTLS_CERTIFICATE, not
# valid until 2026 - the capture is from 2023) with Unknown CA, a server
# turning a client away with Handshake Failure, and a completed handshake
# whose closing alert is encrypted - which no one can read, so it's no
# record.

TLS_FAILURE_CLIENT = '10.1.0.10'
TLS_REFUSED_SERVER, TLS_UNWILLING_SERVER, TLS_GOOD_SERVER = '10.1.0.44', '10.1.0.45', '10.1.0.46'
TLS_REFUSED_SNI = 'vpn.example'


def _tls12_record(content_type, payload):
    return struct.pack('!BHH', content_type, 0x0303, len(payload)) + payload


def _tls12_handshake(msg_type, body):
    return bytes([msg_type]) + struct.pack('!I', len(body))[1:] + body


def _tls12_client_hello(sni):
    name = sni.encode()
    exts = (_ext(0x0000, struct.pack('!HBH', len(name) + 3, 0, len(name)) + name)
            + _ext(0x000a, struct.pack('!HH', 2, 0x0017)) + _ext(0x000b, b'\x01\x00')
            + _ext(0x000d, struct.pack('!HH', 2, 0x0403)))
    suites = struct.pack('!HH', 0xc02b, 0xc02f)
    body = (struct.pack('!H', 0x0303) + bytes(range(32)) + b'\x00' + struct.pack('!H', len(suites)) + suites
            + b'\x01\x00' + struct.pack('!H', len(exts)) + exts)
    return _tls12_record(22, _tls12_handshake(1, body))


def _tls12_server_flight():
    hello = _tls12_handshake(2, struct.pack('!H', 0x0303) + bytes(range(64, 96)) + b'\x00'
                             + struct.pack('!HB', 0xc02b, 0) + struct.pack('!H', 0))
    cert = len(DTLS_CERTIFICATE).to_bytes(3, 'big') + DTLS_CERTIFICATE
    certificate = _tls12_handshake(11, len(cert).to_bytes(3, 'big') + cert)
    return _tls12_record(22, hello + certificate + _tls12_handshake(14, b''))


def _tls12_alert(description):
    return _tls12_record(21, bytes([2, description]))       # fatal


def tls_failure_packets():
    refused = tcp_segments(TLS_FAILURE_CLIENT, TLS_REFUSED_SERVER, 41201, 443, [
        (True, _tls12_client_hello(TLS_REFUSED_SNI)), (False, _tls12_server_flight()),
        (True, _tls12_alert(48))])                                                    # unknown_ca
    unwilling = tcp_segments(TLS_FAILURE_CLIENT, TLS_UNWILLING_SERVER, 41202, 443, [
        (True, _tls12_client_hello('legacy.example')), (False, _tls12_alert(40))])   # handshake_failure
    ccs, finished = _tls12_record(20, b'\x01'), _tls12_record(22, bytes(40))       # Finished: encrypted
    completed = tcp_segments(TLS_FAILURE_CLIENT, TLS_GOOD_SERVER, 41203, 443, [
        (True, _tls12_client_hello('good.example')), (False, _tls12_server_flight()),
        (True, _tls12_record(22, _tls12_handshake(16, b'\x41' + bytes(65))) + ccs + finished),
        (False, ccs + finished), (True, _tls12_record(23, bytes(48))),
        (True, _tls12_record(21, bytes(26)))])                                       # an encrypted alert
    return refused + unwilling + completed


def write_tls_failure_pcap(path):
    write_pcap(path, tls_failure_packets())
