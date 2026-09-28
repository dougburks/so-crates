"""Tiny hand-built pcaps for tests that need real tshark/tcpdump input.

Built with struct rather than scapy so the test suite needs no extra
dependency. Checksums are computed properly so tools that validate them
still accept the packets.
"""
import socket
import struct

# A request, and a response holding every byte value plus bytes that aren't
# valid UTF-8 - exactly what the ASCII transcript can't carry.
HTTP_REQUEST = b'GET /x HTTP/1.1\r\nHost: a\r\n\r\n'
HTTP_RESPONSE = b'HTTP/1.1 200 OK\r\n\r\n' + bytes(range(256)) * 2 + b'\xff\xfe\x00\x80END'


def _checksum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def _tcp_packet(src, dst, sport, dport, seq, ack, flags, payload=b'', vlan=None):
    v6 = ':' in src
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    if v6:
        s, d = socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst)
        pseudo = s + d + struct.pack('!I3xB', len(tcp), 6)
        tcp = tcp[:16] + struct.pack('!H', _checksum(pseudo + tcp)) + tcp[18:]
        ip = struct.pack('!IHBB', 6 << 28, len(tcp), 6, 64) + s + d
        ethertype = 0x86dd
    else:
        s, d = socket.inet_aton(src), socket.inet_aton(dst)
        pseudo = s + d + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', _checksum(pseudo + tcp)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, s, d)
        ip = ip[:10] + struct.pack('!H', _checksum(ip)) + ip[12:]
        ethertype = 0x0800
    tag = struct.pack('!HH', 0x8100, vlan) if vlan is not None else b''
    return b'\x00' * 6 + b'\x11' * 6 + tag + struct.pack('!H', ethertype) + ip + tcp


def tcp_conversation(client, server, cport, sport, request, response, retransmit=False, vlan=None):
    """Handshake, one request, a two-segment response (the first segment
    optionally retransmitted), then FIN/FIN - optionally inside 802.1Q
    frames tagged with VLAN id vlan."""
    pkts = []
    cs, ss = 1000, 5000
    pkts.append(_tcp_packet(client, server, cport, sport, cs, 0, 0x02, vlan=vlan)); cs += 1
    pkts.append(_tcp_packet(server, client, sport, cport, ss, cs, 0x12, vlan=vlan)); ss += 1
    pkts.append(_tcp_packet(client, server, cport, sport, cs, ss, 0x10, vlan=vlan))
    pkts.append(_tcp_packet(client, server, cport, sport, cs, ss, 0x18, request, vlan=vlan)); cs += len(request)
    half = len(response) // 2
    pkts.append(_tcp_packet(server, client, sport, cport, ss, cs, 0x18, response[:half], vlan=vlan))
    if retransmit:
        pkts.append(_tcp_packet(server, client, sport, cport, ss, cs, 0x18, response[:half], vlan=vlan))
    pkts.append(_tcp_packet(server, client, sport, cport, ss + half, cs, 0x18, response[half:], vlan=vlan))
    ss += len(response)
    pkts.append(_tcp_packet(client, server, cport, sport, cs, ss, 0x11, vlan=vlan))
    pkts.append(_tcp_packet(server, client, sport, cport, ss, cs + 1, 0x11, vlan=vlan))
    return pkts


def tcp_segments(client, server, cport, sport, segments):
    """Handshake, then each (from_client, payload) in order as its own
    segment - e.g. an interactive session's keystrokes - then FIN/FIN."""
    pkts = []
    cs, ss = 7000, 9000
    pkts.append(_tcp_packet(client, server, cport, sport, cs, 0, 0x02)); cs += 1
    pkts.append(_tcp_packet(server, client, sport, cport, ss, cs, 0x12)); ss += 1
    pkts.append(_tcp_packet(client, server, cport, sport, cs, ss, 0x10))
    for from_client, payload in segments:
        if from_client:
            pkts.append(_tcp_packet(client, server, cport, sport, cs, ss, 0x18, payload)); cs += len(payload)
        else:
            pkts.append(_tcp_packet(server, client, sport, cport, ss, cs, 0x18, payload)); ss += len(payload)
    pkts.append(_tcp_packet(client, server, cport, sport, cs, ss, 0x11))
    pkts.append(_tcp_packet(server, client, sport, cport, ss, cs + 1, 0x11))
    return pkts


# An interactive (telnet-style) session: each command and each Enter is its
# own segment, the way a terminal sends keystrokes.
TELNET_SEGMENTS = [(True, b'ls'), (True, b'\r\n'), (False, b'file1\r\n'), (True, b'pwd'), (True, b'\r\n'), (False, b'/root\r\n')]


def write_pcap(path, packets):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(packets):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)


def write_http_pcap(path):
    """An IPv4 flow 10.0.0.1:40000 -> 10.0.0.2:80 (with a retransmitted
    response segment), an IPv6 flow [2001:db8::1]:40001 ->
    [2001:db8::2]:8080, and a VLAN 244-tagged IPv4 flow 10.0.0.3:40002 ->
    10.0.0.4:443, all carrying HTTP_REQUEST/HTTP_RESPONSE - plus the
    TELNET_SEGMENTS session 10.0.0.5:40003 -> 10.0.0.6:23."""
    write_pcap(path,
               tcp_conversation('10.0.0.1', '10.0.0.2', 40000, 80,
                                HTTP_REQUEST, HTTP_RESPONSE, retransmit=True)
               + tcp_conversation('2001:db8::1', '2001:db8::2', 40001, 8080,
                                  HTTP_REQUEST, HTTP_RESPONSE)
               + tcp_conversation('10.0.0.3', '10.0.0.4', 40002, 443,
                                  HTTP_REQUEST, HTTP_RESPONSE, vlan=244)
               + tcp_segments('10.0.0.5', '10.0.0.6', 40003, 23, TELNET_SEGMENTS))
