#!/usr/bin/env python3
"""Generate the pcap scripts/record_cyberchef_demo.py records against.

An infected finance desktop talks to a fake C2 server over three channels,
one for each way SO-CRATES hands data to CyberChef:

1. An HTTP POST whose JSON body hides an encoded blob in one field - the
   Send selection to CyberChef case (select just the blob).
2. A raw-TCP beacon on port 4444 whose reply is nothing but an encoded
   blob - the Payload panel's Send to CyberChef "Dest" case.
3. An HTTP GET whose response body is an encoded blob, which Suricata
   extracts as a file - the File Info Send to CyberChef case.

Each blob is base64(hex(hexdump(message))), so CyberChef's Magic operation
(applied automatically for payloads up to 16KB) finds From Base64 -> From
Hex -> From Hexdump and shows the message. The hex has no delimiter on
purpose: space-separated hex inside base64 takes Magic ~80 seconds to work
through, undelimited ~0.3 seconds (measured in the bundled CyberChef).
to_hexdump() reproduces CyberChef's own "To Hexdump" output (width 16)
byte for byte, so Magic's From Hexdump reverses it exactly.

Addresses and the domain are from documentation-only ranges (RFC 5737
TEST-NET-3, RFC 6761 .example). Output is deterministic.

Usage:
    python3 scripts/make_cyberchef_demo_pcap.py <output.pcap>
"""

import base64
import json
import random
import socket
import struct
import sys

EXFIL = """*** EXFILTRATION REPORT - CLASSIFICATION: EMBARRASSING ***
Stolen from: DESKTOP-FINANCE-07
 - Admin password: Password123! (rotated in 2019, to Password124!)
 - The CISO's fantasy football lineup (0-11, please send help)
 - "Q3_budget_FINAL_final_v7_USE_THIS_ONE.xlsx"
 - 4,812 unread emails titled "Mandatory Security Awareness Training"
Protected with military-grade triple encryption.
"""

BEACON = """BEACON ACK - implant uptime: 437 days. Times anyone noticed: 0.
Sleep: 60s. Jitter: yes. Encryption: base64, hex AND hexdump (unbreakable).
Reminder: an analyst with Security Onion and CyberChef can read this. Hi!
"""

TASKING = """C2 TASKING v6.6.6
Congratulations, analyst! You just defeated our "military-grade encryption":
    base64( hex( hexdump( this message ) ) )
Encoding is not encryption. Please do not tell our investors.
Next tasking: none. We are on vacation. Try the Security Onion boot camp.
"""

VICTIM, C2, DNS = '10.13.37.23', '203.0.113.66', '10.13.37.1'
DOMAIN = 'cdn.definitely-not-c2.example'
VICTIM_MAC, GATEWAY_MAC = bytes.fromhex('525400133723'), bytes.fromhex('525400000001')
START = 1790340000.0  # 2026-09-25
MSS = 1448
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) TotallyLegitUpdater/6.6.6'


def to_hexdump(data):
    """CyberChef's "To Hexdump" (width 16, lowercase, no length line)."""
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk).ljust(16 * 3 - 1)
        text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{off:08x}  {hex_part}  |{text}|')
    return '\n'.join(lines)


def encode(message):
    """base64(hex(hexdump(message))) - see the module docstring."""
    hexdump = to_hexdump(message.encode())
    return base64.b64encode(hexdump.encode().hex().encode()).decode()


def _checksum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class _Capture:
    def __init__(self):
        self.packets = []
        self.t = START
        self.rng = random.Random(7)

    def _frame(self, src, dst, proto, transport):
        s, d = socket.inet_aton(src), socket.inet_aton(dst)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(transport),
                         self.rng.randint(1, 65535), 0x4000, 64, proto, 0, s, d)
        ip = ip[:10] + struct.pack('!H', _checksum(ip)) + ip[12:]
        smac, dmac = (VICTIM_MAC, GATEWAY_MAC) if src == VICTIM else (GATEWAY_MAC, VICTIM_MAC)
        return dmac + smac + b'\x08\x00' + ip + transport

    def _add(self, frame, dt):
        self.t += dt
        self.packets.append((self.t, frame))

    def udp(self, src, dst, sport, dport, payload, dt):
        h = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0)
        pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 0, 17, len(h) + len(payload))
        h = h[:6] + struct.pack('!H', _checksum(pseudo + h + payload) or 0xffff)
        self._add(self._frame(src, dst, 17, h + payload), dt)

    def tcp(self, src, dst, sport, dport, seq, ack, flags, payload=b'', dt=0.0005):
        h = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0)
        pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 0, 6, len(h) + len(payload))
        h = h[:16] + struct.pack('!H', _checksum(pseudo + h + payload)) + h[18:]
        self._add(self._frame(src, dst, 6, h + payload), dt)

    def conversation(self, cport, sport, request, response, gap):
        """Handshake, the request and the response split into MSS-sized
        segments, then FIN/FIN."""
        cs, ss = self.rng.randint(10**8, 4 * 10**9), self.rng.randint(10**8, 4 * 10**9)
        self.tcp(VICTIM, C2, cport, sport, cs, 0, 0x02, dt=gap); cs += 1
        self.tcp(C2, VICTIM, sport, cport, ss, cs, 0x12, dt=0.041); ss += 1
        self.tcp(VICTIM, C2, cport, sport, cs, ss, 0x10, dt=0.0004)
        for i in range(0, len(request), MSS):
            seg = request[i:i + MSS]
            self.tcp(VICTIM, C2, cport, sport, cs, ss, 0x18 if i + MSS >= len(request) else 0x10, seg, dt=0.0003)
            cs += len(seg)
        self.tcp(C2, VICTIM, sport, cport, ss, cs, 0x10, dt=0.040)
        for i in range(0, len(response), MSS):
            seg = response[i:i + MSS]
            self.tcp(C2, VICTIM, sport, cport, ss, cs, 0x18 if i + MSS >= len(response) else 0x10, seg, dt=0.002)
            ss += len(seg)
        self.tcp(VICTIM, C2, cport, sport, cs, ss, 0x10, dt=0.0005)
        self.tcp(VICTIM, C2, cport, sport, cs, ss, 0x11, dt=0.001); cs += 1
        self.tcp(C2, VICTIM, sport, cport, ss, cs, 0x11, dt=0.040); ss += 1
        self.tcp(VICTIM, C2, cport, sport, cs, ss, 0x10, dt=0.0004)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for ts, frame in self.packets:
                sec = int(ts)
                f.write(struct.pack('<IIII', sec, int(round((ts - sec) * 1e6)), len(frame), len(frame)) + frame)


def _dns_name(name):
    return b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0'


def _http_request(method, path, body=b'', content_type=None):
    head = f'{method} {path} HTTP/1.1\r\nHost: {DOMAIN}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\n'
    if body:
        head += f'Content-Type: {content_type}\r\nContent-Length: {len(body)}\r\n'
    return (head + 'Connection: close\r\n\r\n').encode() + body


def _http_response(body, content_type):
    return (f'HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: {content_type}\r\n'
            f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode() + body


def build(path):
    cap = _Capture()
    question = _dns_name(DOMAIN) + struct.pack('!HH', 1, 1)
    cap.udp(VICTIM, DNS, 53124, 53, struct.pack('!HHHHHH', 0x1337, 0x0100, 1, 0, 0, 0) + question, 0.0)
    cap.udp(DNS, VICTIM, 53, 53124, struct.pack('!HHHHHH', 0x1337, 0x8180, 1, 1, 0, 0) + question
            + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 300, 4) + socket.inet_aton(C2), 0.018)
    post_body = json.dumps({'host': 'DESKTOP-FINANCE-07', 'build': '6.6.6', 'status': 'checking in',
                            'telemetry': encode(EXFIL), 'encryption': 'military-grade'}, indent=2).encode()
    cap.conversation(49731, 80, _http_request('POST', '/api/v2/telemetry', post_body, 'application/json'),
                     _http_response(b'{"status":"received","next":"/api/v2/tasking"}', 'application/json'), 0.3)
    cap.conversation(49733, 4444, b'HELLO FROM DESKTOP-FINANCE-07 build=6.6.6\n', encode(BEACON).encode(), 1.2)
    cap.conversation(49734, 80, _http_request('GET', '/api/v2/tasking'),
                     _http_response(encode(TASKING).encode(), 'application/octet-stream'), 2.1)
    cap.write(path)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(__doc__.split('Usage:')[1])
    build(sys.argv[1])
