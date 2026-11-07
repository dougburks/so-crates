#!/usr/bin/env python3
"""Give a capture taken on loopback (tcpdump -i lo in a container) real-
looking addresses, as attack-lab.pcap's were: the side on one of the
server ports given becomes that server, the other side the client. IPv4
and TCP checksums are rewritten, so neither Suricata nor tshark sees a bad
one. Classic pcap only.

attack-lab.pcap was made from five such captures - the attacker
203.0.113.66 against Redis (10.20.5.21), MySQL (10.20.5.30) and SQL Server
(10.20.5.31), a Zabbix agent (10.20.5.40) talking to its server
(10.20.5.10) and probed on 10.20.5.41, and a bot (10.20.7.88) on an IRC
server (198.51.100.67) - merged with mergecap -F pcap.

Usage: readdress.py <in.pcap> <out.pcap> <client IP> <port>=<server IP> ...
"""
import socket, struct, sys

src, dst, client, servers = sys.argv[1], sys.argv[2], sys.argv[3], dict(a.split('=') for a in sys.argv[4:])
servers = {int(p): ip for p, ip in servers.items()}


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


raw = open(src, 'rb').read()
out = bytearray(raw[:24])
link = struct.unpack('<I', raw[20:24])[0]
at = 24
while at + 16 <= len(raw):
    hdr = raw[at:at + 16]
    incl = struct.unpack('<I', hdr[8:12])[0]
    pkt = bytearray(raw[at + 16:at + 16 + incl])
    at += 16 + incl
    off = 14 if link == 1 else 16 if link == 113 else 4 if link == 0 else None
    if off is not None and len(pkt) > off + 20 and pkt[off] >> 4 == 4 and pkt[off + 9] == 6:
        ihl = (pkt[off] & 15) * 4
        sport, dport = struct.unpack('!HH', pkt[off + ihl:off + ihl + 4])
        server_ip = servers.get(dport) or servers.get(sport)
        if server_ip:
            to_server = dport in servers
            a, b = (client, server_ip) if to_server else (server_ip, client)
            pkt[off + 12:off + 16], pkt[off + 16:off + 20] = socket.inet_aton(a), socket.inet_aton(b)
            pkt[off + 10:off + 12] = b'\0\0'
            pkt[off + 10:off + 12] = struct.pack('!H', csum(bytes(pkt[off:off + ihl])))
            total = struct.unpack('!H', pkt[off + 2:off + 4])[0]
            tcp = off + ihl
            seg = pkt[tcp:off + total]
            seg[16:18] = b'\0\0'
            pseudo = pkt[off + 12:off + 20] + struct.pack('!BBH', 0, 6, len(seg))
            seg[16:18] = struct.pack('!H', csum(bytes(pseudo + seg)))
            pkt[tcp:off + total] = seg
    out += hdr + pkt
open(dst, 'wb').write(out)
