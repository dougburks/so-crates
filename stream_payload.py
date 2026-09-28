#!/usr/bin/env python3
"""Exact-byte stream payloads for SO-CRATES.

The ASCII transcript (socrates.py's _extract_payload_lines) is built for
reading: it decodes each packet as UTF-8 and turns non-printable bytes into
'.', so it can't feed anything that needs the real bytes - an XOR key,
gzip data, shellcode. This module reassembles a flow's payload exactly,
per direction, via tshark's "follow ... raw" mode, which also handles TCP
retransmissions and out-of-order segments (verified against a capture
with a retransmitted segment: it appears once, not twice).
"""

import ipaddress

DIRECTIONS = ('src', 'dst', 'both')


def _follow_endpoint(ip, port):
    """tshark's follow syntax for one endpoint - IPv6 addresses need
    brackets ([2001:db8::1]:80), IPv4 addresses don't."""
    addr = ipaddress.ip_address(ip)
    host = f'[{addr.compressed}]' if addr.version == 6 else addr.compressed
    return f'{host}:{int(port)}'


def follow_command(pcap, proto, src, sport, dst, dport):
    """The tshark command that follows one flow in raw (hex) mode.
    src/dst must already be validated IPs and sport/dport validated
    ports - this builds an argv list (no shell), but the follow spec is
    still parsed by tshark itself."""
    spec = f'follow,{proto},raw,{_follow_endpoint(src, sport)},{_follow_endpoint(dst, dport)}'
    return ['tshark', '-r', pcap, '-q', '-z', spec]


def _parse_node(line):
    """'Node 0: [2001:db8::1]:40001' / 'Node 0: 10.0.0.1:40000' ->
    (ip_address, port), or None for tshark's ':0' no-such-flow marker."""
    endpoint = line.split(':', 1)[1].strip()
    host, _, port = endpoint.rpartition(':')
    host = host.strip('[]')
    if not host:
        return None
    try:
        return ipaddress.ip_address(host), int(port)
    except ValueError:
        return None


def parse_follow_raw(output, src, sport, direction):
    """Payload bytes from tshark 'follow,<proto>,raw' output.

    tshark prints one hex line per segment: unindented for bytes sent by
    'Node 0' (whichever endpoint sent first in the capture - not
    necessarily src, whatever order the endpoints were given in),
    tab-indented for bytes sent by Node 1. direction is 'src' (bytes sent
    by src:sport), 'dst' (bytes sent by the other endpoint) or 'both' (all
    of it, in capture order). Returns b'' for a flow that isn't in the
    capture.
    """
    if direction not in DIRECTIONS:
        raise ValueError(f'direction must be one of {DIRECTIONS}')
    src_endpoint = (ipaddress.ip_address(src), int(sport))
    node0 = None
    chunks = []
    for line in output.split('\n'):
        if line.startswith('Node 0:'):
            node0 = _parse_node(line)
            continue
        if not line.strip() or line.startswith(('=', 'Follow:', 'Filter:', 'Node ')):
            continue
        sent_by_node0 = not line.startswith('\t')
        if direction != 'both':
            if node0 is None:
                return b''
            sent_by_src = sent_by_node0 == (node0 == src_endpoint)
            if sent_by_src != (direction == 'src'):
                continue
        chunks.append(bytes.fromhex(line.strip()))
    return b''.join(chunks)


def run_follow_raw(run_capped, pcap, src, sport, dst, dport, direction, max_bytes, timeout):
    """Exact payload bytes for one flow, trying TCP then UDP (the same
    order as the ASCII transcript). run_capped is socrates.py's
    _run_capped, passed in so its incremental-read size cap applies here
    too. Returns (payload, too_large); raises subprocess.TimeoutExpired.

    tshark's hex output takes at worst ~4 characters per payload byte (two
    hex digits, plus a newline and indent per segment on a stream of 1-byte
    segments), so reading up to 4x max_bytes of it is enough to decide
    whether the payload fits. That read cap covers the whole flow, both
    directions - tshark has no per-direction follow - so asking for one
    small direction of a flow whose other direction is huge also comes
    back too_large.
    """
    read_cap = 4 * max_bytes + 65536
    for proto in ('tcp', 'udp'):
        _, output, truncated = run_capped(
            follow_command(pcap, proto, src, sport, dst, dport),
            max_bytes=read_cap, timeout=timeout, text=True)
        if truncated:
            return b'', True
        payload = parse_follow_raw(output, src, sport, direction)
        if len(payload) > max_bytes:
            return b'', True
        if payload:
            return payload, False
    return b'', False
