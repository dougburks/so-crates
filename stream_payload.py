#!/usr/bin/env python3
"""Stream payloads for SO-CRATES: one flow's packets, as exact bytes or as
text to read.

The ASCII transcript (transcript_lines) and the hexdump (parse_hexdump,
of tcpdump -X) are built for reading: the transcript decodes each packet
as UTF-8 and turns non-printable bytes into '.', so it can't feed
anything that needs the real bytes - an XOR key, gzip data, shellcode.
run_follow_raw reassembles a flow's payload exactly, per direction, via
tshark's "follow ... raw" mode, which also handles TCP retransmissions
and out-of-order segments (verified against a capture with a
retransmitted segment: it appears once, not twice).

Carving the flow out of the capture first stays in socrates.py's
handlers; they pass in their _run_capped, so its size cap applies here.
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
        try:
            chunks.append(bytes.fromhex(line.strip()))
        except ValueError:
            continue  # skip a malformed hex line rather than fail the whole read
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


def transcript_command(pcap, src, sport, dst, dport, proto):
    """The tshark command printing each packet's source address and payload
    (hex) for one flow - src/dst validated IPs, sport/dport validated
    ports."""
    # tshark's ip.* fields don't match IPv6 at all ("not a valid
    # hostname or IPv4 address", silently giving an empty transcript) -
    # IPv6 flows need the ipv6.* fields instead.
    family = 'ipv6' if ipaddress.ip_address(src).version == 6 else 'ip'
    display_filter = (f'{family}.addr == {src} && {family}.addr == {dst} && '
                      f'{proto}.port == {sport} && {proto}.port == {dport}')
    if proto == 'tcp':
        # The transcript joins a TCP stream's segments into one byte
        # stream, so a retransmitted segment would be spliced into the
        # middle of a line rather than show as a harmless duplicate.
        display_filter += ' && !tcp.analysis.retransmission'
    return ['tshark', '-r', pcap, '-Y', display_filter,
            '-T', 'fields', '-e', f'{family}.src', '-e', f'{proto}.payload']


def parse_transcript(output, src):
    """transcript_command's output -> [{'text', 'direction'}], one per
    packet with a payload: printable ASCII (and newlines/tabs) kept, every
    other byte '.', direction 'src' for packets from src."""
    src_addr = ipaddress.ip_address(src)
    lines = []
    for line in output.strip().split('\n'):
        if not line.strip():
            continue
        parts = line.split('\t')
        if len(parts) < 2:
            continue
        packet_src = parts[0].strip()
        payload_hex = parts[1].replace(':', '')
        if payload_hex:
            try:
                payload_bytes = bytes.fromhex(payload_hex)
                payload_str = payload_bytes.decode('utf-8', errors='replace')
                cleaned = ''.join(c if c in '\n\r\t' or 32 <= ord(c) < 127 else '.' for c in payload_str)
                # Whitespace-only payloads are kept: an interactive
                # session sends Enter or a space as its own segment, and
                # dropping it ran the neighboring commands together once
                # the transcript joins segments.
                # Compared as addresses, not strings: Suricata logs IPv6
                # fully expanded, tshark prints it compressed.
                direction = 'src' if ipaddress.ip_address(packet_src) == src_addr else 'dst'
                lines.append({'text': cleaned, 'direction': direction})
            except ValueError:
                pass
    return lines


def transcript_lines(run_capped, pcap, src, sport, dst, dport, proto, max_bytes, timeout):
    """The ASCII transcript of one flow over proto ('tcp' or 'udp'):
    parse_transcript of transcript_command, read through run_capped
    (socrates.py's _run_capped, as for run_follow_raw) up to max_bytes -
    the response is trimmed far below that, so anything past it could
    never be shown anyway. Raises subprocess.TimeoutExpired."""
    _, output, _ = run_capped(transcript_command(pcap, src, sport, dst, dport, proto),
                              max_bytes=max_bytes, timeout=timeout, text=True)
    return parse_transcript(output, src)


def parse_hexdump(output, max_packets, max_chars):
    """tcpdump -X's output -> ([{'header', 'lines'}], truncated): one entry
    per packet, its header line and its hex lines, stopping at max_packets
    packets or max_chars characters of hex lines."""
    packets = []
    current_packet = None
    total_chars = 0
    truncated = False

    for line in output.split('\n'):
        if not line.strip():
            if current_packet:
                packets.append(current_packet)
                current_packet = None
            continue

        if line.startswith('\t0x'):
            if current_packet:
                current_packet['lines'].append(line.strip())
                total_chars += len(line)
        else:
            if current_packet:
                packets.append(current_packet)
            current_packet = {'header': line.strip(), 'lines': []}

        if len(packets) >= max_packets or total_chars > max_chars:
            truncated = True
            break

    # (stopped at the packet limit, current_packet is the next
    # packet's header alone - one more than the limit, and empty)
    if current_packet and len(packets) < max_packets:
        packets.append(current_packet)
    return packets, truncated
