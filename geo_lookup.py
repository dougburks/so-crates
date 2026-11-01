#!/usr/bin/env python3
"""IP address to country, for the Traffic Map and its country:XX filter.

The data is DB-IP's "IP to Country Lite" (CC BY 4.0), converted at image
build time by scripts/build_geoip.py into one gzip-compressed file baked
into GEOIP_DIR - see that script for the format. Like playbook_lookup.py,
it's static reference data with no runtime refresh, read once into
memory on first use (about 8 MB). A local dev run without it still works:
every public address is then '??'.

country() returns an ISO 3166-1 alpha-2 code, 'LAN' for an address that
doesn't route on the internet (private, loopback, link-local, multicast,
unspecified, shared CGNAT space), or '??' when there's no answer.
"""

import functools
import gzip
import ipaddress
import json
import os
import threading

# Overridable the same way PLAYBOOKS_DIR is (playbook_lookup.py).
GEOIP_DIR = os.environ.get('GEOIP_DIR', '/usr/share/geoip')
GEOIP_FILE = 'country.bin.gz'
_MAGIC = b'SOGEO1\n'

LOCAL = 'LAN'
UNKNOWN = '??'

_lock = threading.Lock()
_data = {}   # base_dir -> loaded index, or None when it's missing or unreadable


def _load(base_dir):
    with _lock:
        if base_dir in _data:
            return _data[base_dir]
        index = None
        try:
            with gzip.open(os.path.join(base_dir, GEOIP_FILE), 'rb') as f:
                blob = f.read()
            if blob.startswith(_MAGIC):
                end = blob.index(b'\n', len(_MAGIC))
                header = json.loads(blob[len(_MAGIC):end])
                pos = end + 1
                n4, n6 = header['v4'], header['v6']
                v4 = blob[pos:pos + 4 * n4]; pos += 4 * n4
                i4 = blob[pos:pos + n4]; pos += n4
                v6 = blob[pos:pos + 16 * n6]; pos += 16 * n6
                i6 = blob[pos:pos + n6]; pos += n6
                if pos == len(blob) and n4 and n6:
                    index = {'header': header, 'codes': header['codes'],
                             4: (v4, i4, 4, n4), 6: (v6, i6, 16, n6)}
        except (OSError, EOFError, ValueError, KeyError, TypeError, gzip.BadGzipFile):
            index = None
        _data[base_dir] = index
        return index


def info(base_dir=None):
    """{'source', 'date'} of the baked-in data, or None without it."""
    index = _load(base_dir or GEOIP_DIR)
    if not index:
        return None
    return {'source': index['header'].get('source', ''), 'date': index['header'].get('date', '')}


def _find(table, packed):
    """Index of the last range starting at or before packed - big-endian
    bytes of a fixed width compare the same as the numbers."""
    starts, _, width, n = table
    lo, hi = 0, n
    while lo < hi:
        mid = (lo + hi) // 2
        if starts[mid * width:(mid + 1) * width] <= packed:
            lo = mid + 1
        else:
            hi = mid
    return lo - 1


@functools.lru_cache(maxsize=200000)
def _country(ip, base_dir):
    try:
        addr = ipaddress.ip_address(ip.strip())
    except (ValueError, AttributeError):
        return UNKNOWN
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if addr.version == 4 and addr.is_reserved and int(addr) != 0xFFFFFFFF:
        return UNKNOWN   # 240/4: never assigned, so no network of anyone's - but its broadcast, which is local
    if addr.is_multicast or not addr.is_global:
        # private, loopback, link-local, unspecified, CGNAT, multicast
        return LOCAL
    index = _load(base_dir)
    if not index:
        return UNKNOWN
    table = index[addr.version]
    i = _find(table, addr.packed)
    if i < 0:
        return UNKNOWN
    cc = index['codes'][table[1][i]]
    return UNKNOWN if cc == 'ZZ' else cc


def country(ip, base_dir=None):
    if not ip:
        return UNKNOWN
    return _country(str(ip), base_dir or GEOIP_DIR)


def clear_cache():
    """For tests: forget loaded data and cached answers."""
    with _lock:
        _data.clear()
    _country.cache_clear()
