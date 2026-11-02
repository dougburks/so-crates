#!/usr/bin/env python3
"""Convert DB-IP's "IP to Country Lite" CSV into geo_lookup.py's compact index.

Usage: build_geoip.py <dbip-country-lite-YYYY-MM.csv.gz> <out country.bin.gz> <YYYY-MM>

The Dockerfile's resources-builder stage downloads the CSV and runs this;
a local dev server can use the same command and point GEOIP_DIR at the
output's folder. DB-IP's ranges cover the whole address space with no
gaps, so only each range's first address is kept (checked here - a gap
would make a lookup return the previous range's country). The format is
geo_lookup.py's: a magic line, a JSON header line, then the IPv4 starts
(4 bytes each, big-endian), one country index byte per IPv4 range, the
IPv6 starts (16 bytes each) and one byte per IPv6 range.
"""

import csv
import gzip
import ipaddress
import json
import sys

MAGIC = b'SOGEO1\n'
MIN_ROWS = 100000   # a truncated download is far smaller


def build(csv_path, out_path, date, min_rows=MIN_ROWS):
    codes, code_index = [], {}
    tables = {4: ([], bytearray()), 6: ([], bytearray())}
    last_end = {4: None, 6: None}
    rows = 0
    with gzip.open(csv_path, 'rt', newline='') as f:
        for start, end, cc in csv.reader(f):
            a, b = ipaddress.ip_address(start), ipaddress.ip_address(end)
            if a.version != b.version or int(b) < int(a):
                raise ValueError(f'bad range {start}-{end}')
            prev = last_end[a.version]
            expected = 0 if prev is None else prev + 1
            if int(a) != expected:
                raise ValueError(f'ranges not contiguous at {start}')
            last_end[a.version] = int(b)
            cc = cc.strip().upper()
            if len(cc) != 2 or not cc.isalpha():
                raise ValueError(f'bad country code {cc!r} for {start}')
            if cc not in code_index:
                if len(codes) == 256:
                    raise ValueError('more than 256 country codes')
                code_index[cc] = len(codes)
                codes.append(cc)
            starts, idx = tables[a.version]
            starts.append(a.packed)
            idx.append(code_index[cc])
            rows += 1
    if rows < min_rows:
        raise ValueError(f'only {rows} ranges - truncated download?')
    for version, top in ((4, (1 << 32) - 1), (6, (1 << 128) - 1)):
        if last_end[version] != top:
            raise ValueError(f'IPv{version} ranges stop before the end of the address space')
    header = {'source': 'DB-IP IP to Country Lite', 'date': date, 'codes': codes,
              'v4': len(tables[4][0]), 'v6': len(tables[6][0])}
    with gzip.open(out_path, 'wb', compresslevel=9) as out:
        out.write(MAGIC)
        out.write(json.dumps(header, separators=(',', ':')).encode() + b'\n')
        for version in (4, 6):
            starts, idx = tables[version]
            out.write(b''.join(starts))
            out.write(bytes(idx))
    return header


if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.exit(__doc__.split('\n\n')[1])
    h = build(*sys.argv[1:4])
    print(f"geoip: {h['v4']} IPv4 and {h['v6']} IPv6 ranges, {len(h['codes'])} countries, {h['date']}")
