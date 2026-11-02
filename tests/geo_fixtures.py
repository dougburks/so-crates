"""A tiny DB-IP-shaped country index for tests - geo_lookup.py's format,
built by scripts/build_geoip.py from ranges that cover every address."""

import csv
import gzip
import importlib.util
import os

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')

RANGES = [
    ('0.0.0.0', '8.8.8.255', 'US'),
    ('8.8.9.0', '100.255.255.255', 'DE'),
    ('101.0.0.0', '199.255.255.255', 'ZZ'),
    ('200.0.0.0', '255.255.255.255', 'FR'),
    ('::', '2a00:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'JP'),
    ('2a01::', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'BR'),
]


def load_build_geoip():
    spec = importlib.util.spec_from_file_location('build_geoip', os.path.join(ROOT, 'scripts', 'build_geoip.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_csv(path, ranges=RANGES):
    with gzip.open(path, 'wt', newline='') as f:
        csv.writer(f).writerows(ranges)
    return path


def build_geoip_dir(directory, ranges=RANGES):
    """Writes country.bin.gz into directory and returns directory."""
    os.makedirs(directory, exist_ok=True)
    src = write_csv(os.path.join(directory, 'dbip.csv.gz'), ranges)
    load_build_geoip().build(src, os.path.join(directory, 'country.bin.gz'), '2026-11', min_rows=1)
    os.remove(src)
    return directory
