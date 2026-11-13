#!/usr/bin/env python3
"""Download the corpus of real captures that scripts/fuzz_shark_parsers.py
and scripts/sweep_shark_suricata.py are run over (see the docs' testing
page) - into the folder layout both expect, and checked against the
SHA-256 of every file the corpus held when this was written
(scripts/corpus/manifest.sha256).

    python3 scripts/fetch_corpus.py <corpus dir> [<folder> ...]

Folders (all of them by default):

    wstest      the manifest's share of Wireshark's test captures
                (test/captures in its source), by name, and some of its
                wiki's sample captures
                (scripts/corpus/ws_urls.txt, 10 MB or smaller), named
                <upload hash or SampleCaptures>_<file>
    ws_tns      the Oracle TNS ones among them, named as uploaded
    ws_syslog   two of Wireshark's syslog samples
    ws_ics2     EtherCAT and Omron FINS (automayt/ICS-pcap) and HART-IP
                (Wireshark's samples)
    ics         4SICS's three days of an ICS lab's traffic (Netresec)
    ics_iti     ITI/ICS-Security-Tools' BACnet, IEC 104, IEC 61850, OPC
                and PROFINET captures
    ics_emre    EmreEkin/ICS-Pcaps' BACnet, IEC 104, IEC 61850, LLDP,
                OPC UA and PROFINET captures
    ics_inl     fourteen of Idaho National Laboratory's ICS captures
                (idaholab/Malcolm-Test-Artifacts)
    mta         infections from malware-traffic-analysis.net
    mta_scans   six weeks of scans hitting that site's own web server
    mta_ex      its traffic analysis exercises

A file already there is kept, so a run that stopped can be run again. A
file whose hash differs from the manifest's - its source changed it - is
kept and reported; one that couldn't be fetched is reported too, and the
exit status is 1 if anything is missing. malware-traffic-analysis.net's
zips hold live malware traffic behind its published password
(infected_<date>); only the capture inside is written. GitHub archives
and zips are read in memory and only their capture files written, by
name, so nothing in them chooses a path.

Sweeping needs Suricata's output for each capture too, which this
doesn't make - see --eve.

    python3 scripts/fetch_corpus.py <corpus dir> --eve so-crates:local

runs Suricata in that SO-CRATES image (podman, or docker) over every
capture without an eve/<folder>__<file>.eve.json yet - the same Suricata
version and config as an analysis.
"""

import argparse
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(HERE, 'corpus', 'manifest.sha256')
WS_URLS = os.path.join(HERE, 'corpus', 'ws_urls.txt')
USER_AGENT = 'SO-CRATES corpus fetch (https://github.com/dougburks/so-crates)'
CAPTURE_MAGIC = (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a')
CAPTURE_SUFFIXES = ('.pcap', '.pcapng', '.cap', '.pcap.gz', '.pcapng.gz')
WS_MAX_BYTES = 10 * 1024 * 1024
MTA = 'https://www.malware-traffic-analysis.net'
MTA_MAX_BYTES = 300 * 1024 * 1024
# Wireshark's own test captures, from its source tree
WS_TEST_CAPTURES = 'https://gitlab.com/wireshark/wireshark/-/archive/master/wireshark-master.tar.gz?path=test/captures'
WIKI_SAMPLES = 'https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/'

ICS = [
    'https://share.netresec.com/s/xYj2qCNbsLEAd6M/download/4SICS-GeekLounge-151020.pcap',
    'https://share.netresec.com/s/camL59aoxbCRyyZ/download/4SICS-GeekLounge-151021.pcap',
    'https://share.netresec.com/s/gw6Y2QzJHqDD5pr/download/4SICS-GeekLounge-151022.pcap',
]
# GitHub repositories: (archive, the folders inside it to copy, flattened)
ICS_ITI = ('https://codeload.github.com/ITI/ICS-Security-Tools/tar.gz/refs/heads/master', 'ICS-Security-Tools-master/pcaps',
           ('BACnet', 'IEC60870-5-104', 'IEC61850', 'OPC', 'profinet'))
ICS_EMRE = ('https://codeload.github.com/EmreEkin/ICS-Pcaps/tar.gz/refs/heads/master', 'ICS-Pcaps-master',
            ('BacNET', 'IEC60870-104', 'IEC61850', 'OPC-UA', 'Profinet', 'LLDP'))
# Plain files in the repository (media.githubusercontent.com, for Git LFS
# files, has none of them)
INL = 'https://raw.githubusercontent.com/idaholab/Malcolm-Test-Artifacts/main/'
ICS_INL = [
    'pcap/other/Digital Bond S4/BACnet_FIU.pcap', 'pcap/other/Digital Bond S4/BACnet_Host.pcap',
    'pcap/protocols/BACnet.pcap', 'pcap/protocols/BACnet_device_control.pcap', 'pcap/protocols/IEC104.pcap',
    'pcap/protocols/OPCUA-Binary.pcap', 'pcap/protocols/PROFINET.pcap', 'pcap/protocols/S7comm.pcap',
    'pcap/protocols/ENIP.pcap', 'pcap/protocols/Modbus.pcap', 'pcap/protocols/DNP3.pcap',
    'pcap/protocols/Synchrophasor.pcap', 'pcap/protocols/BSAP.pcap', 'pcap/protocols/ETHERCAT.pcap',
]
AUTOMAYT = 'https://media.githubusercontent.com/media/automayt/ICS-pcap/master/'
WS_ICS2 = {'ethercat.pcap': AUTOMAYT + 'ETHERCAT/ethercat/ethercat.pcap',
           'omron.pcap': AUTOMAYT + 'FINS%20(OMRON)/omron/omron.pcap',
           'hart_ip.pcap': WIKI_SAMPLES + 'hart_ip.pcap'}
WS_SYSLOG = ('nb6-startup.pcap', 'packlog-example.cap')
# malware-traffic-analysis.net's exercises whose capture's name doesn't
# start with its post's date
MTA_EX_POSTS = {'2021-07-traffic-analysis-exercise.pcap': '2021/07/14'}


class Fetch:
    """Downloads with a pause between requests, backing off when a
    server says too many - for that request's retries only, so one refusal
    doesn't slow every request after it."""

    def __init__(self, delay):
        self.delay = delay

    def get(self, url, max_bytes=None):
        wait = self.delay
        for _attempt in range(6):
            time.sleep(wait)
            request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
            try:
                with urllib.request.urlopen(request, timeout=900) as response:
                    if max_bytes and int(response.headers.get('Content-Length') or 0) > max_bytes:
                        return None
                    data = response.read(max_bytes + 1 if max_bytes else -1)
                    return None if max_bytes and len(data) > max_bytes else data
            except urllib.error.HTTPError as error:
                if error.code != 429:
                    raise
                after = error.headers.get('Retry-After', '')
                wait = min(120, int(after)) if after.isdigit() else min(60, wait * 2)
        raise RuntimeError(f'still refused after retries: {url}')


def is_capture(data):
    return data[:4] in CAPTURE_MAGIC or data[:2] == b'\x1f\x8b'


def write(folder, name, data):
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, os.path.basename(name))
    with open(path + '.part', 'wb') as f:
        f.write(data)
    os.replace(path + '.part', path)
    return path


def fetch_urls(fetch, folder, named_urls, max_bytes=None, report=print):
    for name, url in named_urls:
        if os.path.exists(os.path.join(folder, name)):
            continue
        try:
            data = fetch.get(url, max_bytes)
        except (OSError, RuntimeError, urllib.error.URLError) as error:
            report(f'  failed {name}: {error}')
            continue
        if data is None:
            report(f'  skipped {name}: over {max_bytes // (1024 * 1024)} MB')
        elif not is_capture(data):
            report(f'  skipped {name}: not a capture')
        else:
            write(folder, name, data)


def ws_urls():
    with open(WS_URLS) as f:
        return [line.strip() for line in f if line.strip()]


def ws_name(url):
    """A sample capture's name in wstest: its folder in the URL (an upload's
    hash, or SampleCaptures) in front of its own - two uploads can share a
    name, and Wireshark's test captures, beside them, keep theirs alone."""
    folder, name = url.rstrip('/').split('/')[-2:]
    return f'{folder}_{name}'


def wstest(fetch, out):
    """Only the captures the manifest lists: Wireshark keeps adding test
    captures, and the wiki's names can match another folder's files."""
    folder = os.path.join(out, 'wstest')
    listed = {p.split('/', 1)[1] for p in _manifest() if p.startswith('wstest/')}
    tests = {name for name in listed if not re.match(r'([0-9a-f]{32}|SampleCaptures)_', name)}
    if not all(os.path.exists(os.path.join(folder, name)) for name in tests):
        for path, data in archive_captures(fetch.get(WS_TEST_CAPTURES), '/test/captures/'):
            name = os.path.basename(path)
            if name in tests and not os.path.exists(os.path.join(folder, name)):
                write(folder, name, data)
    fetch_urls(fetch, folder, [(ws_name(url), url) for url in ws_urls() if ws_name(url) in listed], WS_MAX_BYTES)


def ws_tns(fetch, out):
    named = [(urllib.parse.unquote(u.rsplit('/', 1)[-1]), u) for u in ws_urls() if re.search('tns|oracle', u, re.I)]
    fetch_urls(fetch, os.path.join(out, 'ws_tns'), named, WS_MAX_BYTES)


def ws_syslog(fetch, out):
    fetch_urls(fetch, os.path.join(out, 'ws_syslog'), [(n, WIKI_SAMPLES + n) for n in WS_SYSLOG])


def ws_ics2(fetch, out):
    fetch_urls(fetch, os.path.join(out, 'ws_ics2'), sorted(WS_ICS2.items()))


def ics(fetch, out):
    fetch_urls(fetch, os.path.join(out, 'ics'), [(u.rsplit('/', 1)[-1], u) for u in ICS])


def ics_inl(fetch, out):
    fetch_urls(fetch, os.path.join(out, 'ics_inl'),
               [(p.rsplit('/', 1)[-1], INL + urllib.parse.quote(p)) for p in ICS_INL])


def archive_captures(data, within):
    """The capture files in a .tar.gz under a path containing `within`, as
    (path in the archive, bytes) - read in memory, written by the caller
    by name alone."""
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
        for member in tar:
            if within in member.name and member.isfile() and member.name.lower().endswith(CAPTURE_SUFFIXES):
                yield member.name, tar.extractfile(member).read()


def github_archive(fetch, out, folder, source):
    archive, root, folders = source
    wanted = {f'{root}/{d}/': d for d in folders}
    if all(os.path.isdir(os.path.join(out, folder, d)) and os.listdir(os.path.join(out, folder, d)) for d in folders):
        return
    for path, data in archive_captures(fetch.get(archive), f'{root}/'):
        prefix = next((p for p in wanted if path.startswith(p)), None)
        if prefix is not None:
            target = os.path.join(out, folder, wanted[prefix])
            if not os.path.exists(os.path.join(target, os.path.basename(path))):
                write(target, path, data)


def ics_iti(fetch, out):
    github_archive(fetch, out, 'ics_iti', ICS_ITI)


def ics_emre(fetch, out):
    github_archive(fetch, out, 'ics_emre', ICS_EMRE)


def _manifest():
    entries = {}
    with open(MANIFEST) as f:
        for line in f:
            digest, path = line.rstrip('\n').split('  ', 1)
            entries[path] = digest
    return entries


def mta_posts(folder, report=print):
    """The manifest's captures in one of malware-traffic-analysis.net's
    folders, each with its post (YYYY/MM/DD)."""
    for path in sorted(_manifest()):
        top, name = path.split('/', 1)
        if top != folder:
            continue
        post = MTA_EX_POSTS.get(name)
        if post is None:
            match = re.match(r'(\d{4})-(\d\d)-(\d\d)-', name)
            if not match:
                report(f'  no post date in {name}')
                continue
            post = '/'.join(match.groups())
        yield name, post


def mta_folder(fetch, out, folder, report=print):
    target = os.path.join(out, folder)
    for name, post in mta_posts(folder, report):
        if os.path.exists(os.path.join(target, name)):
            continue
        try:
            page = fetch.get(f'{MTA}/{post}/index.html').decode('utf-8', 'replace')
            zips = re.findall(r'href="([^"/]+\.zip)"', page)
            # the post's zip of this capture - by name, or its only capture zip
            zip_name = next((z for z in zips if z == name + '.zip'), None) or \
                next((z for z in zips if 'pcap' in z.lower()), None)
            if zip_name is None:
                report(f'  failed {name}: no zip on {post}')
                continue
            data = fetch.get(f'{MTA}/{post}/{zip_name}', MTA_MAX_BYTES)
            if data is None:
                report(f'  skipped {name}: over 300 MB')
                continue
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                member = next((m for m in archive.infolist() if os.path.basename(m.filename) == name), None)
                if member is None or member.file_size > MTA_MAX_BYTES:
                    report(f'  failed {name}: not in {zip_name}')
                    continue
                write(target, name, archive.read(member, pwd=f"infected_{post.replace('/', '')}".encode()))
        except (OSError, RuntimeError, urllib.error.URLError, zipfile.BadZipFile) as error:
            report(f'  failed {name}: {error}')


def mta(fetch, out):
    mta_folder(fetch, out, 'mta')


def mta_scans(fetch, out):
    mta_folder(fetch, out, 'mta_scans')


def mta_ex(fetch, out):
    mta_folder(fetch, out, 'mta_ex')


FOLDERS = {'wstest': (wstest, 3), 'ws_tns': (ws_tns, 3), 'ws_syslog': (ws_syslog, 3), 'ws_ics2': (ws_ics2, 1),
           'ics': (ics, 1), 'ics_iti': (ics_iti, 1), 'ics_emre': (ics_emre, 1), 'ics_inl': (ics_inl, 1),
           'mta': (mta, 1), 'mta_scans': (mta_scans, 1), 'mta_ex': (mta_ex, 1)}


def check(out, folders):
    """Each folder's files against the manifest: (missing, changed, extra)."""
    expected = {p: d for p, d in _manifest().items() if p.split('/', 1)[0] in folders}
    missing, changed = [], []
    for path, digest in sorted(expected.items()):
        full = os.path.join(out, path)
        if not os.path.exists(full):
            missing.append(path)
            continue
        h = hashlib.sha256()
        with open(full, 'rb') as f:
            for block in iter(lambda: f.read(1 << 20), b''):
                h.update(block)
        if h.hexdigest() != digest:
            changed.append(path)
    extra = []
    for folder in folders:
        for root, _dirs, files in os.walk(os.path.join(out, folder)):
            for name in files:
                path = os.path.relpath(os.path.join(root, name), out)
                if path not in expected:
                    extra.append(path)
    return missing, changed, sorted(extra)


def make_eve(out, image):
    """Suricata's output for every capture without one, from Suricata in
    the SO-CRATES image - one container, a run per capture."""
    engine = shutil.which('podman') or shutil.which('docker')
    if not engine:
        sys.exit('--eve needs podman or docker')
    eve = os.path.join(out, 'eve')
    os.makedirs(eve, exist_ok=True)
    name = 'so-crates-corpus-eve'
    subprocess.run([engine, 'rm', '-f', name], capture_output=True)
    subprocess.run([engine, 'run', '-d', '--name', name, '-v', f'{os.path.abspath(out)}:/corpus:ro,Z', image],
                   check=True, capture_output=True)
    try:
        time.sleep(8)        # the image copies its baked-in rules into place at startup
        for folder in FOLDERS:
            for root, _dirs, files in os.walk(os.path.join(out, folder)):
                for capture in sorted(files):
                    rel = os.path.relpath(os.path.join(root, capture), out)
                    top, rest = rel.split('/', 1)
                    target = os.path.join(eve, f"{top}__{rest.replace('/', '+')}.eve.json")
                    if os.path.exists(target):
                        continue
                    inner = ('rm -rf /tmp/o && mkdir -p /tmp/o && suricata -r "/corpus/$1" -c /data/suricata/suricata.yaml '
                             '-l /tmp/o -k none --runmode single >/dev/null 2>&1; cat /tmp/o/eve.json')
                    result = subprocess.run([engine, 'exec', name, 'sh', '-c', inner, 'sh', rel], capture_output=True)
                    if result.returncode or not result.stdout:
                        print(f'  no eve for {rel}')
                        continue
                    write(eve, target, result.stdout)
                    print(f'  eve {rel}', flush=True)
    finally:
        subprocess.run([engine, 'rm', '-f', name], capture_output=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n', 1)[0])
    parser.add_argument('corpus', help='the folder to fetch into')
    parser.add_argument('folders', nargs='*', help=f"which folders (default: all - {', '.join(FOLDERS)})")
    parser.add_argument('--check', action='store_true', help='only compare what is there with the manifest')
    parser.add_argument('--eve', metavar='IMAGE', help="then run Suricata in this SO-CRATES image for eve/")
    args = parser.parse_args(argv)
    folders = args.folders or list(FOLDERS)
    unknown = [f for f in folders if f not in FOLDERS]
    if unknown:
        parser.error(f"unknown folder: {', '.join(unknown)}")
    if not args.check:
        for folder in folders:
            fetcher, delay = FOLDERS[folder]
            print(f'{folder}...', flush=True)
            fetcher(Fetch(delay), args.corpus)
    missing, changed, extra = check(args.corpus, folders)
    for label, paths in (('missing', missing), ('changed since the manifest', changed), ('not in the manifest', extra)):
        if paths:
            print(f'{len(paths)} {label}:')
            for path in paths:
                print(f'  {path}')
    total = sum(1 for p in _manifest() if p.split('/', 1)[0] in folders)
    print(f'{total - len(missing) - len(changed)} of {total} files as in the manifest')
    if args.eve:
        make_eve(args.corpus, args.eve)
    return 1 if missing else 0


if __name__ == '__main__':
    sys.exit(main())
