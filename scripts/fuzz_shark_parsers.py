#!/usr/bin/env python3
"""Fuzz tshark's protocol parsers (shark_protocols) - before a release, and
after adding or changing a parser. A parser reads bytes a capture's sender
chose; one that raises costs the run that packet (shark_analyzer's
_parser_failed), one that hangs stalls it to its timeout. This looks for
both, two ways:

1. Field level, most of the work: tshark runs over every protocol fixture
   (tests/protocol_fixtures.py) and any captures given, and each parser's
   calls are recorded - the fields (or, for the structured protocols, the
   JSON tree) it was handed for each packet. Each parser then replays a
   recording thousands of times with one to three of those values mutated:
   bytes flipped, cut short or repeated, numbers huge, negative or not
   ASCII digits (int() refuses some of what str.isdigit() takes), JSON of
   the wrong type, fields given many times. Any exception, a replay taking
   more than 2 seconds (5 is a hang), or a record that won't serialize as
   JSON is a finding.
2. Packet level: the fixtures' and the captures' classic pcaps with their
   payload bytes mutated (Ethernet, IP and TCP/UDP headers left alone, so
   tshark still names the protocol), each run through run_tshark - what
   tshark's own dissectors make of damaged packets.

Each distinct finding is printed once - parser, error and where, the
recording or capture it came from - and the exit status is 1 if there was
any. Packet-level findings keep the variant that caused them in --out.

Captures (pcap, pcapng or cap, up to --max-size MB each) are found under
the directories given; the corpus the docs' testing page describes is a
good source (its wstest, ics and ics_emre subdirectories cover most
parsers). With none, only the fixtures are used - every parser has one.

Memory: about 2 GB at its peak with the defaults (8 workers, each holding
one parser's recordings). Run it in a scope of its own anyway, so a parser
whose memory runs away under some mutation is stopped there rather than
by the kernel's out-of-memory killer, which picks its own victim - on a
desktop, as likely the app it was started from:
    systemd-run --user --scope -p MemoryMax=8G python3 scripts/fuzz_shark_parsers.py ...

Usage: python3 scripts/fuzz_shark_parsers.py [<capture dir> ...]
           [--iterations N] [--packets N] [--seed N] [--jobs N] [--only Parser,...]
           [--max-size MB] [--out DIR]
"""

import argparse
import copy
import json
import multiprocessing
import os
import pickle
import random
import re
import signal
import struct
import sys
import tempfile
import time
import traceback

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.insert(0, ROOT)
# A parser that raises fails the run here, as in the tests - not skipped
os.environ['SOCRATES_STRICT_PARSERS'] = '1'

NUMBERS = ['-1', '0', '-2147483649', '4294967296', '99999999999999999999999', '0xffffffff', '0x', '²', '٣',
           'NaN', 'inf', '-0', '1e400', 'True', 'False', '', ' ', '\x00', '1.5', '65535', '-65536']
TEXT = ['', 'A' * 20000, '�', '\x00\x01\xff', '{', '[', '{"a":', '%s%n', '‮', '\\', '\\x', ':', ',',
        '<script>', 'null']
JUNK_JSON = [None, 0, -1, 1e308, True, [], {}, [[[]]], {'a': {'b': []}}, 'x', [1, 'x', None], 2 ** 70]
SEQUENCES_MAX = 150       # recordings kept per parser
CALLS_MAX = 2000          # calls kept per recording
SLOW_SECONDS, HANG_SECONDS = 2, 5
HEADERS = 54              # Ethernet, IPv4 and TCP without options: past them, the payload
# What a number in a text protocol (memcached, Redis, IRC...) becomes:
# lengths and counts a parser may trust
TEXT_NUMBERS = [b'-1', b'-17', b'0', b'99999999999999999999', b'4294967296', b'\xc2\xb2', b'\xd9\xa3', b'']
_NUMBER = re.compile(rb'\d+')


# ---------------------------------------------------------------- recording

_calls = None              # this worker's recording: parser name -> calls


def _wrap_parsers():
    """Have every parser's feed record its calls in _calls - once per
    worker process, which records capture after capture."""
    import shark_protocols

    def wrap(cls, method):
        original = getattr(cls, method)

        def recorder(self, pkt, value):
            _calls.setdefault(cls.__name__, []).append((method, pkt, copy.deepcopy(value)))
            return original(self, pkt, value)
        setattr(cls, method, recorder)
    for cls in shark_protocols.PROTOCOLS:
        wrap(cls, 'feed')
    for cls in shark_protocols.STRUCTURED_PROTOCOLS:
        wrap(cls, 'feed_json')


def _record(path):
    """Run tshark over one capture with every parser's feed recorded:
    {parser name: [(method, packet, value), ...]}."""
    global _calls
    import shark_analyzer
    if _calls is None:
        _wrap_parsers()
    _calls = calls = {}
    try:
        shark_analyzer.run_tshark(path, timeout=600)
    except Exception as e:
        return path, {}, f'{type(e).__name__}: {e}'
    return path, {name: seq[:CALLS_MAX] for name, seq in calls.items()}, None


# ---------------------------------------------------------------- mutation

def _mutate_bytes(data, rnd):
    numbers = list(_NUMBER.finditer(data))
    if numbers and rnd.random() < 0.4 and sum(32 <= b < 127 or b in (9, 10, 13) for b in data) > 0.9 * len(data):
        # text: one of its numbers changed, as a sender would
        match = rnd.choice(numbers)
        # (a negative one of any size: one that cancels its own line's
        # length sends a parser back to where it started)
        number = b'-%d' % rnd.randint(1, 300) if rnd.random() < 0.5 else rnd.choice(TEXT_NUMBERS)
        return data[:match.start()] + number + data[match.end():]
    data = bytearray(data)
    for _ in range(rnd.randint(1, 4)):
        op = rnd.random()
        if not data or op < 0.15:
            data += bytes(rnd.getrandbits(8) for _ in range(rnd.randint(1, 16)))
        elif op < 0.35:
            del data[rnd.randrange(len(data)):]
        elif op < 0.6:
            data[rnd.randrange(len(data))] = rnd.choice([0, 0xff, 0x7f, 0x80, rnd.getrandbits(8)])
        elif op < 0.75:
            i = rnd.randrange(len(data))
            data[i:i + 4] = rnd.choice([b'\xff\xff\xff\xff', b'\x00\x00\x00\x00', b'\x7f\xff\xff\xff', b'\x80\x00'])
        elif op < 0.85:
            i = rnd.randrange(len(data))
            data[i:i] = data[i:i + rnd.randint(1, 64)] * rnd.randint(2, 50)
        else:
            data = data[:rnd.randrange(len(data) + 1)] + bytes(rnd.randint(0, 3))
    return bytes(data)


def _mutate_string(s, rnd, raw):
    r = rnd.random()
    if raw or (len(s) >= 4 and all(c in '0123456789abcdefABCDEF:' for c in s)):
        try:
            data = bytes.fromhex(s.replace(':', ''))
            return _mutate_bytes(data, rnd).hex() if rnd.random() < 0.9 else s[:rnd.randrange(len(s) + 1)]
        except ValueError:
            pass
    if s[:1] in ('{', '[') and r < 0.6:
        try:
            return json.dumps(_mutate_tree(json.loads(s), rnd))
        except ValueError:
            return s[:rnd.randrange(len(s) + 1)]
    if r < 0.35:
        return rnd.choice(NUMBERS)
    if r < 0.6:
        return rnd.choice(TEXT)
    if r < 0.8 and s:
        return s[:rnd.randrange(len(s))]
    if s:
        i = rnd.randrange(len(s))
        return s[:i] + rnd.choice(['\x00', '²', 'ÿ', '\n', '\r\n', '=', '*', '"', "'", ' ']) + s[i:]
    return rnd.choice(TEXT)


def _mutate_tree(tree, rnd, depth=0):
    if isinstance(tree, dict) and tree:
        tree = dict(tree)
        key = rnd.choice(list(tree))
        r = rnd.random()
        if r < 0.2:
            del tree[key]
        elif r < 0.5 or depth > 6:
            tree[key] = rnd.choice(JUNK_JSON + [_mutate_string(str(tree[key]), rnd, False)])
        else:
            tree[key] = _mutate_tree(tree[key], rnd, depth + 1)
        return tree
    if isinstance(tree, list) and tree:
        tree = list(tree)
        i = rnd.randrange(len(tree))
        r = rnd.random()
        if r < 0.2:
            del tree[i]
        elif r < 0.35:
            tree += tree * rnd.randint(1, 20)
        elif r < 0.6 or depth > 6:
            tree[i] = rnd.choice(JUNK_JSON)
        else:
            tree[i] = _mutate_tree(tree[i], rnd, depth + 1)
        return tree
    if isinstance(tree, str):
        return _mutate_string(tree, rnd, False)
    return rnd.choice(JUNK_JSON + [tree])


def _mutate_fields(value, rnd):
    value = {k: list(vals) for k, vals in value.items()}
    keys = list(value)
    for _ in range(rnd.randint(1, 3)):
        k = rnd.choice(keys)
        vals = value[k]
        r = rnd.random()
        if r < 0.1:
            value[k] = []
        elif r < 0.2 and vals:
            value[k] = vals * rnd.randint(2, 30)
        elif r < 0.3:
            value[k] = vals + [_mutate_string(vals[0] if vals else '', rnd, k.startswith('@'))]
        elif vals:
            i = rnd.randrange(len(vals))
            vals[i] = _mutate_string(vals[i], rnd, k.startswith('@'))
        else:
            value[k] = [rnd.choice(NUMBERS)]
    return value


# ---------------------------------------------------------------- field-level fuzzing

class _Hang(Exception):
    pass


def _alarm(*_):
    raise _Hang()


def _where(error):
    frames = traceback.extract_tb(error.__traceback__)
    return next((f'{os.path.basename(f.filename)}:{f.lineno}' for f in reversed(frames)
                 if 'shark_' in f.filename), '?')


def _fuzz_parser(job):
    """One parser's replays: [(finding, recording), ...], one per distinct
    finding."""
    name, sequences, iterations, seed = job
    import shark_protocols
    cls = getattr(shark_protocols, name)
    rnd = random.Random(f'{seed}:{name}')
    signal.signal(signal.SIGALRM, _alarm)
    found = {}
    for _ in range(iterations):
        capture, seq = rnd.choice(sequences)
        targets = set(rnd.sample(range(len(seq)), min(len(seq), rnd.randint(1, 3))))
        start = time.monotonic()
        signal.alarm(HANG_SECONDS)
        try:
            handler = cls()
            for i, (method, pkt, value) in enumerate(seq):
                if i in targets:
                    value = _mutate_tree(copy.deepcopy(value), rnd) if method == 'feed_json' \
                        else _mutate_fields(value, rnd)
                getattr(handler, method)(pkt, value)
            for _, _, _, body in handler.finish():
                json.dumps(body, allow_nan=False)
            took = time.monotonic() - start
            key, problem = ('slow', f'slow ({took:.1f}s)') if took > SLOW_SECONDS else (None, None)
        except _Hang:
            key = problem = f'hang (over {HANG_SECONDS}s)'
        except Exception as e:
            key = f'{type(e).__name__} at {_where(e)}'
            problem = f'{key}: {str(e)[:150]}'
        finally:
            signal.alarm(0)
        if key and key not in found:
            found[key] = (problem, capture)
    return name, list(found.values())


# ---------------------------------------------------------------- packet-level fuzzing

def _variants(data, rnd, n):
    """n copies of a classic pcap with payload bytes mutated - none for
    another format."""
    if data[:4] not in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
        return
    records, at = [], 24
    while at + 16 <= len(data):
        incl = struct.unpack('<I', data[at + 8:at + 12])[0]
        records.append((at, incl))
        at += 16 + incl
    payloads = [(at, incl) for at, incl in records if incl > HEADERS + 2]
    if not payloads:
        return
    for _ in range(n):
        out = bytearray(data)
        for _ in range(rnd.randint(1, 4)):
            at, incl = rnd.choice(payloads)
            start = at + 16 + rnd.randrange(HEADERS - 12, incl)        # (UDP's headers end sooner)
            for i in range(start, min(at + 16 + incl, start + rnd.randint(1, 8))):
                out[i] = rnd.choice([0, 0xff, 0x7f, 0x80, rnd.getrandbits(8)])
        yield bytes(out)


def _fuzz_capture(job):
    path, n, seed, out_dir = job
    import shark_analyzer
    rnd = random.Random(f'{seed}:{path}')
    found, tried = {}, 0
    with tempfile.TemporaryDirectory(prefix='fuzz-') as tmp:
        for i, variant in enumerate(_variants(open(path, 'rb').read(), rnd, n)):
            tried += 1
            variant_path = os.path.join(tmp, f'{i}.pcap')
            with open(variant_path, 'wb') as f:
                f.write(variant)
            try:
                for record in shark_analyzer.run_tshark(variant_path, timeout=120):
                    json.dumps(record, allow_nan=False)
            except Exception as e:
                key = f'{type(e).__name__} at {_where(e)}'
                if key not in found:
                    keep = os.path.join(out_dir, f'{os.path.basename(path)}-{i}.pcap')
                    with open(keep, 'wb') as f:
                        f.write(variant)
                    found[key] = (f'{key}: {str(e)[:150]}', keep)
    return path, tried, list(found.values())


# ---------------------------------------------------------------- main

def _captures(dirs, max_mb):
    for root in dirs:
        for dirpath, _, names in os.walk(root):
            for name in sorted(names):
                path = os.path.join(dirpath, name)
                if name.endswith(('.pcap', '.pcapng', '.cap', '.pcap.gz', '.pcapng.gz')) and \
                        os.path.getsize(path) <= max_mb * 1024 * 1024:
                    yield path


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('dirs', nargs='*', help='directories of captures to record parsers\' input from')
    parser.add_argument('--iterations', type=int, default=3000, help='replays per parser (default 3000)')
    parser.add_argument('--packets', type=int, default=30, help='mutated variants per pcap (default 30; 0 skips)')
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--jobs', type=int, default=max(1, min(8, (os.cpu_count() or 2) - 2)),
                        help='worker processes (default 8, at most) - each holds its parser\'s recordings')
    parser.add_argument('--only', help='comma-separated parser class names (Redis,IRC...)')
    parser.add_argument('--max-size', type=float, default=3, help='largest capture to use, in MB (default 3)')
    parser.add_argument('--out', default=os.path.join(tempfile.gettempdir(), 'fuzz-shark-parsers'),
                        help='where packet-level findings keep their variant')
    args = parser.parse_args()
    import tests.protocol_fixtures as fixtures
    only = set(args.only.split(',')) if args.only else None
    os.makedirs(args.out, exist_ok=True)
    findings = 0
    with tempfile.TemporaryDirectory(prefix='fuzz-fixtures-') as tmp:
        paths = []
        for attr in sorted(dir(fixtures)):
            if attr.startswith('write_') and attr.endswith('_pcap') and attr != 'write_pcap':
                path = os.path.join(tmp, attr[len('write_'):-len('_pcap')] + '.pcap')
                getattr(fixtures, attr)(path)
                paths.append(path)
        paths += list(_captures(args.dirs, args.max_size))
        print(f'Recording parsers\' input from {len(paths)} captures...', flush=True)
        # (at most SEQUENCES_MAX recordings kept per parser as they come in -
        # a sample of them all, so memory stays bounded however many
        # captures there are)
        recordings, seen, rnd = {}, {}, random.Random(args.seed)
        # (a pool of its own: its workers' parsers record every call, which
        # the fuzzing's replays mustn't - they'd be copied and kept, without
        # end)
        with multiprocessing.Pool(args.jobs) as pool:
            for path, calls, error in pool.imap_unordered(_record, paths):
                if error:
                    print(f'  (tshark failed on {path}: {error})')
                for name, seq in calls.items():
                    if only and name not in only:
                        continue
                    kept = recordings.setdefault(name, [])
                    seen[name] = seen.get(name, 0) + 1
                    if len(kept) < SEQUENCES_MAX:
                        kept.append((os.path.basename(path), seq))
                    elif rnd.random() < SEQUENCES_MAX / seen[name]:
                        kept[rnd.randrange(SEQUENCES_MAX)] = (os.path.basename(path), seq)
        jobs = [(name, seqs, args.iterations, args.seed) for name, seqs in sorted(recordings.items())]
        recordings.clear()
        pool = multiprocessing.Pool(args.jobs)
        print(f'Fuzzing {len(jobs)} parsers, {args.iterations} replays each...', flush=True)
        for name, found in pool.imap_unordered(_fuzz_parser, jobs):
            for problem, capture in found:
                findings += 1
                print(f'  {name}: {problem} (from {capture})', flush=True)
        if args.packets:
            classic = [p for p in paths if p.endswith(('.pcap', '.cap'))]
            print(f'Mutating packets: {args.packets} variants of each of {len(classic)} pcaps...', flush=True)
            tried = 0
            for path, n, found in pool.imap_unordered(_fuzz_capture,
                                                      [(p, args.packets, args.seed, args.out) for p in classic]):
                tried += n
                for problem, keep in found:
                    findings += 1
                    print(f'  {os.path.basename(path)}: {problem} (variant kept: {keep})', flush=True)
            print(f'  ({tried} variants run)')
        pool.close()
        pool.join()
    print(f'{findings} finding(s)' if findings else 'No findings.')
    return 1 if findings else 0


if __name__ == '__main__':
    sys.exit(main())
