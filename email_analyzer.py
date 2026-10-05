"""Email message (.eml) analysis: parsing a message into SO-CRATES events,
and storing and scanning its attachments.

A message becomes:
  - one 'email' event per message - the top-level one plus each forwarded
    message attached to it (message/rfc822 parts) - with its headers, the
    Received chain, SPF/DKIM/DMARC results, body text and warning signs
  - one 'link' event per http(s) URL in a body, flagged when the link's
    visible text names a different domain than it goes to
  - one 'fileinfo' event per attachment, stored in the analysis's
    filestore/ the way Suricata stores extracted files (so File Info's Send
    to CyberChef works on it), plus one for the message itself
  - 'filealerts' events for YARA matches on any of those files

Everything is parsed with the standard library (email, html.parser). The
message's HTML is only ever read, never rendered, and every value is
displayed escaped. Phishing mail is hostile input, so parsing degrades
rather than fails: a header the strict parser chokes on is read raw, a
structure it can't parse falls back to raw headers or to the headers
alone, and whatever
the config.MAX_EMAIL_* limits cut off is reported as a warning rather
than silently dropped. Messages over config.MAX_EMAIL_SIZE never get
here - they're analyzed as plain files (socrates.py's _detect_file_type).
"""

import hashlib
import ipaddress
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import urlsplit

import config

_URL_RE = re.compile(r'https?://[^\s<>"\'`]+', re.IGNORECASE)
# Characters a URL found in running text tends to pick up from the
# sentence around it.
_URL_TRAILING = '.,;:!?)]}>\'"'
_AUTH_RE = re.compile(r'\b(spf|dkim|dmarc)\s*=\s*([a-z]+)', re.IGNORECASE)
_RECEIVED_FROM_RE = re.compile(r'\bfrom\s+(\S+)', re.IGNORECASE)
_RECEIVED_BY_RE = re.compile(r'\bby\s+(\S+)', re.IGNORECASE)
_BRACKETED_IP_RE = re.compile(r'\[(?:IPv6:)?([0-9a-fA-F:.]+)\]')
_FAILING_AUTH = ('fail', 'softfail', 'permerror')
# Office formats that can carry macros - the classic phishing attachment.
_MACRO_EXTENSIONS = ('.docm', '.dotm', '.xlsm', '.xltm', '.xlam', '.pptm', '.potm', '.ppam', '.ppsm')
# Last labels that make 'name.ext' link text a filename, not a domain.
_FILE_EXTENSIONS = {
    'pdf', 'doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'txt',
    'rtf', 'csv', 'zip', 'rar', 'gz', 'tgz', '7z', 'exe', 'dll', 'msi', 'js',
    'html', 'htm', 'php', 'aspx', 'jpg', 'jpeg', 'png', 'gif', 'svg', 'iso',
    'img', 'eml', 'msg', 'json', 'xml',
}
# Extensions Windows will run when double-clicked - an attachment named
# like this is worth a warning on the email itself.
_EXECUTABLE_EXTENSIONS = (
    '.exe', '.scr', '.com', '.pif', '.bat', '.cmd', '.vbs', '.vbe', '.js',
    '.jse', '.wsf', '.wsh', '.hta', '.ps1', '.msi', '.lnk', '.jar', '.cpl',
    '.iso', '.img',
)


def _text(value, limit=2000):
    """A header value as a bounded plain string."""
    return ' '.join(str(value or '').split())[:limit]


def _header_all(msg, name):
    """Every value of a header, as strings. Reading through policy.default
    parses the value, and the stdlib's parser raises on some hostile input
    (a From of a lone '"') - fall back to the header's raw text then."""
    try:
        return [str(v) for v in (msg.get_all(name) or [])]
    except Exception:
        return [str(v) for k, v in msg.raw_items() if k.lower() == name.lower()]


def _header(msg, name):
    values = _header_all(msg, name)
    return values[0] if values else ''


def _addresses(values):
    """'Name <addr>' strings for every address in the given header values."""
    out = []
    for name, addr in getaddresses([str(v) for v in values if v]):
        if addr or name:
            out.append(f'{name} <{addr}>' if name and addr else (addr or name))
    return out


def _domain_of_address(value):
    addr = parseaddr(str(value or ''))[1]
    return addr.rsplit('@', 1)[1].lower() if '@' in addr else ''


def _host_of(url):
    try:
        host = urlsplit(url).hostname or ''
    except ValueError:
        return ''
    return host.lower().rstrip('.')


def _same_site(a, b):
    """Whether two hostnames belong together: equal, or one a subdomain of
    the other ('www.example.com' and 'example.com')."""
    if not a or not b:
        return False
    a, b = a.removeprefix('www.'), b.removeprefix('www.')
    return a == b or a.endswith('.' + b) or b.endswith('.' + a)


def _text_domain(text):
    """The hostname a link's visible text claims to go to, if it reads as a
    URL or domain ('https://bank.example/login', 'www.bank.example',
    'bank.com'), else ''. Ordinary words ('Click here') claim nothing, and
    neither does a filename ('invoice.pdf') - a bare name only counts when
    its last label isn't a common file extension."""
    t = text.strip().lower()
    if not t or ' ' in t:
        return ''
    if re.match(r'^[a-z][a-z0-9+.-]*://', t):
        host = _host_of(t)
    else:
        host = _host_of('http://' + t)
        last = host.rsplit('.', 1)[-1] if '.' in host else ''
        if not t.startswith('www.') and (not re.fullmatch(r'[a-z]{2,24}', last) or last in _FILE_EXTENSIONS):
            return ''
    return host if host and '.' in host and re.fullmatch(r'[a-z0-9.-]+', host) else ''


class _HtmlScanner(HTMLParser):
    """Collects <a href> links with their visible text, and the document's
    text (scripts and styles left out), from an HTML body. outside is the
    text that isn't some link's visible text - where a bare URL is a link
    of its own rather than the label of one already collected."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.text = []
        self.outside = []
        self._href = None
        self._anchor = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self._skip += 1
        elif tag == 'a':
            self._href = dict(attrs).get('href') or ''
            self._anchor = []
        elif tag in ('br', 'p', 'div', 'tr', 'li'):
            self.text.append('\n')

    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self._skip = max(0, self._skip - 1)
        elif tag == 'a' and self._href is not None:
            self.links.append((self._href.strip(), ' '.join(''.join(self._anchor).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._anchor.append(data)
        else:
            self.outside.append(data)


def _clean_url(url):
    return url.rstrip(_URL_TRAILING)


def _part_text(part):
    """A text part's content as str, whatever its declared charset."""
    try:
        return part.get_content()
    except Exception:
        try:
            payload = part.get_payload(decode=True) or b''
        except Exception:
            return ''
        return payload.decode('utf-8', errors='replace')


def _auth_results(msg):
    """SPF/DKIM/DMARC results from the topmost Authentication-Results header
    (the one the receiving server added), falling back to Received-SPF for
    SPF."""
    results = {}
    headers = _header_all(msg, 'Authentication-Results')
    if headers:
        for method, result in _AUTH_RE.findall(str(headers[0])):
            results.setdefault(method.lower(), result.lower())
    if 'spf' not in results:
        received_spf = _header(msg, 'Received-SPF')
        if received_spf:
            first = str(received_spf).split(None, 1)
            if first:
                results['spf'] = first[0].lower()
    return results


def _received_hops(msg):
    """The Received chain, oldest hop first - the order the message
    travelled in."""
    hops = []
    for value in reversed(_header_all(msg, 'Received')):
        raw = _text(value, 1000)
        route, _, when = raw.rpartition(';')
        if not route:
            route, when = when, ''
        hop = {'raw': raw}
        m = _RECEIVED_FROM_RE.search(route)
        if m:
            hop['from'] = m.group(1)
        m = _RECEIVED_BY_RE.search(route)
        if m:
            hop['by'] = m.group(1)
        for candidate in _BRACKETED_IP_RE.findall(route):
            try:
                hop['ip'] = str(ipaddress.ip_address(candidate))
                break
            except ValueError:
                continue
        if when.strip():
            hop['date'] = when.strip()
        hops.append(hop)
    return hops


# Addresses that never identify where a message came from: private,
# carrier-grade NAT, loopback, link-local and their IPv6 counterparts.
_INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10',
    '127.0.0.0/8', '169.254.0.0/16', '0.0.0.0/8',
    '::1/128', 'fc00::/7', 'fe80::/10',
)]


def _originating_ip(hops):
    """The first external IP in the Received chain - the earliest hop that
    isn't a private, loopback or otherwise internal address. (Not
    ipaddress's is_global, which also rules out the documentation ranges
    a sample message has to use.)"""
    for hop in hops:
        ip = hop.get('ip')
        if not ip:
            continue
        addr = ipaddress.ip_address(ip)
        if not any(addr in net for net in _INTERNAL_NETWORKS if net.version == addr.version):
            return ip
    return ''


def _timestamp(msg, fallback):
    """The Date header as UTC ISO time, or fallback for a missing or
    unusable one (unparsable, or out of range once converted - year 9999
    with a negative offset overflows)."""
    try:
        when = parsedate_to_datetime(_header(msg, 'Date'))
        if when is None:
            return fallback
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return when.astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError, IndexError, OverflowError):
        return fallback


def _blank_event(event_type, timestamp):
    return {
        'event_type': event_type, 'timestamp': timestamp,
        'src_ip': '', 'src_port': 0, 'dest_ip': '', 'dest_port': 0,
        'proto': '', 'app_proto': '',
    }


def parse_message(raw, now=None):
    """Parse raw .eml bytes. Returns (events, attachments): the 'email' and
    'link' events (see the module docstring), and the decoded attachments as
    (filename, data, timestamp) for analyze_message to store and scan.

    Degrades rather than raises. The stdlib parser recurses per nesting
    level, both in a message's structure (thousands of nested parts) and
    in a structured header (thousands of nested comments), raising
    RecursionError. So a message policy.default can't parse is retried
    with policy.compat32, which leaves headers as raw text; failing that,
    its headers alone are analyzed; failing that, an email event carries
    only a warning. Each step down says so in a warning."""
    now = now or datetime.now(timezone.utc).isoformat()
    attempts = (
        (policy.default, False, None),
        (policy.compat32, False, "Some of the message's headers could not be decoded - they are shown as raw text"),
        (policy.compat32, True, "The message's structure could not be parsed - only its headers were analyzed"),
    )
    for msg_policy, headers_only, warning in attempts:
        try:
            msg = BytesParser(policy=msg_policy).parsebytes(raw, headersonly=headers_only)
            events, attachments = _parse(msg, now, headers_only)
        except Exception:
            continue
        if warning:
            events[0]['email']['warnings'].append(warning)
        return events, attachments
    events, attachments = _parse(Message(), now, headers_only=True)
    events[0]['email']['warnings'].append("The message could not be parsed")
    return events, attachments


def _parse(msg, now, headers_only):
    events, attachments = [], []
    budget = {'links': config.MAX_EMAIL_LINKS, 'attachments': config.MAX_EMAIL_ATTACHMENTS,
              'messages': config.MAX_EMAIL_MESSAGES}
    skipped = {'attachments': 0, 'links': 0, 'messages': 0, 'unparsable': 0}
    _parse_into(msg, 0, now, events, attachments, budget, skipped, headers_only)
    cut = []
    if skipped['attachments']:
        cut.append(f"{skipped['attachments']} attachment(s)")
    if skipped['links']:
        cut.append(f"{skipped['links']} link(s)")
    if skipped['messages']:
        cut.append(f"{skipped['messages']} forwarded message(s) (and anything inside them)")
    if cut:
        # Somewhere for an attacker to hide something - say so.
        events[0]['email']['warnings'].append(
            'Beyond the analysis limits, not analyzed: ' + ', '.join(cut))
    if skipped['unparsable']:
        events[0]['email']['warnings'].append(
            f"{skipped['unparsable']} forwarded message(s) could not be parsed")
    return events, attachments


def _own_parts(msg, nested):
    """The message's own leaf parts, in order. Forwarded messages
    (message/rfc822 parts) are collected into nested instead of descended
    into - their parts are theirs, parsed in their own _parse_into call.
    Iterative, and each part visited once."""
    stack = [msg]
    while stack:
        part = stack.pop()
        if part is not msg and part.get_content_type() == 'message/rfc822':
            payload = part.get_payload()
            nested.extend(m for m in (payload if isinstance(payload, list) else [payload]) if m is not None)
            continue
        if part.is_multipart():
            payload = part.get_payload()
            if isinstance(payload, list):
                stack.extend(reversed(payload))
            continue
        yield part


def _parse_into(msg, depth, fallback_ts, events, attachments, budget, skipped, headers_only=False):
    # Every event of an upload carries the uploaded message's time, so they
    # sort and group together with the message first; a forwarded message's
    # own Date is still in its 'date' field.
    ts = _timestamp(msg, fallback_ts) if depth == 0 else fallback_ts
    plain, html, names, nested = [], [], [], []

    for part in ([] if headers_only else _own_parts(msg, nested)):
        # Reading these parses the header, which can raise on hostile input;
        # a part that won't say what it is gets stored and scanned.
        try:
            filename = part.get_filename()
        except Exception:
            filename = None
        try:
            disposition = (part.get_content_disposition() or '').lower()
        except Exception:
            disposition = 'attachment'
        try:
            ctype = part.get_content_type()
        except Exception:
            ctype = 'application/octet-stream'
        if filename or disposition == 'attachment' or not ctype.startswith('text/'):
            if not budget['attachments']:
                skipped['attachments'] += 1
                continue
            budget['attachments'] -= 1
            try:
                data = part.get_payload(decode=True) or b''
            except Exception:
                data = b''
            name = _text(filename, 255) or f'attachment-{len(attachments) + 1}'
            names.append(name)
            attachments.append((name, data, ts))
        elif ctype == 'text/html':
            html.append(_part_text(part))
        else:
            plain.append(_part_text(part))

    links = []
    seen = set()
    html_text, html_outside = [], []
    for doc in html:
        scanner = _HtmlScanner()
        try:
            scanner.feed(doc)
            scanner.close()
        except Exception:
            pass
        html_text.append(''.join(scanner.text))
        html_outside.append(''.join(scanner.outside))
        for href, text in scanner.links:
            if href.lower().startswith(('http://', 'https://')):
                links.append((_clean_url(href), text, 'html'))
    for doc in plain + html_outside:
        for url in _URL_RE.findall(doc):
            links.append((_clean_url(url), '', 'text'))

    link_events = []
    for url, text, source in links:
        if (url, text) in seen:
            continue
        seen.add((url, text))
        # A bare URL in text repeats an <a> already seen - keep the one
        # that has visible text to compare against.
        if not text and any(u == url for u, t in seen if t):
            continue
        if not budget['links']:
            skipped['links'] += 1
            continue
        budget['links'] -= 1
        host = _host_of(url)
        claimed = _text_domain(text)
        event = _blank_event('link', ts)
        event['link'] = {
            'url': url[:2000], 'domain': host, 'text': text[:500], 'source': source,
            'mismatch': bool(claimed and host and not _same_site(claimed, host)),
        }
        if event['link']['mismatch']:
            event['link']['text_domain'] = claimed
        link_events.append(event)

    body = '\n'.join(p.strip() for p in plain if p.strip()) or \
        '\n'.join(' '.join(t.split()) for t in html_text if t.strip())
    hops = _received_hops(msg)
    auth = _auth_results(msg)
    from_header = _header(msg, 'From')
    from_domain = _domain_of_address(from_header)
    reply_to = _addresses(_header_all(msg, 'Reply-To'))
    return_path = _text(_header(msg, 'Return-Path'), 500).strip('<>')

    warnings = []
    reply_domain = _domain_of_address(reply_to[0]) if reply_to else ''
    if reply_domain and from_domain and not _same_site(reply_domain, from_domain):
        warnings.append(f'Reply-To domain ({reply_domain}) differs from From ({from_domain})')
    return_domain = return_path.rsplit('@', 1)[1].lower() if '@' in return_path else ''
    if return_domain and from_domain and not _same_site(return_domain, from_domain):
        warnings.append(f'Return-Path domain ({return_domain}) differs from From ({from_domain})')
    for method in ('spf', 'dkim', 'dmarc'):
        if auth.get(method) in _FAILING_AUTH:
            warnings.append(f'{method.upper()} {auth[method]}')
    mismatched = sum(1 for e in link_events if e['link']['mismatch'])
    if mismatched:
        warnings.append(f'{mismatched} link(s) whose text names a different domain than they go to')
    for name in names:
        if name.lower().endswith(_EXECUTABLE_EXTENSIONS):
            warnings.append(f'Attachment with an executable extension: {name}')
        elif name.lower().endswith(_MACRO_EXTENSIONS):
            warnings.append(f'Attachment is a macro-enabled Office document: {name}')

    event = _blank_event('email', ts)
    event['email'] = {
        'from': _text(from_header),
        'to': _addresses(_header_all(msg, 'To')),
        'cc': _addresses(_header_all(msg, 'Cc')),
        'reply_to': reply_to,
        'return_path': return_path,
        'subject': _text(_header(msg, 'Subject'), 1000),
        'date': _text(_header(msg, 'Date'), 200),
        'message_id': _text(_header(msg, 'Message-ID'), 500),
        'mailer': _text(_header(msg, 'X-Mailer') or _header(msg, 'User-Agent'), 500),
        'spf': auth.get('spf', ''),
        'dkim': auth.get('dkim', ''),
        'dmarc': auth.get('dmarc', ''),
        'received': hops[:50],
        'originating_ip': _originating_ip(hops),
        'attachments': names,
        'link_count': len(link_events),
        'warnings': warnings,
        'body': body[:config.MAX_EMAIL_BODY_CHARS],
        'body_truncated': len(body) > config.MAX_EMAIL_BODY_CHARS,
        'depth': depth,
    }
    events.append(event)
    events.extend(link_events)

    for sub in nested:
        if depth + 1 > config.MAX_EMAIL_DEPTH or not budget['messages']:
            skipped['messages'] += 1
            continue
        budget['messages'] -= 1
        # One broken forward doesn't sink the message it came in. Collect
        # its results apart and keep them only if it parses, so a forward
        # that fails leaves no attachment behind that no email lists.
        saved_budget, saved_skipped = dict(budget), dict(skipped)
        sub_events, sub_attachments = [], []
        try:
            _parse_into(sub, depth + 1, ts, sub_events, sub_attachments, budget, skipped)
        except Exception:
            budget.update(saved_budget)
            skipped.update(saved_skipped)
            skipped['unparsable'] += 1
            continue
        events.extend(sub_events)
        attachments.extend(sub_attachments)


def _magic(path):
    try:
        result = subprocess.run(['file', '--brief', path], capture_output=True, text=True,
                                timeout=config.FILE_COMMAND_TIMEOUT)
        return result.stdout.strip() if result.returncode == 0 else ''
    except (OSError, subprocess.TimeoutExpired):
        return ''


def store_file(dir_path, data):
    """Store data in dir_path's filestore/ under its SHA256, the layout
    Suricata uses (filestore/<sha256[:2]>/<sha256>) - so
    suricata_analyzer.find_extracted_file, and through it File Info's Send
    to CyberChef, finds it. Returns (path, sha256)."""
    sha256 = hashlib.sha256(data).hexdigest()
    subdir = os.path.join(dir_path, 'filestore', sha256[:2])
    os.makedirs(subdir, exist_ok=True)
    path = os.path.join(subdir, sha256)
    if not os.path.exists(path):
        tmp = path + '.tmp'
        with open(tmp, 'wb') as f:
            f.write(data)
        os.replace(tmp, path)
    return path, sha256


def _file_events(path, filename, timestamp, source, rules_file, scan):
    """A stored file's 'fileinfo' event and its 'filealerts' events. A scan
    that fails leaves this one file hashed but unscanned, not the whole
    message's analysis failed."""
    try:
        matches, sha256, md5, sha1, metadata = scan(path, rules_file) if scan else ([], '', '', '', {})
    except Exception:
        matches, sha256, md5, sha1, metadata = [], '', '', '', {}
    if not sha256:
        with open(path, 'rb') as f:
            data = f.read()
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
    info = _blank_event('fileinfo', timestamp)
    info['fileinfo'] = {
        'filename': filename, 'size': os.path.getsize(path),
        'md5': md5, 'sha1': sha1, 'sha256': sha256, 'magic': _magic(path),
        'stored': True, 'source': source,
        'yara': [{'rule_name': m.get('rule_name', ''), 'tags': m.get('tags', [])} for m in matches],
        **({'metadata': metadata} if metadata else {}),
    }
    events = [info]
    for m in matches:
        alert = _blank_event('filealerts', timestamp)
        alert['filealerts'] = {
            'rule_name': m.get('rule_name', ''), 'tags': m.get('tags', []),
            'author': m.get('meta', {}).get('author', ''), 'sha256': sha256,
            'filename': filename, 'file_id': '', 'strings': m.get('strings', []),
            'meta': m.get('meta', {}),
        }
        events.append(alert)
    return events


def analyze_message(dir_path, file_path, rules_file=None, scan=None):
    """Parse the .eml at file_path and return every event for its analysis:
    the email/link events, plus fileinfo/filealerts for the message itself
    and each attachment, all stored in dir_path's filestore/. scan is
    yara_analyzer.scan_single_file (or None when YARA is unavailable, in
    which case files are still stored and hashed, just not scanned)."""
    with open(file_path, 'rb') as f:
        raw = f.read()
    events, attachments = parse_message(raw)
    timestamp = events[0]['timestamp'] if events else datetime.now(timezone.utc).isoformat()

    path, _ = store_file(dir_path, raw)
    events.extend(_file_events(path, os.path.basename(file_path), timestamp, 'message', rules_file, scan))
    for filename, data, ts in attachments:
        path, _ = store_file(dir_path, data)
        events.extend(_file_events(path, filename, ts, 'attachment', rules_file, scan))
    return events


def remove_filestore(dir_path):
    """Drop a previous analysis's stored files before re-analyzing."""
    shutil.rmtree(os.path.join(dir_path, 'filestore'), ignore_errors=True)
