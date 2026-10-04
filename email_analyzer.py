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
displayed escaped. The counts are bounded by config.MAX_EMAIL_* - the
attachments are decoded from the message itself, so their total size is
already bounded by the upload's.
"""

import hashlib
import ipaddress
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from email import policy
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
    except (LookupError, UnicodeError, AssertionError):
        payload = part.get_payload(decode=True) or b''
        return payload.decode('utf-8', errors='replace')


def _auth_results(msg):
    """SPF/DKIM/DMARC results from the topmost Authentication-Results header
    (the one the receiving server added), falling back to Received-SPF for
    SPF."""
    results = {}
    headers = msg.get_all('Authentication-Results') or []
    if headers:
        for method, result in _AUTH_RE.findall(str(headers[0])):
            results.setdefault(method.lower(), result.lower())
    if 'spf' not in results:
        received_spf = msg.get('Received-SPF')
        if received_spf:
            first = str(received_spf).split(None, 1)
            if first:
                results['spf'] = first[0].lower()
    return results


def _received_hops(msg):
    """The Received chain, oldest hop first - the order the message
    travelled in."""
    hops = []
    for value in reversed(msg.get_all('Received') or []):
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
    try:
        when = parsedate_to_datetime(str(msg.get('Date')))
    except (TypeError, ValueError, IndexError):
        return fallback
    if when is None:
        return fallback
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc).isoformat()


def _blank_event(event_type, timestamp):
    return {
        'event_type': event_type, 'timestamp': timestamp,
        'src_ip': '', 'src_port': 0, 'dest_ip': '', 'dest_port': 0,
        'proto': '', 'app_proto': '',
    }


def parse_message(raw, now=None):
    """Parse raw .eml bytes. Returns (events, attachments): the 'email' and
    'link' events (see the module docstring), and the decoded attachments as
    (filename, content_type, data, timestamp) for analyze_message to store
    and scan. Never raises on a malformed message - the email package
    records defects and carries on."""
    now = now or datetime.now(timezone.utc).isoformat()
    events, attachments = [], []
    budget = {'links': config.MAX_EMAIL_LINKS, 'attachments': config.MAX_EMAIL_ATTACHMENTS}
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    _parse_into(msg, 0, now, events, attachments, budget)
    return events, attachments


def _parse_into(msg, depth, fallback_ts, events, attachments, budget):
    # Every event of an upload carries the uploaded message's time, so they
    # sort and group together with the message first; a forwarded message's
    # own Date is still in its 'date' field.
    ts = _timestamp(msg, fallback_ts) if depth == 0 else fallback_ts
    plain, html, names, nested = [], [], [], []

    for part in msg.walk():
        # Parts inside a forwarded message belong to it (parsed below, in
        # its own call), not to this one - including forwards it contains.
        if part is not msg and any(_contains(n, part) for n in nested):
            continue
        if part is not msg and part.get_content_type() == 'message/rfc822':
            # Its payload is the forwarded message itself (iter_parts only
            # covers multipart/*).
            payload = part.get_payload()
            nested.extend(m for m in (payload if isinstance(payload, list) else [payload]) if m is not None)
            continue
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or '').lower()
        ctype = part.get_content_type()
        if filename or disposition == 'attachment' or not ctype.startswith('text/'):
            if not budget['attachments']:
                continue
            budget['attachments'] -= 1
            data = part.get_payload(decode=True) or b''
            name = _text(filename, 255) or f'attachment-{len(attachments) + 1}'
            names.append(name)
            attachments.append((name, ctype, data, ts))
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
        if (url, text) in seen or not budget['links']:
            continue
        seen.add((url, text))
        # A bare URL in text repeats an <a> already seen - keep the one
        # that has visible text to compare against.
        if not text and any(u == url for u, t in seen if t):
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
    from_header = msg.get('From')
    from_domain = _domain_of_address(from_header)
    reply_to = _addresses(msg.get_all('Reply-To') or [])
    return_path = _text(msg.get('Return-Path'), 500).strip('<>')

    warnings = []
    reply_domain = _domain_of_address(reply_to[0]) if reply_to else ''
    if reply_domain and from_domain and reply_domain != from_domain:
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
        'to': _addresses(msg.get_all('To') or []),
        'cc': _addresses(msg.get_all('Cc') or []),
        'reply_to': reply_to,
        'return_path': return_path,
        'subject': _text(msg.get('Subject'), 1000),
        'date': _text(msg.get('Date'), 200),
        'message_id': _text(msg.get('Message-ID'), 500),
        'mailer': _text(msg.get('X-Mailer') or msg.get('User-Agent'), 500),
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

    if depth < config.MAX_EMAIL_DEPTH:
        for sub in nested:
            _parse_into(sub, depth + 1, ts, events, attachments, budget)


def _contains(container, part):
    return any(p is part for p in container.walk())


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
    """A stored file's 'fileinfo' event and its 'filealerts' events."""
    matches, sha256, md5, sha1, metadata = scan(path, rules_file) if scan else ([], '', '', '', {})
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
    for filename, _ctype, data, ts in attachments:
        path, _ = store_file(dir_path, data)
        events.extend(_file_events(path, filename, ts, 'attachment', rules_file, scan))
    return events


def remove_filestore(dir_path):
    """Drop a previous analysis's stored files before re-analyzing."""
    shutil.rmtree(os.path.join(dir_path, 'filestore'), ignore_errors=True)
