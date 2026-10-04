"""Sample files built into SO-CRATES, for the Welcome screen's sample
buttons that work with no internet access (POST /api/load-sample).

Each sample is generated on request, not shipped as a file: the email
sample carries the EICAR antivirus test string as an attachment, and
building it here - with the string split in this source - means no file
in the container image contains the signature for a scanner to flag or
quarantine. It only exists in full in the analysis directory once someone
loads the sample, the same as the internet-loaded Sample binary file.

Samples are byte-for-byte deterministic, so loading one twice reopens the
same analysis (same MD5) instead of creating another.
"""

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


# name -> (filename the analysis is given, builder). The only names
# POST /api/load-sample accepts.
SAMPLES = {
    'email': ('sample-phishing-email.eml', build_email_sample),
}
