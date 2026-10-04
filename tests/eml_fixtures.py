"""Builds .eml messages for the email analysis tests, with the standard
library's email package - no binary fixtures checked in, same idea as
tests/pcap_fixtures.py."""

from email.message import EmailMessage

# The EICAR test string - a harmless file every antivirus/YARA ruleset is
# expected to flag, split so this source file itself doesn't match.
EICAR = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$' + b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


def phishing_message():
    """A phishing-style message: failing SPF/DMARC, a Reply-To elsewhere, a
    link whose text names a different domain, an executable attachment,
    and a forwarded message with its own link and attachment."""
    msg = EmailMessage()
    msg['Received'] = 'from mail.example.com (mail.example.com [10.0.0.5]) by mx.example.com; Tue, 3 Feb 2026 10:00:05 +0000'
    msg['Received'] = 'from sender.badhost.example (sender.badhost.example [1.2.3.4]) by mail.example.com; Tue, 3 Feb 2026 10:00:03 +0000'
    msg['Authentication-Results'] = 'mx.example.com; spf=fail smtp.mailfrom=bank.example; dkim=none; dmarc=fail header.from=bank.example'
    msg['Date'] = 'Tue, 3 Feb 2026 10:00:00 +0000'
    msg['From'] = '"Bank, Security Team" <security@bank.example>'
    msg['Reply-To'] = 'refunds@collector.example'
    msg['Return-Path'] = '<bounce@badhost.example>'
    msg['To'] = 'victim@example.com, "Other Person" <other@example.com>'
    msg['Subject'] = '=?utf-8?q?Action_required=3A_verify_your_account?='
    msg['Message-ID'] = '<abc123@badhost.example>'
    msg['X-Mailer'] = 'TotallyLegitMailer 1.0'
    msg.set_content('Dear customer,\n\nVerify at https://bank.example.verify-login.example/start.\n')
    msg.add_alternative(
        '<html><body><p>Dear customer,</p>'
        '<p><a href="https://bank.example.verify-login.example/start">https://www.bank.example/login</a></p>'
        '<p><a href="https://help.bank.example/faq">Help</a></p>'
        '<p><a href="https://cdn.example/invoice.pdf">invoice.pdf</a></p>'
        '<script>var x = "https://not-a-link.example/";</script>'
        '</body></html>', subtype='html')
    msg.add_attachment(EICAR, maintype='application', subtype='octet-stream', filename='invoice.com')

    forwarded = EmailMessage()
    forwarded['Date'] = 'Mon, 2 Feb 2026 09:00:00 +0000'
    forwarded['From'] = 'colleague@example.com'
    forwarded['To'] = 'victim@example.com'
    forwarded['Subject'] = 'FW: earlier notice'
    forwarded.set_content('See http://earlier.example/notice for details.')
    forwarded.add_attachment(b'just some notes\n', maintype='text', subtype='plain', filename='notes.txt')
    msg.add_attachment(forwarded)
    return msg.as_bytes()


def plain_message():
    """A minimal, unremarkable text-only message."""
    msg = EmailMessage()
    msg['Date'] = 'Wed, 4 Feb 2026 08:30:00 -0500'
    msg['From'] = 'alice@example.com'
    msg['To'] = 'bob@example.com'
    msg['Subject'] = 'Lunch'
    msg.set_content('Noon at the usual place?\n')
    return msg.as_bytes()
