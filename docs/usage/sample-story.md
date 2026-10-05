# The Sample Story

<video controls preload="none" width="100%" src="../../videos/story.mp4" poster="../../videos/story-poster.jpg"></video>

SO-CRATES has four sample files built in - an email, a Sysmon log, a PCAP, and a binary - that you can load from the sample cards on the Welcome screen, with nothing to upload and no internet access needed. Together they tell the story of one phishing incident, seen four ways, which the video above walks through. Try them yourself in the order below.

Everything in them is fictional: they use only reserved `.example` domains and IP addresses set aside for documentation, and the "malware" is a fake that carries the [EICAR](https://www.eicar.org/) antivirus test string, so YARA flags it even though it's harmless.

1. **Sample email file**
    - At 08:41 on 3 February 2026, Jordan Lee gets an urgent "confirm your direct deposit" email that appears to come from Northbridge Payroll.
    - It was sent from `203.0.113.66`, fails SPF and DMARC, sends replies to a look-alike domain, has a "portal" link that goes somewhere else entirely, and attaches a macro-enabled Word document, `Payroll_Adjustment_Form.docm`.
    - In the **Links** tab, select the value after `?u=` in the mismatched link and choose CyberChef from the pivot menu - the value decodes to `jordan.lee@corp.example`, so the sender knows exactly who clicked.
2. **Sample log file**
    - Sysmon logs from Jordan's workstation, `FIN-WS-0412`. At 08:44 Word opens the form and launches a hidden PowerShell window running a base64-encoded command. certutil then downloads `update.bin` from the email's sending IP and saves it as `update.exe`.
    - The payload enumerates the user, persists with a scheduled task and a Run key, hunts for saved credentials, and at 08:46 connects out to the same IP over FTP. Sigma flags each step.
    - Expand the PowerShell event, select the base64 string in its command line and choose CyberChef from the pivot menu - CyberChef's Magic operation decodes it, revealing the certutil download and `Start-Process` command that run next.
3. **Sample PCAP file**
    - The same workstation (`10.20.4.12`) on the wire: the certutil download (same source port, same second as in the log), then the FTP upload of `PW_jordan.lee-FIN-WS-0412_….html` - a file of Jordan's harvested passwords, named the way the AgentTesla infostealer names them.
    - Suricata raises the AgentTesla alert, with its playbook, and extracts the payload. SO-CRATES automatically scans what Suricata extracts with YARA, so the payload's matches are already in the **File Alerts** tab.
4. **Sample binary file**
    - `update.exe` itself: byte-for-byte identical to the payload Suricata extracted from the PCAP, so the hashes match.
    - YARA flags it on its own, without the PCAP - its **File Alerts** tab shows the same matches as the PCAP's.
