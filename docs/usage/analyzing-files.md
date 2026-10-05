# Analyzing Files

1. **Upload a file** - click **Choose file or drag and drop here** (or drop a file on it) and select a `.pcap`, `.pcapng`, `.cap`, `.trace`, `.evtx`, `.json`, `.jsonl`, `.csv`, `.xml`, `.log`, `.eml`, or any other file type (or a `.zip` containing one). File types are auto-detected:
   - **PCAP** files → Suricata network analysis
   - **Log files** (`.evtx`, `.json`, `.jsonl`, `.csv`, `.xml`, `.log`) → Zircolite Sigma rule detection
   - **Email messages** (`.eml`, or any file that starts with an email's headers) → email analysis of headers, links, and attachments, with each attachment YARA-scanned. A message over 100 MB gets YARA binary scanning instead, and anything past the per-message limits (100 attachments, 1,000 links, 50 forwarded messages, 5 levels of forwarding) is reported as a warning on the email
   - **Other files** → YARA binary scanning
2. **Try a sample** - the Welcome screen's sample cards load a PCAP, log, binary, or email file. All four are built into SO-CRATES, so they work with no internet access, and together they tell one story - see [The sample story](#the-sample-story) below
3. **Load from URL** - paste a URL to a file and press **Enter** (or click **Go**). The URL box is pre-filled with a link to a real infection's traffic on malware-traffic-analysis.net - click **Go** to try it (this one needs internet access). Password-protected zips from `malware-traffic-analysis.net` are auto-decrypted using the date-based password format
4. **Reopen a previous analysis** - previously analyzed files are listed on the Welcome screen
5. **Reanalyze or delete an open analysis** - once an analysis is open, its header (next to the notes icon) has reanalyze and delete icons - reanalyze deletes the existing results and re-runs the pipeline in place; delete removes the analysis and returns to the Welcome screen. To delete every previous analysis at once, use the Danger Zone section in Settings ([Gear Menu](keyboard-and-menus.md#gear-menu) → Settings) instead

## The sample story

The four sample files are one incident, seen four ways - try them in this order. Everything in them is fictional: they use only reserved `.example` domains and IP addresses set aside for documentation, and the "malware" is a fake that carries the [EICAR](https://www.eicar.org/) antivirus test string, so YARA flags it even though it's harmless.

1. **Sample email file**
    - At 08:41 on 3 February 2026, Jordan Lee gets an urgent "confirm your direct deposit" email that appears to come from Northbridge Payroll. It was sent from `203.0.113.66`, fails SPF and DMARC, sends replies to a look-alike domain, has a "portal" link that goes somewhere else entirely, and attaches a macro-enabled Word document, `Payroll_Adjustment_Form.docm`.
    - In the **Links** tab, select the value after `?u=` in the mismatched link and choose CyberChef from the pivot menu - the value decodes to `jordan.lee@corp.example`, so the sender knows exactly who clicked.
2. **Sample log file**
    - Sysmon logs from Jordan's workstation, `FIN-WS-0412`. At 08:44 Word opens the form and launches a hidden PowerShell window running a base64-encoded command. certutil then downloads `update.bin` from the email's sending IP and saves it as `update.exe`. The payload enumerates the user, persists with a scheduled task and a Run key, hunts for saved credentials, and at 08:46 connects out to the same IP over FTP. Sigma flags each step.
    - Expand the PowerShell event, select the base64 string in its command line and choose CyberChef from the pivot menu - CyberChef's Magic operation decodes it, revealing the certutil download and `Start-Process` command that run next.
3. **Sample PCAP file**
    - The same workstation (`10.20.4.12`) on the wire: the certutil download (same source port, same second as in the log), then the FTP upload of `PW_jordan.lee-FIN-WS-0412_….html` - a file of Jordan's harvested passwords, named the way the AgentTesla infostealer names them. Suricata raises the AgentTesla alert, with its playbook, and extracts the payload.
4. **Sample binary file**
    - `update.exe` itself: byte-for-byte identical to the payload Suricata extracted from the PCAP, so the hashes match - and YARA flags it on its own, without the PCAP.
