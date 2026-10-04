# Analyzing Files

1. **Upload a file** - click "Choose File" and select a `.pcap`, `.pcapng`, `.cap`, `.trace`, `.evtx`, `.json`, `.jsonl`, `.csv`, `.xml`, `.log`, `.eml`, or any other file type (or a `.zip` containing one). File types are auto-detected:
   - **PCAP** files → Suricata network analysis
   - **Log files** (`.evtx`, `.json`, `.jsonl`, `.csv`, `.xml`, `.log`) → Zircolite Sigma rule detection
   - **Email messages** (`.eml`, or any file that starts with an email's headers) → headers, links and attachments, with each attachment YARA-scanned
   - **Other files** → YARA binary scanning
2. **Try a sample** - the Welcome screen's sample buttons load a PCAP, log, binary, or email file. All four are built into SO-CRATES, so they work with no internet access, and together they tell one story - see [The sample story](#the-sample-story) below
3. **Load from URL** - paste a URL to a file and press **Enter** (or click **Go**). The box starts out holding a real infection's traffic from malware-traffic-analysis.net - click **Go** to try it (this one needs internet access). Password-protected zips from `malware-traffic-analysis.net` are auto-decrypted using the date-based password format
4. **Reopen a previous analysis** - previously analyzed files are listed on the welcome screen
5. **Reanalyze or delete an open analysis** - once an analysis is open, its header (next to the notes icon) has reanalyze and delete icons - reanalyze deletes the existing results and re-runs the pipeline in place; delete removes the analysis and returns to the welcome screen. To delete every previous analysis at once, use the Danger Zone section in Settings ([Gear Menu](keyboard-and-menus.md#gear-menu) → Settings) instead

## The sample story

The four sample files are one incident, seen four ways - try them in this order. Everything in them is made up: only reserved `.example` domains and documentation-range IP addresses, and the "malware" is a harmless fake that carries the [EICAR](https://www.eicar.org/) antivirus test string, so YARA flags it without anything being dangerous.

1. **Sample email file** - at 08:41 on 3 February 2026, Jordan Lee gets an urgent "confirm your direct deposit" email that appears to come from Northbridge Payroll. It was sent from `203.0.113.66`, fails SPF and DMARC, has its replies going to a look-alike domain, links its "portal" to somewhere else entirely, and attaches a macro-enabled Word document, `Payroll_Adjustment_Form.docm`.
2. **Sample log file** - Sysmon on Jordan's workstation, `FIN-WS-0412`. At 08:44 Word opens the form and launches hidden, encoded PowerShell; certutil downloads `update.exe` from the email's sending IP; the payload enumerates the user, persists with a scheduled task and a Run key, hunts for saved credentials, and at 08:46 connects out to the same IP over FTP. Sigma flags each step.
3. **Sample PCAP file** - the same workstation (`10.20.4.12`) on the wire: the certutil download - on the same source port, the same second the log records it - and then the FTP upload of `PW_jordan.lee-FIN-WS-0412_….html`, Jordan's harvested passwords, named the way the AgentTesla infostealer names them. Suricata raises the AgentTesla alert, with its playbook, and extracts the payload.
4. **Sample binary file** - `update.exe` itself: byte-for-byte the payload Suricata extracted from the PCAP, so its hashes match, and YARA flags it on its own.
