# Analyzing Files

1. **Upload a file** - click "Choose File" and select a `.pcap`, `.pcapng`, `.cap`, `.trace`, `.evtx`, `.json`, `.jsonl`, `.csv`, `.xml`, `.log`, `.eml`, or any other file type (or a `.zip` containing one). File types are auto-detected:
   - **PCAP** files → Suricata network analysis
   - **Log files** (`.evtx`, `.json`, `.jsonl`, `.csv`, `.xml`, `.log`) → Zircolite Sigma rule detection
   - **Email messages** (`.eml`, or any file that starts with an email's headers) → headers, links and attachments, with each attachment YARA-scanned
   - **Other files** → YARA binary scanning
2. **Try a sample** - the Welcome screen's sample buttons load a PCAP, log, binary, or email file. All four are built into SO-CRATES, so they work with no internet access, and tell one story. The **Sample PCAP file** is a workstation downloading a payload and uploading stolen credentials AgentTesla-style - it raises Suricata alerts and YARA hits on the extracted payload; the **Sample log file** is a short Sysmon log (JSON) from a workstation where a malicious payroll document ran - it fires Sigma alerts from high to low severity; the **Sample binary file** is the harmless EICAR antivirus test file; and the **Sample email file** is a phishing message that shows every email warning, with the EICAR file as its attachment
3. **Load from URL** - paste a URL to a file and press **Enter** (or click **Go**). The box starts out holding a real infection's traffic from malware-traffic-analysis.net - click **Go** to try it (this one needs internet access). Password-protected zips from `malware-traffic-analysis.net` are auto-decrypted using the date-based password format
4. **Reopen a previous analysis** - previously analyzed files are listed on the welcome screen
5. **Reanalyze or delete an open analysis** - once an analysis is open, its header (next to the notes icon) has reanalyze and delete icons - reanalyze deletes the existing results and re-runs the pipeline in place; delete removes the analysis and returns to the welcome screen. To delete every previous analysis at once, use the Danger Zone section in Settings ([Gear Menu](keyboard-and-menus.md#gear-menu) → Settings) instead
