# Analyzing Files

1. **Upload a file** - click **Choose file or drag and drop here** (or drop a file on it) and select a `.pcap`, `.pcapng`, `.cap`, `.trace`, `.evtx`, `.json`, `.jsonl`, `.csv`, `.xml`, `.log`, `.eml`, or any other file type (or a `.zip` containing one). File types are auto-detected:
    - **PCAP** files → Suricata network analysis
    - **Log files** (`.evtx`, `.json`, `.jsonl`, `.csv`, `.xml`, `.log`) → Zircolite Sigma rule detection
    - **Email messages** (`.eml`, or any file that starts with an email's headers) → email analysis of headers, links, and attachments, with each attachment YARA-scanned. A message over 100 MB gets YARA binary scanning instead, and anything past the per-message limits (100 attachments, 1,000 links, 50 forwarded messages, 5 levels of forwarding) is reported as a warning on the email
    - **Other files** → YARA binary scanning
2. **Try a sample** - the Welcome screen's sample cards load a PCAP, log, binary, or email file. All four are built into SO-CRATES, so they work with no internet access, and together they tell one story - see [The Sample Story](sample-story.md)
3. **Load from URL** - paste a URL to a file and press **Enter** (or click **Go**). The URL box is pre-filled with a link to a real infection's traffic on malware-traffic-analysis.net - click **Go** to try it (this one needs internet access). Password-protected zips from `malware-traffic-analysis.net` are auto-decrypted using the date-based password format
4. **Reopen a previous analysis** - previously analyzed files are listed on the Welcome screen
5. **Reanalyze or delete an open analysis** - once an analysis is open, its header (next to the notes icon) has reanalyze and delete icons - reanalyze deletes the existing results and re-runs the pipeline in place; delete removes the analysis and returns to the Welcome screen. To delete every previous analysis at once, use the Danger Zone section in Settings ([Gear Menu](keyboard-and-menus.md#gear-menu) → Settings) instead
