# Exploring Results

## Navigate Results

After analysis completes, the UI displays different views depending on the file type:

**For PCAP files:**

- **Stats Grid** - clickable cards showing event counts by type (Alerts, DNS, HTTP, TLS, Flows, etc.). If you've enabled "Show protocol-anomaly noise alerts" (Gear Menu → Rules), those alerts get their own **Decoder Alerts** card instead of mixing into Network Alerts. A **DNS Heuristics** card appears immediately before the **DNS Queries** card whenever any domain in the capture trips a scoring flag; see [DNS Heuristics](#dns-heuristics) below
- **Sankey Diagram** - expand the collapsible heading to visualize network flow relationships (Source IP → Dest IP → Dest Port)
- **Aggregation Tables** - frequency counts for each column; click a value to open the [pivot menu](filtering-and-drilldown.md#pivot-menu). Each table pages through its values with Prev/Next instead of growing the page, at a size (10/25/50/100) set by the "Items per page" selector, which applies to every table in the section and persists across sessions
- **Data Table** - sortable table with expandable detail rows showing full event JSON, ASCII transcripts, and hexdumps. Every row's flow carries a community ID, and a TLS row's detail panel includes JA3/JA3S/JA4 fingerprints whenever present - both computed by Suricata automatically, no configuration needed
- **Search** - full-text search across all event data using SQLite FTS5 (falls back to `LIKE` if FTS5 is unavailable)
- **Filtering** - filter via the pivot menu's Include/Exclude/Only actions on any table cell or aggregation value; filter chips show active filters; filters persist across all tabs and the Sankey diagram

**For log files (`.evtx`, `.json`, `.jsonl`, `.csv`, `.xml`, `.log`):**

- **Sigma Alerts** - detections matched by Sigma rules, with severity, MITRE techniques, and rule metadata
- **Log Events** - all parsed log events with dynamic column discovery based on the actual data
- **Aggregation Tables** - filterable counts for discovered fields (Channel, EventID, Image, Source IP, etc.), with the same Prev/Next paging and adjustable page size as PCAP mode
- **Search & Filtering** - same full-text search and pivot-menu filtering as PCAP mode

**For binary files:**

- **File Info** - metadata extracted from the file
- **YARA Matches** - any rules that matched, with tags and author attribution

## DNS Heuristics

When a capture contains DNS queries, a **DNS Heuristics** card appears on the Stats Grid immediately before the **DNS Queries** card, but only once at least one domain in the capture trips a flag - it's simply absent otherwise. Opening it groups every DNS query by registrable domain and scores each one 0-100 against five independent signals:

- a high-entropy, low-vowel-ratio subdomain label under an otherwise ordinary parent domain (the classic DNS tunneling shape - scored per label with the same vowel guard as the DGA check, so neither a deep chain of short labels nor a long hyphenated word-mashup reads as random)
- a high-entropy/low-vowel-ratio registrable domain itself (the DGA (Domain Generation Algorithm) shape)
- 15 or more distinct subdomains queried under the same parent (fan-out, not just repeated lookups of the same name)
- an unusually long query name or label
- TXT/NULL query types, more associated with tunneling/exfil tooling than ordinary browsing

Known CDN domains and ubiquitous OS/vendor domains (Microsoft, Google, Apple, Mozilla, and similar update/telemetry endpoints) are excluded before scoring to cut noise - DGA and tunneling both require an attacker-controlled domain, which those are not. A collapsible **About DNS Heuristics** info card at the top of the tab explains the scoring in place. Clicking a flagged domain's row searches for it and jumps straight to the real **DNS Queries** tab so you can see every individual query behind the score - unlike every other tab, a row here doesn't expand a detail panel in place. Treat a flag as a lead to investigate, not a confirmed verdict.
