# Architecture Overview

SO-CRATES is a web app: a single Python backend process (`socrates.py`) that serves a browser-based UI and orchestrates a handful of subprocess tools:

```
Browser ──▶ socrates.py (Python HTTP server, port 8000)
                │
                ├──▶ Suricata (subprocess, analyzes PCAPs → eve.json)
                ├──▶ Zircolite (subprocess, analyzes log files → Sigma matches)
                ├──▶ YARA (scans binary/other files → yara_matches.json)
                ├──▶ exiftool (subprocess, optional EXIF metadata on binary files)
                ├──▶ SQLite (indexes eve.json/Sigma matches → events.db)
                ├──▶ tcpdump (carves individual streams & hexdumps)
                └──▶ tshark (extracts ASCII transcripts)
```

All state is file-based under `~/socrates-data/`. No database server, no external services.

## Server

A stdlib-only Python HTTP server (`http.server.SimpleHTTPRequestHandler`). Handles static file serving for `socrates.html` and JSON API endpoints.

### Modules

| File | Responsibility |
|---|---|
| `socrates.py` | HTTP request dispatch, stream carving, ZIP extraction, upload/load-url orchestration |
| `db.py` | SQLite schema, bulk loading, FTS5 full-text search, query functions |
| `models.py` | Suricata event field extraction helpers (IP, port, protocol) |
| `validators.py` | Input validation: IP, port, filename, path safety, URL safety (SSRF/DNS-rebinding), zip-slip and zip-bomb limits, PCAP magic bytes |
| `suricata_analyzer.py` | Suricata orchestration: executable checks, rules download/config, background spawn |
| `suricata_sid_ranges.py` | Maps Suricata SIDs to their source ruleset, shared by `db.py` and the API |
| `yara_analyzer.py` | YARA scanning: executable checks, rules download/setup, scanning extracted files, parsing output |
| `sigma_analyzer.py` | Zircolite/Sigma orchestration: log type detection, running Zircolite, parsing and importing results into SQLite |
| `file_analyzer.py` | Lightweight binary file metadata: file type, Shannon entropy, extracted strings; delegates to `exif_analyzer.py` |
| `exif_analyzer.py` | EXIF/media metadata extraction via `exiftool` subprocess |
| `playbook_lookup.py` | Looks up per-rule investigation playbooks from the pre-generated index |
| `ai_summary_lookup.py` | Looks up pre-generated AI rule summaries |
| `ohmydebn_colors.py` | Derives a full SO-CRATES theme from an OhMyDebn/Aether color palette (`colors.toml` or `alacritty.toml`), for the theme-sync feature |
| `config.py` | Centralized application constants: size limits, timeouts, thresholds |

### Request Flow

1. **Upload/URL load** → validates input → saves file → spawns Suricata (PCAPs), Zircolite (log files), or YARA (everything else) → returns `processing`
2. **Client polls** `/api/check-status` until analysis finishes
3. **Analysis callback** (background thread) → indexes results into SQLite
4. **Client loads analysis** → UI fetches events via `/api/events`
5. **User interacts** → stream carving (`tcpdump`), ASCII extraction (`tshark`), hexdump (`tcpdump -X`), filtering (client-side)
