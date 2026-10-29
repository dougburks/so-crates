# Architecture Overview

SO-CRATES is a web app: a single Python backend process (`socrates.py`) that serves a browser-based UI and orchestrates a handful of subprocess tools:

```
Browser ──▶ socrates.py (Python HTTP server, port 8000)
                │
                ├──▶ Suricata (subprocess, analyzes PCAPs → eve.json)
                ├──▶ Zircolite (subprocess, analyzes log files → Sigma matches)
                ├──▶ YARA (scans binary/other files → yara_matches.json)
                ├──▶ email_analyzer.py (in-process: parses .eml → email/link/fileinfo events, YARA on attachments)
                ├──▶ exiftool (subprocess, optional EXIF metadata on binary files)
                ├──▶ SQLite (indexes eve.json/Sigma matches → events.db)
                ├──▶ tcpdump (carves individual streams & hexdumps)
                └──▶ tshark (alongside Suricata: protocols Suricata doesn't parse →
                             shark.db → merged into events.db; ASCII transcripts,
                             exact stream payloads)

Browser ──▶ /cyberchef/ (bundled CyberChef, served by the same process;
                         Send to CyberChef hands it payloads from the app)
```

All state is file-based under `~/socrates-data/`. No database server, no external services.

## Server

A stdlib-only Python HTTP server (`http.server.SimpleHTTPRequestHandler`). Handles static file serving for `socrates.html`, `static/` and the bundled CyberChef at `/cyberchef/`, and the JSON API endpoints.

### Modules

| File | Responsibility |
|---|---|
| `socrates.py` | HTTP request dispatch, stream carving (a flow tshark reads is carved into `/tmp` first: faster than tshark reading the whole capture, and the one place AppArmor 5's tshark profile lets it read), upload/load-url orchestration |
| `db.py` | SQLite schema, bulk loading, FTS5 full-text search, query functions |
| `models.py` | Suricata event field extraction helpers (IP, port, protocol) |
| `url_fetch.py` | Downloads a "Load from URL" file through only the IPs `validators.py` validated, re-checking every redirect hop |
| `storage.py` | Files on disk: the upload scratch directory, the startup sweep of what a server that died left in `/tmp` (`cleanup_stale_tmp`), ZIP extraction, hashing, and an analysis directory's `.meta`, pcap and artifact lists |
| `analysis_cache.py` | In-memory caches of unfiltered Sankey/aggregation results per analysis, and their eviction |
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
| `cyberchef.py` | The bundled CyberChef: where it lives (`CYBERCHEF_DIR`) and the Content-Security-Policy its responses get |
| `stream_payload.py` | Exact-byte stream payloads for `/api/raw-stream`, via `tshark`'s follow mode |
| `shark_analyzer.py` | tshark's part of a PCAP analysis: one run per capture, alongside Suricata, in a child process at the lowest CPU and I/O priority (`python3 -m shark_analyzer build`) with a memory limit, grouping tshark's fields into flows and records streamed into `shark.db` (a staging store with no search indexes - only the merge reads it) (a tunneled packet split into its inner flow and its tunnel's outer one, as Suricata logs them, with a `tunnel` record per tunnel) - a first tshark run reads every packet for just what flows need, and a second reads only the packets of flows whose protocols keep records here (copied out by `pcap_subset.py`) for those protocols' fields - or, for a capture made almost wholly of them (judged from a sample of its packets), one run asks for the flows' fields and those of the recorded protocols the sample saw. A tshark not allowed to read the analysis's directory (AppArmor 5's profile for `/usr/bin/tshark`, which reaches a rootless container's tshark too) reads the capture from the run's own folder in `/tmp` instead - a hard link where one can be made, else a copy if there's room - and once one run has had to, later runs go straight to it rather than each being refused (and logged by the kernel) first. That folder is also the run's `TMPDIR`, so its second passes' copies of frames go there too, and it's removed when the run ends, even a cancelled or killed one. A failure that can't be written to `.shark_error` is kept in memory, and the status API reports it. Once both are done, `merge` adds to `events.db` what Suricata lacks - records of protocols it doesn't parse, and connection rows (`conn_<protocol>`) - except on flows Suricata identified (gave a protocol and backed it with records), where Suricata's word stands - but for TLS failures (the TLS alerts a connection sent before encryption began, which Suricata never logs), which also take the certificate from Suricata's TLS record of the connection. A structured pass (tshark as JSON over just the flows that need it, copied out the same way) is ready for protocols whose messages nest |
| `shark_protocols.py` | Records for protocols Suricata doesn't parse or logs nothing about - LLMNR, NBNS, DHCPv6, SSDP, S7comm (one per request/response transaction), syslog (one per message), DTLS (one per connection's handshake), ONC RPC (one per call), SOCKS (one per connection through the proxy), RADIUS (one per login and per accounting message), STUN (one per flow and method), CoAP (one per request/response), SLP (one per request and its replies, or per advertisement), IPMI (one per flow to a management controller), L2TP (one per control connection), RIP and RIPng (one per sender and kind of message), XDMCP (one per client and login manager), Telnet (one per session), IEC 104 (one per control action, and one per monitored point), BACnet (one per action, per polled property, and per device), OPC UA (one per connection's session, and one per change - read from tshark's JSON, since its messages nest), GOOSE (one per state change), the Windows Browser protocol (one per host and kind of message) and LLDP and CDP (one per device and port announced) |
| `findings.py` | The Findings tab's rules: each one an SQL condition over one type of protocol record in `events.db` (an IPMI weakness, a PLC stopped, a tunnel probe...), with a severity and a short detail line from the record - never a password - served by `GET /api/findings` |
| `pcap_subset.py` | Copying chosen frames out of a capture (classic pcap or pcapng) for tshark's second passes - any number of ranges, where editcap keeps at most 512 |
| `samples.py` | Sample files built into SO-CRATES (the main screen's offline Sample PCAP, log, binary and email files), generated on request for `POST /api/load-sample` |
| `email_analyzer.py` | Email message (`.eml`) analysis: parsing headers, links and forwarded messages into events, and storing and YARA-scanning the message and its attachments |
| `config.py` | Centralized application constants: size limits, timeouts, thresholds |

### Request Flow

1. **Upload/URL load** → validates input → saves file → spawns Suricata (PCAPs), Zircolite (log files), the email parser + YARA (email messages), or YARA (everything else) → returns `processing`
2. **Client polls** `/api/check-status` until analysis finishes
3. **Analysis callback** (background thread) → indexes results into SQLite
4. **Client loads analysis** → UI fetches events via `/api/events`
5. **User interacts** → stream carving (`tcpdump`), ASCII extraction (`tshark`), hexdump (`tcpdump -X`), filtering (client-side)
