# Testing

```bash
# Server tests
python3 -m unittest tests.test_socrates_server -v

# UI tests
python3 -m unittest tests.test_socrates_ui -v

# All tests
python3 -m unittest discover -v
```

## Test Coverage

Twenty-two test files serve as executable specifications:

- **test_socrates_server.py** - Server-side: validation, security, API endpoints, SQLite, Suricata config
- **test_socrates_ui.py** - UI-side: HTML structure, CSS, JS functions, syntax, filtering, accessibility, performance, and that a record's strings - which came from a capture, so from whoever sent its packets - render as text: every tshark record type, from the protocol fixtures, with every string replaced by markup that tries to break out of an element or attribute or by a `javascript:` URL, through its row, detail panel and Findings row
- **test_socrates_db.py** - Database: SQLite schema, bulk loading, query functions
- **test_sigma_db.py** - Sigma alerts table: insert/query, severity filtering, search, stats, log event import
- **test_sigma_analyzer.py** - Zircolite/Sigma pipeline: log type detection, result parsing, importing Zircolite output into SQLite
- **test_sigma_analyzer_rules_setup.py** - Sigma rule setup: no-network/force-refresh behavior, baked-in fallback
- **test_yara_analyzer.py** - YARA rule setup: no-network/force-refresh behavior, baked-in fallback
- **test_exif_analyzer.py** - File category detection from MIME type/file-type heuristics
- **test_validators.py** - Input validation: office/log file detection by extension, email-message detection by content (so a header like `Date: Tue, 3 Feb ...` isn't read as CSV), safe-IP resolution and the SSRF block list, IP/port validation, atomic decompression of baked-in rules
- **test_ohmydebn_colors.py** - OhMyDebn theme-sync color derivation: `colors.toml`/`alacritty.toml` parsing, contrast-safety adjustments
- **test_suricata_rule_sources.py** - Multi-ruleset Suricata source support: per-source fetch/enable/disable, baked-in library seeding
- **test_suricata_sid_ranges.py** - SID-range-to-ruleset classification, and its consistency with `SURICATA_RULE_SOURCES`
- **test_geo_lookup.py** - IP address to country: DB-IP ranges for IPv4 and IPv6, addresses that don't route as `LAN`, missing or corrupt data, and `scripts/build_geoip.py`'s checks on a download
- **test_traffic_map.py** - The Traffic Map's data (flows bucketed by time and country, alerts, the most severe kept) and `country:` search terms filtering every query
- **test_playbook_lookup.py** - Security Onion Playbooks lookup: exact-rule/engine-fallback resolution, index caching
- **test_ai_summary_lookup.py** - AI-generated rule summary lookup: exact-match resolution (no fallback), index caching
- **test_stream_payload.py** - Stream payloads: the `tshark` follow command (IPv6 bracketing) and per-direction parsing of its output, the ASCII transcript and the hexdump's parsing, against real `tshark` runs on a generated pcap (`tests/pcap_fixtures.py`)
- **test_email_analyzer.py** - Email message (`.eml`) analysis: headers, SPF/DKIM/DMARC, the Received chain, warnings, link extraction and text/destination mismatches, forwarded messages, limits, and attachment storage and scanning, on messages built by `tests/eml_fixtures.py`; plus the built-in Sample email file (`samples.py`) - deterministic, every warning type, reserved names only, and no whole EICAR string in the source
- **test_shark_analyzer.py** - tshark's part of a PCAP analysis: grouping its fields into flows (direction and orientation, IPv6, non-IP traffic, ICMP errors, Suricata's protocol names) checked against Suricata's flows for the same captures (`tests/protocol_fixtures.py`, `tests/data/*.eve.json`), every protocol's records (`shark_protocols.PROTOCOLS`), tunnels, TLS failures, the one-pass/two-pass choice, the structured pass, the merge into events.db (which rows join, never on a flow Suricata identified), the child process and its memory limit, reading a capture tshark may not read in place from a copy in `/tmp` (and later runs going straight to the copy), a killed run leaving nothing in `/tmp`, a run that can't write its folder (an error, not queued again), the packet-count cutoff, the settings switch, the run queue and the status API. Real captures catch what fixtures don't: `scripts/sweep_shark_suricata.py` checks a corpus of them (not in the repository) against Suricata's output, and `scripts/fuzz_shark_parsers.py` replays what every parser is handed for the fixtures and a corpus thousands of times mutated, and runs mutated pcaps through tshark, reporting any exception, hang or record that won't serialize
- **test_pcap_subset.py** - Carving chosen frames out of a capture (classic pcap and pcapng) for tshark's second passes: any number of frame ranges, and the editcap fallback for captures it can't read directly (`pcap_subset.py`)
- **test_findings.py** - The Findings tab: each rule's SQL condition over a record type, the detail line that never carries a password, and grouping matches by detail and source host (`findings.py`'s `RULES`, with a matching record per rule in the `MATCHES` fixture)
- **test_fetch_corpus.py** - `scripts/fetch_corpus.py` without the network: its manifest, the post each malware-traffic-analysis.net capture comes from, taking only captures out of a GitHub archive (by name, so a path in it can't place one elsewhere), and checking a folder against the manifest
- **test_docs_hooks.py** - The docs site's MkDocs hooks: reading the container download count from the package page, and leaving it unset when that fails

Tests are static analysis (string matching in source files), live server integration tests, and JSDOM-based behavioral tests (`tests/jsdom_helper.py`) for JS functions that need real execution rather than source inspection. No Selenium/Playwright-style full-browser tests.

## The capture corpus

tshark's parsers are checked against real captures too, which fixtures can't stand in for: `scripts/sweep_shark_suricata.py` compares tshark's flows with Suricata's and lists the rows tshark would add, and `scripts/fuzz_shark_parsers.py` replays what each parser is handed thousands of times mutated. The captures aren't part of the repository - about 2.3 GB, some of them live malware traffic - so `scripts/fetch_corpus.py` downloads them:

```bash
python3 scripts/fetch_corpus.py ~/so-crates-corpus
```

| Folder | What | From |
|---|---|---|
| `wstest` | Wireshark's test captures (`test/captures` in its source - the ones the manifest lists, since Wireshark keeps adding to them) and some of its wiki's sample captures (`scripts/corpus/ws_urls.txt`) | Wireshark's GitLab, wiki.wireshark.org |
| `ws_tns`, `ws_syslog` | Oracle TNS and syslog samples from the wiki | wiki.wireshark.org |
| `ws_ics2` | EtherCAT, Omron FINS and HART-IP | automayt/ICS-pcap on GitHub, wiki.wireshark.org |
| `ics` | 4SICS: three days of an ICS lab's traffic | Netresec |
| `ics_iti` | BACnet, IEC 104, IEC 61850, OPC and PROFINET | ITI/ICS-Security-Tools on GitHub |
| `ics_emre` | BACnet, IEC 104, IEC 61850, LLDP, OPC UA and PROFINET | EmreEkin/ICS-Pcaps on GitHub |
| `ics_inl` | 14 captures of 11 ICS protocols, BSAP and Synchrophasor among them | Idaho National Laboratory's Malcolm-Test-Artifacts |
| `mta`, `mta_scans`, `mta_ex` | infections, six weeks of scans hitting a web server, and traffic analysis exercises | malware-traffic-analysis.net |

Every file is checked against the SHA-256 the corpus held when the script was written (`scripts/corpus/manifest.sha256`): one a source has since changed is kept and reported, and one that can't be fetched is reported missing. A run that stopped can be run again - what's there is kept - and `--check` only compares. The sweep also needs Suricata's output for each capture, in `eve/`, from the same Suricata version and config as an analysis; `--eve so-crates:local` makes it by running Suricata in that image (podman or docker) for every capture without one yet.

To add captures, add them to `scripts/fetch_corpus.py` (or `ws_urls.txt`) and their hashes to the manifest (`sha256sum`, run from the corpus folder).
