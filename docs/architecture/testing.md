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

Seventeen test files serve as executable specifications:

- **test_socrates_server.py** - Server-side: validation, security, API endpoints, SQLite, Suricata config
- **test_socrates_ui.py** - UI-side: HTML structure, CSS, JS functions, syntax, filtering, accessibility, performance
- **test_socrates_db.py** - Database: SQLite schema, bulk loading, query functions
- **test_sigma_db.py** - Sigma alerts table: insert/query, severity filtering, search, stats, log event import
- **test_sigma_analyzer.py** - Zircolite/Sigma pipeline: log type detection, result parsing, importing Zircolite output into SQLite
- **test_sigma_analyzer_rules_setup.py** - Sigma rule setup: no-network/force-refresh behavior, baked-in fallback
- **test_yara_analyzer.py** - YARA rule setup: no-network/force-refresh behavior, baked-in fallback
- **test_exif_analyzer.py** - File category detection from MIME type/file-type heuristics
- **test_validators.py** - Input validation: office/log file detection by extension, safe-IP resolution and the SSRF block list, IP/port validation, atomic decompression of baked-in rules
- **test_ohmydebn_colors.py** - OhMyDebn theme-sync color derivation: `colors.toml`/`alacritty.toml` parsing, contrast-safety adjustments
- **test_suricata_rule_sources.py** - Multi-ruleset Suricata source support: per-source fetch/enable/disable, baked-in library seeding
- **test_suricata_sid_ranges.py** - SID-range-to-ruleset classification, and its consistency with `SURICATA_RULE_SOURCES`
- **test_playbook_lookup.py** - Security Onion Playbooks lookup: exact-rule/engine-fallback resolution, index caching
- **test_ai_summary_lookup.py** - AI-generated rule summary lookup: exact-match resolution (no fallback), index caching
- **test_stream_payload.py** - Exact-byte stream payloads: the `tshark` follow command (IPv6 bracketing) and per-direction parsing of its output, against real `tshark` runs on a generated pcap (`tests/pcap_fixtures.py`)
- **test_email_analyzer.py** - Email message (`.eml`) analysis: headers, SPF/DKIM/DMARC, the Received chain, warnings, link extraction and text/destination mismatches, forwarded messages, limits, and attachment storage and scanning, on messages built by `tests/eml_fixtures.py`; plus the built-in Sample email file (`samples.py`) - deterministic, every warning type, reserved names only, and no whole EICAR string in the source
- **test_docs_hooks.py** - The docs site's MkDocs hooks: reading the container download count from the package page, and leaving it unset when that fails

Tests are static analysis (string matching in source files), live server integration tests, and JSDOM-based behavioral tests (`tests/jsdom_helper.py`) for JS functions that need real execution rather than source inspection. No Selenium/Playwright-style full-browser tests.
