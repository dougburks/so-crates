# Data Storage

```
~/socrates-data/
  suricata/
    suricata.yaml          # Copied from /etc/suricata/, rule path rewritten
    rules/                 # Active rules: one file per enabled source, named by _source_filename()
                           # (e.g. et-open.rules), plus Suricata's own bundled event rule files
    rules-available/       # Per-source rules library - seeded from baked-in/staged copies;
                           # downloads happen only via the Rules modal
    enabled_sources.json   # Which curated rule sources are currently active
    custom.rules           # Custom rules as saved (suricata_analyzer.save_custom_rules); rules/custom.rules is
                           # the active copy, present only while they're on, and last in suricata.yaml's rule-files
    show_protocol_decode_alerts.json  # Whether Suricata's built-in decoder rules stay active
    disable.conf
    cache/                 # Suricata's compiled-rule cache (cache/sgh/), so later runs load rules faster
  zircolite/               # Optional: the `zircolite`/`zircolite.py` command on PATH (installed via pip,
                           # or baked into the Docker image at build time) is used first; a pre-existing
                           # zircolite.py copy here is only a fallback if nothing is found on PATH - never
                           # auto-cloned at runtime
  sigma-rules/
    windows.json           # Pre-compiled Sigma rules for Windows logs
    linux.json             # Pre-compiled Sigma rules for Linux logs
  yara-rules/              # Downloaded/baked-in YARA rules
  upload-tmp/              # Streaming-upload scratch space; swept on startup (see storage.cleanup_upload_tmp_dir)
  shark_settings.json      # The Settings switch for whether tshark runs (absent means on; shark_analyzer.SHARK_SETTINGS)
  <md5>/
    <filename>             # Original uploaded file
    .meta                  # Analysis metadata (file type, extracted name, version)
    eve.json               # Suricata JSON output (newline-delimited, PCAP only) - removed once imported into events.db
    events.db              # SQLite index (auto-created after analysis); for a PCAP, also the rows tshark adds (JSON "source": "tshark") once both are done - see shark_analyzer.merge
    shark.db               # tshark's flows and records - events.db's events table without its search indexes, built alongside Suricata; what Suricata lacks is merged into events.db (PCAP only)
    .shark_error           # Present if the last tshark run failed and the error could be written here; contains the error message
                           # (one that couldn't be written is kept in memory, and the status API reports it)
    name.txt               # Human-readable display name
    notes.txt              # Freeform per-analysis notes (optional, written by POST /api/analysis-notes)
    filestore/             # Extracted files from Suricata file-store (PCAP), or an email's message and decoded attachments (email)
    yara_matches.json      # YARA scan results (auto-created after analysis, PCAP only)
    sigma_matches.json     # Sigma detection results (log files only)
    file_metadata.json     # Type/MIME/entropy/strings/EXIF per extracted filestore file with no YARA match, keyed by SHA256 (PCAP only - standalone uploads keep theirs in events.db)
    fast.log               # Suricata's plaintext alert log (PCAP only)
    stats.log               # Suricata's periodic stats log (PCAP only)
    suricata.log            # Suricata's own process log (PCAP only)
    zircolite.log           # Zircolite's own process log (log files only)
    .zircolite_events.db    # Zircolite's intermediate SQLite output (log files only)
    .phase                  # Current pipeline phase, while analysis is in progress
    .error                  # Present only if analysis failed; contains the error message
    .warnings               # Present only if something went wrong without failing the analysis (e.g. a failed YARA scan); storage.add_analysis_warning
```

Two things live in the system temp directory (`/tmp`) instead, because AppArmor 5's profile for tshark lets it read files there and hardly anywhere else:

```
/tmp/
  socrates-flow-XXXXXXXX.pcap  # A flow carved out for an ASCII transcript or a stream payload, removed once read
  shark-run-XXXXXXXX/          # One tshark run's temp folder: its second passes' copies of frames, and the
                               # capture's copy if tshark may not read it in place - removed when the run ends,
                               # however it ends (cancelled or killed too)
```

The server removes them itself; a startup sweep (`storage.cleanup_stale_tmp`) catches what a server that died left, if they're its own user's and older than `config.STALE_TMP_SECONDS` - `/tmp` may be shared with another SO-CRATES on the same computer, unlike `upload-tmp/`, so one still young enough to be in use is left for a later start.
