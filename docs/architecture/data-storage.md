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
    show_protocol_decode_alerts.json  # Whether Suricata's built-in decoder rules stay active
    disable.conf
  zircolite/               # Optional: the `zircolite`/`zircolite.py` command on PATH (installed via pip,
                           # or baked into the Docker image at build time) is used first; a pre-existing
                           # zircolite.py copy here is only a fallback if nothing is found on PATH - never
                           # auto-cloned at runtime
  sigma-rules/
    windows.json           # Pre-compiled Sigma rules for Windows logs
    linux.json             # Pre-compiled Sigma rules for Linux logs
  yara-rules/              # Downloaded/baked-in YARA rules
  upload-tmp/              # Streaming-upload scratch space; swept on startup (see _cleanup_upload_tmp_dir)
  <md5>/
    <filename>             # Original uploaded file
    .meta                  # Analysis metadata (file type, extracted name, version)
    eve.json               # Suricata JSON output (newline-delimited, PCAP only)
    events.db              # SQLite index (auto-created after analysis)
    name.txt               # Human-readable display name
    notes.txt              # Freeform per-analysis notes (optional, written by POST /api/analysis-notes)
    filestore/             # Extracted files from Suricata file-store (PCAP only)
    yara_matches.json      # YARA scan results (auto-created after analysis, PCAP only)
    sigma_matches.json     # Sigma detection results (log files only)
    file_metadata.json     # Hashes/entropy/strings/EXIF, keyed by SHA256 (standalone binary uploads and extracted PCAP filestore files)
    fast.log               # Suricata's plaintext alert log (PCAP only)
    stats.log               # Suricata's periodic stats log (PCAP only)
    suricata.log            # Suricata's own process log (PCAP only)
    zircolite.log           # Zircolite's own process log (log files only)
    .zircolite_events.db    # Zircolite's intermediate SQLite output (log files only)
    .phase                  # Current pipeline phase, while analysis is in progress
    .error                  # Present only if analysis failed; contains the error message
```
