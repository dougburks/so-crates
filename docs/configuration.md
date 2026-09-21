# Configuration

## Data Storage

All analyzed files are stored in `~/socrates-data/`. It holds a set of shared rule/config directories plus one `<md5>/` subdirectory per analysis:

```
~/socrates-data/
  suricata/
    suricata.yaml          # Copied from /etc/suricata/, rule path rewritten
    rules/                 # Active rules - one file per enabled source (e.g. et-open.rules),
                           # copied in from the rules-available/ library
    rules-available/       # Staged per-source rules library, seeded from the baked-in image
                           # copies; fresh downloads only happen via the Rules modal
    enabled_sources.json   # Which rule sources are currently enabled
    show_protocol_decode_alerts.json  # Persisted "show protocol/decoder alerts" setting
    disable.conf
  zircolite/               # Optional: only a fallback zircolite.py copy for manual installs; the app looks
                           # for `zircolite`/`zircolite.py` on PATH first (installed via pip, or baked into
                           # the Docker image at build time) - never auto-cloned at runtime
  sigma-rules/
    windows.json           # Pre-compiled Sigma rules for Windows logs
    linux.json             # Pre-compiled Sigma rules for Linux logs
  yara-rules/              # Downloaded/baked-in YARA rules
  upload-tmp/              # Streaming-upload scratch space; swept on startup
  <md5>/
    <original-filename>        # The uploaded file
    .meta                      # Analysis metadata (file type, extracted name, version)
    eve.json                   # Suricata's JSON output (PCAP only)
    events.db                  # SQLite database (alerts + events + log events + sigma alerts)
    name.txt                   # Human-readable display name
    notes.txt                  # Freeform analyst notes (absent unless explicitly added)
    filestore/                 # Extracted files from Suricata file-store (PCAP only)
    yara_matches.json          # YARA scan results (PCAP only; standalone binary uploads write matches straight to events.db)
    sigma_matches.json         # Sigma detection results (log files)
    file_metadata.json         # Hashes/entropy/strings/EXIF (binary files and extracted filestore files)
    fast.log, stats.log, suricata.log  # Suricata's own log output (PCAP only)
```

## Configuration Constants

| Constant | Default | Description |
|---|---|---|
| `PORT` | `8000` | HTTP server port |
| `DATA_DIR` | `~/socrates-data` | Root directory for analyzed files |
| `MAX_UPLOAD_SIZE` | `5000 MB` | Hard ceiling for file upload size, regardless of any user override (see Settings in the UI) |
| `DEFAULT_UPLOAD_SIZE` | `1000 MB` | Upload size ceiling used when no user override is sent |
| `MAX_EVE_SIZE` | `5000 MB` | Maximum eve.json size |
| `MAX_TRANSCRIPT_SIZE` | `100,000 chars` | Maximum ASCII transcript / hexdump length |
| `MAX_QUERY_LIMIT` | `100,000` | Hard ceiling for the `limit` query param on paginated endpoints, regardless of any user override |
| `DISK_SPACE_SAFETY_MARGIN` | `100 MB` | Free-space buffer required (on top of the upload size) before an upload is accepted |
| `MAX_DISPLAY_NAME_LENGTH` | `255 chars` | Maximum length of a user-renamed analysis display name |
| `MAX_NOTES_LENGTH` | `10,000 chars` | Maximum length of a per-analysis Notes field |
| `MAX_ROW_NOTE_LENGTH` | `500 chars` | Maximum length of a per-row note (a short annotation on a single table row) |

Of these, only `PORT` and `DATA_DIR` can be overridden by environment variables (see [Development Setup](development-setup.md#environment-variables)) - they are environment-driven values in `socrates.py` rather than `config.py` constants; the remaining limits are constants in `config.py` and require editing that file.

Suricata config is auto-generated from `/etc/suricata/` on first run. On startup the app seeds rules from the baked-in image copies (Docker/Podman) or warns and continues without rules (source install). Downloading fresh rules via `suricata-update` is an explicit action from the Rules modal - never automatic.
