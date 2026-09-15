# Development Setup

This page covers running SO-CRATES directly from source, without Docker or
Podman - mainly useful for contributing to the project (editing code, running
the test suite) or if your environment genuinely can't run containers. For
actually using SO-CRATES, the container image is the recommended path (see
[Installation](installation/index.md)) - it's the only path with baked-in
Suricata/YARA/Sigma rules and Security Onion Playbooks, so a from-source
setup starts out with noticeably less working out of the box.

You'll need these prerequisites:

- **Python 3** (stdlib only - no pip packages required)
- **Suricata** - for PCAP analysis and rule-based alerting
- **suricata-update** - for downloading/updating Suricata rules (internet access required; the app will warn and continue without rules if offline)
- **tcpdump** - for stream carving (`/api/download-stream`) and hexdump extraction (`/api/hexdump-stream`)
- **tshark** - for ASCII transcript extraction (`/api/ascii-stream`)
- **yara** (optional) - if installed, SO-CRATES scans extracted/uploaded files with YARA rules (baked-in in Docker; otherwise downloaded on demand via the Rules modal). If missing, YARA scanning and File Alerts are skipped (files are still extracted).
- **Zircolite** (optional) - for Sigma rule detection on log files. SO-CRATES auto-detects if Zircolite is installed and skips log analysis if absent. The Dockerfile bakes in Zircolite v3.7.1.
- **exiftool** (optional) - for extracting EXIF/media metadata from binary files. If missing, EXIF extraction is silently skipped (the rest of the file analysis still runs).
- **file** (optional) - for MIME/file-type detection on non-PCAP uploads. If missing, this detection is silently skipped (the rest of the file analysis still runs).

Once you have the prerequisites, you can clone this GitHub repo and run the server:

```bash
python3 socrates.py
```

Then open http://localhost:8000/socrates.html in your browser.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATA_DIR` | `~/socrates-data` | Directory for analyzed files and Suricata config |
| `BIND_ADDRESS` | `127.0.0.1` | Address to bind the HTTP server to |
| `PORT` | `8000` | HTTP server port |
| `ENABLE_ARP_LOGGING` | unset (disabled) | Set to any non-empty value to enable Suricata's `arp` eve-log output. Off by default since ARP volume can be significant on a live network (Suricata's own default is disabled too, for the same reason) - only enable if you actually want ARP events. |
| `OHMYDEBN_THEME_DIR` | unset (feature off) | Base OhMyDebn config directory (e.g. `~/.config/ohmydebn`), for the opt-in "Sync theme to OhMyDebn theme" feature - see [Themes](themes.md). No-op for any deployment not launched via OhMyDebn. |
| `DEMO` | unset | Set to any non-empty value to show a shortened startup message pointing at a hosted demo link, instead of the usual `http://<host>:<port>/socrates.html` URL - used for the public demo deployment, not a typical local install. |
| `PLAYBOOKS_DIR` | `/usr/share/playbooks` | Directory holding the Security Onion Playbooks gzip-compressed indexes (`nids.json.gz`/`sigma.json.gz`). The default path is only populated inside the Docker/Podman image (baked in by the Dockerfile's `resources-builder` stage) - a from-source setup has nothing there by default, so Playbook sections simply don't appear on alerts. Point this at a directory containing your own indexes (in the same format) to enable the feature locally. |
| `AI_SUMMARIES_DIR` | `/usr/share/ai-summaries` | Directory holding the AI-generated rule summary gzip-compressed indexes (`nids.json.gz`/`sigma.json.gz`/`yara.json.gz`). Same story as `PLAYBOOKS_DIR` above - only populated inside the Docker/Podman image, baked by the same `resources-builder` stage. Point this at a directory containing your own indexes (in the same format) to enable the feature locally. |

Environment variables override the hardcoded defaults at startup.
