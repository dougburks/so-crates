# SO-CRATES

*Security Onion Containerized Rapid Analysis of Threats, Evil, and Sus*

A standalone web application for analyzing pcap files, log files, and binary files. Features include Suricata network analysis, YARA binary scanning, Sigma rule detection for logs, and a single-page UI for browsing alerts, metadata, transcripts, and hexdumps.

📖 **Full documentation:** https://so-crates.org/

![Main screen](docs/images/so-crates-main.png)

## Documentation

- [Interactive Demo](https://so-crates.org/quick-demo/)
- [Installation](https://so-crates.org/installation/) ([OhMyDebn](https://so-crates.org/installation/ohmydebn/), [Docker](https://so-crates.org/installation/docker/), [Podman](https://so-crates.org/installation/podman/))
- [Usage](https://so-crates.org/usage/)
- [Themes](https://so-crates.org/themes/)
- [Configuration](https://so-crates.org/configuration/)
- [Security](https://so-crates.org/security/)
- [Architecture](https://so-crates.org/architecture/) / [API Reference](https://so-crates.org/api/) / [Filtering](https://so-crates.org/filtering/)
- [Credits](https://so-crates.org/credits/)
- [Release Notes](https://so-crates.org/release-notes/)

## Development

See [AGENTS.md](AGENTS.md) for agent-focused guidance on maintaining SO-CRATES, including updating vendored dependencies.

```bash
# All tests
python3 -m unittest discover -v
```

## License

See [LICENSE](LICENSE).
