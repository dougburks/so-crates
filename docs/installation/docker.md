# Docker

## Docker Desktop (Windows / macOS)

1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) and start it.
2. Open a terminal - on Windows, use a WSL2 terminal (Docker Desktop's default backend), so the same commands below work unchanged rather than needing PowerShell-style paths - and run:

```bash
mkdir -p ~/socrates-data
docker run -v ~/socrates-data:/data -p 127.0.0.1:8000:8000 ghcr.io/dougburks/so-crates:main
```

This publishes the port on localhost only. To let other machines on your network connect, use `-p 8000:8000` instead.

## docker run (Linux)

If you prefer `docker run`, here are the steps you can use on Debian 13 or compatible distros:
```bash
# Install and configure docker.io
sudo apt update && sudo apt -y install docker.io && sudo usermod -aG docker $USER
# Create data directory
mkdir -p ~/socrates-data
# Start SO-CRATES
newgrp docker -c "docker run -v ~/socrates-data:/data -p 127.0.0.1:8000:8000 ghcr.io/dougburks/so-crates:main"
```

## docker compose (Linux)

If you prefer to use `docker compose`, here are the steps you can use on Debian 13 or compatible distros:
```bash
# Install and configure docker.io and docker-compose
sudo apt update && sudo apt -y install docker.io docker-compose && sudo usermod -aG docker $USER
# Download docker-compose.yml
wget https://raw.githubusercontent.com/dougburks/so-crates/refs/heads/main/docker-compose.yml
# Create data directory
mkdir -p socrates-data
# Start SO-CRATES (add the -d option to run in the background if desired)
newgrp docker -c "docker compose up"
```

Note that `docker compose` stores its data in `./socrates-data` next to `docker-compose.yml`, rather than `~/socrates-data` as in the `docker run` instructions above.

To stop:
```bash
newgrp docker -c "docker compose down"
```

To restart:
```bash
newgrp docker -c "docker compose restart"
```

Once you log out and back in, your `docker` group membership takes effect and you can run these `docker compose` commands without the `newgrp docker -c` wrapper.

## Air-Gapped / Offline Deployment for Docker

Our container image bakes in the Emerging Threats Open ruleset, YARA Forge rules, and SigmaHQ/Zircolite rules at build time, so PCAP, binary, and log analysis all work without internet access. To copy to an isolated network, pull and save the container image using an internet-connected machine:

```bash
docker pull ghcr.io/dougburks/so-crates:main
docker save ghcr.io/dougburks/so-crates:main > so-crates.tar
```

Then transfer `so-crates.tar` to the isolated network via USB or other media. On the air-gapped machine:
```bash
docker load < so-crates.tar
mkdir -p ~/socrates-data
docker run -v ~/socrates-data:/data -p 127.0.0.1:8000:8000 ghcr.io/dougburks/so-crates:main
```

## Build Your Own Docker Image

If you prefer to build your own Docker image, you can clone this GitHub repo and then build the image:

```bash
git clone https://github.com/dougburks/so-crates
cd so-crates
docker build -t so-crates .
mkdir -p ~/socrates-data
docker run -v ~/socrates-data:/data -p 127.0.0.1:8000:8000 so-crates
```


## Cloud and proxied environments

If you access SO-CRATES through a proxy hostname rather than localhost or an IP (e.g. Killercoda, GitHub Codespaces, or your own reverse proxy), add the hostname to the `ALLOWED_HOSTS` environment variable or requests are rejected with "Invalid Host header" (a DNS-rebinding defense). A wildcard covers per-session hostnames:

```bash
docker run -v ~/socrates-data:/data -p 8000:8000 -e ALLOWED_HOSTS='*.killercoda.com' ghcr.io/dougburks/so-crates:main
```
