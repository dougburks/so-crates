# Podman

## podman run

If you prefer to use `podman run`, here are the steps you can use on Debian 13 or compatible distros:
```bash
# Install podman
sudo apt update && sudo apt -y install podman
# Create data directory
mkdir -p ~/socrates-data
# Start SO-CRATES
podman run --userns=keep-id --user $(id -u):$(id -g) \
  -v $HOME/socrates-data:/data:Z -p 127.0.0.1:8000:8000 \
  ghcr.io/dougburks/so-crates:main
```

This publishes the port on localhost only. To let other machines on your network connect, use `-p 8000:8000` instead.

## podman compose

If you prefer to use `podman compose`, here are the steps you can use on Debian 13 or compatible distros:
```bash
# Install and configure podman and podman-compose
sudo apt update && sudo apt -y install podman podman-compose
# Download the Podman compose file
wget https://raw.githubusercontent.com/dougburks/so-crates/refs/heads/main/docker-compose.podman.yml
# Record your UID/GID in a .env file for the compose file's user mapping -
# podman compose reads this automatically, every time, from any terminal
# (an `export UID GID` only lasts for the current shell session, so `down`/
# `restart` run later or from a new terminal would silently run as root
# instead - see docker-compose.podman.yml's `user: "${UID}:${GID}"`)
echo "UID=$(id -u)" > .env
echo "GID=$(id -g)" >> .env
# Create data directory
mkdir -p socrates-data
# Start SO-CRATES (add the -d option to run in the background if desired)
podman compose -f docker-compose.podman.yml up
```

To stop:
```bash
podman compose -f docker-compose.podman.yml down
```

To restart:
```bash
podman compose -f docker-compose.podman.yml restart
```

## Air-Gapped / Offline Deployment for Podman

Our container image bakes in the Emerging Threats Open ruleset, YARA Forge rules, and SigmaHQ/Zircolite rules at build time, so PCAP, binary, and log analysis all work without internet access. To copy to an isolated network, pull and save the container image using an internet-connected machine:

```bash
podman pull ghcr.io/dougburks/so-crates:main
podman save ghcr.io/dougburks/so-crates:main > so-crates.tar
```

Then transfer so-crates.tar to the isolated network via USB or other media. On the air-gapped machine:
```bash
podman load < so-crates.tar
mkdir -p ~/socrates-data
podman run --userns=keep-id --user $(id -u):$(id -g) \
  -v $HOME/socrates-data:/data:Z -p 127.0.0.1:8000:8000 \
  ghcr.io/dougburks/so-crates:main
```

## Build Your Own Podman Image

If you prefer to build your own Podman image, you can clone this GitHub repo and then build the image:

```bash
git clone https://github.com/dougburks/so-crates
cd so-crates
podman build -t so-crates .
mkdir -p ~/socrates-data
podman run --userns=keep-id --user $(id -u):$(id -g) \
  -v $HOME/socrates-data:/data:Z -p 127.0.0.1:8000:8000 \
  so-crates
```
