#!/bin/sh
# Downloads the pinned CyberChef release and unpacks it into a directory
# SO-CRATES serves at /cyberchef/ (see cyberchef.py). Used by the
# Dockerfile's resources-builder stage, and runnable by hand for a local dev
# server:
#
#   scripts/fetch-cyberchef.sh ./cyberchef
#   CYBERCHEF_DIR=./cyberchef python3 socrates.py
#
# To upgrade, change the four pins below - see AGENTS.md's "Updating
# CyberChef" section. The release asset's filename carries a commit hash,
# not the version, so it's pinned separately. CYBERCHEF_ZIP_SHA256 is
# GitHub's own published digest for that asset.
set -eu

CYBERCHEF_VERSION=v11.5.0
CYBERCHEF_ZIP=CyberChef_8cd426dd4f40f1423912d5fad91b578a86a65112.zip
CYBERCHEF_ZIP_SHA256=f6478925d3eaa16ec08626a85f5b85eed10d531a5e18700615fed7ecb024cccf
CYBERCHEF_LICENSE_SHA256=58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd

DEST=${1:?usage: fetch-cyberchef.sh <destination directory>}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

curl -fsSL -o "$WORK/cyberchef.zip" \
    "https://github.com/gchq/CyberChef/releases/download/$CYBERCHEF_VERSION/$CYBERCHEF_ZIP"
echo "$CYBERCHEF_ZIP_SHA256  $WORK/cyberchef.zip" | sha256sum -c -

# The release zip ships no top-level LICENSE (only third-party
# *.LICENSE.txt notices), but Apache-2.0 requires distributing it - fetch
# it from the same tag, pinned the same way.
curl -fsSL -o "$WORK/LICENSE" \
    "https://raw.githubusercontent.com/gchq/CyberChef/$CYBERCHEF_VERSION/LICENSE"
echo "$CYBERCHEF_LICENSE_SHA256  $WORK/LICENSE" | sha256sum -c -

mkdir -p "$WORK/out"
unzip -q "$WORK/cyberchef.zip" -d "$WORK/out"
cp "$WORK/LICENSE" "$WORK/out/LICENSE"

# Pre-compressed .gz/.br duplicates of every asset (~32MB) - SO-CRATES's
# stdlib file server never negotiates Content-Encoding, so they'd only ever
# be dead weight in the image.
find "$WORK/out" \( -name '*.gz' -o -name '*.br' \) -delete

# Served as the directory index, so /cyberchef/ needs no version-specific
# redirect.
mv "$WORK/out/CyberChef_$CYBERCHEF_VERSION.html" "$WORK/out/index.html"

# Send to CyberChef (static/socrates.js) drives CyberChef through its
# internal window.app object, not a published API - fail the build here if
# an upgrade renamed any piece it uses, rather than shipping a silently
# broken button.
for needle in 'window.app=' 'loadUIFiles' 'setRecipeConfig' 'options.updateUrl' 'setInput'; do
    if ! grep -qF "$needle" "$WORK/out/assets/main.js"; then
        echo "fetch-cyberchef.sh: '$needle' not found in CyberChef $CYBERCHEF_VERSION's main.js" >&2
        exit 1
    fi
done

rm -rf "$DEST"
mkdir -p "$(dirname "$DEST")"
mv "$WORK/out" "$DEST"
echo "CyberChef $CYBERCHEF_VERSION installed to $DEST"
