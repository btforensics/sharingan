#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Install Ghidra + a compatible JDK for the malware-triage --deep stage.
#
# Ghidra 11.x requires JDK 17 or 21 (NOT 25, which is what this box currently has
# as the default `java`). This script installs openjdk-21 alongside it and points
# Ghidra at JDK 21 via launch.properties — it does not change the system default.
#
# Usage:   sudo bash tools/ghidra/install-ghidra.sh
# Result:  /opt/ghidra -> /opt/ghidra_<ver>_PUBLIC, GHIDRA_HOME ready for config.env
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

INSTALL_DIR=/opt
JDK_PKG=openjdk-21-jdk-headless

need_root() { [ "$(id -u)" -eq 0 ] || { echo "Run with sudo: sudo bash $0"; exit 1; }; }
need_root

echo "==> [1/4] Installing JDK 21 (Ghidra-compatible)..."
if ! dpkg -s "$JDK_PKG" >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y "$JDK_PKG" unzip curl
else
    echo "    $JDK_PKG already installed."
fi
JDK21_HOME=$(dirname "$(dirname "$(readlink -f "$(command -v java || echo /usr/lib/jvm/java-21-openjdk-amd64/bin/java)")")")
# Prefer the explicit 21 path if present
[ -d /usr/lib/jvm/java-21-openjdk-amd64 ] && JDK21_HOME=/usr/lib/jvm/java-21-openjdk-amd64
echo "    JDK 21 home: $JDK21_HOME"

echo "==> [2/4] Resolving latest Ghidra release from GitHub..."
API=https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest
ZIP_URL=$(curl -fsSL "$API" | grep -oE 'https://[^"]+_PUBLIC[^"]+\.zip' | head -1)
[ -n "$ZIP_URL" ] || { echo "Could not resolve Ghidra zip URL from GitHub API."; exit 1; }
ZIP_NAME=$(basename "$ZIP_URL")
echo "    Latest: $ZIP_NAME"

echo "==> [3/4] Downloading + extracting to $INSTALL_DIR ..."
TMP=$(mktemp -d)
curl -fL --progress-bar "$ZIP_URL" -o "$TMP/$ZIP_NAME"
unzip -q "$TMP/$ZIP_NAME" -d "$INSTALL_DIR"
rm -rf "$TMP"
GHIDRA_DIR=$(find "$INSTALL_DIR" -maxdepth 1 -type d -name 'ghidra_*_PUBLIC' | sort | tail -1)
ln -sfn "$GHIDRA_DIR" "$INSTALL_DIR/ghidra"
echo "    Installed: $GHIDRA_DIR"
echo "    Symlink:   $INSTALL_DIR/ghidra"

echo "==> [4/4] Pinning Ghidra to JDK 21 (without changing system default)..."
LP="$INSTALL_DIR/ghidra/support/launch.properties"
# Remove any prior override we added, then append.
grep -v '^JAVA_HOME_OVERRIDE=' "$LP" > "$LP.tmp" 2>/dev/null || true
mv "$LP.tmp" "$LP" 2>/dev/null || true
echo "JAVA_HOME_OVERRIDE=$JDK21_HOME" >> "$LP"
echo "    Wrote JAVA_HOME_OVERRIDE=$JDK21_HOME to launch.properties"

echo ""
echo "============================================================"
echo " Ghidra installed."
echo "   GHIDRA_HOME = $INSTALL_DIR/ghidra"
echo " Verify headless:"
echo "   $INSTALL_DIR/ghidra/support/analyzeHeadless -version 2>/dev/null || \\"
echo "   $INSTALL_DIR/ghidra/support/analyzeHeadless /tmp/g t -help"
echo ""
echo " config.env already references GHIDRA_HOME=$INSTALL_DIR/ghidra"
echo " Run a deep analysis with:  ./triage.sh <sample> --deep"
echo "============================================================"
