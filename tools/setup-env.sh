#!/bin/bash
# ─────────────────────────────────────────────────────────────
# Sharingan environment setup (per-analyst, run once).
# Creates a project-local Python venv with the non-PE analysis
# deps (oletools, LnkParse3, extract_msg). The venv is NOT
# committed — each analyst runs this to reproduce it locally,
# the same way Ghidra is installed per-analyst.
#
# Usage:  bash tools/setup-env.sh
# ─────────────────────────────────────────────────────────────
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/venv"

echo "[*] Creating venv at $VENV (with system site-packages for pefile/olefile)..."
python3 -m venv --system-site-packages "$VENV"

echo "[*] Upgrading pip..."
"$VENV/bin/pip" install --quiet --upgrade pip

echo "[*] Installing non-PE analysis deps..."
"$VENV/bin/pip" install --quiet oletools LnkParse3 extract_msg

echo "[*] Installing emulation-unpacking dep (Speakeasy — roadmap N4)..."
"$VENV/bin/pip" install --quiet speakeasy-emulator

echo "[*] Verifying..."
"$VENV/bin/python" -c "from oletools import olevba; import LnkParse3, extract_msg; from speakeasy import Speakeasy; print('    olevba', olevba.__version__, '· LnkParse3 ok · extract_msg ok · speakeasy ok')"

echo "[+] Done. triage.sh will auto-detect $VENV and use it for Office/LNK/email"
echo "    stages and for the --unpack emulation stage."
echo "    (System tools pdfid / binwalk / 7z / capa / floss / yara / die are used as-is.)"
