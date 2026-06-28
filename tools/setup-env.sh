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

echo "[*] Installing config-extraction deps (configextractor-py + parser packs — roadmap N2)..."
"$VENV/bin/pip" install --quiet configextractor-py cape-parsers rat-king-parser
# rat-king's MACO output path calls validators.ValidationError + domain(consider_tld=),
# which only exist in validators>=0.22 (Kali ships 0.20.0 in system site-packages,
# which throws "no attribute 'ValidationError'"). Shadow it with a current build.
"$VENV/bin/pip" install --quiet 'validators>=0.22'

# IMPORTANT: cape-parsers pulls unicorn>=2.1.1, but speakeasy-emulator pins
# unicorn==1.0.2. They share this venv, so re-pin unicorn LAST — Speakeasy needs
# 1.0.2 to run, and ConfigExtractor still loads ~60 family parsers under it (only
# the few unicorn-2.x emulation-based CAPE parsers are skipped). Keep this last.
echo "[*] Re-pinning unicorn==1.0.2 (Speakeasy requirement; CX tolerates it)..."
"$VENV/bin/pip" install --quiet 'unicorn==1.0.2'

echo "[*] Verifying..."
"$VENV/bin/python" -c "from oletools import olevba; import LnkParse3, extract_msg; from speakeasy import Speakeasy; from configextractor.main import ConfigExtractor; import cape_parsers, rat_king_parser; print('    olevba', olevba.__version__, '· LnkParse3 ok · extract_msg ok · speakeasy ok · configextractor ok')"

echo "[+] Done. triage.sh will auto-detect $VENV and use it for Office/LNK/email"
echo "    stages and for the --unpack emulation stage."
echo "    (System tools pdfid / binwalk / 7z / capa / floss / yara / die are used as-is.)"
