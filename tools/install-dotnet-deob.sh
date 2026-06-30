#!/bin/bash
# ─────────────────────────────────────────────────────────────
# Sharingan — install the .NET deobfuscation dependency (de4dot)
# for the N7 managed-unpack stage (tools/dotnet_deob.py).
#
# Builds de4dot's .NET Core solution with the `dotnet` SDK into
# tools/de4dot/, where dotnet_deob.py autodetects it and runs it
# as `dotnet tools/de4dot/de4dot.dll` (rolled forward to the
# installed runtime). Per-analyst, run once — like the venv /
# Ghidra. NO sudo needed if `dotnet` + `git` are already present.
#
# Usage:  bash tools/install-dotnet-deob.sh
# ─────────────────────────────────────────────────────────────
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="$SCRIPT_DIR/de4dot"

# Prereqs: dotnet SDK + git. (No mono needed — the netcore build runs on dotnet.)
missing=""
command -v dotnet >/dev/null || missing="$missing dotnet (apt install dotnet-sdk-8.0 / dotnet-sdk-6.0)"
command -v git    >/dev/null || missing="$missing git (apt install git)"
if [ -n "$missing" ]; then
    echo "[!] Missing prerequisite(s):$missing" >&2
    echo "    Install them (apt needs sudo), then re-run this script." >&2
    exit 1
fi

if [ -f "$DEST/de4dot.dll" ]; then
    echo "[*] de4dot already built at $DEST — skipping. (Delete it to rebuild.)"
else
    # Build in a fresh temp dir so no build artifacts (and no root-owned files)
    # land in the repo tree; only the final binaries are copied into tools/de4dot/.
    BUILD="$(mktemp -d)"
    trap 'rm -rf "$BUILD"' EXIT
    echo "[*] Cloning de4dot (with dnlib submodule) into a temp build dir..."
    git clone --quiet --recurse-submodules https://github.com/de4dot/de4dot "$BUILD/de4dot-src"

    echo "[*] Building de4dot.netcore.sln (Release) with the dotnet SDK..."
    dotnet build "$BUILD/de4dot-src/de4dot.netcore.sln" -c Release -v q --nologo

    BUILT=$(find "$BUILD/de4dot-src" -name de4dot.dll -path '*Release*' \
            ! -path '*/obj/*' | sort | tail -1)
    if [ -z "$BUILT" ]; then
        echo "[!] Build produced no de4dot.dll — inspect the output above. Aborting." >&2
        exit 1
    fi
    echo "[*] Installing build output -> $DEST"
    mkdir -p "$DEST"
    cp -f "$(dirname "$BUILT")"/* "$DEST"/ 2>/dev/null || true
fi

echo "[*] Smoke test (dotnet de4dot.dll)..."
if DOTNET_ROLL_FORWARD=LatestMajor dotnet "$DEST/de4dot.dll" 2>&1 | grep -qi "de4dot v"; then
    echo "[+] de4dot is runnable. dotnet_deob.py (N7) will autodetect it."
else
    echo "[!] de4dot.dll present but the smoke test was inconclusive — verify manually:" >&2
    echo "      DOTNET_ROLL_FORWARD=LatestMajor dotnet \"$DEST/de4dot.dll\"" >&2
fi

echo "[+] Done. The N7 .NET deobfuscation stage is now enabled."
echo "    (config.env DE4DOT can stay empty — autodetected at tools/de4dot/de4dot.dll.)"
