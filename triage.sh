#!/bin/bash

# ─────────────────────────────────────────
# Malware Triage Script
# Usage: ./triage.sh <path_to_sample>
# ─────────────────────────────────────────



# Load config (resolve this script's dir so the tool stays portable / relocatable)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.env"

# Parse args: positional <sample> plus optional --deep / --unpack stages
DEEP=0
DO_UNPACK=0
SAMPLE=""
for a in "$@"; do
    case "$a" in
        --deep)   DEEP=1 ;;
        --unpack) DO_UNPACK=1 ;;
        -*)       echo "Unknown option: $a"; exit 1 ;;
        *)        [ -z "$SAMPLE" ] && SAMPLE="$a" ;;
    esac
done

if [ -z "$SAMPLE" ]; then
    echo "Usage: ./triage.sh <path_to_sample> [--deep] [--unpack]"
    echo "  --deep     also run Ghidra headless decompilation (slow; needs Ghidra installed)"
    echo "  --unpack   emulate the loader stub (Speakeasy) to recover a packed payload,"
    echo "             then re-run the binary tools on it (PE only; needs the venv)"
    exit 1
fi

SAMPLE_NAME=$(basename "$SAMPLE")
REPORT_DIR="$SCRIPT_DIR/reports/${SAMPLE_NAME}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT_DIR"

# ── Sharingan banner — two red eyes (color only on an interactive terminal) ──
print_banner() {
    if [ -t 1 ] && [ -z "$NO_COLOR" ]; then
        R=$'\033[1;31m'; X=$'\033[0m'
    else
        R=""; X=""
    fi
    printf '%s' "$R"
    cat <<'EYES'
     .-=======-.              .-=======-.
    /     ,     \            /     ,     \
   |    \   /    |          |    \   /    |
   |  -- (O) --  |          |  -- (O) --  |
   |    /   \    |          |    /   \    |
    \  '     '  /            \  '     '  /
     '-=======-'              '-=======-'
EYES
    printf '%s        S H A R I N G A N%s   — see through the disguise\n\n' "$R" "$X"
}
print_banner

echo "========================================"
echo " Malware Triage: $SAMPLE_NAME"
echo " Report dir: $REPORT_DIR"
echo "========================================"

# ── File identification (the routing front door) ──
# Classify ANY input (PE/.NET/ELF/Office/PDF/LNK/script/archive/email/unknown)
# so the stages below run only what fits the sample. Also flags extension/content
# mismatch (masquerade). The skill reads fileinfo.json first.
echo "[*] Identifying file type..."
python3 "$IDENTIFY" "$SAMPLE" "$REPORT_DIR/fileinfo.json" >/dev/null 2>&1
CATEGORY=$(python3 -c "import json;print(json.load(open('$REPORT_DIR/fileinfo.json')).get('category','unknown'))" 2>/dev/null || echo unknown)
SUBTYPE=$(python3 -c "import json;print(json.load(open('$REPORT_DIR/fileinfo.json')).get('subtype') or '')" 2>/dev/null || echo "")
MISMATCH=$(python3 -c "import json;print(json.load(open('$REPORT_DIR/fileinfo.json')).get('extension_mismatch'))" 2>/dev/null || echo "")
echo "    Category: $CATEGORY${SUBTYPE:+/$SUBTYPE}"
[ "$MISMATCH" = "True" ] && echo "    ⚠ extension/content MISMATCH — possible masquerade (see fileinfo.json)"

# Prefer the project venv interpreter (has oletools/LnkParse3/extract_msg);
# fall back to system python3 (non-PE library stages then degrade gracefully).
PY="$VENV_PY"; [ -x "$PY" ] || PY="python3"

# ── Hash Generation ──────────────────────
echo "[*] Generating hashes..."
MD5=$(md5sum "$SAMPLE" | awk '{print $1}')
SHA1=$(sha1sum "$SAMPLE" | awk '{print $1}')
SHA256=$(sha256sum "$SAMPLE" | awk '{print $1}')

cat > "$REPORT_DIR/hashes.json" << HEOF
{
  "md5": "$MD5",
  "sha1": "$SHA1",
  "sha256": "$SHA256",
  "filename": "$SAMPLE_NAME"
}
HEOF
echo "    MD5:    $MD5"
echo "    SHA1:   $SHA1"
echo "    SHA256: $SHA256"

# ── VirusTotal Hash Lookup ───────────────
echo "[*] Querying VirusTotal..."
curl -s --request GET \
    --url "https://www.virustotal.com/api/v3/files/$SHA256" \
    --header "x-apikey: $VT_API_KEY" \
    -o "$REPORT_DIR/virustotal.json"
VT_STATUS=$(python3 -c "
import json
try:
    d = json.load(open('$REPORT_DIR/virustotal.json'))
    stats = d['data']['attributes']['last_analysis_stats']
    name = d['data']['attributes'].get('meaningful_name', 'unknown')
    print(f'FOUND | Family: {name} | Malicious: {stats[\"malicious\"]}/{sum(stats.values())}')
except:
    print('NOT FOUND or API error')
")
echo "    VT: $VT_STATUS"

# ── MalwareBazaar Hash Lookup ────────────
echo "[*] Querying MalwareBazaar..."
curl -s --request POST \
    --url "https://mb-api.abuse.ch/api/v1/" \
    --header "Auth-Key: $BAZAAR_API_KEY" --data "query=get_info&hash=$SHA256" \
    -o "$REPORT_DIR/malwarebazaar.json"
MB_STATUS=$(python3 -c "
import json
try:
    d = json.load(open('$REPORT_DIR/malwarebazaar.json'))
    if d['query_status'] == 'ok':
        info = d['data'][0]
        print(f'FOUND | Family: {info.get(\"signature\",\"unknown\")} | Tags: {info.get(\"tags\",[])}')
    else:
        print('NOT FOUND')
except:
    print('API error')
")
echo "    Bazaar: $MB_STATUS"

# ═══════════════════════════════════════════════════════════════
#  ROUTED ANALYSIS — stages chosen by the file category above
# ═══════════════════════════════════════════════════════════════
case "$CATEGORY" in
  pe|dotnet|elf)
    echo "[bin] Detect-It-Easy..."
    diec --json "$SAMPLE" > "$REPORT_DIR/die.json" 2>/dev/null

    if [ "$CATEGORY" != "elf" ]; then
        echo "[bin] pestats.py (PE info)..."
        python3 $PESTATS "$SAMPLE" > "$REPORT_DIR/peinfo.json" 2>/dev/null
    fi

    echo "[bin] flare-floss (this may take a few minutes)..."
    floss --json "$SAMPLE" > "$REPORT_DIR/floss.json" 2>/dev/null

    echo "[bin] capa (this may take a few minutes)..."
    capa --rules "$CAPA_RULES" -s "$CAPA_SIGS" --json "$SAMPLE" > "$REPORT_DIR/capa.json" 2>"$REPORT_DIR/capa.err"
    [ -s "$REPORT_DIR/capa.err" ] && echo "    (capa warnings logged to capa.err)" || rm -f "$REPORT_DIR/capa.err"

    # ── Automated config / C2 extraction (N2) — recognized-family parsers ──
    # Statically rips the embedded config (C2/keys/campaign IDs/mutex) from
    # ~200 known families via configextractor-py. no_match is a real result;
    # "unavailable" means the venv lacks the parser packs (run setup-env.sh).
    echo "[bin] config/C2 extraction (configextractor-py)..."
    "$PY" "$CONFIGEXT" "$SAMPLE" "$REPORT_DIR/config.json"

    # ── Ghidra headless (deep RE) — binary samples only ──
    if [ "$DEEP" -eq 1 ]; then
        echo "[+] Deep RE: running Ghidra headless decompilation (this is slow)..."
        HEADLESS="$GHIDRA_HOME/support/analyzeHeadless"
        if [ -x "$HEADLESS" ]; then
            GPROJ=$(mktemp -d)
            "$HEADLESS" "$GPROJ" "triage_$$" \
                -import "$SAMPLE" \
                -scriptPath "$GHIDRA_SCRIPTS" \
                -postScript ExportGhidra.java "$REPORT_DIR/ghidra.json" \
                -analysisTimeoutPerFile 900 \
                -deleteProject \
                > "$REPORT_DIR/ghidra.log" 2>&1 || true
            rm -rf "$GPROJ"
            if [ -s "$REPORT_DIR/ghidra.json" ]; then
                echo "    Ghidra export -> ghidra.json"
            else
                echo "    Ghidra produced no JSON (see ghidra.log) — likely a packed/crypter layout."
            fi
        else
            echo "    SKIPPED: Ghidra not found at \$GHIDRA_HOME ($GHIDRA_HOME)."
            echo "             Install it: sudo bash $GHIDRA_SCRIPTS/install-ghidra.sh"
        fi
    fi

    # ── Emulation-based unpacking (N4) — opt-in, PE only ──
    # Emulate the loader stub in Speakeasy (no VM/detonation/network), carve the
    # payload it decrypts in memory, then re-run the binary tools on the real
    # body. Recovers EMBEDDED indicators only; a stub that bails early is recorded
    # as a gap (escalate to a sandbox), never a fake unpack.
    if [ "$DO_UNPACK" -eq 1 ]; then
        if [ "$CATEGORY" = "elf" ]; then
            echo "[+] --unpack: skipped (Speakeasy emulates Windows PE, not ELF)."
        else
            echo "[+] Unpack: emulating loader stub (Speakeasy) to recover payload..."
            "$PY" "$UNPACK" "$SAMPLE" "$REPORT_DIR" "$REPORT_DIR/fileinfo.json"
            PRIMARY=$(python3 -c "import json;print(json.load(open('$REPORT_DIR/unpacked.json')).get('meta',{}).get('primary_region') or '')" 2>/dev/null || echo "")
            if [ -n "$PRIMARY" ] && [ -s "$REPORT_DIR/$PRIMARY" ]; then
                DUMP="$REPORT_DIR/$PRIMARY"
                UDIR="$REPORT_DIR/unpacked"
                echo "    Recovered payload -> $PRIMARY ; re-running binary tools on it..."
                strings -a -n 6 "$DUMP" > "$UDIR/strings.txt" 2>/dev/null || true
                echo "    [unpack] floss on recovered body..."
                floss --json "$DUMP" > "$UDIR/floss.json" 2>/dev/null || true
                echo "    [unpack] capa on recovered body..."
                capa --rules "$CAPA_RULES" -s "$CAPA_SIGS" --json "$DUMP" \
                    > "$UDIR/capa.json" 2>"$UDIR/capa.err"
                [ -s "$UDIR/capa.err" ] || rm -f "$UDIR/capa.err"
                echo "    [unpack] YARA on recovered body..."
                yara -r "$YARA_RULES_DIR/yara-rules/index.yar" "$DUMP" > "$UDIR/yara.txt" 2>/dev/null || true
                yara -r "$YARA_RULES_DIR/signature-base/index.yml" "$DUMP" >> "$UDIR/yara.txt" 2>/dev/null || true
                echo "    [unpack] config/C2 extraction on recovered body..."
                "$PY" "$CONFIGEXT" "$DUMP" "$UDIR/config.json"
                echo "    [unpack] re-analysis written to unpacked/ (floss/capa/yara/strings/config)"
            else
                echo "    No payload recovered — emulation gap recorded in unpacked.json"
                echo "    (stub likely bailed early / anti-emulation / remote-keyed — escalate to a sandbox)"
            fi
        fi
    fi
    ;;

  office_ole|office_ooxml|pdf|lnk|archive|email)
    echo "[$CATEGORY] Running non-PE handler..."
    OLEVBA="$OLEVBA" OLEID="$OLEID" IDENTIFY="$IDENTIFY" \
        "$PY" "$NONPE" "$SAMPLE" "$CATEGORY" "$REPORT_DIR"
    [ "$DEEP" -eq 1 ]   && echo "    (--deep / Ghidra has no effect on $CATEGORY samples)"
    [ "$DO_UNPACK" -eq 1 ] && echo "    (--unpack / emulation has no effect on $CATEGORY samples — PE only)"
    ;;

  *)
    echo "[$CATEGORY] No binary/format-specific stage — relying on universal strings + YARA."
    [ "$DO_UNPACK" -eq 1 ] && echo "    (--unpack / emulation has no effect on $CATEGORY samples — PE only)"
    ;;
esac

# ═══════════════════════════════════════════════════════════════
#  UNIVERSAL STAGES — run for every sample type
# ═══════════════════════════════════════════════════════════════

# ── Raw strings (any file) + unified strings.json for the extractors ──
echo "[*] Extracting strings..."
strings -a -n 6      "$SAMPLE" >  "$REPORT_DIR/strings.txt" 2>/dev/null || true
strings -a -n 6 -e l "$SAMPLE" >> "$REPORT_DIR/strings.txt" 2>/dev/null || true
# strings.json = flat {"strings":[...]} from floss.json (PE) or strings.txt (rest);
# this is also the fix for the old nested-FLOSS IP-extraction bug.
python3 "$COLLECT" "$REPORT_DIR"
STRINGS_SRC="$REPORT_DIR/strings.json"

# ── YARA (any file — rules also match docs / scripts / archives) ──
echo "[*] Running YARA rules..."
yara -r "$YARA_RULES_DIR/yara-rules/index.yar" "$SAMPLE" > "$REPORT_DIR/yara.txt" 2>/dev/null || true
yara -r "$YARA_RULES_DIR/signature-base/index.yml" "$SAMPLE" >> "$REPORT_DIR/yara.txt" 2>/dev/null || true

# ── Extract IPs for AbuseIPDB (from the unified strings.json) ──
echo "[*] Extracting IPs and querying AbuseIPDB..."
python3 << PYEOF
import json, re, urllib.request

try:
    data = json.load(open('$STRINGS_SRC'))
    all_strings = [s if isinstance(s, str) else s.get('string', '')
                   for s in data.get('strings', [])]

    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    ips = list(set(ip_pattern.findall(' '.join(all_strings))))
    private = re.compile(r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|255\.)')
    public_ips = [ip for ip in ips
                  if not private.match(ip)
                  and all(0 <= int(o) <= 255 for o in ip.split('.'))]

    print(f'    Found {len(public_ips)} public IPs: {public_ips[:10]}')

    results = []
    for ip in public_ips[:5]:
        req = urllib.request.Request(
            f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90',
            headers={'Key': '$ABUSEIPDB_API_KEY', 'Accept': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            results.append(json.loads(resp.read()))

    json.dump(results, open('$REPORT_DIR/abuseipdb.json', 'w'), indent=2)
    print('    AbuseIPDB lookup complete')
except Exception as e:
    print(f'    IP extraction skipped: {e}')
PYEOF

# ── Domain / C2 reputation (ThreatFox + URLhaus + VT-domain) ──
echo "[*] Domain/C2 reputation (ThreatFox / URLhaus / VT-domain)..."
ABUSECH_API_KEY="$BAZAAR_API_KEY" VT_API_KEY="$VT_API_KEY" \
    python3 "$DOMAINREP" "$STRINGS_SRC" "$REPORT_DIR/domain_rep.json"

# ── VirusTotal pivoting (sample → family/campaign) ──
# Pivots on the VT report fetched in step 2: contacted domains/ips, dropped
# files, in-the-wild URLs, and sibling samples sharing those indicators or the
# imphash. Paced for the VT public-tier rate limit; degrades gracefully if a
# pivot is gated. Needs virustotal.json to exist (skip if the sample is unknown).
if [ -s "$REPORT_DIR/virustotal.json" ]; then
    echo "[+] VirusTotal pivoting (this is paced for the rate limit; may take a few min)..."
    VT_API_KEY="$VT_API_KEY" \
        python3 "$VTPIVOT" "$REPORT_DIR/virustotal.json" "$REPORT_DIR/vt_pivot.json"
fi

# ── Tool / rule-set provenance ────────────
# Stamp the report with the version of every tool and the commit/date of every
# rule-set used above, so findings are reproducible and audit-grade. Local-only,
# cheap, no network — runs last so it documents exactly the stack that just ran.
echo "[+] Stamping tool & rule-set provenance..."
CAPA_RULES="$CAPA_RULES" CAPA_SIGS="$CAPA_SIGS" \
    YARA_RULES_DIR="$YARA_RULES_DIR" GHIDRA_HOME="$GHIDRA_HOME" \
    python3 "$PROVENANCE" "$REPORT_DIR"

# ── Final Summary ─────────────────────────
echo ""
echo "========================================"
echo " TRIAGE COMPLETE"
echo " All reports saved to: $REPORT_DIR"
echo "========================================"
echo ""
echo " Files generated:"
ls -lh "$REPORT_DIR"
echo ""
echo " Next step: Open Claude Code in this project and run:"
echo "   /analyze-sample $SAMPLE_NAME"
echo " (with no argument, /analyze-sample lists samples/ and asks which to analyze)"
echo "========================================"
