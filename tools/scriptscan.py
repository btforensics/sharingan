#!/usr/bin/env python3
"""
scriptscan.py — Sharingan script deobfuscation stage.

The `script` category (PowerShell / JScript / VBScript / HTA / BAT / WSF / shell)
is the dominant *first-stage* dropper layer and is almost always obfuscated, so
raw strings + YARA see noise. This stage peels the obfuscation: it recursively
decodes the common encodings (base64, hex, char-code arrays, %-escapes,
gzip/deflate, PowerShell -EncodedCommand) and re-extracts IOCs from every layer.

It is the script analogue of N4/N7: it recovers EMBEDDED indicators (intent), so
promote any C2/URL it surfaces to High *intent*, never "confirmed live".

Design (per the gating & speed rubric):
  - CHEAP, auto-on-match: stdlib only, no external tools, bounded recursion.
  - Caps: MAX_DEPTH / MAX_LAYERS / MAX_BLOB so a hostile input can't blow up.

Safe handling (per CLAUDE.md): live IOCs in the JSON are DEFANGED; full decoded
bodies are written raw to <report_dir>/script_layers/ for the analyst to mine,
never echoed back. A carved PE/ZIP inside a script is written out as a child.

Usage:  scriptscan.py <sample> <report_dir>
Emits:  <report_dir>/scriptscan.json  (+ script_layers/layerNN.* for each layer)
Stdlib only. Never raises into the pipeline — failures are captured in the JSON.
"""
import sys, os, re, json, base64, binascii, gzip, zlib, hashlib

# ── caps (gating rubric: bounded so breadth stays cheap) ──────────────────
MAX_DEPTH   = 6          # recursion depth through nested encodings
MAX_LAYERS  = 60         # total decoded layers recorded
MAX_BLOB    = 8 << 20    # 8 MB — ignore a decoded blob bigger than this
MIN_B64     = 40         # shortest base64 run worth decoding
MAX_IOCS    = 300        # per IOC type

# ── IOC patterns ──────────────────────────────────────────────────────────
URL_RE    = re.compile(rb"[a-zA-Z][a-zA-Z0-9+.\-]{1,12}://[^\s\"'<>)\]}\\]{4,}")
IP_RE     = re.compile(rb"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
DOMAIN_RE = re.compile(rb"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
                       rb"(?:com|net|org|io|ru|cn|info|biz|xyz|top|club|online|site|"
                       rb"shop|live|icu|cc|tk|ml|ga|cf|gq|su|pw|me|co|us|uk|de|fr|nl|"
                       rb"eu|in|br|ir|kz|ua|tv|ws|stream|download|host|space|fun|link)\b")
UNC_RE    = re.compile(rb"\\\\[a-zA-Z0-9._\-]+\\[^\s\"'<>|]{2,}")
REG_RE    = re.compile(rb"(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[^\s\"'<>|]{3,}", re.I)

# Suspicious tokens — capability fingerprints across script families.
SUSPICIOUS = [
    b"Invoke-Expression", b"IEX", b"DownloadString", b"DownloadData", b"DownloadFile",
    b"Net.WebClient", b"WebClient", b"Invoke-WebRequest", b"Start-BitsTransfer",
    b"FromBase64String", b"Reflection.Assembly", b"[Reflection.Assembly]",
    b"GzipStream", b"DeflateStream", b"MemoryStream", b"EncodedCommand",
    b"-enc", b"-e ", b"-w hidden", b"-WindowStyle Hidden", b"-nop", b"-NoProfile",
    b"-ExecutionPolicy Bypass", b"-ep bypass", b"VirtualAlloc", b"CreateThread",
    b"WriteProcessMemory", b"CreateRemoteThread", b"RtlMoveMemory", b"memset",
    b"WScript.Shell", b"Shell.Application", b"CreateObject", b"ShellExecute",
    b"ActiveXObject", b"eval(", b"unescape(", b"GetObject", b"Run(", b"Exec(",
    b"powershell", b"cmd.exe", b"cmd /c", b"mshta", b"rundll32", b"regsvr32",
    b"certutil", b"bitsadmin", b"schtasks", b"wmic", b"wscript", b"cscript",
    b"AddType", b"GetDelegateForFunctionPointer", b"VirtualProtect",
    b"New-Object", b"Hidden", b"bypass", b"Add-MpPreference", b"Set-MpPreference",
    b"\\Run", b"CurrentVersion\\Run", b"Startup", b"schtasks /create",
]


def sha256(b):  return hashlib.sha256(b).hexdigest()


def defang(s):
    """Defang a live indicator for the JSON (raw layers on disk stay intact)."""
    s = re.sub(r"(?i)^([a-z][a-z0-9+.\-]*)://", lambda m: m.group(1) + "[://]", s)
    s = s.replace("http", "hxxp")
    s = re.sub(r"\.(?=[a-z0-9])", "[.]", s, flags=re.I)
    return s


def is_textish(b):
    """Does this blob look like text (so we should recurse) vs binary?"""
    if not b:
        return False
    if b[:2] == b"MZ" or b[:4] == b"PK\x03\x04" or b[:2] == b"\x1f\x8b":
        return False
    sample = b[:4096]
    printable = sum(1 for c in sample if 9 <= c <= 13 or 32 <= c <= 126 or c == 0)
    return printable / len(sample) > 0.85


def to_text(b):
    """Best-effort decode of a text-ish blob (handles UTF-16LE, the PS favourite)."""
    if b.count(b"\x00") > len(b) // 4:           # lots of nulls → likely UTF-16
        try:
            return b.decode("utf-16-le", "replace")
        except Exception:
            pass
    return b.decode("utf-8", "replace")


def maybe_decompress(b):
    """If the blob is gzip/zlib/raw-deflate, return the inflated bytes, else None."""
    if b[:2] == b"\x1f\x8b":
        try:    return gzip.decompress(b)
        except Exception: pass
    for wbits in (15, -15, 47):
        try:
            out = zlib.decompress(b, wbits)
            if out:
                return out
        except Exception:
            continue
    return None


# ── extractors: each yields (technique, decoded_bytes) candidates from a text ─
def ex_b64(text):
    out = []
    # explicit -EncodedCommand / FromBase64String args first (UTF-16 hint)
    for m in re.finditer(r"(?:-e(?:nc(?:odedcommand)?)?|FromBase64String)\s*[\(\s'\"]+"
                         r"([A-Za-z0-9+/=]{%d,})" % MIN_B64, text, re.I):
        out.append(("base64(encodedcommand)", m.group(1)))
    for m in re.finditer(r"[A-Za-z0-9+/]{%d,}={0,2}" % MIN_B64, text):
        out.append(("base64", m.group(0)))
    res = []
    for tech, s in out:
        try:
            dec = base64.b64decode(s + "=" * (-len(s) % 4), validate=False)
            if dec:
                res.append((tech, dec))
        except (binascii.Error, ValueError):
            continue
    return res


def ex_hex(text):
    res = []
    for m in re.finditer(r"(?:0x|\\x|%)?([0-9a-fA-F]{2})(?:[,\s]|0x|\\x|%){0,2}", text):
        pass  # placeholder; real runs handled below
    # \xNN or 0xNN runs
    for m in re.finditer(r"(?:(?:\\x|0x|%)[0-9a-fA-F]{2}){8,}", text):
        hx = re.findall(r"[0-9a-fA-F]{2}", m.group(0))
        try:    res.append(("hex(escaped)", bytes(int(h, 16) for h in hx)))
        except Exception: pass
    # long plain hex runs (even length)
    for m in re.finditer(r"\b[0-9a-fA-F]{32,}\b", text):
        s = m.group(0)
        if len(s) % 2 == 0:
            try:    res.append(("hex", binascii.unhexlify(s)))
            except Exception: pass
    return res


def ex_charcode(text):
    res = []
    # String.fromCharCode(72,73,...) / [char[]] (72,73) / Chr(72)&Chr(73)
    for m in re.finditer(r"(?:fromCharCode|char\[\]|chr)\s*[\(\s]*((?:\s*\d{1,7}\s*[,)&+]?){4,})",
                         text, re.I):
        nums = re.findall(r"\d{1,7}", m.group(1))
        try:
            res.append(("charcode", bytes(n & 0xFF for n in map(int, nums))))
        except Exception:
            pass
    return res


def ex_percent(text):
    res = []
    for m in re.finditer(r"(?:%[0-9a-fA-F]{2}){6,}", text):
        hx = re.findall(r"%([0-9a-fA-F]{2})", m.group(0))
        try:    res.append(("percent-escape", bytes(int(h, 16) for h in hx)))
        except Exception: pass
    return res


EXTRACTORS = [ex_b64, ex_hex, ex_charcode, ex_percent]


def extract_iocs(b):
    def grab(rx):
        seen, out = set(), []
        for m in rx.findall(b):
            v = m.decode("latin-1", "replace")
            if v not in seen:
                seen.add(v); out.append(v)
            if len(out) >= MAX_IOCS:
                break
        return out
    urls = grab(URL_RE)
    ips  = [ip for ip in grab(IP_RE)
            if all(0 <= int(o) <= 255 for o in ip.split(".")) and not ip.startswith(
                ("0.", "127.", "255.", "10.", "192.168."))]
    return {
        "urls":    [defang(u) for u in urls],
        "ips":     [defang(i) for i in ips],
        "domains": [defang(d) for d in grab(DOMAIN_RE)],
        "unc_paths": grab(UNC_RE),
        "registry":  grab(REG_RE),
    }


def find_suspicious(b):
    low = b.lower()
    return sorted({t.decode().strip() for t in SUSPICIOUS if t.lower() in low})


def scan(sample, report_dir):
    layers_dir = os.path.join(report_dir, "script_layers")
    with open(sample, "rb") as f:
        raw = f.read()

    result = {
        "sample": os.path.basename(sample),
        "size_bytes": len(raw),
        "layers": [],
        "carved_files": [],
        "iocs": {"urls": [], "ips": [], "domains": [], "unc_paths": [], "registry": []},
        "suspicious_tokens": [],
        "max_depth_reached": 0,
        "notes": [],
    }

    seen_hashes = set()
    agg = {k: [] for k in result["iocs"]}
    agg_susp = set()
    layer_no = 0
    carve_no = 0
    truncated = False

    # worklist of (text, depth, origin)
    work = [(to_text(raw), 0, "source")]
    while work:
        if layer_no >= MAX_LAYERS:
            truncated = True
            break
        text, depth, origin = work.pop(0)
        result["max_depth_reached"] = max(result["max_depth_reached"], depth)

        for extractor in EXTRACTORS:
            try:
                candidates = extractor(text)
            except Exception:
                continue
            for tech, dec in candidates:
                if not dec or len(dec) > MAX_BLOB:
                    continue
                # inflate if compressed (record as part of the same layer technique)
                inflated = maybe_decompress(dec)
                if inflated and len(inflated) <= MAX_BLOB:
                    dec, tech = inflated, tech + "+inflate"
                h = sha256(dec)
                if h in seen_hashes:
                    continue
                seen_hashes.add(h)
                if layer_no >= MAX_LAYERS:
                    truncated = True
                    break

                textish = is_textish(dec)
                # write the raw layer to disk for mining (undefanged, isolated dir)
                os.makedirs(layers_dir, exist_ok=True)
                ext = "txt" if textish else "bin"
                fname = f"layer{layer_no:02d}_{tech.split('(')[0].split('+')[0]}.{ext}"
                with open(os.path.join(layers_dir, fname), "wb") as lf:
                    lf.write(dec)

                iocs = extract_iocs(dec)
                susp = find_suspicious(dec)
                for k in agg:
                    agg[k].extend(iocs[k])
                agg_susp.update(susp)

                # carve embedded executables / archives
                carved = None
                if dec[:2] == b"MZ" or dec[:4] == b"PK\x03\x04":
                    kind = "PE" if dec[:2] == b"MZ" else "ZIP/OOXML"
                    cname = f"carved{carve_no:02d}_{kind.split('/')[0].lower()}.bin"
                    with open(os.path.join(layers_dir, cname), "wb") as cf:
                        cf.write(dec)
                    carved = {"file": os.path.join("script_layers", cname),
                              "kind": kind, "sha256": h, "size_bytes": len(dec)}
                    result["carved_files"].append(carved)
                    carve_no += 1

                result["layers"].append({
                    "index": layer_no,
                    "depth": depth,
                    "technique": tech,
                    "from": origin,
                    "size_bytes": len(dec),
                    "sha256": h,
                    "textish": textish,
                    "file": os.path.join("script_layers", fname),
                    "iocs": iocs,
                    "suspicious_tokens": susp,
                    "carved": carved,
                })
                layer_no += 1

                # recurse only into further text-ish layers, within depth cap
                if textish and depth + 1 < MAX_DEPTH:
                    work.append((to_text(dec), depth + 1, f"layer{layer_no - 1}"))
            if truncated:
                break

    # top-level IOCs/tokens from the source itself
    src_iocs = extract_iocs(raw)
    for k in agg:
        agg[k] = src_iocs[k] + agg[k]
    agg_susp.update(find_suspicious(raw))

    # dedup aggregates preserving order
    for k in result["iocs"]:
        seen, out = set(), []
        for v in agg[k]:
            if v not in seen:
                seen.add(v); out.append(v)
        result["iocs"][k] = out[:MAX_IOCS]
    result["suspicious_tokens"] = sorted(agg_susp)

    if truncated:
        result["notes"].append(
            f"CAP REACHED: stopped at {MAX_LAYERS} layers / depth {MAX_DEPTH} — "
            "deeper nesting not fully unrolled (raw source retained for manual review).")
    if not result["layers"]:
        result["notes"].append(
            "No decodable obfuscation layers found — script may be plaintext, use a "
            "custom/unsupported encoding, or be benign. Review strings.txt + source.")
    if result["carved_files"]:
        result["notes"].append(
            f"{len(result['carved_files'])} embedded executable/archive(s) carved from "
            "script layers — treat as child samples (re-triage).")
    result["notes"].append(
        "EMBEDDED indicators only — promote any C2/URL to High *intent*, not "
        "confirmed-live (only a sandbox/VT-behaviour confirms execution).")
    return result


def main():
    if len(sys.argv) < 3:
        print("Usage: scriptscan.py <sample> <report_dir>", file=sys.stderr)
        sys.exit(1)
    sample, rd = sys.argv[1], sys.argv[2]
    try:
        result = scan(sample, rd)
    except Exception as e:
        result = {"sample": os.path.basename(sample),
                  "error": f"{type(e).__name__}: {e}"}
    with open(os.path.join(rd, "scriptscan.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    n_layers = len(result.get("layers", []))
    n_carved = len(result.get("carved_files", []))
    print(f"    scriptscan -> scriptscan.json ({n_layers} layer(s) decoded"
          + (f", {n_carved} carved" if n_carved else "") + ")")


if __name__ == "__main__":
    main()
