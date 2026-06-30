#!/usr/bin/env python3
"""
htmlsmuggle.py — Sharingan HTML / SVG smuggling extraction stage.

HTML smuggling delivers a payload as an encoded blob *inside* an HTML or SVG file
that reassembles client-side (atob → Uint8Array → Blob → an <a download> that
auto-clicks), so it sails past content filters and the MOTW. SVG is now used the
same way via an embedded <script>. To a strings/YARA pass these look like inert
markup, so this stage: (1) fingerprints the smuggling primitives, (2) decodes the
embedded data: URIs / atob() / base64 blobs (inflating gzip/deflate), and (3)
identifies + carves any executable/archive/document payload it reconstructs.

Recovers EMBEDDED indicators (intent) — promote a recovered payload/URL to High
*intent*, not "confirmed live". Shares the decode/IOC/defang core with scriptscan.

Design (per the gating & speed rubric): CHEAP, auto-on-match, stdlib only, bounded.
Safe handling (per CLAUDE.md): IOCs in the JSON are DEFANGED; decoded blobs are
written raw to <report_dir>/html_payloads/ for mining, never echoed.

Usage:  htmlsmuggle.py <sample> <report_dir>
Emits:  <report_dir>/htmlsmuggle.json (+ html_payloads/ for decoded/carved blobs)
Stdlib only. Never raises into the pipeline — failures captured in the JSON.
"""
import sys, os, re, json, base64, binascii

# reuse the verified decode/IOC/defang core from the script stage
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from scriptscan import (defang, extract_iocs, is_textish, maybe_decompress,
                            sha256, EXTRACTORS, MAX_BLOB)
except Exception:                                    # pragma: no cover
    EXTRACTORS, MAX_BLOB = [], 8 << 20
    import hashlib
    def sha256(b): return hashlib.sha256(b).hexdigest()
    def defang(s): return s.replace("http", "hxxp").replace(".", "[.]")
    def extract_iocs(b): return {"urls": [], "ips": [], "domains": [],
                                 "unc_paths": [], "registry": []}
    def is_textish(b): return False
    def maybe_decompress(b): return None

# Smuggling primitives — the client-side reassembly fingerprint.
SMUGGLE_PRIMS = [
    "atob", "Blob", "msSaveOrOpenBlob", "msSaveBlob", "createObjectURL",
    "URL.createObjectURL", "navigator.msSaveBlob", "Uint8Array", "charCodeAt",
    "fromCharCode", "decodeURIComponent", "unescape", "createElement",
    "download", ".click(", "base64", "ActiveXObject", "WScript.Shell",
    "document.write", "eval(", "window.location", "FileReader",
]


def identify_bytes(b):
    """Magic-sniff a decoded blob so we can flag/carve a reconstructed payload."""
    if b[:2] == b"MZ":                                   return "PE"
    if b[:4] == b"PK\x03\x04":                           return "ZIP/OOXML/JAR/APK"
    if b[:4] == b"%PDF":                                 return "PDF"
    if b[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":     return "OLE/Office/MSI"
    if b[:4] == b"\x7fELF":                              return "ELF"
    if b[:4] == b"Rar!":                                 return "RAR"
    if b[:6] == b"7z\xbc\xaf\x27\x1c":                   return "7Z"
    if b[:4] == b"\x4c\x00\x00\x00":                     return "LNK"
    if b[:2] == b"\x1f\x8b":                             return "GZIP"
    if b[32769:32774] == b"CD001" or b[:5] == b"CD001": return "ISO"
    return None


def html_b64_blobs(text):
    """HTML-specific base64 sources where the blob may span newlines/whitespace:
    data: URIs, atob('...') args, and very long quoted string literals."""
    out = []
    for m in re.finditer(r"data:[\w.+/\-]*;base64,([A-Za-z0-9+/=\s]{40,})", text, re.I):
        out.append(("data-uri", m.group(1)))
    for m in re.finditer(r"atob\(\s*[`'\"]([A-Za-z0-9+/=\s]{40,})[`'\"]", text, re.I):
        out.append(("atob", m.group(1)))
    for m in re.finditer(r"[`'\"]([A-Za-z0-9+/=]{200,})[`'\"]", text):
        out.append(("js-string-literal", m.group(1)))
    res = []
    for tech, s in out:
        s = re.sub(r"\s+", "", s)
        try:
            dec = base64.b64decode(s + "=" * (-len(s) % 4), validate=False)
            if dec:
                res.append((tech, dec))
        except (binascii.Error, ValueError):
            continue
    return res


def scan(sample, report_dir):
    pay_dir = os.path.join(report_dir, "html_payloads")
    with open(sample, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8", "replace")
    low = text.lower()
    is_svg = "<svg" in low

    result = {
        "sample": os.path.basename(sample),
        "subtype": "svg" if is_svg else "html",
        "size_bytes": len(raw),
        "smuggling_indicators": [],
        "smuggling_suspected": False,
        "embedded_scripts": low.count("<script"),
        "decoded_blobs": [],
        "carved_files": [],
        "iocs": {"urls": [], "ips": [], "domains": [], "unc_paths": [], "registry": []},
        "notes": [],
    }

    # 1) fingerprint the reassembly primitives
    prims = [p for p in SMUGGLE_PRIMS if p.lower() in low]
    result["smuggling_indicators"] = prims
    has_download = "download" in low and (".click(" in low or "createelement" in low)
    has_reassembly = any(p in low for p in
                         ("atob", "blob", "createobjecturl", "mssaveblob", "uint8array"))

    # 2) decode candidate blobs (HTML-specific first, then the generic extractors)
    candidates = html_b64_blobs(text)
    for extractor in EXTRACTORS:
        try:
            candidates += extractor(text)
        except Exception:
            continue

    seen = set()
    blob_no = carve_no = 0
    src_iocs = extract_iocs(raw)
    for k in result["iocs"]:
        result["iocs"][k] = list(src_iocs[k])

    for tech, dec in candidates:
        if not dec or len(dec) > MAX_BLOB:
            continue
        inflated = maybe_decompress(dec)
        if inflated and len(inflated) <= MAX_BLOB:
            dec, tech = inflated, tech + "+inflate"
        h = sha256(dec)
        if h in seen:
            continue
        seen.add(h)

        os.makedirs(pay_dir, exist_ok=True)
        kind = identify_bytes(dec)
        ext = "txt" if (kind is None and is_textish(dec)) else "bin"
        fname = f"blob{blob_no:02d}_{tech.split('(')[0].split('+')[0]}.{ext}"
        with open(os.path.join(pay_dir, fname), "wb") as bf:
            bf.write(dec)

        iocs = extract_iocs(dec)
        for k in result["iocs"]:
            result["iocs"][k].extend(iocs[k])

        carved = None
        if kind and kind not in ("GZIP",):
            cname = f"carved{carve_no:02d}_{kind.split('/')[0].lower()}.bin"
            with open(os.path.join(pay_dir, cname), "wb") as cf:
                cf.write(dec)
            carved = {"file": os.path.join("html_payloads", cname), "kind": kind,
                      "sha256": h, "size_bytes": len(dec)}
            result["carved_files"].append(carved)
            carve_no += 1

        result["decoded_blobs"].append({
            "index": blob_no, "technique": tech, "size_bytes": len(dec),
            "sha256": h, "identified_as": kind,
            "file": os.path.join("html_payloads", fname),
            "iocs": iocs, "carved": carved,
        })
        blob_no += 1

    # drop standard XML/markup namespace hosts (noise on every SVG/XHTML),
    # then dedup preserving order
    benign = ("w3.org", "w3[.]org", "openxmlformats.org", "openxmlformats[.]org",
              "schemas.microsoft.com", "schemas[.]microsoft[.]com",
              "purl.org", "purl[.]org", "xml.org", "xml[.]org")
    for k in ("urls", "domains"):
        result["iocs"][k] = [v for v in result["iocs"][k]
                             if not any(b in v for b in benign)]
    for k in result["iocs"]:
        s, o = set(), []
        for v in result["iocs"][k]:
            if v not in s:
                s.add(v); o.append(v)
        result["iocs"][k] = o[:300]

    # 3) verdict
    reconstructed_payload = any(c["kind"] in ("PE", "ZIP/OOXML/JAR/APK", "PDF",
                                "OLE/Office/MSI", "ELF", "LNK", "RAR", "7Z", "ISO")
                                for c in result["carved_files"])
    result["smuggling_suspected"] = bool(
        reconstructed_payload or (has_reassembly and has_download))

    if result["smuggling_suspected"]:
        result["notes"].append(
            "HTML/SVG SMUGGLING SUSPECTED: client-side reassembly primitives "
            + ("+ a reconstructed " + ", ".join(sorted({c["kind"] for c in result["carved_files"]}))
               + " payload " if reconstructed_payload else "+ auto-download ")
            + "present. Treat carved payload(s) as child samples (re-triage).")
    if is_svg and result["embedded_scripts"]:
        result["notes"].append(
            f"SVG carries {result['embedded_scripts']} embedded <script> block(s) — "
            "active content in an image container (SVG smuggling / XSS vector).")
    if not result["decoded_blobs"] and not prims:
        result["notes"].append(
            "No smuggling primitives or decodable blobs found — may be a benign page. "
            "Review strings.txt + source.")
    result["notes"].append(
        "EMBEDDED indicators only — promote recovered payloads/URLs to High *intent*, "
        "not confirmed-live (a sandbox/VT-behaviour confirms execution).")
    return result


def main():
    if len(sys.argv) < 3:
        print("Usage: htmlsmuggle.py <sample> <report_dir>", file=sys.stderr)
        sys.exit(1)
    sample, rd = sys.argv[1], sys.argv[2]
    try:
        result = scan(sample, rd)
    except Exception as e:
        result = {"sample": os.path.basename(sample),
                  "error": f"{type(e).__name__}: {e}"}
    with open(os.path.join(rd, "htmlsmuggle.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    n_blob = len(result.get("decoded_blobs", []))
    n_carve = len(result.get("carved_files", []))
    flag = " SMUGGLING SUSPECTED" if result.get("smuggling_suspected") else ""
    print(f"    htmlsmuggle -> htmlsmuggle.json ({n_blob} blob(s) decoded"
          + (f", {n_carve} payload(s) carved" if n_carve else "") + flag + ")")


if __name__ == "__main__":
    main()
