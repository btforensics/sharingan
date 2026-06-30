#!/usr/bin/env python3
"""
nonpe.py — Sharingan non-PE analysis handlers.

Dispatched by triage.sh for samples that aren't PE/.NET/ELF. One handler per
category; each writes its own artifact(s) into the report dir and never lets a
failure kill the others (a missing tool is captured as a note, not a crash).

  office_ole / office_ooxml → olevba.json (macros/IOCs) + oleid.txt
  pdf                       → pdfid.txt (+ pdfparser.txt if available)
  lnk                       → lnk.json (target, args, working dir)
  archive                   → archive.json (listing + per-entry identify)
  email                     → email.json (headers, urls, attachments)
  script                    → scriptscan.json (recursive deobfuscation + IOCs)
  unknown                   → handled via the universal strings stage

Run under the project venv (tools/venv) so LnkParse3 / extract_msg import;
olevba / oleid / pdfid are invoked as subprocesses by path (env) or PATH.

Usage:  nonpe.py <sample> <category> <report_dir>
Env:    OLEVBA, OLEID, IDENTIFY, VENV_PY (all optional; sensible fallbacks)
"""
import json, os, re, sys, subprocess

URL_RE = re.compile(r"https?://[^\s\"'<>)\]}]+", re.I)
IP_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


_VENV_BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "venv", "bin")


def tool(envvar, default):
    """Resolve an external tool, in order of preference:
      1) explicit path in <envvar> (triage.sh injects these from config.env);
      2) the project venv (self-located relative to this file) — so a hand-run
         `nonpe.py <doc> office_ole <rd>` finds olevba/oleid/pdfid even when the
         env vars aren't set (the footgun that made macro analysis silently skip);
      3) bare name on PATH.
    """
    p = os.environ.get(envvar, "")
    if p and os.path.exists(p):
        return p
    cand = os.path.join(_VENV_BIN, default)
    if os.path.exists(cand):
        return cand
    return default


def run(cmd, timeout=120):
    try:
        # stdin=DEVNULL so password-prompting tools (7z) fail fast instead of hanging
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", f"not found: {cmd[0]}"
    except Exception as e:
        return 1, "", f"{type(e).__name__}: {e}"


def write(rd, name, content):
    with open(os.path.join(rd, name), "w", encoding="utf-8", errors="replace") as f:
        f.write(content)


# ── Office (legacy OLE + OOXML) ──────────────────────────────────────────
def handle_office(sample, rd):
    olevba = tool("OLEVBA", "olevba")
    rc, out, err = run([olevba, "--json", sample])
    if rc == 0 and out.strip():
        try:
            json.dump(json.loads(out),
                      open(os.path.join(rd, "olevba.json"), "w"), indent=2)
            print("    olevba -> olevba.json")
        except Exception:
            write(rd, "olevba.json", json.dumps({"raw": out}))
    else:
        write(rd, "olevba.json",
              json.dumps({"error": err or "olevba produced no output "
                          "(install via tools/setup-env.sh)"}))
        print("    olevba unavailable/failed — captured as note")
    oleid = tool("OLEID", "oleid")
    rc, out, err = run([oleid, sample])
    write(rd, "oleid.txt", out or (err or "oleid unavailable"))


# ── PDF ──────────────────────────────────────────────────────────────────
def handle_pdf(sample, rd):
    rc, out, err = run(["pdfid", sample])
    write(rd, "pdfid.txt", out or (err or "pdfid unavailable"))
    print("    pdfid -> pdfid.txt")
    # pdf-parser is optional (not always installed)
    for cand in ("pdf-parser", "pdf-parser.py"):
        rc, out, err = run([cand, "-a", sample])
        if rc == 0 and out.strip():
            write(rd, "pdfparser.txt", out)
            print("    pdf-parser -> pdfparser.txt")
            break


# ── LNK ───────────────────────────────────────────────────────────────────
def handle_lnk(sample, rd):
    try:
        import LnkParse3
        with open(sample, "rb") as f:
            lnk = LnkParse3.lnk_file(f)
        data = lnk.get_json()
        # surface the operative fields up top for the analyst
        data["_sharingan_summary"] = {
            k: data.get("data", {}).get(k)
            for k in ("command_line_arguments", "relative_path",
                      "working_directory", "icon_location")
        }
        json.dump(data, open(os.path.join(rd, "lnk.json"), "w"),
                  indent=2, default=str)
        print("    LnkParse3 -> lnk.json")
    except Exception as e:
        write(rd, "lnk.json", json.dumps(
            {"error": f"{type(e).__name__}: {e} "
             "(LnkParse3 missing? run tools/setup-env.sh)"}))
        print("    LNK parse failed — captured as note")


# ── Archive ───────────────────────────────────────────────────────────────
# Default passwords commonly used for malware-sample archives. The analyst can
# override/extend via SHARINGAN_ARCHIVE_PWD (tried first); if everything fails
# the handler reports password_required and the skill asks the user.
DEFAULT_ARCHIVE_PWDS = ["virus", "infected", "N0virus", "novirus"]

# Gating rubric — bound a carve/extract stage so a hostile container (zip bomb,
# deeply-nested or ISO/IMG with thousands of files) can't blow up disk or time:
MAX_ARCHIVE_ENTRIES = 500          # children recorded/identified
MAX_ARCHIVE_TOTAL   = 2 << 30      # 2 GB total extracted-size guard
# Depth is bounded by design: nested archives among the children are IDENTIFIED
# but not auto-extracted (no recursive descent), so depth never exceeds 1.


def _looks_encrypted(text):
    t = (text or "").lower()
    return "wrong password" in t or "encrypted" in t or "can not open encrypted" in t


def _7z_extract(sample, extract_dir, pwd):
    cmd = ["7z", "x", "-y", f"-o{extract_dir}"]
    if pwd is not None:
        cmd.append(f"-p{pwd}")          # -p<pwd>; omitted entirely for the no-password try
    cmd.append(sample)
    return run(cmd, timeout=180)


def handle_archive(sample, rd):
    rc, listing, lerr = run(["7z", "l", sample])
    result = {"listing_raw": listing, "encrypted": False, "password_used": None,
              "password_required": False, "passwords_tried": [], "extracted": [],
              "entries_truncated": False, "total_extracted_bytes": 0,
              "nested_archives": [], "notes": []}
    extract_dir = os.path.join(rd, "extracted")
    os.makedirs(extract_dir, exist_ok=True)

    # candidate order: analyst-supplied (env) → no-password → defaults
    explicit = os.environ.get("SHARINGAN_ARCHIVE_PWD")
    candidates = ([explicit] if explicit else []) + [None] + DEFAULT_ARCHIVE_PWDS

    success = False
    for pwd in candidates:
        rc, out, err = _7z_extract(sample, extract_dir, pwd)
        if rc == 0:
            success = True
            result["password_used"] = pwd
            result["encrypted"] = pwd is not None
            break
        if pwd is not None:
            result["passwords_tried"].append(pwd)
        if _looks_encrypted(err) or _looks_encrypted(out) or _looks_encrypted(listing):
            result["encrypted"] = True

    if not success:
        if result["encrypted"]:
            result["password_required"] = True
            result["extract_status"] = (
                "PASSWORD-PROTECTED — default passwords failed "
                "(virus / infected / N0virus / novirus). Provide the password.")
            print("    archive is PASSWORD-PROTECTED — defaults failed; password required")
        else:
            result["extract_status"] = lerr or "extract failed (not password-related)"
            print("    archive extract failed — see archive.json")
        json.dump(result, open(os.path.join(rd, "archive.json"), "w"), indent=2)
        return

    result["extract_status"] = "ok"
    identify = tool("IDENTIFY", os.path.join(os.path.dirname(__file__), "identify.py"))
    count = 0
    for root, _, files in os.walk(extract_dir):
        for fn in files:
            fp = os.path.join(root, fn)
            try:
                result["total_extracted_bytes"] += os.path.getsize(fp)
            except OSError:
                pass
            if count >= MAX_ARCHIVE_ENTRIES:
                result["entries_truncated"] = True
                continue
            rc, out, err = run([sys.executable, identify, fp])
            try:
                info = json.loads(out)
            except Exception:
                info = {"filename": fn, "category": "unknown"}
            entry = {
                "path": os.path.relpath(fp, rd),
                "category": info.get("category"),
                "subtype": info.get("subtype"),
                "size_bytes": info.get("size_bytes"),
                "extension_mismatch": info.get("extension_mismatch"),
            }
            result["extracted"].append(entry)
            # depth cap: a nested archive is flagged, not auto-extracted
            if info.get("category") == "archive":
                result["nested_archives"].append(entry["path"])
            count += 1

    if result["entries_truncated"]:
        result["notes"].append(
            f"ENTRY CAP: container holds >{MAX_ARCHIVE_ENTRIES} files — only the first "
            f"{MAX_ARCHIVE_ENTRIES} were identified (gating cap). Inspect extracted/ manually.")
    if result["total_extracted_bytes"] > MAX_ARCHIVE_TOTAL:
        result["notes"].append(
            f"SIZE GUARD: extracted {result['total_extracted_bytes'] >> 20} MB "
            f"(> {MAX_ARCHIVE_TOTAL >> 20} MB) — possible decompression bomb; verify disk use.")
    if result["nested_archives"]:
        result["notes"].append(
            f"{len(result['nested_archives'])} nested archive(s) identified but NOT "
            "auto-extracted (depth cap = 1) — re-run triage.sh on each if relevant.")
    json.dump(result, open(os.path.join(rd, "archive.json"), "w"), indent=2)
    pw = result["password_used"]
    print(f"    archive -> archive.json ({len(result['extracted'])} entries"
          + (f", password='{pw}'" if pw else "")
          + (", TRUNCATED" if result["entries_truncated"] else "") + ")")


# ── Script (PowerShell / JS / VBS / HTA / BAT / WSF / shell) ───────────────
def handle_script(sample, rd):
    """Recursive deobfuscation: peel base64/hex/charcode/%-escape/gzip layers and
    re-extract IOCs from each. Delegates to the stdlib-only scriptscan.py."""
    scriptscan = tool("SCRIPTSCAN",
                      os.path.join(os.path.dirname(__file__), "scriptscan.py"))
    rc, out, err = run([sys.executable, scriptscan, sample, rd], timeout=180)
    if out.strip():
        print("    " + out.strip().splitlines()[-1].strip())
    if rc != 0 and not os.path.exists(os.path.join(rd, "scriptscan.json")):
        write(rd, "scriptscan.json", json.dumps(
            {"error": err or "scriptscan failed", "sample": os.path.basename(sample)}))
        print("    scriptscan failed — captured as note")


# ── HTML / SVG (smuggling) ─────────────────────────────────────────────────
def handle_html(sample, rd):
    """Extract HTML/SVG-smuggled payloads: fingerprint client-side reassembly
    primitives, decode embedded data:/atob/base64 blobs, carve the payload.
    Delegates to the stdlib-only htmlsmuggle.py."""
    hs = tool("HTMLSMUGGLE",
              os.path.join(os.path.dirname(__file__), "htmlsmuggle.py"))
    rc, out, err = run([sys.executable, hs, sample, rd], timeout=180)
    if out.strip():
        print("    " + out.strip().splitlines()[-1].strip())
    if rc != 0 and not os.path.exists(os.path.join(rd, "htmlsmuggle.json")):
        write(rd, "htmlsmuggle.json", json.dumps(
            {"error": err or "htmlsmuggle failed", "sample": os.path.basename(sample)}))
        print("    htmlsmuggle failed — captured as note")


# ── Email (.eml / .msg) ────────────────────────────────────────────────────
def handle_email(sample, rd):
    out = {"headers": {}, "urls": [], "attachments": []}
    try:
        if sample.lower().endswith(".msg"):
            import extract_msg
            m = extract_msg.Message(sample)
            out["headers"] = {"from": m.sender, "to": m.to,
                              "subject": m.subject, "date": str(m.date)}
            body = m.body or ""
            out["attachments"] = [a.longFilename or a.shortFilename
                                  for a in m.attachments]
        else:
            import email
            from email import policy
            msg = email.message_from_binary_file(open(sample, "rb"),
                                                 policy=policy.default)
            out["headers"] = {h: msg.get(h) for h in
                              ("From", "To", "Subject", "Date", "Reply-To",
                               "Return-Path", "Received")}
            body = ""
            for part in msg.walk():
                ct = part.get_content_type()
                disp = part.get_content_disposition()
                if disp == "attachment":
                    out["attachments"].append(part.get_filename())
                elif ct in ("text/plain", "text/html"):
                    try:
                        body += part.get_content()
                    except Exception:
                        pass
        out["urls"] = sorted(set(URL_RE.findall(body)))[:50]
        json.dump(out, open(os.path.join(rd, "email.json"), "w"),
                  indent=2, default=str)
        print(f"    email -> email.json ({len(out['attachments'])} attachments, "
              f"{len(out['urls'])} urls)")
    except Exception as e:
        write(rd, "email.json", json.dumps(
            {"error": f"{type(e).__name__}: {e} "
             "(extract_msg missing? run tools/setup-env.sh)"}))
        print("    email parse failed — captured as note")


HANDLERS = {
    "office_ole": handle_office, "office_ooxml": handle_office,
    "pdf": handle_pdf, "lnk": handle_lnk,
    "archive": handle_archive, "email": handle_email,
    "script": handle_script, "html": handle_html,
}


def main():
    if len(sys.argv) < 4:
        print("Usage: nonpe.py <sample> <category> <report_dir>", file=sys.stderr)
        sys.exit(1)
    sample, category, rd = sys.argv[1], sys.argv[2], sys.argv[3]
    h = HANDLERS.get(category)
    if not h:
        print(f"    no dedicated handler for '{category}' "
              "(universal strings/YARA stages still apply)")
        return
    try:
        h(sample, rd)
    except Exception as e:
        write(rd, f"{category}_error.txt", f"{type(e).__name__}: {e}")
        print(f"    {category} handler error captured: {e}")


if __name__ == "__main__":
    main()
