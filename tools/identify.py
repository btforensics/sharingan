#!/usr/bin/env python3
"""
identify.py — Sharingan file-type front door.

Classify ANY sample (PE / .NET / ELF / Office / PDF / LNK / script / archive /
email / shellcode / unknown) so triage.sh can route it to the right analysis
stages. Detection blends magic bytes, the `file` command, structural peeks
(pefile / olefile / zipfile) and the filename extension — and flags when the
content disagrees with the extension (a classic masquerade signal).

Usage:  python3 identify.py <sample> [out.json]
Emits fileinfo.json (or prints to stdout if no out path given). Never raises into
the pipeline: any failure is captured in the JSON, not thrown.

Stdlib only, plus optional pefile/olefile (already present in the Sharingan env).
Self-contained — takes the sample path as an argument, holds no project paths.
"""
import sys, os, json, struct, subprocess

# ── extension → expected category (for masquerade detection) ──────────────
EXT_CATEGORY = {
    ".exe": "pe", ".dll": "pe", ".sys": "pe", ".scr": "pe", ".ocx": "pe", ".cpl": "pe",
    ".elf": "elf", ".so": "elf", ".o": "elf",
    ".doc": "office_ole", ".xls": "office_ole", ".ppt": "office_ole", ".msi": "office_ole",
    ".docx": "office_ooxml", ".docm": "office_ooxml", ".xlsx": "office_ooxml",
    ".xlsm": "office_ooxml", ".pptx": "office_ooxml", ".pptm": "office_ooxml",
    ".pdf": "pdf", ".lnk": "lnk",
    ".ps1": "script", ".psm1": "script", ".vbs": "script", ".vbe": "script",
    ".js": "script", ".jse": "script", ".hta": "script", ".wsf": "script",
    ".bat": "script", ".cmd": "script", ".sh": "script", ".py": "script", ".pl": "script",
    ".zip": "archive", ".rar": "archive", ".7z": "archive", ".gz": "archive",
    ".tar": "archive", ".cab": "archive", ".iso": "archive", ".img": "archive", ".jar": "archive",
    ".eml": "email", ".msg": "email",
}

SCRIPT_EXTS = {".ps1",".psm1",".vbs",".vbe",".js",".jse",".hta",".wsf",".bat",".cmd",".sh",".py",".pl"}

# ── analysis stages each category should trigger (consumed by triage.sh) ──
STAGES = {
    "pe":           ["die", "pestats", "floss", "capa", "yara"],
    "dotnet":       ["die", "pestats", "floss", "capa", "yara"],
    "elf":          ["die", "floss", "capa", "yara"],
    "office_ole":   ["olevba", "oleid", "yara"],
    "office_ooxml": ["olevba", "oleid", "yara"],
    "pdf":          ["pdfid", "pdfparser", "yara"],
    "lnk":          ["lnk", "yara"],
    "script":       ["scriptscan", "yara"],
    "archive":      ["archive", "yara"],
    "email":        ["email", "yara"],
    "shellcode":    ["capa", "yara"],
    "unknown":      ["yara"],
}


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:
        return ""


def sniff_ooxml(path):
    """A PK zip might be a real archive or an OOXML document / JAR / APK."""
    try:
        import zipfile
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
        if "[Content_Types].xml" in names:
            if any(n.startswith("word/") for n in names):       return "office_ooxml", "docx"
            if any(n.startswith("xl/") for n in names):         return "office_ooxml", "xlsx"
            if any(n.startswith("ppt/") for n in names):        return "office_ooxml", "pptx"
            return "office_ooxml", "ooxml"
        if "AndroidManifest.xml" in names:                      return "archive", "apk"
        if any(n.startswith("META-INF/") and n.endswith(".MF") for n in names):
            return "archive", "jar"
        return "archive", "zip"
    except Exception:
        return "archive", "zip"


def sniff_pe(path):
    """Distinguish exe vs dll vs sys, and flag .NET assemblies."""
    subtype, is_dotnet = "exe", False
    try:
        import pefile
        pe = pefile.PE(path, fast_load=True)
        ch = pe.FILE_HEADER.Characteristics
        if ch & 0x2000:
            subtype = "dll"
        if pe.OPTIONAL_HEADER.Subsystem == 1:   # native / driver
            subtype = "sys"
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']])
        com = getattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR", None) or \
              pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress
        if (isinstance(com, int) and com) or com:
            is_dotnet = True
        pe.close()
    except Exception:
        pass
    return ("dotnet" if is_dotnet else "pe"), ("dotnet" if is_dotnet else subtype)


def sniff_ole(path):
    """Legacy OLE compound: Word/Excel/PPT/MSI/MSG."""
    try:
        import olefile
        ole = olefile.OleFileIO(path)
        streams = ["/".join(s).lower() for s in ole.listdir()]
        ole.close()
        if any("worddocument" in s for s in streams):           return "office_ole", "doc"
        if any("workbook" in s or "book" in s for s in streams): return "office_ole", "xls"
        if any("powerpoint" in s for s in streams):             return "office_ole", "ppt"
        if any("__substg1.0" in s for s in streams):            return "email", "msg"
        return "office_ole", "ole"
    except Exception:
        return "office_ole", "ole"


def classify(path):
    with open(path, "rb") as f:
        head = f.read(16)
    magic_hex = head.hex()
    file_desc = run(["file", "-b", path])
    mime = run(["file", "-b", "--mime-type", path])
    ext = os.path.splitext(path)[1].lower()

    category, subtype = "unknown", None

    # ---- binary magic first (content beats extension) ----
    if head[:2] == b"MZ":
        category, subtype = sniff_pe(path)
    elif head[:4] == b"\x7fELF":
        category, subtype = "elf", "elf"
    elif head[:4] == b"%PDF":
        category, subtype = "pdf", "pdf"
    elif head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        category, subtype = sniff_ole(path)
    elif head[:4] == b"PK\x03\x04":
        category, subtype = sniff_ooxml(path)
    elif head[:4] == b"\x4c\x00\x00\x00":
        category, subtype = "lnk", "lnk"
    elif head[:4] == b"Rar!":
        category, subtype = "archive", "rar"
    elif head[:6] == b"7z\xbc\xaf\x27\x1c":
        category, subtype = "archive", "7z"
    elif head[:2] == b"\x1f\x8b":
        category, subtype = "archive", "gzip"
    elif head[:4] == b"MSCF":
        category, subtype = "archive", "cab"
    else:
        # ---- text / script: no binary magic ----
        try:
            with open(path, "rb") as f:
                blob = f.read(8192)
            is_text = b"\x00" not in blob
        except Exception:
            blob, is_text = b"", False
        low = blob.lower()
        if ext == ".eml" or low.startswith(b"received:") or low.startswith(b"from ") \
                or b"\nmime-version:" in low:
            category, subtype = "email", "eml"
        elif is_text and (ext in SCRIPT_EXTS or any(k in low for k in (
                b"powershell", b"function ", b"createobject", b"wscript",
                b"<script", b"#!/bin", b"import ", b"eval("))):
            category, subtype = "script", (ext.lstrip(".") or "script")
        elif is_text:
            category, subtype = "script", "text"
        # else: stays unknown (could be raw shellcode / data)

    expected = EXT_CATEGORY.get(ext)
    # treat dotnet/pe as the same family for mismatch purposes
    fam = {"dotnet": "pe"}.get(category, category)
    exp_fam = {"dotnet": "pe"}.get(expected, expected)
    mismatch = bool(expected) and exp_fam != fam

    notes = []
    if mismatch:
        notes.append(f"EXTENSION MISMATCH: '{ext}' implies {expected} but content is {category} "
                     f"— possible masquerade / disguised payload.")
    if category == "unknown":
        notes.append("Unrecognized container — may be raw shellcode, encrypted data, or an "
                     "unsupported format. Falls back to strings + YARA.")

    return {
        "filename": os.path.basename(path),
        "size_bytes": os.path.getsize(path),
        "category": category,
        "subtype": subtype,
        "mime": mime,
        "file_output": file_desc,
        "magic_hex": magic_hex,
        "extension": ext,
        "extension_mismatch": mismatch,
        "recommended_stages": STAGES.get(category, STAGES["unknown"]),
        "notes": " ".join(notes),
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: identify.py <sample> [out.json]", file=sys.stderr)
        sys.exit(1)
    path = sys.argv[1]
    try:
        result = classify(path)
    except Exception as e:
        result = {"filename": os.path.basename(path), "category": "unknown",
                  "error": f"{type(e).__name__}: {e}",
                  "recommended_stages": STAGES["unknown"]}
    out = json.dumps(result, indent=2)
    if len(sys.argv) >= 3:
        with open(sys.argv[2], "w", encoding="utf-8") as f:
            f.write(out + "\n")
        print(f"identify -> {sys.argv[2]} : {result.get('category')}/{result.get('subtype')}")
    else:
        print(out)


if __name__ == "__main__":
    main()
