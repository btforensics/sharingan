#!/usr/bin/env python3
"""Emulation-based unpacking for the Sharingan triage pipeline (roadmap N4).

The problem this attacks: on a packed/crypted PE, every static tool
(floss/capa/Ghidra/YARA) only ever sees the *loader stub*. The real payload —
C2, keys, capabilities — is produced at runtime by the stub decrypting/
decompressing an overlay or allocated buffer, so it is invisible statically and
every payload claim has to stay at "Investigate" until unpacked.

This stage emulates ONLY the loader stub in a controlled CPU emulator (Mandiant
Speakeasy — Windows-API emulation, no VM, no real OS, no network, no detonation),
lets the stub self-decrypt in emulated memory, then carves the recovered regions
out of memory so the binary stages can be re-run on the *real* body. It is the
sandbox-free arm of roadmap #4.

What it can and cannot do (kept honest, per CLAUDE.md):
  - WORKS when the stub is self-contained — it decrypts using its own embedded
    code + key in one process (classic packers: UPX, most in-place crypters).
    Verified: a UPX-packed PE decompresses its body into memory under emulation.
  - STALLS when the stub needs an API/syscall the emulator doesn't implement,
    guards decryption behind anti-emulation checks, injects into another process
    the emulator doesn't follow, or fetches the key/next-stage from C2. When that
    happens this stage records a GAP (status + instruction count + error) and
    carves whatever was decrypted before the stall — it never fabricates a payload.
    Those samples still need a real sandbox (roadmap #1).

It recovers EMBEDDED indicators (strings/imports/capabilities baked into the
payload). It does NOT confirm runtime *behaviour* (no packets sent, no files
really dropped) — only a sandbox does. So an unpack-recovered C2 is "embedded /
High", not "confirmed live".

Design mirrors the other stages: never raises into the pipeline (every failure is
captured in meta), self-locating (no hardcoded paths), prints one summary line,
and always writes unpacked.json so downstream knows the stage ran.

Re-analysis (floss/capa/yara on the carved body) is driven by triage.sh, which
reads meta.primary_region from unpacked.json. This tool only emulates + carves.

Usage:  unpack_emulate.py <sample> <out_dir> [fileinfo.json]
Env:    UNPACK_MAX_INSTRS   (default 20000000) instruction cap (anti-hang)
        UNPACK_TIMEOUT      (default 180)      wall-clock seconds cap (anti-hang)
        UNPACK_MIN_REGION   (default 1024)     skip carved regions smaller than this
        UNPACK_MAX_REGIONS  (default 24)       cap carved regions written
        UNPACK_MAX_READ     (default 16777216) cap bytes read per region (16 MiB)
"""
import hashlib
import json
import math
import os
import re
import sys
import time
from collections import Counter

MAX_INSTRS = int(os.environ.get("UNPACK_MAX_INSTRS", "20000000"))
TIMEOUT = float(os.environ.get("UNPACK_TIMEOUT", "180"))
MIN_REGION = int(os.environ.get("UNPACK_MIN_REGION", "1024"))
MAX_REGIONS = int(os.environ.get("UNPACK_MAX_REGIONS", "24"))
MAX_READ = int(os.environ.get("UNPACK_MAX_READ", str(16 * 1024 * 1024)))

# Emulator scaffolding the engine maps for the fake Windows environment — never
# the payload, so excluded from carving. emu.module.* (the loaded image, where
# in-place unpackers like UPX decrypt) and heap/alloc regions are KEPT.
SCAFFOLD_PREFIXES = (
    "emu.gdt", "emu.segment", "emu.struct", "emu.stack", "emu.tls",
    "emu.module_arg", "emu.peb", "emu.teb", "api.",
)

# match printable ASCII and UTF-16LE runs >= 6 chars (same floor as triage's strings -n 6)
_ASCII_RE = re.compile(rb"[\x20-\x7e]{6,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")


def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return round(-sum((v / n) * math.log2(v / n) for v in c.values()), 3)


def extract_strings(b):
    """ASCII + UTF-16LE printable runs (>=6), as a set of str for diffing."""
    out = set(m.group().decode("ascii", "ignore") for m in _ASCII_RE.finditer(b))
    out |= set(m.group().decode("utf-16le", "ignore") for m in _UTF16_RE.finditer(b))
    return out


def pe_view(b):
    """Return (has_mz, valid_pe) for a buffer that may start with a PE image."""
    if len(b) < 0x40 or b[:2] != b"MZ":
        return False, False
    e_lfanew = int.from_bytes(b[0x3C:0x40], "little")
    valid = (0 < e_lfanew < min(0x1000, len(b) - 4)
             and b[e_lfanew:e_lfanew + 4] == b"PE\x00\x00")
    return True, valid


def write_stub(out_path, out):
    """Persist unpacked.json and print the one-line summary. Always called."""
    try:
        json.dump(out, open(out_path, "w"), indent=2)
    except Exception as e:  # last-resort: never raise into the pipeline
        sys.stderr.write(f"unpack: failed to write {out_path}: {e}\n")


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: unpack_emulate.py <sample> <out_dir> [fileinfo.json]")
    sample, out_dir = sys.argv[1], sys.argv[2]
    fileinfo = sys.argv[3] if len(sys.argv) > 3 else None
    out_json = os.path.join(out_dir, "unpacked.json")

    out = {
        "meta": {
            "stage": "emulation-unpack (N4)",
            "emulator": "speakeasy",
            "instruction_cap": MAX_INSTRS,
            "wall_timeout_s": TIMEOUT,
            "status": None,
            "note": (
                "Emulates the loader stub in Speakeasy (no VM/detonation/network) and "
                "carves regions decrypted in memory. Recovers EMBEDDED indicators only — "
                "it does NOT confirm runtime behaviour (use a sandbox for that). A low "
                "instruction count with status 'stalled'/'load_failed' is a GAP (stub "
                "bailed early — e.g. unsupported API or anti-emulation), NOT proof the "
                "sample is unpacked or benign. Carved regions are raw MEMORY IMAGES "
                "(not file-aligned PEs): strings/floss/yara read them cleanly, but capa's "
                "PE loader is best-effort on a memory dump — trust its hits, not its misses."
            ),
        },
        "regions": [],
        "dropped_files": [],
    }

    # ── Category gate: Speakeasy emulates Windows PE / shellcode only ──
    category = None
    if fileinfo and os.path.exists(fileinfo):
        try:
            category = json.load(open(fileinfo, encoding="utf-8")).get("category")
        except Exception:
            category = None
    if category and category not in ("pe", "dotnet"):
        out["meta"]["status"] = "skipped"
        out["meta"]["error"] = f"category '{category}' is not an emulatable Windows PE"
        write_stub(out_json, out)
        print(f"    unpack skipped: {category} is not a Windows PE")
        return

    # ── Emulator availability (lives in the per-analyst venv via setup-env.sh) ──
    try:
        from speakeasy import Speakeasy
        try:
            from importlib.metadata import version as _pkg_version
            out["meta"]["emulator_version"] = _pkg_version("speakeasy-emulator")
        except Exception:
            out["meta"]["emulator_version"] = "unknown"
    except Exception as e:
        out["meta"]["status"] = "no_emulator"
        out["meta"]["error"] = (f"speakeasy not importable ({e}); install it via "
                                f"tools/setup-env.sh")
        write_stub(out_json, out)
        print("    unpack skipped: speakeasy not installed (run tools/setup-env.sh)")
        return

    try:
        orig = open(sample, "rb").read()
    except Exception as e:
        out["meta"]["status"] = "load_failed"
        out["meta"]["error"] = f"cannot read sample ({e})"
        write_stub(out_json, out)
        print(f"    unpack skipped: cannot read sample ({e})")
        return

    orig_sha = hashlib.sha256(orig).hexdigest()
    orig_strings = extract_strings(orig)
    out["meta"]["sample_sha256"] = orig_sha
    out["meta"]["sample_string_count"] = len(orig_strings)

    # ── Emulate the stub, bounded by an instruction cap AND a wall-clock cap ──
    se = Speakeasy()
    state = {"instrs": 0}
    deadline = time.monotonic() + TIMEOUT

    def code_hook(emu, addr, size, ctx):
        state["instrs"] += 1
        # check the wall clock occasionally (cheap) — unicorn holds the GIL in
        # native code, so this hook is our only reliable place to time out
        if state["instrs"] % 50000 == 0 and time.monotonic() > deadline:
            state["timed_out"] = True
            emu.stop()
        elif state["instrs"] >= MAX_INSTRS:
            state["hit_cap"] = True
            emu.stop()

    try:
        module = se.load_module(sample)
    except Exception as e:
        out["meta"]["status"] = "load_failed"
        out["meta"]["error"] = f"speakeasy could not load module ({type(e).__name__}: {e})"
        write_stub(out_json, out)
        print(f"    unpack: load failed ({type(e).__name__}) — recorded as a gap")
        return

    se.add_code_hook(code_hook)
    run_error = None
    t0 = time.monotonic()
    try:
        se.run_module(module)
    except Exception as e:
        run_error = f"{type(e).__name__}: {e}"
    elapsed = round(time.monotonic() - t0, 2)

    instrs = state["instrs"]
    if state.get("timed_out"):
        status = "timeout"
    elif state.get("hit_cap"):
        status = "instr_cap"
    elif run_error:
        status = "stalled"  # engine raised mid-run — stub hit something unsupported
    elif instrs < 5000:
        status = "stalled"  # returned almost immediately = stub bailed early
    else:
        status = "ran"
    out["meta"].update({"status": status, "instructions": instrs,
                        "elapsed_s": elapsed, "run_error": run_error})

    # ── Carve memory: keep payload-bearing regions, skip emulator scaffolding ──
    unpack_dir = os.path.join(out_dir, "unpacked")
    os.makedirs(unpack_dir, exist_ok=True)

    try:
        maps = se.get_mem_maps()
    except Exception as e:
        maps = []
        out["meta"]["maps_error"] = str(e)

    candidates = []
    for mp in maps:
        try:
            base, size, tag = mp.get_base(), mp.get_size(), (mp.get_tag() or "")
        except Exception:
            continue
        if size < MIN_REGION or any(tag.startswith(p) for p in SCAFFOLD_PREFIXES):
            continue
        try:
            data = se.mem_read(base, min(size, MAX_READ))
        except Exception:
            continue
        if not data or not data.strip(b"\x00"):
            continue  # all-zero reservation, nothing decrypted here
        strs = extract_strings(data)
        new_strs = strs - orig_strings  # strings revealed by unpacking
        has_mz, valid_pe = pe_view(data)
        is_image = tag.startswith("emu.module.")
        candidates.append({
            "base": hex(base), "size": size, "tag": tag,
            "entropy": entropy(data), "sha256": hashlib.sha256(data).hexdigest(),
            "has_mz": has_mz, "valid_pe": valid_pe, "is_module_image": is_image,
            "string_count": len(strs), "new_string_count": len(new_strs),
            "_data": data,
        })

    # Primary = the region that revealed the most strings NOT in the original
    # file (the clearest "this is the decrypted body" signal); fall back to the
    # module image, then the largest region.
    candidates.sort(key=lambda c: (c["new_string_count"], c["is_module_image"],
                                   c["size"]), reverse=True)

    primary = None
    written = 0
    for c in candidates:
        if written >= MAX_REGIONS:
            break
        data = c.pop("_data")
        fname = f"region_{c['base']}_{c['tag'].replace('.', '_')[:48]}.bin"
        fpath = os.path.join(unpack_dir, fname)
        try:
            open(fpath, "wb").write(data)
        except Exception:
            continue
        c["file"] = os.path.join("unpacked", fname)
        out["regions"].append(c)
        # A region is a genuine recovery only if emulation revealed something NOT
        # already on disk: new strings, or a valid PE living somewhere OTHER than
        # the module's own image base (i.e. injected / unpacked into an allocation).
        # A valid PE at the module image base with no new strings is just the
        # unchanged on-disk image, not an unpack — don't promote it.
        if primary is None and (c["new_string_count"] >= 5
                                or (c["valid_pe"] and not c["is_module_image"])):
            primary = c
        written += 1
    # ensure leftover _data keys are gone
    for c in out["regions"]:
        c.pop("_data", None)

    # ── Files the stub "wrote" during emulation (droppers / self-extractors) ──
    try:
        for df in (se.get_dropped_files() or []):
            info = {}
            for k in ("path", "size"):
                if isinstance(df, dict) and k in df:
                    info[k] = df[k]
            data = df.get("data") if isinstance(df, dict) else None
            if data:
                info["sha256"] = hashlib.sha256(data).hexdigest()
                info["entropy"] = entropy(data)
                dfname = "dropped_" + hashlib.sha256(data).hexdigest()[:16] + ".bin"
                dpath = os.path.join(unpack_dir, dfname)
                try:
                    open(dpath, "wb").write(data)
                    info["file"] = os.path.join("unpacked", dfname)
                except Exception:
                    pass
            out["dropped_files"].append(info)
    except Exception as e:
        out["meta"]["dropped_error"] = str(e)

    # ── Decide the headline: did unpacking actually recover anything new? ──
    max_new = max((c["new_string_count"] for c in out["regions"]), default=0)
    out["meta"]["max_new_strings"] = max_new
    out["meta"]["region_count"] = len(out["regions"])
    if primary:
        out["meta"]["primary_region"] = primary["file"]
        out["meta"]["recovered"] = True
    else:
        out["meta"]["primary_region"] = None
        out["meta"]["recovered"] = False
        if status in ("stalled", "timeout", "load_failed"):
            out["meta"].setdefault("gap", (
                "Stub did not self-decrypt under emulation (likely unsupported API, "
                "anti-emulation, remote-keyed, or injection the emulator can't follow). "
                "Escalate to a dynamic sandbox (#1) to recover the payload."))
        else:
            out["meta"].setdefault("gap", (
                "Emulation completed but revealed no new strings/PE beyond the on-disk "
                "image — sample may already be unpacked, or the payload stayed encrypted."))

    try:
        se.shutdown()
    except Exception:
        pass

    write_stub(out_json, out)
    if out["meta"]["recovered"]:
        print(f"    unpack: status={status} instrs={instrs} — recovered payload "
              f"({max_new} new strings) -> {out['meta']['primary_region']}")
    else:
        print(f"    unpack: status={status} instrs={instrs} — no payload recovered "
              f"(gap recorded; see unpacked.json)")


if __name__ == "__main__":
    main()
