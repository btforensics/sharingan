#!/usr/bin/env python3
"""
dotnet_deob.py — Sharingan managed (.NET) unpack / deobfuscation stage (N7).

Commodity RATs (DCRat / AsyncRAT / Quasar / XWorm) are .NET and ship wrapped in a
managed protector (.NET Reactor, ConfuserEx, SmartAssembly, …). N4's native-stub
emulation can't follow the CLR hand-off and N2's family parsers can't recognise the
obfuscated assembly, so the real payload is statically invisible. This stage is the
managed analogue of N4: it detects the protector (from die), runs de4dot to strip it,
and lets triage.sh re-run capa / config / strings on the recovered clean assembly.

Recovers EMBEDDED indicators only — promote any C2/keys it surfaces to High *intent*,
never "confirmed live" (only a sandbox / VT-behaviour confirms execution).

Trigger (per the gating & speed rubric): CHEAP auto-on-match — this tool only reads
JSON unless a known .NET protector is present on a .NET sample, and only THEN invokes
de4dot. de4dot itself is fast; the expensive re-analysis (capa) runs only when a clean
assembly was actually recovered. de4dot is an optional system dep: if mono/de4dot is
absent the status is `unavailable` (a GAP — run tools/install-dotnet-deob.sh), never a
silent clean.

Usage:  dotnet_deob.py <sample> <report_dir> <die.json> [<fileinfo.json>]
Env:    DE4DOT — command to run de4dot (e.g. "mono /opt/de4dot/de4dot.exe"); if unset,
        autodetected on PATH or at tools/de4dot/de4dot.exe (+ mono).
Emits:  <report_dir>/dotnet_deob.json (+ deobfuscated/<name> on success)
"""
import sys, os, re, json, shlex, shutil, subprocess

# Managed protectors de4dot recognises/strips (matched against die's protector
# names + free text). Native packers (Themida/VMProtect) are NOT managed — they're
# N4's job — so they are intentionally excluded here.
DOTNET_PROTECTORS = [
    ".NET Reactor", "ConfuserEx", "Confuser", "SmartAssembly", "Eazfuscator",
    "Agile.NET", "CliSecure", "Babel", "Dotfuscator", "CryptoObfuscator",
    "Goliath", "ILProtector", "MaxtoCode", "Skater", "Spices", "Obfuscar",
    "DeepSea", "Phoenix", "Xenocode", ".NET Spider",
]


def detect(die_path, fileinfo_path):
    """Return (is_dotnet, protector_name_or_None) from die.json (+ fileinfo)."""
    is_dotnet = False
    protector = None
    try:
        with open(fileinfo_path) as f:
            fi = json.load(f)
        if fi.get("category") == "dotnet":
            is_dotnet = True
    except Exception:
        pass
    try:
        with open(die_path) as f:
            die = json.load(f)
        for det in die.get("detects", []):
            for v in det.get("values", []):
                t = (v.get("type") or "").lower()
                name = v.get("name") or ""
                s = v.get("string") or ""
                if ".net" in (name + s).lower() or "clr" in s.lower():
                    is_dotnet = True
                hay = f"{name} {s}"
                for p in DOTNET_PROTECTORS:
                    if p.lower() in hay.lower():
                        protector = protector or p
                        is_dotnet = True  # a .NET protector implies a .NET body
                if t == "protector" and not protector:
                    # an unrecognised protector on a .NET file — still worth a de4dot pass
                    protector = name or "unknown protector"
    except Exception:
        pass
    return is_dotnet, protector


def resolve_de4dot():
    """Return the de4dot command prefix (list) or None if unavailable.
    Prefers the .NET Core build (de4dot.dll via dotnet) that install-dotnet-deob.sh
    produces; falls back to a native de4dot.exe via mono, or `de4dot` on PATH."""
    env = os.environ.get("DE4DOT", "").strip()
    if env:
        parts = shlex.split(env)
        if parts and (shutil.which(parts[0]) or os.path.exists(parts[0])):
            return parts
    if shutil.which("de4dot"):
        return ["de4dot"]
    here = os.path.dirname(__file__)
    dll = os.path.join(here, "de4dot", "de4dot.dll")
    if os.path.exists(dll) and shutil.which("dotnet"):
        return ["dotnet", dll]
    exe = os.path.join(here, "de4dot", "de4dot.exe")
    if os.path.exists(exe) and shutil.which("mono"):
        return ["mono", exe]
    return None


def main():
    if len(sys.argv) < 4:
        print("Usage: dotnet_deob.py <sample> <report_dir> <die.json> [<fileinfo.json>]",
              file=sys.stderr)
        sys.exit(1)
    sample, rd, die_path = sys.argv[1], sys.argv[2], sys.argv[3]
    fileinfo_path = sys.argv[4] if len(sys.argv) > 4 else ""

    result = {"sample": os.path.basename(sample), "status": None,
              "is_dotnet": False, "protector_detected": None,
              "tool": None, "output_file": None, "notes": []}

    is_dotnet, protector = detect(die_path, fileinfo_path)
    result["is_dotnet"] = is_dotnet
    result["protector_detected"] = protector

    # 1) not a .NET assembly → nothing to do (no gap)
    if not is_dotnet:
        result["status"] = "not_dotnet"
        result["notes"].append("Not a .NET assembly — managed deobfuscation N/A "
                               "(native packers are N4's --unpack stage).")
    # 2) .NET but unprotected → capa/config already see the real IL
    elif not protector:
        result["status"] = "no_protector"
        result["notes"].append("No managed protector detected — capa/config already "
                               "operate on the real IL; de4dot pass skipped (cheap-on-match).")
    else:
        # 3) protected .NET → invoke de4dot if available
        de4dot = resolve_de4dot()
        if not de4dot:
            result["status"] = "unavailable"
            result["notes"].append(
                f"{protector} detected but de4dot/mono not installed — GAP. Install via "
                "tools/install-dotnet-deob.sh, then re-run. NOT a clean result.")
        else:
            out_dir = os.path.join(rd, "deobfuscated")
            os.makedirs(out_dir, exist_ok=True)
            out_file = os.path.join(out_dir, os.path.basename(sample) + ".cleaned.dll")
            cmd = de4dot + [sample, "-o", out_file]
            result["tool"] = " ".join(de4dot)
            # the .NET Core de4dot.dll targets netcoreapp3.1; roll it forward to
            # whatever runtime is installed (e.g. net6) so `dotnet de4dot.dll` runs.
            denv = dict(os.environ, DOTNET_ROLL_FORWARD="LatestMajor")
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=300, env=denv)
                if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
                    result["status"] = "deobfuscated"
                    result["output_file"] = os.path.relpath(out_file, rd)
                    result["notes"].append(
                        f"{protector} stripped by de4dot — clean assembly recovered. "
                        "capa/config/strings re-run on it (see deobfuscated/). EMBEDDED "
                        "intent only.")
                else:
                    result["status"] = "error"
                    result["notes"].append(
                        f"de4dot ran but produced no clean assembly (rc={proc.returncode}) — "
                        f"{protector} may use a variant de4dot can't strip. stderr: "
                        + (proc.stderr or "")[:400] + " — escalate to manual RE / sandbox.")
            except subprocess.TimeoutExpired:
                result["status"] = "error"
                result["notes"].append("de4dot timed out (300s) — escalate to manual RE.")
            except Exception as e:
                result["status"] = "error"
                result["notes"].append(f"de4dot invocation failed: {type(e).__name__}: {e}")

    with open(os.path.join(rd, "dotnet_deob.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"    dotnet_deob -> dotnet_deob.json (status={result['status']}"
          + (f", protector={protector}" if protector else "") + ")")


if __name__ == "__main__":
    main()
