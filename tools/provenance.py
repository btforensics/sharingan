#!/usr/bin/env python3
"""Tool & rule-set provenance stamping for the Sharingan triage pipeline.

Captures the version of every analysis tool and the date/commit of every
rule-set that produced a report, so findings are reproducible and audit-grade
(IR / legal-grade reproducibility). A capa hit or YARA match is only as
trustworthy as the rule version behind it — this stage records that version.

Writes provenance.json into the report dir; the /analyze-sample skill renders it
as a "Tooling & Rule Provenance" footer table in analysis_report.md.

Design mirrors domain_rep.py / vt_pivot.py: stdlib only, and it never raises
into the pipeline — every probe failure is captured in-place as {"error": ...}
rather than crashing the stage.

Usage:  provenance.py <report-dir>
Env (all optional; default to self-located paths derived from this file):
        CAPA_RULES, CAPA_SIGS, YARA_RULES_DIR, GHIDRA_HOME
"""
import datetime
import json
import os
import platform
import re
import subprocess
import sys

# Self-locate: this file lives in <BASE>/tools/, mirroring config.env's BASE so
# the stage stays portable when the project is moved/renamed (team-distributed).
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(SCRIPT_DIR)

CAPA_RULES = os.environ.get("CAPA_RULES", os.path.join(BASE, "rules", "capa-rules"))
CAPA_SIGS = os.environ.get("CAPA_SIGS", os.path.join(BASE, "rules", "capa-sigs"))
YARA_RULES_DIR = os.environ.get("YARA_RULES_DIR", os.path.join(BASE, "rules"))
GHIDRA_HOME = os.environ.get("GHIDRA_HOME", "/opt/ghidra")


def _run(cmd, timeout=20):
    """Run a command, return combined stdout/stderr text. Raises on failure."""
    p = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout
    )
    out = (p.stdout or "").strip() or (p.stderr or "").strip()
    return out


def tool_version(name, cmd, pattern=None):
    """Probe a CLI tool's version. Returns {version, raw} or {error}."""
    try:
        raw = _run(cmd)
        if not raw:
            return {"error": "no version output"}
        first = raw.splitlines()[0].strip()
        version = first
        if pattern:
            m = re.search(pattern, raw)
            if m:
                version = m.group(1)
        return {"version": version, "raw": first}
    except FileNotFoundError:
        return {"error": "not installed (not on PATH)"}
    except subprocess.TimeoutExpired:
        return {"error": "version probe timed out"}
    except Exception as e:  # never raise into the pipeline
        return {"error": f"{type(e).__name__}: {e}"}


def ghidra_version(home):
    """Read Ghidra's version from its application.properties (no exec needed)."""
    props = os.path.join(home, "Ghidra", "application.properties")
    try:
        with open(props, encoding="utf-8") as f:
            for line in f:
                if line.startswith("application.version="):
                    return {"version": line.split("=", 1)[1].strip(),
                            "home": home}
        return {"error": "version key not found in application.properties"}
    except FileNotFoundError:
        return {"error": f"not installed (no {props})"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def git_provenance(path):
    """Commit + commit-date of a rule-set checkout, or fall back to mtime."""
    if not os.path.isdir(path):
        return {"error": f"path not found: {path}"}
    try:
        if os.path.isdir(os.path.join(path, ".git")):
            out = _run(["git", "-C", path, "log", "-1",
                        "--format=%h|%ci"], timeout=15)
            if out and "|" in out:
                commit, date = out.split("|", 1)
                return {"source": "git", "path": path,
                        "commit": commit.strip(), "date": date.strip()}
    except Exception:
        pass  # fall through to mtime
    return dir_mtime_provenance(path)


def dir_mtime_provenance(path):
    """Newest-file mtime + file count for a non-git rule-set (e.g. capa-sigs)."""
    if not os.path.isdir(path):
        return {"error": f"path not found: {path}"}
    try:
        newest = 0.0
        count = 0
        for root, _dirs, files in os.walk(path):
            if ".git" in root:
                continue
            for fn in files:
                count += 1
                try:
                    m = os.path.getmtime(os.path.join(root, fn))
                    newest = max(newest, m)
                except OSError:
                    pass
        date = (datetime.datetime.fromtimestamp(newest, datetime.timezone.utc)
                .strftime("%Y-%m-%d %H:%M:%S UTC")) if newest else None
        return {"source": "mtime", "path": path,
                "newest_file": date, "file_count": count}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def venv_pkg_version(package):
    """Version of a dep that lives in the per-analyst venv (roadmap N2/N4 stages).
    Probes the venv interpreter's package metadata rather than the system python
    running this stage. Returns {version, package} or {error}."""
    venv_py = os.path.join(BASE, "tools", "venv", "bin", "python")
    py = venv_py if os.path.exists(venv_py) else sys.executable
    try:
        ver = _run([py, "-c",
                    "from importlib.metadata import version;"
                    f"print(version('{package}'))"], timeout=15)
        if ver and ver[0].isdigit():
            return {"version": ver, "package": package}
        return {"error": "not installed (run tools/setup-env.sh)"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def de4dot_provenance():
    """Stamp the N7 .NET-deob dependency. de4dot has no clean --version, so record
    mono's version + whether de4dot is resolvable (PATH or tools/de4dot/de4dot.exe)."""
    import shutil
    mono = tool_version("mono", ["mono", "--version"],
                        r"version ([0-9][\w.\-]*)")
    local = os.path.join(BASE, "tools", "de4dot", "de4dot.exe")
    on_path = bool(shutil.which("de4dot"))
    return {
        "de4dot_present": on_path or os.path.exists(local),
        "de4dot_path": "PATH" if on_path else (local if os.path.exists(local) else None),
        "mono": mono.get("version", mono.get("error")),
        "note": "install via tools/install-dotnet-deob.sh" if not (
            on_path or os.path.exists(local)) else None,
    }


def load_sample(report_dir):
    """Pull the sample identity from hashes.json so the stamp is bound to it."""
    try:
        with open(os.path.join(report_dir, "hashes.json"), encoding="utf-8") as f:
            h = json.load(f)
        return {"filename": h.get("filename"), "sha256": h.get("sha256")}
    except Exception:
        return {}


def main():
    if len(sys.argv) != 2:
        print("Usage: provenance.py <report-dir>", file=sys.stderr)
        return 2
    report_dir = sys.argv[1]

    prov = {
        "generated_utc": datetime.datetime.now(
            datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": {
            "platform": platform.platform(),
            "node": platform.node(),
        },
        "sample": load_sample(report_dir),
        "tools": {
            "capa": tool_version("capa", ["capa", "--version"],
                                 r"capa\s+([0-9][\w.\-]*)"),
            "floss": tool_version("floss", ["floss", "--version"],
                                  r"floss\s+([0-9][\w.\-]*)"),
            "die": tool_version("die", ["diec", "--version"],
                                r"die\s+([0-9][\w.\-]*)"),
            "yara": tool_version("yara", ["yara", "--version"],
                                 r"([0-9][\w.\-]*)"),
            "ghidra": ghidra_version(GHIDRA_HOME),
            "speakeasy": venv_pkg_version("speakeasy-emulator"),
            "configextractor": venv_pkg_version("configextractor-py"),
            # N6 Authenticode verification — signify + its bundled MS trust store.
            # mscerts is the trust-root snapshot, so its version dates the roots
            # any "valid chain" verdict was checked against (audit-grade).
            "signify": venv_pkg_version("signify"),
            "mscerts": venv_pkg_version("mscerts"),
            # N1 VT behaviour ingestion is stdlib-only (no installed package to
            # version) — stamp the upstream data source / API it reads instead.
            "vt_behavior": {"source": "VirusTotal API v3 /behaviour_summary",
                            "note": "ingests VT's existing sandbox detonation; "
                                    "no local engine version"},
            # N7 managed .NET deob — de4dot via mono (optional system dep).
            "dotnet_deob": de4dot_provenance(),
            # N8/N9 script-deob + HTML-smuggling stages are stdlib-only Python
            # (no installed package to version) — versioned with the project.
            "scriptscan": {"engine": "scriptscan.py (stdlib)", "note": "N8 — "
                           "recursive script deobfuscation"},
            "htmlsmuggle": {"engine": "htmlsmuggle.py (stdlib)", "note": "N9 — "
                            "HTML/SVG smuggling extraction"},
            "python": {"version": platform.python_version(),
                       "raw": sys.version.split()[0]},
        },
        "rules": {
            "capa-rules": git_provenance(CAPA_RULES),
            "capa-sigs": dir_mtime_provenance(CAPA_SIGS),
            "yara-rules": git_provenance(
                os.path.join(YARA_RULES_DIR, "yara-rules")),
            "signature-base": git_provenance(
                os.path.join(YARA_RULES_DIR, "signature-base")),
        },
    }

    out_path = os.path.join(report_dir, "provenance.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(prov, f, indent=2)

    # Compact human echo for the triage console.
    t = prov["tools"]

    def _v(d):
        return d.get("version", d.get("error", "?"))

    print(f"    capa {_v(t['capa'])} | floss {_v(t['floss'])} | "
          f"die {_v(t['die'])} | yara {_v(t['yara'])} | "
          f"ghidra {_v(t['ghidra'])}")
    cr = prov["rules"]["capa-rules"]
    sb = prov["rules"]["signature-base"]
    print(f"    capa-rules {cr.get('commit', cr.get('error','?'))} "
          f"({cr.get('date','?')}) | "
          f"signature-base {sb.get('commit', sb.get('error','?'))} "
          f"({sb.get('date','?')})")
    print(f"    provenance -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
