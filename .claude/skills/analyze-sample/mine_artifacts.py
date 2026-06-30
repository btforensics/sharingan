#!/usr/bin/env python3
"""Deterministic artifact-mining digest for the Sharingan analyze-sample skill.

Reads a triage report directory and prints ONE compact, human-readable digest that
covers every artifact — small ones in full, large ones (floss/capa/strings) mined for
just the analytically relevant fields. This replaces the ad-hoc Python heredocs the
analysis step used to run inline (which were unparseable by the command-safety guard
and triggered approval prompts on every run), and it enforces the per-artifact
"must-check" field list so coverage is systematic, not improvised.

Stdlib only, cross-platform (Linux/macOS/Windows), UTF-8, and it NEVER raises — a
missing/broken artifact is reported as a one-line note (a GAP), not a crash.

Usage:  python mine_artifacts.py <report-dir>

The skill still reasons across the digest; this tool only does the reading. It is NOT
a verdict — it surfaces evidence (and gaps) for the analyst pass.
"""
import json
import os
import re
import sys

URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.I)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
REG_RE = re.compile(r'(HKLM|HKCU|HKEY_|SOFTWARE\\|SYSTEM\\CurrentControlSet)', re.I)
INTERESTING_RE = re.compile(
    r'(\.exe\b|\.dll\b|\.ps1\b|powershell|cmd\.exe|schtasks|rundll32|regsvr32|'
    r'\\Temp\\|AppData|ProgramData|mutex|\.onion|bot|C2|/gate|/api/)', re.I)


def _load(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except Exception as e:
        return {"__error__": f"{type(e).__name__}: {e}"}


def _read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return None


def _hdr(title):
    print("\n" + "=" * 4 + " " + title + " " + "=" * 4)


def _valid_ip(ip):
    return all(0 <= int(o) <= 255 for o in ip.split("."))


def _str_list(v):
    """Normalize a floss/strings list of (str | {"string": ...}) into [str]."""
    out = []
    if isinstance(v, list):
        for s in v:
            if isinstance(s, str):
                out.append(s)
            elif isinstance(s, dict):
                out.append(s.get("string", ""))
    return out


def mine_fileinfo(rd):
    d = _load(os.path.join(rd, "fileinfo.json"))
    _hdr("fileinfo (READ FIRST — type & routing)")
    if not d:
        print("  (absent)")
        return None
    cat = d.get("category")
    print(f"  category/subtype: {cat}/{d.get('subtype')}")
    print(f"  file_output: {d.get('file_output')}")
    print(f"  extension: {d.get('extension')!r} | extension_mismatch: {d.get('extension_mismatch')}"
          + ("   <-- MASQUERADE SIGNAL" if d.get("extension_mismatch") else ""))
    if d.get("notes"):
        print(f"  notes: {d.get('notes')}")
    return cat


def mine_hashes(rd):
    d = _load(os.path.join(rd, "hashes.json"))
    if not d:
        return
    _hdr("hashes")
    print(f"  filename: {d.get('filename')}")
    for k in ("md5", "sha1", "sha256"):
        if d.get(k):
            print(f"  {k}: {d.get(k)}")


def mine_die(rd):
    """Returns True if a packer/protector was named (drives the imphash caveat)."""
    d = _load(os.path.join(rd, "die.json"))
    _hdr("die (packer / compiler / protector)")
    if not d:
        print("  (absent)")
        return False
    packed = False
    for det in d.get("detects", []):
        for v in det.get("values", []):
            t = v.get("type", "")
            print(f"  [{t}] {v.get('string') or v.get('name')}")
            if t in ("protector", "packer"):
                packed = True
    if packed:
        print("  >> packer/protector present -> body may be packed; imphash siblings group by PACKER not family")
    return packed


def mine_authenticode(rd):
    d = _load(os.path.join(rd, "authenticode.json"))
    if not d:
        return
    _hdr("authenticode (signature verification)")
    st = d.get("status")
    print(f"  status: {st} | flags: {d.get('flags')}")
    sigs = d.get("signatures") or []
    if sigs:
        leaf = sigs[0].get("leaf_certificate") or {}
        print(f"  signer: {leaf.get('subject_cn')} | issuer: {leaf.get('issuer_cn')}")
    if d.get("abused_cert_matches"):
        print(f"  ABUSED-CERT MATCH: {d['abused_cert_matches']}")
    note = d.get("analyst_note")
    if note:
        print(f"  note: {note}")


def mine_peinfo(rd):
    d = _load(os.path.join(rd, "peinfo.json"))
    if not d:
        return
    _hdr("peinfo (PE structure — MUST-CHECK fields)")
    if "__error__" in d:
        print(f"  (error: {d['__error__']})")
        return
    h = d.get("headers", {})
    print(f"  is_dll: {h.get('is_dll')} | is_exe: {h.get('is_exe')} | subsystem: {h.get('subsystem')} | machine: {h.get('machine')}")
    print(f"  compile timestamp: {h.get('timestamp_utc') or h.get('timestamp')}")
    print(f"  checksum_mismatch: {h.get('checksum_mismatch')}")
    exports = d.get("exports")
    nexp = len(exports) if isinstance(exports, list) else exports
    flag = "   <-- DLL with ZERO exports = masquerade tell" if (h.get("is_dll") and not exports) else ""
    print(f"  exports: {nexp}{flag}")
    vi = d.get("version_info")
    if vi:
        print(f"  version_info: {json.dumps(vi)[:400]}")
        print("    (forged vendor strings = effortful masquerade; random/garbage = automated packer)")
    else:
        print("  version_info: (none)")
    sig = d.get("signature") or {}
    print(f"  signature(pestats): present={sig.get('present')} status={sig.get('status')} signer={sig.get('signer_name')}")
    secs = d.get("sections", [])
    print("  sections:")
    for s in secs:
        ent = s.get("entropy")
        hi = " HIGH-ENTROPY" if s.get("high_entropy") else ""
        print(f"    {s.get('name'):<10} entropy={ent}{hi}")
    ov = d.get("overlay") or {}
    if ov.get("present"):
        print(f"  overlay: present size={ov.get('size_bytes')} entropy={ov.get('entropy')} offset={ov.get('start_offset')}")
    else:
        print("  overlay: none")
    tls = d.get("tls")
    if tls:
        print(f"  tls_callbacks: {tls}")
    imps = d.get("imports", {})
    if isinstance(imps, dict):
        tot = sum(len(v) for v in imps.values() if isinstance(v, list))
        print(f"  imports: {len(imps)} DLL(s), {tot} functions")
        for dll, fns in list(imps.items())[:12]:
            if isinstance(fns, list):
                print(f"    {dll}: {fns[:14]}")


def mine_capa(rd):
    d = _load(os.path.join(rd, "capa.json"))
    if not d:
        return
    _hdr("capa (capabilities — rule names + ATT&CK)")
    if "__error__" in d:
        print(f"  (error: {d['__error__']})")
        return
    rules = d.get("rules", {})
    names, attack = [], set()
    for rn, rv in rules.items():
        m = rv.get("meta", {})
        names.append(m.get("name", rn))
        for at in (m.get("attack") or []):
            attack.add((at.get("tactic"), at.get("technique"), at.get("id")))
    print(f"  {len(names)} rules matched:")
    for n in sorted(set(names)):
        print(f"    - {n}")
    atk = sorted(a for a in attack if a and a[2])
    if atk:
        print(f"  ATT&CK: {atk}")
    err = _read_text(os.path.join(rd, "capa.err"))
    if err and err.strip():
        print(f"  capa.err: {err.strip()[:200]} (PE-parse warnings — trust capa HITS, not misses)")


def mine_floss(rd):
    d = _load(os.path.join(rd, "floss.json"))
    if not d:
        return
    _hdr("floss (decoded + filtered static strings)")
    if "__error__" in d:
        print(f"  (error: {d['__error__']})")
        return
    strs = d.get("strings", d)
    dec = _str_list(strs.get("decoded_strings")) if isinstance(strs, dict) else []
    stack = (_str_list(strs.get("stack_strings")) + _str_list(strs.get("tight_strings"))) if isinstance(strs, dict) else []
    stat = _str_list(strs.get("static_strings")) if isinstance(strs, dict) else []
    print(f"  counts: decoded={len(dec)} stack/tight={len(stack)} static={len(stat)}")
    if dec:
        print("  decoded_strings:")
        for s in dec[:80]:
            print(f"    {s!r}")
    _filter_strings(dec + stack + stat)


def _filter_strings(alls):
    urls, ips, regs, other = set(), set(), set(), set()
    for s in alls:
        if not isinstance(s, str):
            continue
        for u in URL_RE.findall(s):
            urls.add(u)
        for ip in IP_RE.findall(s):
            if _valid_ip(ip) and not ip.startswith(("0.", "127.", "255.")):
                ips.add(ip)
        if REG_RE.search(s):
            regs.add(s.strip()[:120])
        elif INTERESTING_RE.search(s) and len(s) < 120:
            other.add(s.strip())
    def dump(label, items, cap=40):
        items = sorted(items)
        print(f"  {label} ({len(items)}):")
        for x in items[:cap]:
            print(f"    {x!r}")
    dump("URLs", urls)
    dump("valid public IPs", ips)
    dump("registry-ish", regs)
    dump("interesting (exe/dll/cmd/paths/mutex)", other)
    if ips:
        print("  NOTE: verify 'IP-like' hits against peinfo.version_info — junk FileVersion fields look like IPs")


def mine_yara(rd):
    t = _read_text(os.path.join(rd, "yara.txt"))
    _hdr("yara (local rules)")
    if t is None:
        print("  (absent)")
        return
    rules = sorted({ln.split()[0] for ln in t.splitlines() if ln.strip()})
    print(f"  {len(rules)} rule(s): {rules}")


def mine_virustotal(rd):
    d = _load(os.path.join(rd, "virustotal.json"))
    _hdr("VirusTotal")
    if not d:
        print("  (absent)")
        return
    a = (d.get("data") or {}).get("attributes", {})
    if not a:
        print("  not found on VT (unknown sample) — a GAP for reputation, not 'clean'")
        return
    st = a.get("last_analysis_stats", {})
    print(f"  detections: {st.get('malicious')}/{sum(v for v in st.values() if isinstance(v,int))} malicious")
    ptc = a.get("popular_threat_classification", {})
    print(f"  suggested_threat_label: {ptc.get('suggested_threat_label')}")
    if ptc.get("popular_threat_name"):
        print(f"  threat_names: {[(c.get('value'), c.get('count')) for c in ptc['popular_threat_name']]}")
    print(f"  meaningful_name: {a.get('meaningful_name')}")
    print(f"  names: {a.get('names', [])[:8]}")
    res = a.get("last_analysis_results", {})
    for k in ("Microsoft", "Kaspersky", "ESET-NOD32", "CrowdStrike", "BitDefender", "Fortinet"):
        if k in res and res[k].get("result"):
            print(f"    {k}: {res[k]['result']}")
    print(f"  first_submission: {a.get('first_submission_date')} | times_submitted: {a.get('times_submitted')}")


def mine_vt_pivot(rd, packed):
    d = _load(os.path.join(rd, "vt_pivot.json"))
    if not d:
        return
    _hdr("vt_pivot (family / campaign)")
    fwd = d.get("forward", {})
    for k in ("contacted_domains", "contacted_ips", "dropped_files", "itw_urls"):
        blk = fwd.get(k, {})
        items = blk.get("items", [])
        if items:
            print(f"  forward.{k} ({blk.get('count')}): " +
                  ", ".join(i.get("id") or i.get("meaningful_name") or str(i) for i in items[:6]))
    sibs = d.get("siblings", [])
    if sibs:
        print(f"  siblings ({len(sibs)}):")
        for s in sibs[:12]:
            print(f"    {s.get('sha256','?')[:16]}… via={s.get('via')} "
                  f"{s.get('malicious')}/{s.get('total')} {s.get('suggested_threat_label')} "
                  f"({s.get('meaningful_name')})")
        if packed:
            print("  CAVEAT: die saw a packer -> imphash siblings group by PACKER; trust same-label, "
                  "downgrade divergent-label siblings")
    meta = d.get("meta", {})
    if meta.get("note") and "403" in json.dumps(d):
        print("  (a reverse pivot was gated by VT key tier — not 'no siblings')")


def mine_behavior(rd):
    d = _load(os.path.join(rd, "behavior.json"))
    if not d:
        return
    _hdr("behavior (VT runtime — the ONLY confirmed-observed source)")
    meta = d.get("meta", {})
    st = meta.get("status")
    print(f"  status: {st}")
    if st != "found":
        print(f"  >> {st} = GAP (no dynamic detonation on VT) — escalate to a sandbox, do NOT read as 'did nothing'")
    net = d.get("network", {})
    host = d.get("host", {})
    for k, v in list(net.items()) + list(host.items()):
        if isinstance(v, list) and v:
            print(f"  {k} ({len(v)}): {json.dumps(v)[:300]}")
    verd = d.get("verdict", {})
    if verd.get("verdicts"):
        print(f"  verdicts: {verd.get('verdicts')}")
    if verd.get("attack_techniques"):
        print(f"  attack_techniques: {[(t.get('id'), t.get('description')) for t in verd['attack_techniques'][:12]]}")


def mine_config(rd):
    d = _load(os.path.join(rd, "config.json"))
    if not d:
        return
    _hdr("config (embedded family config extraction)")
    st = d.get("status")
    print(f"  status: {st} | parsers_loaded: {d.get('parsers_loaded')}")
    if st == "extracted":
        print(f"  matches: {json.dumps(d.get('matches'))[:600]}")
    elif st == "no_match":
        print("  no family parser matched (a real 'no embedded config', not an error)")
    elif st == "unavailable":
        print("  >> parser packs not installed — GAP, run tools/setup-env.sh")


def mine_domain_rep(rd):
    d = _load(os.path.join(rd, "domain_rep.json"))
    if not d:
        return
    _hdr("domain_rep (C2 / domain reputation)")
    meta = d.get("meta", {})
    print(f"  url_hosts: {meta.get('url_hosts')} | bare_candidates: {meta.get('bare_candidates')}")
    res = d.get("results", {})
    if res:
        print(f"  results: {json.dumps(res)[:500]}")


def mine_optional(rd):
    """unpacked.json / ghidra.json — present only with --unpack / --deep."""
    up = _load(os.path.join(rd, "unpacked.json"))
    if up:
        _hdr("unpacked (N4 emulation)")
        m = up.get("meta", {})
        print(f"  status: {m.get('status')} | recovered: {m.get('recovered')} | instructions: {m.get('instructions')}")
        if not m.get("recovered"):
            print(f"  >> GAP: {m.get('gap')} — stub bailed; escalate to a sandbox")
        else:
            print(f"  primary_region: {m.get('primary_region')} (mine unpacked/ as the REAL body)")
    gh = _load(os.path.join(rd, "ghidra.json"))
    if gh:
        _hdr("ghidra (--deep)")
        fns = gh.get("functions") or []
        print(f"  functions: {len(fns)} | decompiled: {len(gh.get('decompiled', []) or [])} (on packed input = stub only)")


def mine_provenance(rd):
    d = _load(os.path.join(rd, "provenance.json"))
    if not d:
        _hdr("provenance")
        print("  (absent — older report; say so in the report footer)")
        return
    _hdr("provenance (footer source)")
    t = d.get("tools", {})
    def v(x):
        return x.get("version", x.get("error", "?")) if isinstance(x, dict) else x
    print("  tools: " + " | ".join(f"{k} {v(t[k])}" for k in
          ("capa", "floss", "die", "yara", "signify", "python") if k in t))
    r = d.get("rules", {})
    for k in ("capa-rules", "signature-base", "yara-rules"):
        if k in r:
            print(f"  {k}: {r[k].get('commit', r[k].get('error','?'))} ({r[k].get('date','?')})")
    print(f"  generated_utc: {d.get('generated_utc')}")


def main():
    if len(sys.argv) != 2:
        print("Usage: mine_artifacts.py <report-dir>", file=sys.stderr)
        return 2
    rd = sys.argv[1]
    if not os.path.isdir(rd):
        print(f"Not a directory: {rd}", file=sys.stderr)
        return 2
    print(f"# Artifact digest for: {rd}")
    present = sorted(os.listdir(rd))
    print(f"# files: {present}")
    mine_fileinfo(rd)
    mine_hashes(rd)
    packed = mine_die(rd)
    mine_authenticode(rd)
    mine_peinfo(rd)
    mine_capa(rd)
    mine_floss(rd)
    mine_yara(rd)
    mine_virustotal(rd)
    mine_vt_pivot(rd, packed)
    mine_behavior(rd)
    mine_config(rd)
    mine_domain_rep(rd)
    mine_optional(rd)
    mine_provenance(rd)
    print("\n# End of digest. This is EVIDENCE, not a verdict — reason across it per CLAUDE.md.")
    print("# For archive/non-PE samples, also mine olevba/oleid/pdfid/lnk/email/archive artifacts as present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
