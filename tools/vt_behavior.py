#!/usr/bin/env python3
"""VirusTotal behaviour (sandbox) ingestion for the Sharingan triage pipeline.

Everything else in the pipeline recovers EMBEDDED indicators — peinfo/floss/capa
read the file at rest, config_extract.py (N2) and unpack_emulate.py (N4) rip the
config/payload statically. They establish *intent* ("the sample is wired to call
hubscore[.]io"), never confirmed *behaviour*. This stage closes that gap on the
cheap: it pulls VT's *existing* sandbox detonation for the hash — what the sample
actually DID when someone already ran it in VT's backends (Zenbox/CAPE/etc.).

  /files/<sha256>/behaviours          → which sandboxes ran, dates, has_network/procs
  /files/<sha256>/behaviour_summary   → merged runtime activity across those sandboxes:
      network  — dns_lookups, ip_traffic, http_conversations, tls, memory-pattern IOCs
      host     — files_dropped (w/ child hashes), files/registry written, mutexes,
                 processes/commands, services, modules
      verdict  — MITRE techniques, sandbox signatures, crowdsourced IDS (Suricata) alerts

NOTHING IS UPLOADED — this is a hash lookup against detonations VT already has.

Honest status (this is the whole point — distinguish "ran and did X" from "never ran"):
    found        — a dynamic sandbox ran it; real runtime activity recovered
    static_only  — VT has only a STATIC report (e.g. sandbox_name CAPA, has_network
                   false): no dynamic data exists. A GAP, not a clean result — the
                   av45i case (pre-2007 worm that won't run in modern sandboxes).
    not_detonated— VT has no behaviour report at all → escalate to #1 (own sandbox)
    unavailable  — no VT_API_KEY (GAP)
    error        — captured per-call, never raised into the pipeline

Recovered values are CONFIRMED-OBSERVED (per VT sandbox, at the analysis date),
unlike the embedded-only stages — but observed by VT, not by you, and possibly
stale. Promote a contacted host/dropped hash to "confirmed live (per VT, <date>)",
then feed the resolved IPs / dropped hashes back into the IP-rep + VT-pivot stages.
Source tag [behavior].

Design mirrors vt_pivot.py / domain_rep.py: stdlib only (urllib), paced for the
VT public-tier rate limit, and it never raises into the pipeline — every failure
is captured in-place rather than crashing the stage.

Usage:  vt_behavior.py <hashes.json | sha256> <out.json>
Env:    VT_API_KEY                  (required)
        VT_BEHAVIOR_SLEEP           (default 16)  seconds between calls (public tier ~4/min)
        VT_BEHAVIOR_PER_LIST        (default 25)  items kept per activity list
        VT_BEHAVIOR_MAX_SANDBOXES   (default 8)   behaviour reports to enumerate
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VT_BASE = "https://www.virustotal.com/api/v3"

SLEEP = float(os.environ.get("VT_BEHAVIOR_SLEEP", "16"))
PER_LIST = int(os.environ.get("VT_BEHAVIOR_PER_LIST", "25"))
MAX_SANDBOXES = int(os.environ.get("VT_BEHAVIOR_MAX_SANDBOXES", "8"))


class Budget:
    """Paces VT requests to respect the public-tier rate limit (mirrors vt_pivot)."""

    def __init__(self, key, sleep):
        self.key = key
        self.sleep = sleep
        self.used = 0
        self._first = True

    def get(self, url):
        """One paced GET. Returns parsed JSON, or raises (caller captures)."""
        if not self._first and self.sleep > 0:
            time.sleep(self.sleep)
        self._first = False
        self.used += 1
        req = urllib.request.Request(url, headers={"x-apikey": self.key})
        with urllib.request.urlopen(req, timeout=40) as r:
            return json.loads(r.read())


def _truncate(seq, limit):
    """Cap a list and note how many were dropped, so a big report stays readable."""
    seq = list(seq or [])
    if len(seq) <= limit:
        return seq, 0
    return seq[:limit], len(seq) - limit


def load_sha256(arg):
    """Accept either a sha256 hex string or a path to hashes.json."""
    if os.path.isfile(arg):
        with open(arg, encoding="utf-8") as f:
            return (json.load(f).get("sha256") or "").strip()
    return arg.strip()


def fetch_sandboxes(budget, sha256):
    """Enumerate the per-sandbox behaviour reports (which engines ran, when).

    This is what tells dynamic apart from static: each item's attributes carry
    sandbox_name + has_network / has_html_report / analysis_date. Returns a list
    of compact dicts, or [] with the error surfaced by the caller."""
    url = (f"{VT_BASE}/files/{urllib.parse.quote(sha256)}/behaviours"
           f"?limit={MAX_SANDBOXES}")
    data = budget.get(url).get("data", [])
    out = []
    for o in data:
        a = o.get("attributes", {}) or {}
        out.append({
            "sandbox_name": a.get("sandbox_name"),
            "analysis_date": a.get("analysis_date"),
            "has_network": a.get("has_network"),
            "has_html_report": a.get("has_html_report"),
            "has_pcap": a.get("has_pcap"),
        })
    return out


def flatten_summary(d):
    """Reduce VT's merged behaviour_summary to the triage-relevant fields.

    VT field names vary slightly across schema versions; we read the common ones
    and keep raw values (the analyst defangs in prose, per CLAUDE.md — tool output
    stays full-fidelity for grepping/pivoting)."""
    dropped = []
    for it in (d.get("dropped_files") or []):
        if isinstance(it, dict):
            dropped.append({"path": it.get("path"), "sha256": it.get("sha256")})

    dns = []
    for it in (d.get("dns_lookups") or []):
        if isinstance(it, dict):
            dns.append({"hostname": it.get("hostname"),
                        "resolved_ips": it.get("resolved_ips")})

    iptraffic = []
    for it in (d.get("ip_traffic") or []):
        if isinstance(it, dict):
            iptraffic.append({"ip": it.get("destination_ip"),
                              "port": it.get("destination_port"),
                              "proto": it.get("transport_layer_protocol")})

    http = []
    for it in (d.get("http_conversations") or []):
        if isinstance(it, dict):
            http.append({"url": it.get("url"),
                         "method": it.get("request_method"),
                         "status": it.get("response_status_code")})

    tls = []
    for it in (d.get("tls") or []):
        if isinstance(it, dict):
            tls.append({"sni": it.get("sni"), "ja3": it.get("ja3"),
                        "ja3s": it.get("ja3s")})

    regset = []
    for it in (d.get("registry_keys_set") or []):
        if isinstance(it, dict):
            regset.append({"key": it.get("key"), "value": it.get("value")})
        elif isinstance(it, str):
            regset.append({"key": it})

    # MITRE techniques live under one of two keys depending on schema version.
    techniques = []
    raw_tech = d.get("mitre_attack_techniques") or d.get("attack_techniques")
    if isinstance(raw_tech, list):
        for it in raw_tech:
            if isinstance(it, dict):
                techniques.append({"id": it.get("id"),
                                   "description": it.get("signature_description")
                                   or it.get("description"),
                                   "severity": it.get("severity")})
    elif isinstance(raw_tech, dict):
        for tid, val in raw_tech.items():
            desc = None
            if isinstance(val, list) and val and isinstance(val[0], dict):
                desc = val[0].get("description")
            techniques.append({"id": tid, "description": desc})

    sigs = []
    for it in (d.get("signature_matches") or []):
        if isinstance(it, dict):
            sigs.append({"description": it.get("description") or it.get("id"),
                         "severity": it.get("severity")})

    ids = []
    for it in (d.get("crowdsourced_ids_results") or []):
        if isinstance(it, dict):
            ids.append({"rule_msg": it.get("rule_msg"),
                        "severity": it.get("alert_severity"),
                        "category": it.get("rule_category")})

    network = {
        "dns_lookups": dns,
        "ip_traffic": iptraffic,
        "http": http,
        "tls": tls,
        "memory_iocs": {
            "urls": d.get("memory_pattern_urls") or [],
            "ips": d.get("memory_pattern_ips") or [],
            "domains": d.get("memory_pattern_domains") or [],
        },
    }
    host = {
        "files_dropped": dropped,
        "files_written": d.get("files_written") or [],
        "registry_set": regset,
        "registry_deleted": d.get("registry_keys_deleted") or [],
        "mutexes_created": d.get("mutexes_created") or [],
        "processes_created": d.get("processes_created") or [],
        "command_executions": d.get("command_executions") or [],
        "services_created": d.get("services_created") or [],
        "modules_loaded": d.get("modules_loaded") or [],
    }
    return network, host, {
        "attack_techniques": techniques,
        "sandbox_signatures": sigs,
        "ids_alerts": ids,
        "tags": d.get("tags") or [],
        "verdicts": d.get("verdicts") or [],
    }


def _cap_all(network, host):
    """Truncate every activity list to PER_LIST; collect drop counts for meta."""
    dropped_counts = {}
    for sect in (network, host):
        for k, v in list(sect.items()):
            if isinstance(v, list):
                sect[k], n = _truncate(v, PER_LIST)
                if n:
                    dropped_counts[k] = n
    return dropped_counts


def _has_dynamic(network, host, sandboxes):
    """True if any real runtime activity exists (vs a static-only report)."""
    if any(s.get("has_network") for s in sandboxes):
        return True
    if any(network[k] for k in ("dns_lookups", "ip_traffic", "http", "tls")):
        return True
    mem = network.get("memory_iocs", {})
    if mem.get("urls") or mem.get("ips") or mem.get("domains"):
        return True
    if any(host[k] for k in ("files_dropped", "files_written", "registry_set",
                             "mutexes_created", "processes_created",
                             "command_executions", "services_created")):
        return True
    return False


NOTE = (
    "VT behaviour ingestion: runtime activity from sandbox detonations VT ALREADY "
    "ran (nothing uploaded). Unlike the embedded-only stages (config/unpack/peinfo), "
    "these indicators were OBSERVED at runtime — promote a contacted host / dropped "
    "hash to 'confirmed live (per VT, <analysis_date>)', then feed resolved IPs and "
    "dropped hashes back into the IP-rep + VT-pivot stages. status=static_only means "
    "VT has only a STATIC report (no dynamic detonation) — a GAP, escalate to an own "
    "sandbox, do NOT read it as 'did nothing'. Observed by VT and possibly stale, "
    "not observed by you. Source tag [behavior]."
)


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: vt_behavior.py <hashes.json | sha256> <out.json>")
    in_arg, out_path = sys.argv[1], sys.argv[2]
    key = os.environ.get("VT_API_KEY", "")

    out = {"meta": {"source_tag": "[behavior]"}, "network": {}, "host": {},
           "verdict": {}}

    def finish(status, msg=None):
        out["meta"]["status"] = status
        json.dump(out, open(out_path, "w"), indent=2)
        print(f"    VT behaviour: {status}" + (f" — {msg}" if msg else ""))

    if not key:
        out["meta"]["error"] = "VT_API_KEY not set"
        return finish("unavailable", "VT_API_KEY not set (GAP)")

    try:
        sha256 = load_sha256(in_arg)
    except Exception as e:
        out["meta"]["error"] = f"cannot read input ({e})"
        return finish("error", f"cannot read input ({e})")

    if not sha256:
        out["meta"]["error"] = "no sha256 available"
        return finish("not_detonated", "no sha256 (sample likely not on VT)")

    out["meta"]["sha256"] = sha256
    budget = Budget(key, SLEEP)
    print(f"    fetching VT behaviour for {sha256[:16]}…")

    # 1) Enumerate sandboxes (tells dynamic from static; cheap, one call).
    try:
        sandboxes = fetch_sandboxes(budget, sha256)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            out["meta"]["note"] = NOTE
            return finish("not_detonated", "VT has no behaviour report (404)")
        out["meta"]["error"] = f"behaviours: {e}"
        return finish("error", f"behaviours: {e}")
    except Exception as e:
        out["meta"]["error"] = f"behaviours: {e}"
        return finish("error", f"behaviours: {e}")

    out["meta"]["sandboxes"] = sandboxes
    if not sandboxes:
        out["meta"]["note"] = NOTE
        out["meta"]["calls_used"] = budget.used
        return finish("not_detonated", "no sandbox reports on VT")

    # 2) Merged behaviour summary (the activity payload).
    try:
        summ = budget.get(
            f"{VT_BASE}/files/{urllib.parse.quote(sha256)}/behaviour_summary"
        ).get("data", {}) or {}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            summ = {}
        else:
            out["meta"]["error"] = f"behaviour_summary: {e}"
            out["meta"]["calls_used"] = budget.used
            return finish("error", f"behaviour_summary: {e}")
    except Exception as e:
        out["meta"]["error"] = f"behaviour_summary: {e}"
        out["meta"]["calls_used"] = budget.used
        return finish("error", f"behaviour_summary: {e}")

    network, host, verdict = flatten_summary(summ)
    dropped_counts = _cap_all(network, host)
    out["network"], out["host"], out["verdict"] = network, host, verdict
    out["meta"]["calls_used"] = budget.used
    out["meta"]["note"] = NOTE
    if dropped_counts:
        out["meta"]["truncated"] = dropped_counts
        out["meta"]["truncated_note"] = (
            f"activity lists capped at {PER_LIST}; see VT for the full set")

    if not _has_dynamic(network, host, sandboxes):
        names = ", ".join(s.get("sandbox_name") or "?" for s in sandboxes)
        return finish("static_only",
                      f"only static report(s) [{names}] — no dynamic data (GAP)")

    # Compact human echo for the triage console.
    nip = len(network["ip_traffic"])
    ndns = len(network["dns_lookups"])
    ndrop = len(host["files_dropped"])
    nproc = len(host["processes_created"])
    return finish(
        "found",
        f"{len(sandboxes)} sandbox report(s), {ndns} DNS / {nip} IP / "
        f"{ndrop} dropped / {nproc} proc(s)")


if __name__ == "__main__":
    main()
