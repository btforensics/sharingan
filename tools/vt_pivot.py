#!/usr/bin/env python3
"""VirusTotal pivoting for the Sharingan triage pipeline.

The triage already fetches the sample's own VT report (virustotal.json). This
stage *pivots* on it — turning one sample into the family/campaign around it:

  Forward footprint (relationships of the sample):
    - contacted_domains / contacted_ips  — the C2 / network footprint VT observed
    - dropped_files                      — children written at runtime
    - itw_urls                           — in-the-wild distribution URLs

  Reverse pivots (other samples that share an indicator → siblings):
    - <domain>/communicating_files       — other files that talk to the same host
    - <ip>/communicating_files           — other files that talk to the same IP
    - imphash search (intelligence)      — other files with the same import hash

The union of sibling SHA-256s (minus the sample itself) is the "campaign
expansion" — the set of related samples to triage next.

Design mirrors domain_rep.py: stdlib only (urllib), never raises into the
pipeline (every failure captured per-call), and stays inside the VT public-tier
rate limit by capping total calls and pacing them. Reverse pivots and the
imphash search require a privileged VT key; on the public tier they return a
captured 403 rather than crashing — that's expected and recorded in meta.

Usage:  vt_pivot.py <virustotal.json> <out.json>
Env:    VT_API_KEY                (required)
        VT_PIVOT_MAX_CALLS        (default 14)  total VT requests this stage may make
        VT_PIVOT_SLEEP            (default 16)  seconds between calls (public tier ~4/min)
        VT_PIVOT_PER_REL          (default 5)   items kept per forward relationship
        VT_PIVOT_FANOUT           (default 3)   domains + ips to reverse-pivot on (each)
"""
import json
import os
import sys
import time
import urllib.parse
import urllib.request

VT_BASE = "https://www.virustotal.com/api/v3"

MAX_CALLS = int(os.environ.get("VT_PIVOT_MAX_CALLS", "14"))
SLEEP = float(os.environ.get("VT_PIVOT_SLEEP", "16"))
PER_REL = int(os.environ.get("VT_PIVOT_PER_REL", "5"))
FANOUT = int(os.environ.get("VT_PIVOT_FANOUT", "3"))


class Budget:
    """Tracks the VT call budget and paces requests to respect the rate limit."""

    def __init__(self, key, maxcalls, sleep):
        self.key = key
        self.max = maxcalls
        self.sleep = sleep
        self.used = 0
        self._first = True

    def get(self, url):
        """One paced GET. Returns parsed JSON or raises (caller captures)."""
        if self.used >= self.max:
            raise RuntimeError(f"VT call budget exhausted ({self.max})")
        if not self._first and self.sleep > 0:
            time.sleep(self.sleep)
        self._first = False
        self.used += 1
        req = urllib.request.Request(url, headers={"x-apikey": self.key})
        with urllib.request.urlopen(req, timeout=40) as r:
            return json.loads(r.read())


def _stats_brief(attrs):
    """Compact a VT file object's attributes down to the useful triage fields."""
    s = attrs.get("last_analysis_stats") or {}
    ptc = (attrs.get("popular_threat_classification") or {})
    return {
        "meaningful_name": attrs.get("meaningful_name"),
        "type_description": attrs.get("type_description"),
        "malicious": s.get("malicious"),
        "total": sum(s.values()) if s else None,
        "suggested_threat_label": ptc.get("suggested_threat_label"),
        "first_submission_date": attrs.get("first_submission_date"),
        "times_submitted": attrs.get("times_submitted"),
    }


def rel(budget, collection, obj_id, name, limit):
    """Fetch one relationship collection (e.g. files/<id>/contacted_domains).

    Returns {"items": [...], "count": n} or {"error": "..."}. Each item keeps
    its id plus a brief of attributes when present, so the analyst (and the
    skill) get context without extra per-object calls.
    """
    url = (f"{VT_BASE}/{collection}/{urllib.parse.quote(obj_id)}/{name}"
           f"?limit={limit}")
    try:
        data = budget.get(url).get("data", [])
    except Exception as e:
        return {"error": str(e)}
    items = []
    for o in data:
        attrs = o.get("attributes", {}) or {}
        item = {"id": o.get("id"), "type": o.get("type")}
        if o.get("type") == "file":
            item.update(_stats_brief(attrs))
        elif o.get("type") == "url":
            item["url"] = attrs.get("url")
        items.append(item)
    return {"items": items, "count": len(items)}


def imphash_search(budget, imphash, limit):
    """Intelligence search for same-imphash files. Premium-only; on the public
    tier this returns a captured 403 (recorded, not raised)."""
    q = urllib.parse.quote(f'imphash:"{imphash}"')
    url = f"{VT_BASE}/intelligence/search?query={q}&limit={limit}"
    try:
        data = budget.get(url).get("data", [])
    except Exception as e:
        return {"error": str(e)}
    return {"items": [{"id": o.get("id"), **_stats_brief(o.get("attributes", {}))}
                      for o in data if o.get("type") == "file"],
            "count": len(data)}


def load_sample(vt_path):
    """Pull sha256, imphash, name from the existing virustotal.json."""
    with open(vt_path, encoding="utf-8") as f:
        d = json.load(f)
    attrs = d.get("data", {}).get("attributes", {})
    sha256 = d.get("data", {}).get("id") or attrs.get("sha256")
    imphash = (attrs.get("pe_info") or {}).get("imphash")
    return sha256, imphash, attrs.get("meaningful_name")


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: vt_pivot.py <virustotal.json> <out.json>")
    vt_path, out_path = sys.argv[1], sys.argv[2]
    key = os.environ.get("VT_API_KEY", "")

    out = {"meta": {}, "forward": {}, "reverse": {}, "siblings": []}

    if not key:
        out["meta"]["error"] = "VT_API_KEY not set"
        json.dump(out, open(out_path, "w"), indent=2)
        print("    VT pivot skipped: VT_API_KEY not set")
        return

    try:
        sha256, imphash, name = load_sample(vt_path)
    except Exception as e:
        out["meta"]["error"] = f"cannot read virustotal.json ({e})"
        json.dump(out, open(out_path, "w"), indent=2)
        print(f"    VT pivot skipped: cannot read virustotal.json ({e})")
        return

    if not sha256:
        out["meta"]["error"] = "no sha256 in virustotal.json (sample likely not on VT)"
        json.dump(out, open(out_path, "w"), indent=2)
        print("    VT pivot skipped: sample not found on VT (no sha256)")
        return

    budget = Budget(key, MAX_CALLS, SLEEP)
    out["meta"].update({"sha256": sha256, "imphash": imphash, "name": name,
                        "max_calls": MAX_CALLS})
    print(f"    pivoting on {sha256[:16]}…  (imphash={imphash or 'n/a'}, "
          f"budget={MAX_CALLS} calls @ {SLEEP:g}s)")

    # ── Forward footprint: relationships of the sample itself ──
    for relname, lim in (("contacted_domains", PER_REL),
                         ("contacted_ips", PER_REL),
                         ("dropped_files", PER_REL),
                         ("itw_urls", PER_REL)):
        out["forward"][relname] = rel(budget, "files", sha256, relname, lim)

    # Pick the strongest pivot indicators from the forward footprint.
    def ids(relname):
        r = out["forward"].get(relname, {})
        return [i["id"] for i in r.get("items", []) if i.get("id")]

    pivot_domains = ids("contacted_domains")[:FANOUT]
    pivot_ips = ids("contacted_ips")[:FANOUT]

    siblings = {}  # sha256 -> brief (deduped, sample itself excluded)

    def harvest(rel_result, via):
        for it in rel_result.get("items", []):
            sid = it.get("id")
            if sid and sid != sha256 and sid not in siblings:
                siblings[sid] = {**{k: v for k, v in it.items() if k != "id"},
                                 "via": via}

    # ── Reverse pivots: who else touches these indicators (siblings) ──
    out["reverse"]["communicating_files_by_domain"] = {}
    for dom in pivot_domains:
        if budget.used >= budget.max:
            break
        r = rel(budget, "domains", dom, "communicating_files", PER_REL)
        out["reverse"]["communicating_files_by_domain"][dom] = r
        harvest(r, f"domain:{dom}")

    out["reverse"]["communicating_files_by_ip"] = {}
    for ip in pivot_ips:
        if budget.used >= budget.max:
            break
        r = rel(budget, "ip_addresses", ip, "communicating_files", PER_REL)
        out["reverse"]["communicating_files_by_ip"][ip] = r
        harvest(r, f"ip:{ip}")

    # dropped_files are also siblings of interest (children of this sample)
    harvest(out["forward"].get("dropped_files", {}), "dropped_by_sample")

    # ── imphash family search (premium; captured-403 on public tier) ──
    if imphash and budget.used < budget.max:
        r = imphash_search(budget, imphash, PER_REL)
        out["reverse"]["imphash_search"] = r
        harvest(r, f"imphash:{imphash}")
    elif imphash:
        out["reverse"]["imphash_search"] = {"error": "skipped: call budget exhausted"}
    else:
        out["reverse"]["imphash_search"] = {"error": "no imphash in sample PE"}

    out["siblings"] = [{"sha256": k, **v} for k, v in siblings.items()]
    out["meta"]["calls_used"] = budget.used
    out["meta"]["sibling_count"] = len(out["siblings"])
    out["meta"]["note"] = (
        "Forward relationships are this sample's own footprint (high confidence). "
        "Reverse pivots (communicating_files, imphash_search) surface SIBLING "
        "samples sharing an indicator — treat each as a lead to triage, not a "
        "confirmed family member until corroborated. communicating_files / "
        "intelligence search require a privileged VT key; an 'error' with 403/"
        "Forbidden means the public tier gated it, NOT that no siblings exist. "
        f"Capped at {MAX_CALLS} VT calls, paced {SLEEP:g}s apart for the rate limit."
    )

    json.dump(out, open(out_path, "w"), indent=2)
    print(f"    wrote {out_path}  ({len(out['siblings'])} sibling(s), "
          f"{budget.used} VT call(s) used)")


if __name__ == "__main__":
    main()
