#!/usr/bin/env python3
"""Domain / C2 reputation enrichment for the Sharingan triage pipeline.

Extracts domains + URL hosts from a FLOSS json artifact, filters out file
names / IPs / known-benign infra, then checks each against:
  - ThreatFox  (abuse.ch)  — known-IOC / malware-family attribution
  - URLhaus    (abuse.ch)  — malware-distribution URLs for the host
  - VirusTotal domains API — multi-engine verdict + passive DNS resolutions

abuse.ch ThreatFox/URLhaus use the unified abuse.ch Auth-Key (same key as
MalwareBazaar). VT-domain reuses the VT key. Writes <out> as JSON. Never
raises into the pipeline — every failure is captured per-service.

Usage:  domain_rep.py <floss.json> <out.json>
Env:    ABUSECH_API_KEY (falls back to BAZAAR_API_KEY), VT_API_KEY
"""
import json
import os
import re
import sys
import urllib.parse
import urllib.request

ABUSE_CAP = 10          # max domains sent to abuse.ch (generous limits)
VT_CAP = 4              # VT public tier is ~4 req/min — keep at/below it

# Extensions that match a domain regex but are really file names / paths.
FILE_EXT = {
    "dll", "exe", "dat", "inf", "sys", "tmp", "bin", "sav", "log", "ini",
    "bat", "cmd", "ps1", "vbs", "scr", "db", "ocx", "cpl", "drv", "txt",
    "json", "xml", "cfg", "lnk", "url", "ico", "png", "jpg", "gif",
    "php", "htm", "html", "asp", "aspx", "jsp", "js", "css", "cgi", "do",
}
# Benign infrastructure we don't need to score (extend as needed).
SKIP_HOSTS = {
    "microsoft.com", "www.microsoft.com", "windows.com", "msftncsi.com",
    "schemas.xmlsoap.org", "w3.org", "www.w3.org", "verisign.com",
    "example.com", "localhost",
}

DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)
URL_RE = re.compile(r"https?://[^\s\"'<>)\]}]+", re.IGNORECASE)


def gather_strings(data):
    """Pull strings from both old (top-level) and new (nested) FLOSS shapes."""
    buckets = []
    strings = data.get("strings")
    if isinstance(strings, dict):
        for v in strings.values():
            if isinstance(v, list):
                buckets.append(v)
    for key in ("strings", "static_strings", "decoded_strings",
                "stack_strings", "tight_strings"):
        v = data.get(key)
        if isinstance(v, list):
            buckets.append(v)
    out = []
    for b in buckets:
        for s in b:
            out.append(s.get("string", "") if isinstance(s, dict) else str(s))
    return out


def _valid(host, strict):
    """Shared sanity checks. strict=True adds rules for bare-string matches,
    which are far noisier than hosts pulled from real http(s):// URLs."""
    if host in SKIP_HOSTS:
        return False
    if host.replace(".", "").isdigit():          # bare IP — handled elsewhere
        return False
    labels = host.split(".")
    if len(labels) < 2:                           # must be a FQDN, not a fragment
        return False                              # (e.g. FLOSS partial "http://bu")
    tld = labels[-1]
    if tld in FILE_EXT:                           # file name / web path, not a host
        return False
    if not tld.isalpha() or not (2 <= len(tld) <= 18):
        return False
    if strict:
        # A bare token like "5.gm" or "ds9t.bx" is almost always FLOSS noise;
        # require a substantial registrable label and overall length.
        registrable = labels[-2] if len(labels) >= 2 else ""
        if len(registrable) < 5 or len(host) < 8:
            return False
    return True


def extract_domains(text):
    """Return (url_hosts, bare_candidates). URL-derived hosts are high
    confidence (they appeared inside an http(s):// string); bare matches are
    lower confidence and heavily filtered."""
    url_hosts = set()
    for u in URL_RE.findall(text):
        try:
            h = urllib.parse.urlparse(u).hostname
            if h:
                url_hosts.add(h.lower())
        except ValueError:
            pass
    bare = {m.lower() for m in DOMAIN_RE.findall(text)}

    high = sorted(h for h in url_hosts if _valid(h, strict=False))
    cand = sorted(h for h in bare
                  if h not in url_hosts and _valid(h, strict=True))

    # Drop FLOSS partial-decode artifacts: a host with the same name but a TLD
    # that is a strict prefix of another host's TLD (e.g. "x.co" vs "x.com").
    def split_tld(h):
        p = h.split(".")
        return ".".join(p[:-1]), p[-1]

    allh = set(high) | set(cand)
    partials = set()
    for h in allh:
        base, tld = split_tld(h)
        for h2 in allh:
            if h2 == h:
                continue
            b2, t2 = split_tld(h2)
            if b2 == base and t2 != tld and t2.startswith(tld):
                partials.add(h)
                break
    high = [h for h in high if h not in partials]
    cand = [h for h in cand if h not in partials]
    return high, cand, sorted(partials)


def threatfox(domain, key):
    req = urllib.request.Request(
        "https://threatfox-api.abuse.ch/api/v1/",
        data=json.dumps({"query": "search_ioc", "search_term": domain}).encode(),
        headers={"Auth-Key": key, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def urlhaus(domain, key):
    req = urllib.request.Request(
        "https://urlhaus-api.abuse.ch/v1/host/",
        data=urllib.parse.urlencode({"host": domain}).encode(),
        headers={"Auth-Key": key},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def vt_domain(domain, key):
    req = urllib.request.Request(
        "https://www.virustotal.com/api/v3/domains/" + urllib.parse.quote(domain),
        headers={"x-apikey": key},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        a = json.loads(r.read()).get("data", {}).get("attributes", {})
    dns = [rec for rec in a.get("last_dns_records", [])
           if rec.get("type") in ("A", "AAAA", "CNAME")][:10]
    return {
        "last_analysis_stats": a.get("last_analysis_stats"),
        "reputation": a.get("reputation"),
        "categories": a.get("categories"),
        "last_dns_records": dns,
        "registrar": a.get("registrar"),
        "creation_date": a.get("creation_date"),
    }


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: domain_rep.py <floss.json> <out.json>")
    floss_path, out_path = sys.argv[1], sys.argv[2]
    abuse_key = os.environ.get("ABUSECH_API_KEY") or os.environ.get("BAZAAR_API_KEY", "")
    vt_key = os.environ.get("VT_API_KEY", "")

    try:
        with open(floss_path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"    domain reputation skipped: cannot read floss.json ({e})")
        return

    url_hosts, candidates, partials = extract_domains("\n".join(gather_strings(data)))
    # URL-derived hosts first (high confidence), then bare candidates.
    ordered = url_hosts + [c for c in candidates if c not in url_hosts]
    if not ordered:
        print("    no domains found in strings")
        json.dump({"meta": {"domains_found": [], "url_hosts": [],
                            "bare_candidates": []}, "results": {}},
                  open(out_path, "w"), indent=2)
        return

    queried = ordered[:ABUSE_CAP]
    print(f"    {len(url_hosts)} URL host(s), {len(candidates)} bare candidate(s); "
          f"querying {len(queried)}: {queried}")
    results = {}
    for dom in queried:
        entry = {}
        for name, fn in (("threatfox", threatfox), ("urlhaus", urlhaus)):
            try:
                entry[name] = fn(dom, abuse_key)
            except Exception as e:
                entry[name] = {"error": str(e)}
        results[dom] = entry
    for dom in queried[:VT_CAP]:
        try:
            results[dom]["virustotal_domain"] = vt_domain(dom, vt_key)
        except Exception as e:
            results[dom]["virustotal_domain"] = {"error": str(e)}

    meta = {
        "url_hosts": url_hosts,
        "bare_candidates": candidates,
        "dropped_partial_decodes": partials,
        "queried_abusech": queried,
        "queried_vt": queried[:VT_CAP],
        "vt_skipped_rate_limit": queried[VT_CAP:],
        "not_queried_over_cap": ordered[ABUSE_CAP:],
        "note": (f"URL-derived hosts are high confidence; bare_candidates are "
                 f"filtered FLOSS-string matches and may include noise. VT public "
                 f"API ~4 req/min: only the first {VT_CAP} queried domains were sent "
                 f"to VT-domain. abuse.ch covered up to {ABUSE_CAP}; any beyond that "
                 f"are listed in not_queried_over_cap."),
    }
    json.dump({"meta": meta, "results": results}, open(out_path, "w"), indent=2)
    print(f"    wrote {out_path}")


if __name__ == "__main__":
    main()
