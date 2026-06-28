#!/usr/bin/env python3
"""
collect_strings.py — unify a flat strings list for downstream IP / domain
extraction, so the same extractors work on PE and non-PE samples alike.

Reads floss.json (rich, nested FLOSS shape) when present, else strings.txt
(universal `strings` output), and writes strings.json = {"strings": [...]}.

This also fixes a latent bug: the old inline IP extractor did data.get('strings')
on the nested FLOSS object (a dict) and iterated its keys, not the strings —
so IP extraction silently found nothing. Everything now reads this flat file.

Usage:  collect_strings.py <report_dir>
Never raises into the pipeline.
"""
import json, os, sys


def from_floss(path):
    d = json.load(open(path, encoding="utf-8", errors="replace"))
    buckets = []
    s = d.get("strings")
    if isinstance(s, dict):                       # new nested shape
        for v in s.values():
            if isinstance(v, list):
                buckets.append(v)
    for key in ("static_strings", "decoded_strings", "stack_strings",
                "tight_strings", "strings"):      # old flat shapes
        v = d.get(key)
        if isinstance(v, list):
            buckets.append(v)
    out = []
    for b in buckets:
        for x in b:
            out.append(x.get("string", "") if isinstance(x, dict) else str(x))
    return out


def main():
    if len(sys.argv) < 2:
        print("Usage: collect_strings.py <report_dir>", file=sys.stderr)
        sys.exit(1)
    rd = sys.argv[1]
    floss, txt = os.path.join(rd, "floss.json"), os.path.join(rd, "strings.txt")
    strings = []
    try:
        if os.path.getsize(floss) > 0:
            strings = from_floss(floss)
    except Exception:
        strings = []
    if not strings:
        try:
            strings = [l.rstrip("\n") for l in
                       open(txt, encoding="utf-8", errors="replace")]
        except Exception:
            strings = []
    json.dump({"strings": strings},
              open(os.path.join(rd, "strings.json"), "w", encoding="utf-8"))
    print(f"    collected {len(strings)} strings -> strings.json")


if __name__ == "__main__":
    main()
