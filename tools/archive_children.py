#!/usr/bin/env python3
"""archive_children.py — list extracted archive children worth deep analysis.

Reads an archive.json (produced by nonpe.py's archive handler) and prints one
`<relpath>\t<category>` line per extracted child whose type warrants running the
full pipeline on it. triage.sh consumes this to auto-recurse into children,
writing each child's artifacts into children/<name>/ under the parent report dir
(so an archive's real payload — a doc/PE/script — is analyzed end-to-end with no
stray top-level report folder).

Children classified as 'unknown' are skipped here (universal strings/yara on an
unidentified blob is low value and noisy); the analyst can still triage them by
hand. Everything typed — pe/dotnet/elf/office_*/pdf/lnk/script/html/email and
nested archive — is emitted.

Usage:  archive_children.py <archive.json>
"""
import json
import sys

SKIP = {"unknown", ""}


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: archive_children.py <archive.json>")
    try:
        with open(sys.argv[1], encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return  # no/again-unreadable archive.json → nothing to recurse into
    for e in data.get("extracted", []):
        cat = (e.get("category") or "").strip()
        path = (e.get("path") or "").strip()
        if path and cat not in SKIP:
            print(f"{path}\t{cat}")


if __name__ == "__main__":
    main()
