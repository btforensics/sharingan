#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# Sharingan — automated config / C2 extraction (roadmap N2)
#
# Runs the ConfigExtractor (CCCS) framework with the CAPE + rat-king parser
# sets over a binary. For a RECOGNIZED family it statically rips the embedded
# config block — C2 hosts/ports, encryption keys, campaign/botnet IDs, mutex,
# install paths — out of the sample, even when those values are encrypted and
# therefore invisible to strings/floss.
#
# This is NOT a reputation/IOC database lookup: it carries per-family *parsers*
# (a YARA recognizer + the family's decrypt/parse logic), so the values it
# emits come out of THIS sample and may be brand new (never reported anywhere).
#
# Usage:  config_extract.py <sample> <out_json>
#   (Run with the project venv python — configextractor-py lives there.)
#
# Output (out_json):
#   status: extracted | no_match | unavailable | error
#   - extracted  : >=1 family parser produced a config
#   - no_match   : framework ran, nothing matched (a real "no embedded config")
#   - unavailable: configextractor-py / parser packs not installed (a GAP, not a
#                  clean result — note it and rebuild the venv via setup-env.sh)
#   - error      : the extractor raised
#
# Honesty: recovers EMBEDDED indicators only. Promote extracted C2/keys to High
# *intent*, not "confirmed live" — only a sandbox confirms behaviour. Values are
# stored raw (faithful tool output, like domain_rep.json); the analyst/skill
# defangs them in any prose per CLAUDE.md.
# ─────────────────────────────────────────────────────────────────────────────
import json
import logging
import os
import sys


def _discover_extractor_dirs():
    """Locate installed parser packs + any extra dirs from $CX_EXTRACTOR_DIRS."""
    dirs = []
    for mod in ("cape_parsers", "rat_king_parser"):
        try:
            m = __import__(mod)
            dirs.append(os.path.dirname(m.__file__))
        except Exception:
            pass
    extra = os.environ.get("CX_EXTRACTOR_DIRS", "")
    dirs += [d for d in extra.split(":") if d and os.path.isdir(d)]
    return dirs


def _flatten_indicators(cfg):
    """Pull the actionable fields out of a MACO config dict into a flat view."""
    ind = {
        "c2": [], "urls": [], "domains": [], "ips": [], "ports": [],
        "mutex": [], "campaign_id": [], "encryption": [],
        "registry": [], "paths": [], "user_agents": [],
    }

    def add(key, val):
        if val is None:
            return
        if isinstance(val, (list, tuple, set)):
            for v in val:
                add(key, v)
            return
        val = val if isinstance(val, str) else str(val)
        if val and val not in ind[key]:
            ind[key].append(val)

    # HTTP / HTTPS endpoints
    for h in cfg.get("http", []) or []:
        host, port = h.get("hostname"), h.get("port")
        add("urls", h.get("uri"))
        if host:
            (add("ips", host) if _looks_ip(host) else add("domains", host))
            add("c2", f"{host}:{port}" if port else host)
        add("ports", port)
        add("user_agents", h.get("user_agent"))

    # Raw TCP/UDP connections
    for conn in (cfg.get("tcp", []) or []) + (cfg.get("udp", []) or []):
        host = conn.get("server_domain") or conn.get("server_ip")
        port = conn.get("server_port")
        if conn.get("server_ip"):
            add("ips", conn["server_ip"])
        if conn.get("server_domain"):
            add("domains", conn["server_domain"])
        if host:
            add("c2", f"{host}:{port}" if port else host)
        add("ports", port)

    # DNS records the config carries
    for d in cfg.get("dns", []) or []:
        add("domains", d.get("hostname"))
        add("ips", d.get("ip"))

    add("mutex", cfg.get("mutex"))
    add("campaign_id", cfg.get("campaign_id"))
    add("registry", [r.get("key") if isinstance(r, dict) else r for r in (cfg.get("registry") or [])])
    add("paths", [p.get("path") if isinstance(p, dict) else p for p in (cfg.get("paths") or [])])
    for enc in cfg.get("encryption", []) or []:
        if isinstance(enc, dict):
            ind["encryption"].append({k: enc.get(k) for k in ("algorithm", "key", "iv", "mode", "nonce", "salt") if enc.get(k)})

    return {k: v for k, v in ind.items() if v}


def _looks_ip(s):
    parts = str(s).split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def main():
    if len(sys.argv) != 3:
        print("Usage: config_extract.py <sample> <out_json>", file=sys.stderr)
        sys.exit(2)
    sample, out_json = sys.argv[1], sys.argv[2]
    logging.disable(logging.CRITICAL)  # keep framework chatter out of the pipeline

    out = {"status": "no_match", "sample": os.path.basename(sample), "matches": []}

    try:
        from configextractor.main import ConfigExtractor
    except Exception as e:
        out.update(status="unavailable",
                   error=f"configextractor-py not importable ({e}); run tools/setup-env.sh")
        _write(out, out_json)
        return

    dirs = _discover_extractor_dirs()
    out["extractor_dirs"] = dirs
    if not dirs:
        out.update(status="unavailable",
                   error="no parser packs found (cape_parsers / rat_king_parser); run tools/setup-env.sh")
        _write(out, out_json)
        return

    try:
        cx = ConfigExtractor(dirs)
        out["parsers_loaded"] = len(cx.parsers)
        results = cx.run_parsers(sample)  # {framework: [ {id, yara_hits, config, exception?} ]}
    except Exception as e:
        out.update(status="error", error=f"{type(e).__name__}: {e}")
        _write(out, out_json)
        return

    for framework, res_list in (results or {}).items():
        for res in res_list:
            if res.get("exception"):
                out["matches"].append({"parser_id": res.get("id"), "framework": framework,
                                       "exception": res["exception"]})
                continue
            cfg = res.get("config", {}) or {}
            if not cfg:
                continue
            out["matches"].append({
                "parser_id": res.get("id"),
                "framework": framework,
                "family": cfg.get("family") or res.get("id"),
                "version": cfg.get("version"),
                "category": cfg.get("category"),
                "yara_hits": res.get("yara_hits", []),
                "indicators": _flatten_indicators(cfg),
                "config": cfg,  # full MACO config, faithful/raw
            })

    if any("indicators" in m or "config" in m for m in out["matches"]):
        out["status"] = "extracted"
    _write(out, out_json)


def _write(out, path):
    with open(path, "w") as f:
        json.dump(out, f, indent=2, default=str)
    fams = [m.get("family") for m in out.get("matches", []) if m.get("family")]
    if out["status"] == "extracted":
        print(f"    config extracted: {', '.join(fams) or '(see config.json)'}")
    elif out["status"] == "no_match":
        n = out.get("parsers_loaded", "?")
        print(f"    no embedded config matched ({n} family parsers tried)")
    else:
        print(f"    config extraction {out['status']}: {out.get('error', '')}")


if __name__ == "__main__":
    main()
