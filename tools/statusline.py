#!/usr/bin/env python3
"""
Sharingan status line for Claude Code.

Claude Code pipes a JSON blob to this script on stdin every time the status
line refreshes. We render a compact dashboard:

  <model> | ctx <used>/<limit> (<pct>) | $<cost> | +adds/-dels | <dur> | <branch>

Token / context numbers are read from the live transcript (more accurate than
what the status JSON exposes). Everything is wrapped in try/except so a parse
error degrades gracefully instead of blanking the status line.
"""
import sys
import json
import os
import subprocess

# ---- ANSI helpers ---------------------------------------------------------
RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
SEP = f"{DIM} | {RESET}"


def c(text, code):
    return f"\033[{code}m{text}{RESET}"


def human_tokens(n):
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.0f}k"
    return str(n)


def human_duration(ms):
    s = int(ms / 1000)
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m"


# ---- read input -----------------------------------------------------------
try:
    data = json.load(sys.stdin)
except Exception:
    data = {}

model = data.get("model", {}) or {}
model_id = model.get("id", "") or ""
model_name = model.get("display_name", "?") or "?"

cost = data.get("cost", {}) or {}
cost_usd = cost.get("total_cost_usd", 0) or 0
dur_ms = cost.get("total_duration_ms", 0) or 0
adds = cost.get("total_lines_added", 0) or 0
dels = cost.get("total_lines_removed", 0) or 0

workspace = data.get("workspace", {}) or {}
cwd = workspace.get("current_dir") or data.get("cwd") or os.getcwd()
version = data.get("version", "")
output_style = (data.get("output_style", {}) or {}).get("name", "")
transcript_path = data.get("transcript_path", "")

# Context window limit: [1m] / "(1M context)" models get 1,000,000.
limit = 200_000
if "[1m]" in model_id.lower() or "1m" in model_name.lower():
    limit = 1_000_000

# ---- parse transcript for the latest context usage ------------------------
ctx_tokens = 0
try:
    if transcript_path and os.path.exists(transcript_path):
        with open(transcript_path, "r", errors="ignore") as f:
            lines = f.readlines()
        # Walk backwards to the most recent main-chain assistant usage.
        for line in reversed(lines):
            line = line.strip()
            if not line or '"usage"' not in line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if obj.get("isSidechain"):
                continue
            usage = (obj.get("message", {}) or {}).get("usage")
            if not usage:
                continue
            ctx_tokens = (
                (usage.get("input_tokens") or 0)
                + (usage.get("cache_read_input_tokens") or 0)
                + (usage.get("cache_creation_input_tokens") or 0)
            )
            break
except Exception:
    ctx_tokens = 0

# ---- git branch + dirty state ---------------------------------------------
git_part = ""
try:
    branch = subprocess.run(
        ["git", "-C", cwd, "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True, text=True, timeout=1,
    )
    if branch.returncode == 0:
        name = branch.stdout.strip()
        status = subprocess.run(
            ["git", "-C", cwd, "status", "--porcelain"],
            capture_output=True, text=True, timeout=1,
        )
        dirty = "*" if status.stdout.strip() else ""
        git_part = c(f" {name}{dirty}", "35")  # magenta
except Exception:
    git_part = ""

# ---- assemble -------------------------------------------------------------
parts = []

# Model (the headline — sharingan red)
parts.append(c(f"👁 {model_name}", "1;31"))

# Context usage with severity color
if ctx_tokens:
    pct = ctx_tokens / limit * 100
    if pct < 50:
        col = "32"      # green
    elif pct < 80:
        col = "33"      # yellow
    else:
        col = "1;31"    # bold red
    ctx_str = f"ctx {human_tokens(ctx_tokens)}/{human_tokens(limit)} ({pct:.0f}%)"
    parts.append(c(ctx_str, col))

# Cost
parts.append(c(f"${cost_usd:.4f}", "36"))  # cyan

# Lines changed
if adds or dels:
    parts.append(f"{c(f'+{adds}', '32')}{DIM}/{RESET}{c(f'-{dels}', '31')}")

# Wall-clock duration
if dur_ms:
    parts.append(c(human_duration(dur_ms), "34"))  # blue

# Current directory basename
parts.append(c(os.path.basename(cwd.rstrip('/')) or '/', "2"))

# Git
if git_part:
    parts.append(git_part)

# Output style (only if non-default)
if output_style and output_style != "default":
    parts.append(c(f"◈ {output_style}", "2"))

sys.stdout.write(SEP.join(parts))
