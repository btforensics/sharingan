#!/usr/bin/env python3
"""Cross-platform exporter for analyze-sample reports.

Converts an analysis_report.md into HTML / PDF / DOCX. Works on Windows
(native PowerShell/cmd), Linux, and macOS. The .md stays the canonical
artifact — everything else is exported *from* it, never replacing it.

Engines (single external dependency = pandoc):
  HTML  : pandoc  (md -> styled, self-contained .html)
  DOCX  : pandoc  (md -> .docx)
  PDF   : pandoc (md -> .html) then a headless browser prints it to PDF.
          Browser is auto-detected: Edge on Windows (built in, no install),
          Chrome/Chromium/Brave elsewhere. No LaTeX / weasyprint needed.

Usage:
  python export_report.py <report.md> --to html,pdf,docx
  python export_report.py <report.md> --to all
Output files land next to the .md (analysis_report.{html,pdf,docx}).

Override browser detection with the BROWSER_PDF env var (full path to the exe).
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def report_subject(md: Path) -> str:
    """A human title for the report: the sample name from the report dir
    (reports/<sample>_<YYYYmmdd_HHMMSS>/), stripped of the timestamp."""
    name = re.sub(r"_\d{8}_\d{6}$", "", md.parent.name)
    return name or md.stem


# Branded masthead injected at the top of the body (replaces pandoc's redundant
# filename-as-title block, which CSS hides). {SUBJECT} = the sample name.
MASTHEAD_TMPL = """<div class="sg-masthead">
  <div class="sg-eye" aria-hidden="true"></div>
  <div class="sg-brand">
    <div class="sg-word">SHARINGAN</div>
    <div class="sg-tag">See through the disguise · AI-assisted malware triage</div>
  </div>
  <div class="sg-meta">{SUBJECT}</div>
</div>
"""


# Inserted at the top of the Hypothesis List section so every report explains
# its own confidence badges (the colours map to the CLAUDE.md confidence rubric).
CONF_LEGEND_HTML = """<div class="conf-legend">
  <div class="conf-legend-title">Confidence key — the badge grades the behavioural claim, not whether an IOC is worth hunting</div>
  <ul>
    <li><span class="conf conf-confirmed">Confirmed / High</span> Strongly corroborated — ≥2 independent sources agree, read directly from code, or observed at runtime. Stated as fact.</li>
    <li><span class="conf conf-intent">High&nbsp;intent / Medium</span> <strong>High intent:</strong> the artifact is extracted from the sample itself (hardcoded C2 URLs, drop paths, Run keys, mutexes) — <strong>high-fidelity and ready to hunt now</strong>. “Intent” only means the sample is <em>configured</em> to do this; that it actually executed wasn't observed (a sandbox confirms that). <strong>Medium:</strong> a claim resting on a single / weak source — corroborate the claim itself.</li>
    <li><span class="conf conf-investigate">Investigate / Low</span> Suggestive but unconfirmed — carries a named next step to prove or disprove it.</li>
  </ul>
  <div class="conf-legend-note"><strong>For hunters:</strong> every indicator in the IOC table is extracted from this sample and is safe to sweep your telemetry with immediately. The badges qualify the <em>narrative</em> (“it beacons to X”, “it drops Y” — whether we <em>watched</em> it happen), not whether the indicator itself is real.</div>
</div>
"""


def style_hypotheses(html_path: Path):
    """Post-process: turn each '### Hn — claim (VERDICT)' heading into a
    color-coded card with a confidence badge so verdicts are scannable, and
    insert a confidence-key legend at the top of the Hypothesis List section."""
    def level(tag: str) -> str:
        t = tag.lower()
        if "confirm" in t:            return "confirmed"
        if "investigate" in t:        return "investigate"
        if "intent" in t:             return "intent"
        if "critical" in t:           return "confirmed"
        if "high" in t:               return "high"
        if "medium" in t:             return "medium"
        if "low" in t:                return "low"
        return "high"

    def repl(m):
        attrs = m.group(1)
        claim = re.sub(r"\s+", " ", m.group(2)).strip()
        tag = re.sub(r"\s+", " ", m.group(3)).strip()
        lvl = level(tag)
        return (f'<h3{attrs} class="hyp hyp-{lvl}">{claim} '
                f'<span class="conf conf-{lvl}">{tag}</span></h3>')

    html = html_path.read_text(encoding="utf-8")
    # headings look like: <h3 id="...">H1 — claim text (CONFIRMED)</h3>
    # pandoc wraps the heading text across newlines, so DOTALL is required.
    html = re.sub(r'<h3([^>]*)>\s*(H\d+\b.*?)\s*\(([^()<]+)\)\s*</h3>',
                  repl, html, flags=re.DOTALL)
    # drop the confidence-key legend in right after the Hypothesis List heading
    html, n = re.subn(r'(<h2[^>]*>\s*Hypothes[^<]*</h2>)',
                      r'\1\n' + CONF_LEGEND_HTML, html, count=1, flags=re.I)
    html_path.write_text(html, encoding="utf-8")

CSS = r"""
@page { size: A4; margin: 1.6cm 1.4cm;
        @bottom-right { content: "Page " counter(page) " / " counter(pages);
                        font-size: 8pt; color:#888; } }
body { font-family: "Segoe UI", "DejaVu Sans", Arial, sans-serif; font-size: 9.5pt;
       line-height: 1.45; color:#1a1a1a; }
h1 { font-size: 19pt; color:#0b3d6b; border-bottom:3px solid #0b3d6b; padding-bottom:6px; }
h2 { font-size: 13pt; color:#0b3d6b; border-bottom:1px solid #c9d6e3; padding-bottom:3px;
     margin-top:1.4em; }
h3 { font-size: 10.5pt; color:#11507f; margin-top:1em; }
table { border-collapse: collapse; width:100%; margin:0.7em 0; table-layout: fixed; }
th, td { border:1px solid #c9d6e3; padding:4px 6px; text-align:left; vertical-align:top;
         overflow-wrap: anywhere; font-size:8.6pt; }
th { background:#0b3d6b; color:#fff; font-weight:600; }
tr:nth-child(even) td { background:#f3f7fb; }
code { font-family:"Consolas", "DejaVu Sans Mono", monospace; font-size:8.3pt;
       background:#eef2f6; padding:1px 3px; border-radius:3px;
       word-break: break-all; overflow-wrap:anywhere; }
td code { background:transparent; padding:0; }
blockquote { border-left:3px solid #c9d6e3; margin:0.6em 0; padding:2px 10px; color:#555;
             background:#fafcfe; }
strong { color:#0b3d6b; }
/* hide pandoc's redundant filename-as-title block */
#title-block-header { display:none; }
/* Sharingan masthead (light/print) */
.sg-masthead { display:flex; align-items:center; gap:14px; padding:12px 16px; margin:0 0 14px;
  background:linear-gradient(120deg,#fbecec,#f3f7fb 60%); border:1px solid #c9d6e3;
  border-left:4px solid #b21f24; border-radius:8px; }
.sg-eye { width:30px; height:30px; border-radius:50%; flex:0 0 auto;
  background:radial-gradient(circle at 50% 50%,#fff 0 20%,#b21f24 21% 42%,#7a1418 43% 62%,#b21f24 63% 80%,#3a0a0c 81% 100%); }
.sg-word { font-weight:800; letter-spacing:.16em; font-size:15pt; color:#b21f24; }
.sg-tag { font-size:8pt; color:#666; }
.sg-meta { margin-left:auto; font-family:"Consolas",monospace; font-size:8.5pt; color:#0b3d6b;
  background:#fff; border:1px solid #c9d6e3; border-radius:999px; padding:3px 10px; }
/* hypothesis cards + confidence badges */
h3.hyp { padding:7px 11px; border-radius:6px; background:#f3f7fb; border:1px solid #c9d6e3;
  border-left:4px solid #11507f; margin-top:1.1em; }
h3.hyp-confirmed, h3.hyp-high { border-left-color:#1a7f37; }
h3.hyp-medium, h3.hyp-intent { border-left-color:#bf8700; }
h3.hyp-investigate, h3.hyp-low { border-left-color:#888; }
.conf { display:inline-block; font-size:7pt; font-weight:700; letter-spacing:.05em;
  text-transform:uppercase; padding:2px 7px; border-radius:999px; margin-left:6px; }
.conf-confirmed, .conf-high { background:#dafbe1; color:#1a7f37; border:1px solid #1a7f37; }
.conf-medium, .conf-intent { background:#fff8c5; color:#9a6700; border:1px solid #bf8700; }
.conf-investigate, .conf-low { background:#eef1f4; color:#555; border:1px solid #888; }
/* confidence-key legend at the top of the Hypothesis List */
.conf-legend { background:#f3f7fb; border:1px solid #c9d6e3; border-radius:6px;
  padding:8px 12px; margin:0.3em 0 1em; }
.conf-legend-title { font-weight:700; color:#0b3d6b; text-transform:uppercase;
  letter-spacing:.06em; font-size:7pt; margin-bottom:5px; }
.conf-legend ul { list-style:none; margin:0; padding:0; }
.conf-legend li { color:#444; line-height:1.45; font-size:8.4pt; margin-bottom:3px; }
.conf-legend li strong { color:#1a1a1a; }
.conf-legend .conf { margin-left:0; margin-right:6px; }
.conf-legend-note { margin-top:7px; padding-top:6px; border-top:1px solid #c9d6e3;
  font-size:8pt; color:#0b3d6b; line-height:1.45; }
"""

# Dark theme — used for the on-screen .html export only (the PDF keeps CSS above,
# which prints cleanly on white). Screen-optimized: larger font, high contrast.
CSS_DARK = r"""
:root {
  --bg:#0d1117; --panel:#161b22; --panel2:#1c2230; --ink:#e6edf3;
  --muted:#aebac8; --line:#30363d; --accent:#58a6ff; --accent2:#79c0ff;
  --accent-dim:#1f6feb; --code-bg:#1b2130;
}
html { background:#0d1117; }
body { font-family:"Segoe UI","DejaVu Sans",Arial,sans-serif; font-size:16px;
       line-height:1.65; color:var(--ink); background:var(--bg);
       max-width:980px; margin:0 auto; padding:32px 28px 80px;
       -webkit-font-smoothing:antialiased; }
h1,h2,h3,h4 { line-height:1.25; }
h1 { font-size:1.9rem; color:var(--accent2); border-bottom:3px solid var(--accent-dim);
     padding-bottom:.3em; margin:.2em 0 .8em; }
h2 { font-size:1.35rem; color:var(--accent2); border-bottom:1px solid var(--line);
     padding-bottom:.25em; margin:1.8em 0 .7em; }
h3 { font-size:1.1rem; color:var(--accent); margin:1.4em 0 .4em; }
h4 { font-size:1rem; color:var(--ink); margin:1.1em 0 .3em; }
p, li { color:var(--ink); }
a { color:var(--accent); text-underline-offset:3px; }
a:hover { color:var(--accent2); }
strong { color:var(--accent2); font-weight:600; }
em { color:var(--muted); }
hr { border:0; border-top:1px solid var(--line); margin:2em 0; }
table { border-collapse:collapse; width:100%; margin:1em 0; background:var(--panel);
        display:block; overflow-x:auto; }
th, td { border:1px solid var(--line); padding:8px 11px; text-align:left;
         vertical-align:top; overflow-wrap:anywhere; }
th { background:var(--accent-dim); color:#fff; font-weight:600; }
tr:nth-child(even) td { background:var(--panel2); }
td code { background:transparent; padding:0; color:var(--accent2); }
code { font-family:"JetBrains Mono","DejaVu Sans Mono",Consolas,monospace; font-size:.88em;
       background:var(--code-bg); color:var(--ink); padding:2px 5px; border-radius:4px;
       word-break:break-all; border:1px solid var(--line); }
pre { background:var(--code-bg); border:1px solid var(--line); border-radius:8px;
      padding:14px 16px; overflow-x:auto; }
pre code { background:transparent; border:0; padding:0; }
blockquote { border-left:4px solid var(--accent); background:var(--panel); margin:1.1em 0;
             padding:10px 18px; color:var(--muted); border-radius:0 8px 8px 0; }
blockquote strong { color:var(--accent2); }
::selection { background:var(--accent-dim); color:#fff; }
/* hide pandoc's redundant filename-as-title block */
#title-block-header { display:none; }
/* Sharingan masthead (dark/screen) — red eye motif, the brand identity */
.sg-masthead { display:flex; align-items:center; gap:18px; padding:20px 24px; margin:0 0 22px;
  background:linear-gradient(120deg,#1f0f12,#161b22 62%); border:1px solid var(--line);
  border-left:4px solid #e5484d; border-radius:12px;
  box-shadow:0 14px 36px -22px rgba(229,72,77,.5); }
.sg-eye { width:40px; height:40px; border-radius:50%; flex:0 0 auto;
  background:radial-gradient(circle at 50% 50%,#0d1117 0 21%,#ff5a5f 22% 42%,#7a1418 43% 62%,#ff5a5f 63% 80%,#2a0a0c 81% 100%);
  box-shadow:0 0 20px -2px rgba(229,72,77,.65); }
.sg-word { font-weight:800; letter-spacing:.2em; font-size:1.6rem; color:#ff6b6b; }
.sg-tag { font-size:.83rem; color:var(--muted); margin-top:2px; }
.sg-meta { margin-left:auto; font-family:"JetBrains Mono",monospace; font-size:.85rem;
  color:var(--accent2); background:var(--panel2); border:1px solid var(--line);
  border-radius:999px; padding:5px 14px; }
/* hypothesis cards + confidence badges — scannable verdicts */
h3.hyp { padding:9px 13px; border-radius:8px; background:var(--panel); border:1px solid var(--line);
  border-left:4px solid var(--accent); margin-top:1.6em; }
h3.hyp-confirmed, h3.hyp-high { border-left-color:#3fb950; }
h3.hyp-medium, h3.hyp-intent { border-left-color:#d29922; }
h3.hyp-investigate, h3.hyp-low { border-left-color:#8b949e; }
.conf { display:inline-block; font-size:.6em; font-weight:700; letter-spacing:.06em;
  text-transform:uppercase; padding:3px 9px; border-radius:999px; margin-left:8px;
  vertical-align:middle; }
.conf-confirmed, .conf-high { background:rgba(63,185,80,.16); color:#56d364; border:1px solid #2ea043; }
.conf-medium, .conf-intent { background:rgba(210,153,34,.16); color:#e3b341; border:1px solid #9e6a03; }
.conf-investigate, .conf-low { background:rgba(139,148,158,.16); color:#b1bac4; border:1px solid #6e7681; }
/* confidence-key legend at the top of the Hypothesis List */
.conf-legend { background:var(--panel); border:1px solid var(--line); border-radius:8px;
  padding:13px 16px; margin:.4em 0 1.4em; }
.conf-legend-title { font-weight:700; color:var(--accent2); text-transform:uppercase;
  letter-spacing:.08em; font-size:.72rem; margin-bottom:9px; }
.conf-legend ul { list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:8px; }
.conf-legend li { color:var(--muted); line-height:1.5; font-size:.92rem; }
.conf-legend li strong { color:var(--ink); }
.conf-legend .conf { margin-left:0; margin-right:9px; }
.conf-legend-note { margin-top:11px; padding-top:9px; border-top:1px solid var(--line);
  font-size:.88rem; color:var(--accent2); line-height:1.5; }
.conf-legend-note strong { color:#56d364; }
"""

# Browser candidates by command name (resolved on PATH first).
BROWSER_CMDS = ["msedge", "microsoft-edge", "microsoft-edge-stable",
                "google-chrome", "google-chrome-stable", "chrome",
                "chromium", "chromium-browser", "brave", "brave-browser"]

# Common Windows install locations if not on PATH.
WIN_BROWSER_PATHS = [
    r"Microsoft\Edge\Application\msedge.exe",
    r"Google\Chrome\Application\chrome.exe",
    r"BraveSoftware\Brave-Browser\Application\brave.exe",
]


def which(*names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def find_pandoc():
    return which("pandoc")


def find_browser():
    env = os.environ.get("BROWSER_PDF")
    if env and Path(env).exists():
        return env
    found = which(*BROWSER_CMDS)
    if found:
        return found
    bases = [os.environ.get("PROGRAMFILES", ""),
             os.environ.get("PROGRAMFILES(X86)", ""),
             os.environ.get("LOCALAPPDATA", "")]
    for base in filter(None, bases):
        for rel in WIN_BROWSER_PATHS:
            cand = Path(base) / rel
            if cand.exists():
                return str(cand)
    return None


def md_to_html(md: Path, html: Path, pandoc: str, css_path: Path):
    subject = report_subject(md)
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False,
                                     encoding="utf-8") as bf:
        bf.write(MASTHEAD_TMPL.format(SUBJECT=subject))
        banner = bf.name
    try:
        subprocess.run(
            [pandoc, str(md), "-f", "gfm", "-t", "html5", "-s",
             # browser-tab title: brand + sample (the on-page title block is
             # CSS-hidden; the masthead below replaces it)
             "--metadata", f"title=Sharingan · {subject} · Triage",
             "--include-before-body", banner,
             "-c", str(css_path), "--embed-resources",
             "-o", str(html)],
            check=True,
        )
    finally:
        os.unlink(banner)
    style_hypotheses(html)


def md_to_docx(md: Path, docx: Path, pandoc: str):
    subprocess.run([pandoc, str(md), "-o", str(docx)], check=True)


def html_to_pdf(html: Path, pdf: Path, browser: str):
    # Chromium/Edge family. Isolated user-data-dir avoids profile locks.
    with tempfile.TemporaryDirectory() as profile:
        cmd = [browser, "--headless", "--disable-gpu", "--no-sandbox",
               "--no-pdf-header-footer", f"--user-data-dir={profile}",
               f"--print-to-pdf={pdf.resolve()}", html.resolve().as_uri()]
        subprocess.run(cmd, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    ap = argparse.ArgumentParser(description="Export an analysis_report.md to HTML/PDF/DOCX.")
    ap.add_argument("md", help="path to analysis_report.md")
    ap.add_argument("--to", default="html",
                    help="comma-separated formats: html,pdf,docx  (or 'all')")
    args = ap.parse_args()

    md = Path(args.md).resolve()
    if not md.is_file():
        sys.exit(f"ERROR: not found: {md}")

    fmts = ["html", "pdf", "docx"] if args.to.strip().lower() == "all" \
        else [f.strip().lower() for f in args.to.split(",") if f.strip()]
    bad = [f for f in fmts if f not in ("html", "pdf", "docx")]
    if bad:
        sys.exit(f"ERROR: unknown format(s): {', '.join(bad)}")

    pandoc = find_pandoc()
    if not pandoc:
        sys.exit("ERROR: pandoc not found. Install it first:\n"
                 "  Windows : winget install --id JohnMacFarlane.Pandoc\n"
                 "  Debian  : sudo apt install pandoc\n"
                 "  macOS   : brew install pandoc")

    outdir = md.parent
    made = []

    html = outdir / (md.stem + ".html")
    with tempfile.TemporaryDirectory() as td:
        css_dark = Path(td) / "dark.css"
        css_dark.write_text(CSS_DARK, encoding="utf-8")
        css_light = Path(td) / "light.css"
        css_light.write_text(CSS, encoding="utf-8")

        # On-screen HTML: dark theme.
        if "html" in fmts:
            md_to_html(md, html, pandoc, css_dark)
            made.append(html)

        # PDF: render a separate light-themed HTML (prints cleanly on white) and
        # print that — the dark .html is never used as the PDF source.
        if "pdf" in fmts:
            browser = find_browser()
            if not browser:
                print("WARNING: no headless browser (Edge/Chrome/Chromium) found; "
                      "skipping PDF. Open the .html and print to PDF from the browser, "
                      "or set BROWSER_PDF to a browser exe.", file=sys.stderr)
            else:
                light_html = Path(td) / (md.stem + "_print.html")
                md_to_html(md, light_html, pandoc, css_light)
                pdf = outdir / (md.stem + ".pdf")
                html_to_pdf(light_html, pdf, browser)
                made.append(pdf)

        if "docx" in fmts:
            docx = outdir / (md.stem + ".docx")
            md_to_docx(md, docx, pandoc)
            made.append(docx)

    if made:
        print("Wrote:")
        for p in made:
            print(f"  {p}")
    else:
        sys.exit("Nothing was produced.")


if __name__ == "__main__":
    main()
