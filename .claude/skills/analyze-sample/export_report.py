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
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

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
    subprocess.run(
        [pandoc, str(md), "-f", "gfm", "-t", "html5", "-s",
         "--metadata", f"title={md.stem}",
         "-c", str(css_path), "--embed-resources",
         "-o", str(html)],
        check=True,
    )


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
