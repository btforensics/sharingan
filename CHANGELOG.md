# Sharingan — Change Tracker

Single source of truth for what has shipped, what is built-but-uncommitted, and
what is planned. Capability items are scored in `build-roadmap.html` (the build-
priority board); this file is the chronological tracker and also covers
**performance/UX** work that the score-based roadmap doesn't capture.

**Legend:** ✅ shipped & committed · 🟡 built + verified, not yet committed ·
📋 planned · 🔬 needs investigation. Dates are absolute (project tz).

---

## 🟡 Built + verified — NOT yet committed

These work end-to-end but are still in the working tree (last commit is N2,
`6191d26`). **Action: commit.**

- 🟡 **Archive children auto-analyzed + two reliability fixes** — *2026-06-29* — found while
  triaging `readme.doc.zip` (W97M macro virus) and `VCDSLoader X2.exe.zip` (XRed/"Synaptics"
  backdoor) — both archives whose real payload was the *child*, which the pipeline wasn't
  analyzing automatically. **Verified** end-to-end (readme.doc.zip → `children/<hash>/olevba.json`
  recovered the macro; domain filter 183→4; nonpe self-locate with env unset).
    - **#1 Auto-recurse into archive children** — `triage.sh` now runs the FULL pipeline on each
      typed extracted child into `children/<name>/` under the parent report dir (was: extract +
      identify only, analyst had to re-run `triage.sh` by hand → stray top-level report dir).
      New `tools/archive_children.py` lists typed children from `archive.json`; `triage.sh` gained
      a `SHARINGAN_REPORT_DIR` override + `SHARINGAN_RECURSE_DEPTH`/`_MAX` (default cap 2) guard.
      Docs synced (CLAUDE.md stage 8, SKILL.md archive guidance).
    - **#2 `nonpe.py` self-locates the venv** — `tool()` now falls back to `tools/venv/bin/<name>`
      before PATH, so a hand-run `nonpe.py <doc> office_ole <rd>` finds olevba/oleid/pdfid even
      when triage.sh isn't injecting the `OLEVBA`/`OLEID` env vars (the footgun that silently
      skipped macro analysis on Office docs).
    - **#3 Delphi/.NET RTTI domain-noise filter** — `domain_rep.py` drops bare candidates whose
      leading label is a runtime namespace root (`system`/`winapi`/`vcl`/…) or whose TLD isn't a
      real ccTLD/gTLD (code identifiers like `.TComponent`/`.RegStr`). Cut a Delphi sample's
      bare-candidate list 183→4 with zero real-C2 loss, saving wasted reputation lookups.

- 🟡 **File-type breadth: N7 + N8 + N9 + disk-image carving** — *2026-06-29* — agnostic-coverage
  push (the "analyze any file type" axis, distinct from per-type depth). All follow the **gating &
  speed rubric** now captured in `build-roadmap.html` (identify-first → cheap auto-on-match,
  expensive opt-in/bounded, recursion capped). Wired into `identify.py` (new categories/magic),
  `nonpe.py` (handlers), `triage.sh` (routes), `config.env`, `provenance.py`.
    - **N8 — Script deobfuscation** (`tools/scriptscan.py`, stdlib) → `scriptscan.json` +
      `script_layers/`. The `script` category was strings-only; now it recursively peels
      base64/hex/charcode/%-escape/gzip/`-EncodedCommand` layers, re-extracts defanged IOCs +
      suspicious tokens per layer, and carves embedded PE/ZIP. **Verified** end-to-end: 3-layer
      `enc→gzip+b64→C2` PowerShell, JS `fromCharCode`, `unescape` %-escape, base64 PE carve, and a
      benign no-op. Auto-on-match, bounded (MAX_DEPTH/LAYERS/BLOB). EMBEDDED intent only.
    - **N9 — HTML/SVG smuggling** (`tools/htmlsmuggle.py`, stdlib) → `htmlsmuggle.json` +
      `html_payloads/`. New `html` category. Fingerprints client-side reassembly (atob/Blob/
      createObjectURL/`<a download>`.click), decodes data:/atob/base64 blobs (inflating gzip),
      carves + identifies the reconstructed payload. **Verified:** gzipped-PE smuggle (carved +
      flagged), SVG `<script>` vector, benign no-op, w3.org-namespace noise filtered. Reuses
      scriptscan's decode/IOC core.
    - **Disk-image delivery containers** (`identify.py` offset-magic + capped `handle_archive`) —
      ISO9660/UDF/VHD/VHDX/IMG now detected (magic at offset, not byte 0) and routed to the 7z
      archive handler (the MOTW-bypass delivery vector). **Verified:** real `pycdlib` ISO →
      `archive/iso` → 7z-extracted → children identified (LNK+EXE). Added caps to `handle_archive`
      (MAX_ARCHIVE_ENTRIES 500, 2 GB size guard, nested-archives flagged not auto-extracted → depth
      cap = 1). **Verified:** 600-file entry cap + nested-zip flag.
    - **N7 — Managed (.NET) unpack/deobfuscation** (`tools/dotnet_deob.py`) → `dotnet_deob.json`
      + `deobfuscated/`. Detects a managed protector from `die`, de4dot strips it, capa/config/
      strings re-run on the clean assembly (managed analogue of N4). Wired into the `triage.sh`
      PE/.NET branch. Auto-on-match (only invokes de4dot when a protector is present on a .NET body);
      status `unavailable` is an honest GAP, never clean. **VERIFIED end-to-end** on the DCRat/.NET
      Reactor sample: de4dot stripped the (native) .NET Reactor protector → recovered managed
      assembly (file-type `PE32` native → `Mono/.Net assembly`; strings 3203 → 8680; exposed
      `AesCryptoServiceProvider`/`HttpWebResponse`/`ProcessStartInfo` capability fingerprints).
      Decision paths also verified: AsyncRAT → `no_protector`, av45i → `not_dotnet`. *Honest layered
      result:* N2 config extraction stayed `no_match` even on the cleaned body (no matching DCRat
      parser) — N7 unlocks the assembly for capa/strings/manual RE, but a config hit still needs a
      parser. **de4dot dependency:** built from de4dot's `.netcore.sln` with the `dotnet` SDK
      (`tools/install-dotnet-deob.sh`) into `tools/de4dot/de4dot.dll`, run via `dotnet` (no mono
      needed); `dotnet_deob.py` autodetects it. de4dot v3.1.
- 🟡 **UX + workflow improvements (analyze-sample)** — *2026-06-29* — from user feedback on the
  DCRat run. (1) **`mine_artifacts.py`** — new committed skill helper (stdlib, cross-platform) that
  prints a full size-aware digest of a report dir in **one analyzable command**, replacing the inline
  Python heredocs that tripped the command-safety guard on every run (item: "stop asking me yes").
  Verified on the DCRat report. (2) **Command hygiene (SKILL.md §0)** — run tools as bare,
  non-compound, relative commands from the project root (no `cd`/redirect/heredoc/`$(...)`); this,
  not weakening permissions, is what removes the prompts. Added `Bash(mv:*)` to committed
  `settings.json` for archive-child consolidation (the one recurring non-allowlisted command). (3)
  **Messaging conventions (§0)** — narrate each stage in plain language (esp. archive: detected →
  extracting → extracted → analyzing), announce slow stages + "still processing", avoid
  done-sounding words mid-run, and end with a single banner `✅ ANALYSIS COMPLETE — HTML report:
  <path>`. (4) **Trend Vision One — Search App hunting queries** — new required report section
  (CLAUDE.md output spec + skill step 4): turns the IOC table into ready-to-paste V1 Search queries
  (`objectFileHashSha256` / `processFilePath` / `processName` / `dst` / `hostName` / `request`),
  real values, field-names flagged as tenant-verify, network block noted as populate-after-detonation.
  Demoed live on the DCRat report. (User chose Search App queries over Suspicious-Object export.)
- 🟡 **Skill hardening (from the `libGLESv2.dll`/DCRat triage)** — *2026-06-29* — `SKILL.md` only,
  no score change. (1) **PE must-check checklist:** reading `peinfo.json` "in full" wasn't enough —
  added an explicit always-account-for list (`is_dll`/`is_exe`, `exports`, `version_info`,
  `checksum_mismatch`, `tls`, imports, overlay) and a masquerade-diff instruction, after a first
  pass missed `exports: []` + the junk `version_info` on that sample. (2) **imphash-on-packed-stub
  caveat:** when `die` reports a packer/protector, `imphash_search` groups by *packer* not family —
  trust same-label siblings, downgrade divergent-label ones (the `.NET Reactor` imphash pulled
  unrelated `MADARA.exe`/`Healer.exe`). Prompt-only; no tool/accuracy regression involved.
- 🟡 **N6 — Authenticode / digital-signature verification** (89.5 → 90.5) — *2026-06-29*
  `tools/authenticode.py` (signify in the venv) → `authenticode.json`. Verifies the
  PE/.NET signature chain + digest against the MS trust store; flags
  `self_signed` / `hash_mismatch` / `expired` / `weak_digest`; correlates the signer
  against `rules/abused_certs.json` (stolen/abused certs). Wired into `triage.sh`
  (PE branch), `config.env`, `setup-env.sh`, `provenance.py`, CLAUDE.md (item 4b),
  SKILL.md (`[authenticode]`), `build-roadmap.html`, `workflow.html` (stage 6b).
  Verified: pscp.exe → `valid`; tampered byte → `invalid`+`hash_mismatch`;
  av45i + 3 malware samples → `not_signed`. Added `rules/abused_certs.json` to the
  repo via a `.gitignore` exception (bulk rule clones stay ignored).
- 🟡 **N1 — VirusTotal behaviour ingestion** (87.5 → 89.5) — *2026-06-29*
  `tools/vt_behavior.py` (stdlib only) → `behavior.json`. Pulls VT's *existing*
  sandbox detonation for the hash (network / host / verdict). The pipeline's only
  confirmed-OBSERVED source; promotes embedded "intent" to "confirmed live (per VT)".
  Verified end-to-end on a live AsyncRAT sample.

---

## ✅ Shipped & committed

Most of the items below landed together in the initial commit (`3e3d0d5`,
2026-06-28); N2 in `4ac559f` / `6191d26`. Build-score deltas in parentheses.

- ✅ **N2 — Config / C2 extraction** (84.5 → 87.5) — *2026-06-28* — `tools/config_extract.py`,
  configextractor-py + CAPE/rat-king parser packs → `config.json`. Statically rips
  embedded family config (C2 / keys / campaign IDs / mutex).
- ✅ **N4 — Emulation-based unpacking** (81.5 → 84.5) — *2026-06-28* — `tools/unpack_emulate.py`,
  opt-in `--unpack` (PE). Speakeasy emulates the loader stub, carves the payload, re-runs
  the binary tools on it.
- ✅ **N3 — Multi-format / file-type-agnostic triage** (78.5 → 81.5) — *2026-06-28* —
  `tools/identify.py` → `fileinfo.json` (category/subtype + extension_mismatch);
  routed PE vs `tools/nonpe.py` (office/pdf/lnk/archive/email); `tools/collect_strings.py`
  → `strings.json` (fixed the nested-FLOSS IP bug).
- ✅ **#8 — Tool / rule-set provenance** (78 → 78.5) — *2026-06-28* — `tools/provenance.py`
  → `provenance.json`; audit-grade footer of tool versions + rule-set commit dates.
- ✅ **#5 — VirusTotal pivoting** (76 → 78) — *2026-06-28* — `tools/vt_pivot.py` → `vt_pivot.json`;
  imphash / communicating-file siblings, contacted/dropped relationships.
- ✅ **#3 — Domain / C2 reputation** (74 → 76) — *2026-06-27* — `tools/domain_rep.py` → `domain_rep.json`
  (ThreatFox + URLhaus + VT-domain).
- ✅ **#2 — Ghidra deep RE** (70 → 74) — *2026-06-26* — opt-in `--deep` → `ghidra.json` (headless decompilation).
- ✅ **Base pipeline + setup README** — *2026-06-28* — hashing, VT/MalwareBazaar lookups,
  pestats (PE structure), die (packer), floss (strings), capa (capabilities), YARA,
  AbuseIPDB, the `/analyze-sample` skill, statusline, banner.

---

## 📋 Planned — Performance & speed

A full `/analyze-sample` run was ~15 min. Measured breakdown (on `av45i.exe`,
2026-06-29): CPU tools ≈ **35s** (floss 20 · capa 9 · config 3 · yara 1 · rest ~2);
`triage.sh` total ≈ **196s**; the remainder is the AI analysis phase. The CPU tools
are *not* the bottleneck.

- 📋 **PERF-1 — Remove dead VT rate-limit pacing** *(biggest win, lowest risk)*
  `vt_pivot` / `vt_behavior` / `domain_rep` sleep **16s between every VT call**, tuned
  for VT's free tier (4 req/min). **The configured key is premium** — measured quota
  6.6M req/hr; a 6-call back-to-back burst returned all HTTP 200, no 429. The pacing is
  pure idle. Drop `VT_PIVOT_SLEEP` / `VT_BEHAVIOR_SLEEP` (+ domain_rep) to ~0.5s in
  `config.env`, documented, with a note for free-tier teammates to raise it.
  **Expected: triage ~196s → ~60s.**
- 📋 **PERF-2 — Parallelize `triage.sh` stages** (shell background jobs, not agents —
  these are CLI tools). Two concurrent tracks: **CPU** (die · pestats · authenticode ·
  floss · capa · config) and **network** (VT · MalwareBazaar · vt_pivot · vt_behavior ·
  domain_rep · AbuseIPDB — safe to fan out once PERF-1 removes pacing). Honor the
  strings.json dependency (domain_rep / AbuseIPDB wait on floss→collect_strings) and run
  provenance last. **Expected: triage → ~40s (≈ max(CPU, network) on 2 cores).**
- 📋 **PERF-3 — Multi-agent analysis fan-out** (the "divide across agents" idea, in the
  `/analyze-sample` skill). Spawn parallel reader-subagents — e.g. A: strings+floss ·
  B: capa+peinfo+authenticode+die · C: VT+behavior+pivot+reputation+domain ·
  D: config+yara+provenance — each returning a structured digest + extracted IOCs.
  **Then ONE synthesis pass does the cross-artifact correlation, hypotheses, and report.**
  ⚠️ Constraint (CLAUDE.md): "reason across all artifacts *simultaneously*" — correlation
  must stay in a single mind. Agents parallelize the *reading/extraction* only; splitting
  the reasoning itself would hurt confidence. Speeds the read-heavy part, not report writing.

---

## 📋 Planned — Capability (scored in `build-roadmap.html`)

- 🔬 **#1 — Dynamic sandbox** (~95 build, → ~91 overall; High cost). The only path to
  *own* confirmed behaviour; where N1 `static_only`/`not_detonated` and N2/N4 gaps hand off.
- ✅→🟠 **N7 — Managed .NET unpack / deobfuscation** — **BUILT 2026-06-29** (see the 🟡 section above;
  de4dot strip pending the `install-dotnet-deob.sh` install before it's fully verified). Strips a .NET
  protector (.NET Reactor/ConfuserEx/…), then re-runs capa/config/strings on the recovered assembly —
  mirroring N4 on a carved native body. Filled the gap the DCRat (.NET Reactor) + AsyncRAT triages
  exposed: a *protected* .NET payload is invisible to N4 (can't follow the CLR handoff) and N2 (returns
  `no_match`). EMBEDDED intent only.
- 📋 **#6 — IOC export** (MISP / STIX / CSV) — the IR/SOC handoff. Next sandbox-free item after N7.
- 📋 **N5 — Detection-content generation** (YARA + Sigma) — reframed as detection-engineering /
  downstream handoff (not analysis depth); demoted below #6.
- ✅ **#4 — Automated unpacking** — **SUPERSEDED by N4 + N7** (no standalone work left). N4 (Speakeasy)
  unpacks native loader stubs; N7 (de4dot) strips managed .NET protectors; both auto re-run the binary
  tools on the recovered body. The anti-static residual (remote-keyed / virtualized / anti-emulation)
  requires runtime → belongs to **#1 sandbox** (already wired to hand off with a GAP). Packed ELF is a
  separate Linux-depth item (Speakeasy is Windows-PE-only).
- 📋 **#7 — Sample diffing** — parked (user judged low-priority).

---

## Open action items
- [ ] Commit N1 (`tools/vt_behavior.py` + wiring), N6 (`tools/authenticode.py` +
      `rules/abused_certs.json` + wiring), and the analyze-sample UX/skill edits
      (`mine_artifacts.py`, `SKILL.md` §0 + Vision One, `CLAUDE.md` output spec, `settings.json` mv).
- [ ] Implement PERF-1 (quick win) → re-time triage to confirm.
- [ ] Implement PERF-2, then PERF-3.
- [x] Build + verify N7 (managed .NET unpack) — done 2026-06-29; de4dot strip verified end-to-end
      on DCRat/.NET Reactor. de4dot built via `dotnet` SDK (`install-dotnet-deob.sh`).
- [ ] One-time cleanup: `sudo rm -rf tools/de4dot-src` (root-owned leftover from the first
      installer run; now gitignored + the installer builds in a temp dir).
- [x] Build the file-type breadth stages (N8 script-deob, N9 HTML-smuggling, disk-image carving) —
      built + verified 2026-06-29.
