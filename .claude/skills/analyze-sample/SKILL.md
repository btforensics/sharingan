---
name: analyze-sample
description: >-
  End-to-end malware triage + analysis in one command. Give it a raw sample
  (e.g. samples/X.exe) and it runs triage.sh to generate the artifacts, then
  analyzes them; or give it an existing reports/<name>_<timestamp>/ dir (or
  sample-name substring) to analyze artifacts already collected. Reads all
  JSON + text artifacts, reasons across them, writes analysis_report.md and then
  auto-generates a styled analysis_report.html (the deliverable) in the report dir.
  Invoke as /analyze-sample [sample-path | report-dir | name].
---

# Analyze Sample

One command for the whole flow. Replaces the old two-step process (run `triage.sh`, then
manually ask Claude to analyze the JSON). Follow `CLAUDE.md` for analyst role, approach,
required coverage, and output format. Hard requirements: **always account for every artifact**
(read small ones in full; *mine* large ones for their relevant fields rather than dumping raw
bytes — see step 2's size-aware reading), **always persist the report to `analysis_report.md`**,
and **always auto-generate `analysis_report.html` from it** (step 5) — the HTML is the
deliverable, the `.md` is its source.

> **Cross-platform note.** The analysis + reporting path (steps 1–5) is designed to run on
> **Windows (native PowerShell/cmd), Linux, and macOS**. Where a step needs a shell command,
> pick the variant matching the host OS — prefer the built-in file tools (Read/Glob) and the
> bundled `python` helpers (cross-platform) over OS-specific shell. **Artifact *collection*
> (`triage.sh` + floss/capa/die/yara/radare2) is Linux-only**; on Windows, work from an
> existing `reports/<name>_<timestamp>/` dir produced on a Linux box.

## 0. Execution & messaging conventions (apply throughout)

**Open every run with the Sharingan banner.** Before anything else — and regardless of
whether you're running `triage.sh` (raw sample) or analyzing an existing report dir — emit
the banner below as the **first thing** in your reply, in a fenced code block so the eyes
render verbatim. `triage.sh` prints this to a TTY, but the skill runs it through the Bash
tool (no TTY, output collapsed) and the report-dir path never runs `triage.sh` at all, so
the banner only reliably reaches the user if the skill prints it:

```
     .-=======-.              .-=======-.
    /     ,     \            /     ,     \
   |    \   /    |          |    \   /    |
   |  -- (O) --  |          |  -- (O) --  |
   |    /   \    |          |    /   \    |
    \  '     '  /            \  '     '  /
     '-=======-'              '-=======-'
        S H A R I N G A N   — see through the disguise
```

**Run commands the static analyzer can parse — this avoids needless approval prompts.**
The harness prompts on commands it can't statically verify even when an allow-rule exists.
So, for every shell command in this flow:
- **Do not use `cd`.** Run tools as **bare, non-compound commands from the project root** (the
  default working directory) using their existing relative invocation — e.g. `./triage.sh <sample>`
  and `python3 .claude/skills/analyze-sample/mine_artifacts.py <report-dir>`. These match the
  project's allow-rules *and* parse cleanly. Keep paths relative (portable; the tool is
  team-distributed). `cd` + redirection always prompts.
- **Invoke `triage.sh` as `./triage.sh <sample>` — relative and bare, NEVER an absolute path.**
  The allow-rule is `Bash(./triage.sh:*)`; `/home/.../triage.sh <sample>` does NOT match it and
  prompts every time. Pass the sample path as the argument (it may be absolute); the script itself
  stays `./triage.sh`. Accepting an absolute-path allow-rule would also hard-code a non-portable
  path into a team-distributed tool — don't.
- **To read report artifacts, use the Read tool (allowed via `Read(reports/**)`) or
  `mine_artifacts.py` — NEVER a `cd`+`cat` compound.** A command like
  `cd reports/<dir>; cat yara.txt; cat behavior.json …` trips the static-analysis guard (compound
  `cd` + redirection) and prompts *regardless of the `Bash(cat:*)` allow-rule*. Read each artifact
  by absolute/relative path with the Read tool, or mine them all at once with `mine_artifacts.py`.
- **Do not use inline Python heredocs (`python3 - <<'PY'`) to mine artifacts.** Use the bundled
  **`mine_artifacts.py`** helper (step 2) — one analyzable command instead of many that prompt.
- **One purpose per command; avoid `VAR="…"; $VAR`, `$(…)` substitution, and brace/quote tricks**
  inside a command — those are exactly the patterns that trip the guard. Prefer plain
  `tool <absolute-arg>` forms (which match the project's allow-rules).
- Let background runs write to their own captured output; don't wrap them in `> /tmp/log` redirects.

**Progress + completion messaging (so the user always knows whether to wait).**
- **Narrate each stage in plain language as it happens**, especially for archives, e.g.:
  `Detected <file> as a password-protected archive` → `Extracting with default password 'infected'`
  → `Extracted <child> (PE/exe) — analyzing it now`. Keep it to short status lines.
- **Before any slow stage (triage.sh, floss/capa, paced VT, an unpack), say it will take a few
  minutes and that you'll report when it's done** — then actually wait for it.
- **Avoid ambiguous "done"-sounding words** (e.g. "baked", "wrapped up") while work is still
  running — they read as completion. If you're mid-process, say **"still processing — please wait."**
- **End every analysis with a single, unmistakable completion banner** including the path:
  `✅ ANALYSIS COMPLETE — HTML report: <absolute path to analysis_report.html>`
  (only emit this once the `.html` actually exists from step 5).

## 1. Resolve the target — sample vs. report dir

Look at the argument and decide which case you're in:

- **Raw sample** (path to a file, typically under `samples/`, that is NOT a report dir):
  run triage first to generate artifacts — invoke it as a **bare command from the project root**
  (no `cd`, no compound/redirect): `./triage.sh <sample-path>`. It makes **external API calls**
  (VirusTotal / MalwareBazaar / AbuseIPDB) using keys in `config.env`.
  **Run it in the FOREGROUND** (do NOT use `run_in_background`) so Claude Code's native progress
  indicator — the live spinner with **elapsed time + token counter** — is shown for the whole run.
  triage.sh is now time-bounded: the heavy stages (floss/capa) are gated on virtualizing
  protectors and capped by `FLOSS_TIMEOUT`/`CAPA_TIMEOUT` (config.env), so a worst-case run is a
  few minutes, not tens of minutes — short enough to foreground. **Tell the user it'll take a
  couple of minutes and that the timer is live**, then run it and wait. (Only fall back to a
  background run + a Monitor heartbeat if you must do other work meanwhile; the native
  spinner does not render for background tasks.) triage.sh creates
  `reports/<sample-name>_<timestamp>/`; use that new directory as the target.
  **Linux-only** — on Windows there is no triage to run, so fall back to the existing-report-dir
  case (tell the user collection must be done on a Linux box).
  **After this base run completes, apply the auto-escalation policy in step 1b** before moving
  on to analysis.
- **Existing report dir** (a `reports/*` path, or a sample-name substring matching one):
  skip triage; pick the most recent matching directory. **This is the primary path on Windows.**
- **No argument / blank** (the skill was invoked with no sample path or report dir):
  **do not guess and do not auto-pick.** List `samples/` **sorted by modification date, newest
  first**, and **show only the 10 most recent** (note how many are hidden if there are more), then
  ask literally: **"Which sample do you want to analyze?"** Wait for the user to type a sample
  name, then resolve that name against `samples/` (raw sample → triage, Linux only) or `reports/`
  (existing artifacts) per the cases above and proceed. If `samples/` is empty or missing, list
  `reports/` instead (same newest-first, last-10 rule) and offer those; if both are empty, ask for
  a path.

  Use the date-sorted, capped listing for the host OS — do **not** use a name-sorted default:
  - POSIX: `ls -lt samples/ | head -n 11`  (mtime-descending; `head` keeps the newest 10 + the
    `total` line)
  - Windows PowerShell: `Get-ChildItem samples | Sort-Object LastWriteTime -Descending | Select-Object -First 10`
  - or the Glob tool sorted by mtime.
  Present the date (and size) next to each name so the user can tell fresh drops from old ones.

State which case you detected and which directory you chose before proceeding.

## 1b. Auto-escalate the heavy stages (Linux raw-sample path only)

After the base `triage.sh` run finishes, **conditionally** re-run collection with the heavy
stages — automatically, without asking — when the evidence warrants it. Do **not** blindly run
both on every sample: they are no-ops on non-binary types and waste minutes, and on a packed
binary the wrong order produces misleading output. This step applies only on the **Linux
raw-sample path** (you must be able to re-invoke `triage.sh`); on the existing-report-dir /
Windows path you cannot re-trigger collection, so skip to step 2 and surface the heavy stage as
a *recommended next step* instead.

Decide from the base artifacts (`fileinfo.json`, `die`, `peinfo.json`), in this order:

1. **`--unpack` (Speakeasy, PE only) — run it if the sample is a PE that looks packed:** `die`
   names a packer, OR `peinfo.json` shows high section entropy (~7.0+), a very small import
   table (real imports resolved at runtime), or a large/high-entropy overlay. Skip for non-PE
   types (Office/PDF/LNK/script/archive/email/ELF) and for a PE that is plainly not packed.
   ```
   ./triage.sh <sample-path> --unpack
   ```
2. **`--deep` (Ghidra, binary only) — run it if a code-level question remains** that strings/capa
   can't settle: a decrypt / loader / C2 routine worth decompiling. On a packed sample, run this
   **after** `--unpack` (point Ghidra at the recovered body, not the loader stub) — if `--unpack`
   recorded a gap (`recovered: false`), `--deep` on the original stub adds little, so prefer a
   sandbox.
   ```
   ./triage.sh <sample-path> --deep
   ```

**Sequencing & resource rules (this box is RAM-constrained):**
- Run the heavy stages **one at a time, never stacked** (`--deep` is a JVM, `--unpack` emulates;
  together they can exhaust memory). Separate `triage.sh` invocations, in the order above.
- **Tell the user before each heavy stage fires** and why it was triggered (it's slow), e.g.
  "die flags UPX + 7.9 entropy → auto-running `--unpack`."
- If a stage is **not warranted, say so in one line** ("not packed → skipping `--unpack`") so the
  decision is auditable — silence reads as "forgot to run it."
- Each flagged run writes its artifacts into the **same report dir** (`unpacked.json`+`unpacked/`,
  `ghidra.json`); analyze the enriched directory in step 2.

## 2. Read ALL artifacts — size-aware (mine the big ones, don't dump them)

**Why this matters:** the report dir can be huge — `floss.json` is often 700–800 KB, `capa.json`
~400 KB, and a multi-child `archive` report can exceed **9 MB**. Reading every byte into context
verbatim will **exhaust the context window** and kill the analysis mid-run. The fix is not to skip
artifacts — it is to *account for every artifact* while only pulling the analytically relevant
fields of the large ones into context. "Read all artifacts" means **cover** all of them, **mine**
the big ones; it does **not** mean `Read` every raw byte.

**Start with the bundled digest helper (one analyzable command — no heredocs):**
Run `python <skill-dir>/mine_artifacts.py <report-dir>` (use `python3`/`py` per host). It reads
**every** artifact and prints a compact, size-aware digest — the PE must-check fields
(`is_dll`/`exports`/`version_info`/`checksum_mismatch`/sections+entropy/overlay/imports/tls),
authenticode verdict, capa rule names + ATT&CK, floss decoded strings + filtered URLs/IPs/registry/
paths, YARA rules, VT stats + threat label + engine picks, vt_pivot siblings (with the
imphash-groups-by-packer caveat when `die` saw a packer), behaviour status, config status,
domain_rep, optional unpacked/ghidra, and the provenance footer. This replaces the ad-hoc inline
Python and gives systematic coverage. **It is evidence, not a verdict** — still reason across it per
CLAUDE.md, and `Read` any specific artifact in full when you need detail the digest summarized. For
**archive/non-PE** samples also mine the type-specific artifacts (olevba/oleid/pdfid/lnk/email/
archive) it doesn't yet cover, per the guidance below.

**Size-aware ingestion (if you read artifacts directly beyond the digest):**
- First **list the dir with sizes** (`ls -la <report-dir>` / Glob + stat). `Read` small artifacts
  (≲ ~50 KB: `fileinfo.json`, `peinfo.json`, `authenticode.json`, `die`, `yara.txt`, `lnk.json`,
  `oleid.txt`, `pdfid.txt`, `provenance.json`, `domain_rep.json`, most `virustotal.json`) **in full**.
- **PE must-check fields (`peinfo.json`): reading it "in full" is not enough — explicitly account
  for these every time**, because they are easy to skip yet decisive: `headers.is_dll`/`is_exe`
  (does the PE *type* match what it claims to be?), `exports` (a real signed library exports many
  functions; **`exports: []` on a file claiming to be a DLL is a hard masquerade tell**),
  `version_info` (forged vendor strings = effortful masquerade; *random/garbage* strings = an
  automated packer — and junk `FileVersion`/`ProductVersion` are where bogus "IP-like" FLOSS hits
  often come from), `headers.checksum_mismatch`, `tls` callbacks, the import table, and the
  `overlay`. On a **suspected masquerade**, diff these against the impersonated product
  (type, exports, signer, version block) rather than relying on filename/extension alone.
- For any artifact **larger than ~50–100 KB**, do **not** `Read` it raw — **mine it with Python**
  (or `jq`) for just the fields you need, printing a compact extract:
  - **`floss.json`** — `decoded_strings`, plus `static_strings` filtered for URLs, IPs, domains,
    registry keys, file/process names, mutexes, C2/HTTP patterns, credential markers, and
    `analysis.functions.decoding_function_scores`. Never dump the full array.
  - **`capa.json`** — extract the matched **rule names**, their `namespace`, and
    `meta.attack`/`meta.mbc` mappings (the capability + ATT&CK list). Skip the per-rule match-
    location trees, which are the bulk of the bytes and rarely needed for triage.
  - **`strings.json`/`strings.txt`, `virustotal.json`, `vt_pivot.json`** — if large, grep/parse
    for the indicators and verdict fields rather than reading end to end.
- **Archive / recursive reports:** `triage.sh` now **auto-analyzes each typed extracted child
  with the full pipeline into `children/<name>/`** under the report dir (depth-capped), so the
  archive's real payload is already triaged — `mine_artifacts.py <report-dir>/children/<name>`
  and read it as a first-class report. Do **not** load every child at once; process them **one at
  a time**, size-aware. Read `archive.json` for the listing/types. Only re-run `triage.sh` on a
  child by hand for an **older report collected before auto-recursion** (no `children/` dir).
- If you ever approach the context limit mid-triage (watch the **ctx** field in the status line),
  finish mining what's open and **summarize findings to free headroom** before opening more —
  never silently drop an artifact; note any you deferred.

**Read `fileinfo.json` FIRST.** Sharingan is file-type agnostic — it identifies the sample
(`category`/`subtype`: pe/dotnet/elf/office_ole/office_ooxml/pdf/lnk/script/archive/email/
unknown) and routes it to type-appropriate stages, so the *set* of artifacts present depends on
the type. `extension_mismatch: true` is a high-confidence **masquerade** signal (e.g. PE bytes
delivered as `invoice.pdf`) — lead with it. For **non-PE** samples the binary artifacts
(peinfo/die/capa/floss/ghidra) will be absent by design; instead expect:
`olevba.json`+`oleid.txt` (Office macros/IOCs), `pdfid.txt`/`pdfparser.txt` (PDF active content:
`/OpenAction`,`/JS`,`/Launch`,`/EmbeddedFile`), `lnk.json` (LNK `command_line_arguments`/
`relative_path`/`working_directory` — the operative fields are under `_sharingan_summary`),
`archive.json` (listing + each extracted child identified under `extracted/`; recurse your
analysis into suspicious children), `email.json` (headers, URLs, attachments). Every type also
gets universal `strings.txt`, `yara.txt`, `domain_rep.json`, and (when known) VT/MB + `vt_pivot`.
An artifact that is a captured `error`/note (missing tool) is a **gap**, not a clean result.

**Password-protected archives (zip / 7z) — interactive step.** When the sample is an archive,
check `archive.json`. The handler auto-tries default sample passwords (`virus`, `infected`,
`N0virus`, `novirus`); if one works, `password_used` is set and children are already extracted —
just report which password worked and the extracted files + their identified types. **If
`password_required: true`** (encrypted and all defaults failed): tell the user the archive is
password-protected and the defaults didn't work, show `listing_raw` if it reveals the entry
names, and **ask: "What's the password?"** When they answer, re-run just the archive stage with
their password (host-appropriate launcher):

```
SHARINGAN_ARCHIVE_PWD='<password>' python <tools>/nonpe.py <archive-path> archive <report-dir>
```

That regenerates `archive.json` + `extracted/`. Note this runs `nonpe.py` alone, so it does **not**
auto-recurse into the children (only a full `triage.sh` run does). **Report the extracted files
with their `category`/`subtype`**, then either re-run `triage.sh` on the archive to get the
auto-recursed `children/<name>/` reports, or recurse manually on a suspicious child as needed.
Never ask for the
password before the defaults have been tried — the handler already does that.

Account for every `*.json` and `*.txt` in the directory — small ones read in full, large ones
mined per the size-aware rules above (e.g. `floss.json`: mine `decoded_strings` and
`static_strings` filtered for URLs, IPs, domains, registry keys, file/process names, mutexes,
C2/HTTP patterns, and credential markers — never dump it). Reason across all artifacts
**simultaneously**, per CLAUDE.md.

`domain_rep.json` (when present) carries C2/domain reputation: for each extracted domain,
`threatfox` (abuse.ch known-IOC + malware family), `urlhaus` (malware-distribution URLs), and
`virustotal_domain` (multi-engine stats, `reputation`, `categories`, and `last_dns_records` =
passive-DNS resolutions). Mine it for family attribution and for **C2 IPs from the DNS records**
(feed those back through the IP-reputation lens). Note `meta.url_hosts` are high-confidence
(pulled from URLs) vs `meta.bare_candidates` (filtered FLOSS-string matches that may be noise);
`meta.note` records VT's rate-limit cap. A `no_result`/`no_results` is an authenticated miss, not
an error — say so rather than implying the domain is clean.

`vt_pivot.json` (when present) expands the sample into its family/campaign via VirusTotal.
Two layers: **`forward`** = the sample's own footprint VT observed (`contacted_domains`,
`contacted_ips`, `dropped_files`, `itw_urls`) — high-confidence indicators to add to the IOC
table; **`reverse`** + the flattened **`siblings`** list = *other* samples sharing an indicator
(`communicating_files` per domain/ip) or the same `imphash` (`imphash_search`). Each sibling
carries its `sha256`, `via` (which pivot surfaced it), AV `malicious/total`, and
`suggested_threat_label` — mine these for **family attribution** (a consistent label across
siblings is strong evidence) and list them under Recommended Next Steps as samples to triage.
Treat siblings as *leads*, not confirmed family until corroborated. **imphash caveat: when `die`
reports a packer/protector, the imphash is the *stub's* import hash, so `imphash_search` groups by
PACKER, not family** — expect siblings with divergent `suggested_threat_label`s (e.g. a `.NET
Reactor` imphash will pull unrelated families that merely share the packer). Trust same-label
imphash siblings as campaign leads; downgrade divergent-label ones to "same packer". Critically, an `error`
containing `403`/`Forbidden` on a reverse pivot means the VT key tier **gated** that lookup, NOT
that no siblings exist — say so rather than implying the family is small; `count: 0` with no
error is a real empty result. `meta.calls_used`/`max_calls` record the rate-limit budget.

`behavior.json` (when present) carries **VT behaviour ingestion** (roadmap N1) — runtime
activity from sandbox detonations VT *already* ran (nothing is uploaded). This is the pipeline's
one source of **confirmed-observed** behaviour: unlike the embedded-only stages
(`config.json`/`unpacked/`/`peinfo`), these indicators were seen at runtime, so they promote a
contacted host or dropped hash from "High *intent*" to **"confirmed live (per VT, `<analysis_date>`)"**
— exactly the IR/MDR question the static stages can't answer. Read `meta.status` FIRST, it decides
everything: **`found`** = a dynamic sandbox ran it, mine `network` (`dns_lookups`/`ip_traffic`/`http`/
`tls`/`memory_iocs`) and `host` (`files_dropped` *with child hashes*, `registry_set`, `mutexes_created`,
`processes_created`, `command_executions`, `services_created`) and `verdict` (`attack_techniques`,
`sandbox_signatures`, `ids_alerts`); **`static_only`** = VT has only a STATIC report (e.g.
`sandbox_name: CAPA`, `has_network:false`) so NO dynamic data exists — a **GAP**, escalate to an own
sandbox (#1), never read it as "did nothing" (this is the `av45i` case — pre-2007 worm won't run in
modern sandboxes); **`not_detonated`** = VT has no behaviour report at all (GAP); **`unavailable`** =
no VT key (GAP). Feed the resolved IPs (under `dns_lookups[].resolved_ips`) and `files_dropped[].sha256`
**back into the IP-rep + VT-pivot stages** — these are fresh pivots the static stages never had. Tag
findings `[behavior]`; the values are observed by *VT* at a past date, not by you (note staleness).
`meta.truncated` records any activity list capped at the per-list limit.

If `ghidra.json` is present (produced only by `triage.sh --deep`), it carries the Ghidra
headless export: program metadata, full `functions` inventory, `imports`, defined `strings`,
and `decompiled` C for a targeted shortlist (entry point + functions calling network/crypto/
loader imports). Use the decompiled C to read the suspected decrypt/overlay-read routine and
confirm algorithms as code — but remember it reflects only what was analyzed: **on a packed
crypter the export sees the loader stub, not the encrypted payload** (tag such findings `[r2]`-
style as Ghidra-derived and keep the overlay-contents hypothesis at Investigate until unpacked).

`unpacked.json` + the `unpacked/` subdir (present only when `triage.sh --unpack` ran, PE only)
carry the **emulation-unpacking** stage (roadmap N4): Speakeasy emulates the loader stub (no
VM/detonation/network) and carves the regions it decrypts in memory. Read `meta` first:
`status` (`ran`/`instr_cap`/`timeout`/`stalled`/`load_failed`/`skipped`/`no_emulator`),
`instructions`, and `recovered`. **`recovered: true`** with a `primary_region` means a payload was
obtained — the binary tools were re-run on it and their output is in `unpacked/`
(`strings.txt`, `floss.json`, `capa.json`, `yara.txt`) plus the carved `region_*.bin`; mine those
the same way you mine the top-level artifacts, and treat strings/imports/C2 found there as the
**real body**, not the stub. **`recovered: false`** with `meta.gap` is a **GAP, not a clean
result** — the stub bailed early (a low `instructions` count = unsupported API / anti-emulation /
remote-keyed / injection the emulator can't follow); say so and recommend a dynamic sandbox (#1),
do not imply the sample is unpacked or benign. Two honest limits to carry into the report:
(1) unpacking recovers **embedded** indicators only — it does **not** confirm runtime behaviour,
so an unpack-recovered C2/key is "High intent / embedded", **not** "confirmed live"; (2) carved
regions are raw **memory images** (not file-aligned PEs), so trust unpacked `capa`'s *hits* but
not its *misses* (`unpacked/capa.err` will note PE-parse warnings). Source tag `[unpack]`.

`provenance.json` (when present) records the exact stack that produced the report: each tool's
`version` under `tools` (capa, floss, die, yara, ghidra, speakeasy, python) and each rule-set's `commit`+`date`
(git-tracked: `capa-rules`, `yara-rules`, `signature-base`) or `newest_file`+`file_count` (mtime-based:
`capa-sigs`) under `rules`, plus `generated_utc`, `host`, and the `sample` it is bound to. A tool/rule
with `error` instead of a version is one that wasn't installed/found — note it as a gap. Use this to
render the report's provenance footer (step 4); also sanity-check it — e.g. a stale `signature-base`
date weakens a "no YARA match ⇒ clean" inference.

Invoke Python with whatever exists on the host: `python3` (Linux/macOS) or `python` / `py`
(Windows). Read files with explicit `encoding="utf-8"` so decoded strings survive on Windows.

## 3. Optional deep-dive for packed/overlaid samples

If `peinfo.json` shows a high-entropy overlay or `die`/yara indicate packing, attempt to go
deeper. **These RE tools are Linux-box extras and are usually absent on a Windows analyst host**
(`radare2`/`rabin2`, `binwalk`, `upx`); if a tool is missing, skip that sub-step and record it
as a gap rather than failing. The overlay carve + byte-stats below use only **Python** and run
anywhere:

- Carve the overlay to the scratchpad with Python (cross-platform) and characterize it —
  read `peinfo.json` `overlay.start_offset`/`size_bytes`, then in Python:
  `data = open(sample,'rb').read()[start:start+size]` and inspect length, header bytes, and a
  byte-value histogram (near-uniform ⇒ encrypted/compressed). Do **not** rely on `dd`.
- If present, try `upx -t`; if not a known packer, use radare2 to locate the decrypt/overlay-read
  path (`axt` xrefs to `fread`/`fopen`/`GetModuleFileNameA`; `pdf` the candidate functions;
  cross-check FLOSS `analysis.functions.decoding_function_scores`).
- Recover the string/decrypt algorithm if self-contained; **state plainly if it is
  runtime/C2-keyed and statically unrecoverable.** Never claim an unpack that did not happen.
- For a packed PE, prefer the built-in **emulation unpacker**: re-run collection as
  `./triage.sh <sample> --unpack` (Linux only). It emulates the loader stub in Speakeasy and, if
  the stub self-decrypts, writes the recovered body + re-run floss/capa/yara to `unpacked/`
  (read `unpacked.json` — see step 2). If it records a gap (`recovered: false`), that is the
  signal the sample needs a real sandbox, not more static effort.
  **Note:** on the Linux raw-sample path this `--unpack` (and `--deep`) escalation now happens
  **automatically in step 1b** when the evidence warrants it — the manual re-run here is the
  fallback for the existing-report-dir path (a report collected without the flags, or a Windows
  host), where you can't re-trigger `triage.sh` and should instead recommend it as a next step.

**Never execute the sample.** No detonation on this host — recommend an isolated sandbox
instead. Treat all conclusions as hypotheses (High/Medium/Investigate) with cited evidence
and a next action, per CLAUDE.md. Cross-check the submitter filename against the evidence and
flag mislabels (e.g. a file named "Ransomware" that is actually a worm).

## 4. Write the report

Write the full analysis to `<report-dir>/analysis_report.md` using the CLAUDE.md output
format: Executive Summary, Threat Assessment, Hypothesis List, IOC Table, ATT&CK TTP List,
**Trend Vision One — Search App hunting queries**, Recommended Next Steps. Add a "Reverse
Engineering Findings" section if step 3 ran. Then give the user a short summary in chat and the
path to the saved report, ending with the §0 completion banner (`✅ ANALYSIS COMPLETE — HTML
report: <path>`).

**Vision One query block (per the CLAUDE.md output spec).** Derive it from the IOC table:
OR-join the file hashes under `objectFileHashSha256`, add `processFilePath`/`processName`
queries for any install paths/patterns, and `dst`/`hostName`/`request` for recovered network
C2. Use real values (a query field isn't a clickable link; defang only a full URL's scheme).
Mark the field names as a template to validate against the analyst's tenant schema, and if no
network IOCs were recovered, emit only the hash/path queries with a note that network ones
populate after unpack/detonation.

**Provenance footer (required when `provenance.json` exists).** End the report with a
"Tooling & Rule Provenance" section so findings are reproducible / audit-grade: a small table of
tool versions (capa, floss, die, yara, ghidra, speakeasy, python) and rule-set commit/date
(capa-rules, yara-rules, signature-base) + capa-sigs newest-file date, plus the `generated_utc`
stamp and host. This is the reproducibility record for the report — keep it factual, no analysis.
If `provenance.json` is absent (older report, or triage predates this stage), say so in one line
rather than omitting the section silently.

**Hypothesis List format (required).** Open the list with a one-line source-tag legend, then
give each hypothesis these five fields in order:

- **Claim:** one sentence stating what the hypothesis asserts.
- **Evidence (N sources agree):** a bullet per source, each prefixed with a source tag. Put the
  independent-source count in the heading — it is what justifies the confidence.
- **Interpretation:** 1–2 sentences translating the raw artifacts into behavior. Reserve this for
  genuine artifact→behavior translation; if the claim already says it, keep it to one line or omit.
  Flag any inference that is not directly observed.
- **Confidence:** High/Medium/Investigate, *justified by source diversity*. If a claim rests on a
  **single source**, say so and split confidence (e.g. "High intent / Investigate exact values").
- **Next action:** the step to confirm or disprove it.

Source tags — be precise, because the distinction carries analytic weight:
`[peinfo-import]` (static IAT entry = hard fact) · `[floss-string]` (decoded/static string, **incl.
dynamically-resolved API names** via `GetProcAddress` — NOT an import) · `[r2]` (radare2 control
flow) · `[ghidra]` (Ghidra decompiled pseudocode, `--deep` only) · `[unpack]` (emulation-recovered
payload: strings/capa/yara from `unpacked/`, `--unpack` only — embedded indicators, not confirmed
live) · `[config]` (configextractor-py: embedded family config — C2/keys/campaign/mutex ripped
from a recognized family; embedded indicators, High intent not confirmed-live; feed back into
domain/IP-rep + VT-pivot) · `[capa]` · `[VT]` (AV-engine
consensus) · `[VT-YARA]` (crowdsourced YARA on VT) · `[VT-domain]` (VirusTotal domain report) ·
`[VT-pivot]` (VirusTotal pivoting: contacted/dropped relationships + imphash/communicating-file
siblings) · `[behavior]` (VT behaviour ingestion: runtime activity OBSERVED in VT's sandbox —
network/dropped/registry/mutexes/processes; **confirmed-observed per VT at the analysis date**,
unlike the embedded-only `[config]`/`[unpack]` tags — promote to "confirmed live (per VT, <date>)",
not just intent; `static_only`/`not_detonated` status = a GAP, escalate to a sandbox) ·
`[ThreatFox]` / `[URLhaus]` (abuse.ch domain/C2 reputation) · `[AbuseIPDB]` (IP reputation) ·
`[YARA]` (local rules) · `[die]` · `[peinfo]` (PE structure: sections, entropy, overlay) ·
`[authenticode]` (signify signature VERIFICATION, PE/.NET — `authenticode.json`: chain+digest
verified against the MS trust store, validity window, `self_signed`/`hash_mismatch`/`expired`/
`weak_digest` flags, stolen/abused-cert correlation. EMBEDDED evidence: `valid` from a known vendor
leans benign but is NOT "confirmed clean" — stolen-cert + trojanized-legit are signed too;
`hash_mismatch`/`invalid` is a High finding; `unavailable` = signify missing, a GAP not "unsigned";
revocation is NOT checked offline) ·
`[dotnet_deob]` (N7 managed .NET deob, PE/.NET — `dotnet_deob.json` + `deobfuscated/`: de4dot strips
a detected protector, capa/config/strings re-run on the clean assembly. `deobfuscated` = trust the
re-run hits; `no_protector` = .NET but already-clean IL; `unavailable` = de4dot/mono missing, a GAP
not "clean"; `error` = unstrippable variant → escalate. EMBEDDED intent only) ·
`[fileinfo]` (file-type ID / masquerade) · `[olevba]` / `[oleid]` (Office macro & IOC) ·
`[pdfid]` / `[pdf-parser]` (PDF structure & active content) · `[lnk]` (shortcut target/args) ·
`[email]` (mail headers/URLs/attachments) · `[archive]` (container listing + extracted children;
ISO/UDF/VHD/VHDX/IMG delivery images route here too, recursion capped) ·
`[scriptscan]` (N8 script deobfuscation — `scriptscan.json` + `script_layers/`: recursive base64/hex/
charcode/%-escape/gzip layer-peeling, defanged per-layer IOCs, carved PE/ZIP. EMBEDDED intent) ·
`[htmlsmuggle]` (N9 HTML/SVG smuggling — `htmlsmuggle.json` + `html_payloads/`: reassembly-primitive
fingerprint, decoded data:/atob/base64 blobs, carved payload. `smuggling_suspected` flag. EMBEDDED intent) ·
`[strings]` (universal strings.txt/json, non-PE). Never tag a runtime-resolved API as
`[peinfo-import]` — verify against the actual import table first.

The `.md` is the canonical **source** of the report — write it first and never skip it. It is
not the deliverable, though: the **HTML is** (step 5), and the HTML is always generated *from*
the `.md`. Never hand-author the HTML and never replace the `.md` with a document format.

## 5. Auto-generate the HTML report (required — do not ask)

**As soon as `analysis_report.md` is written, automatically convert it to HTML** with the
bundled cross-platform exporter. This is **not** an opt-in step any more — do **not** ask
"do you want an HTML copy?"; just produce it. `analysis_report.html` is the deliverable the
user opens; the `.md` stays beside it as the source. Never hand-roll
`pandoc`/`pdflatex`/`weasyprint` commands, which are not portable:

```
python <skill-dir>/export_report.py <report-dir>/analysis_report.md --to html
```

(use `python3`/`py` if `python` isn't the right launcher.) The script writes
`analysis_report.html` next to the `.md` and prints the path — report that path to the user
as the finished report.

How it works (so you can explain it / debug it):
- **HTML** comes straight from `pandoc` (the single external dependency) — a self-contained,
  styled, dark-theme `.html` with embedded CSS (no external files needed to view it).
- **PDF / DOCX** are still available **on request** — re-run with `--to pdf` / `--to docx` /
  `--to all`. PDF = pandoc renders light-theme HTML, then a **headless browser prints it to
  PDF** (Edge on Windows; Chrome/Chromium/Brave elsewhere, auto-detected; no LaTeX/weasyprint).
  After delivering the HTML, you may briefly offer PDF/DOCX, but never gate the HTML on a prompt.

Error handling (the HTML step must degrade loudly, not silently):
- If the script reports **`pandoc` is missing**, relay its install hint
  (`sudo apt install pandoc` on Debian; `winget install --id JohnMacFarlane.Pandoc` on Windows;
  `brew install pandoc` on macOS) and tell the user the HTML could not be generated — do **not**
  fake it or quietly fall back to only the `.md`.
- For **PDF specifically**, if no headless browser is found the exporter still produces the
  `.html` and warns; relay that the HTML is ready and PDF needs a browser. (The HTML step itself
  does not need a browser.)
