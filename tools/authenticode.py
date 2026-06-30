#!/usr/bin/env python3
"""Authenticode / digital-signature verification (roadmap N6).

Beyond noting that a signature blob EXISTS (pestats reports presence/size from the
PE security directory), this stage VERIFIES it: it validates the PKCS#7/Authenticode
chain against the Microsoft trust store, checks the signing-cert validity window,
flags self-signed / broken-digest / deprecated-digest cases, and matches the signer
against a committed, analyst-maintained list of known stolen/abused signing certs
(rules/abused_certs.json).

Signing status is a cheap, strong, BIDIRECTIONAL signal:
  - signed-and-valid by a recognizable vendor LOWERS suspicion (helps rule benign IN)
  - a broken / expired / self-signed / abused signature is itself a finding

Honesty (per CLAUDE.md):
  * This recovers EMBEDDED evidence only. We can prove the chain and the digest, but
    revocation (OCSP/CRL) is an ONLINE check we do NOT perform offline — it is recorded
    as a gap, never asserted.
  * `valid` means the signature is cryptographically intact AND chains to a trusted root
    AS OF the signing time. It does NOT prove the binary is benign — stolen-cert abuse
    and trojanized-but-still-signed legit binaries are exactly the cases where a VALID
    signature accompanies malware. Promote a valid signature to "benign-leaning" intent,
    never to "confirmed clean".
  * A missing tool is missing evidence, not absence of a signature: if python-signify is
    not installed we emit status `unavailable` (a GAP, run tools/setup-env.sh), never
    `not_signed`.

status: valid | invalid | not_signed | unavailable | error
  valid       — >=1 signature verifies (chain OK as of signing time, digest matches)
  invalid     — signature(s) present but verification failed (see flags + reason)
  not_signed  — no Authenticode signature in the security directory
  unavailable — python-signify not importable in this interpreter (GAP)
  error       — unexpected failure (captured here, never raised into the pipeline)

flags (layered on top of status; each is an analyst signal, not a verdict by itself):
  hash_mismatch        — digest in the signature != computed digest (tampered after signing)
  inconsistent_digest  — signed-data digest algorithms disagree (malformed/tampered)
  expired_at_analysis  — signing cert is past valid_to as of now (weak alone; many old
                         legit binaries are too — weigh with the countersignature time)
  signed_outside_validity — signing time falls outside the leaf cert's validity window
  self_signed          — a leaf subject == its issuer (no real CA vouches for it)
  weak_digest_sha1     — signed with SHA-1 (deprecated; common on pre-2016 binaries)
  weak_digest_md5      — signed with MD5 (broken; strong tamper/forgery concern)
  no_countersignature  — no trusted timestamp, so validity can't be anchored in time
  abused_cert          — signer matches a thumbprint/serial in rules/abused_certs.json (HARD)
  abused_cert_suspected — signer NAME matches an abused-cert entry (SOFT → Investigate)

Source tag [authenticode]. Output: authenticode.json. Applies to PE/.NET only (ELF has
no Authenticode). Runs under the venv python so signify is importable.

Design mirrors the other N-stages (config_extract / vt_behavior): self-locating paths,
stdlib + one venv dep, and it NEVER raises into the pipeline.

Usage:  authenticode.py <sample> <out.json>
"""
import datetime
import json
import os
import re
import sys

# Self-locate so the abused-cert ruleset resolves wherever the project is moved
# (team-distributed tool — see CLAUDE.md / the path-portability memory).
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(SCRIPT_DIR)
ABUSED_CERTS = os.environ.get(
    "ABUSED_CERTS", os.path.join(BASE, "rules", "abused_certs.json"))


def _now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def _iso(dt):
    """Render a datetime as ISO-8601 string, or pass through None/str."""
    if dt is None:
        return None
    try:
        return dt.isoformat()
    except AttributeError:
        return str(dt)


def _cn(dn_obj):
    """Pull the CN from a signify CertificateName (falls back to the full DN)."""
    if dn_obj is None:
        return None
    dn = getattr(dn_obj, "dn", None) or str(dn_obj)
    m = re.search(r"CN=([^,]+)", dn)
    return m.group(1).strip() if m else dn


def _dn(dn_obj):
    if dn_obj is None:
        return None
    return getattr(dn_obj, "dn", None) or str(dn_obj)


def load_abused_certs():
    """Load the analyst-maintained abused/stolen-cert list. Missing list is not an
    error — it just means no hard matches are possible (returns empty + a note)."""
    try:
        with open(ABUSED_CERTS, encoding="utf-8") as f:
            data = json.load(f)
        entries = [e for e in data.get("certs", []) if isinstance(e, dict)]
        return entries, None
    except FileNotFoundError:
        return [], f"abused-cert list not found at {ABUSED_CERTS}"
    except Exception as e:
        return [], f"{type(e).__name__}: {e}"


def match_abused(leaf, chain_subjects, abused):
    """Return (hard_hits, soft_hits). Hard = thumbprint/serial match; soft = the
    signer/issuer NAME contains a known-abused signer name (Investigate-grade)."""
    hard, soft = [], []
    sha1 = (getattr(leaf, "sha1_fingerprint", "") or "").lower().replace(":", "")
    sha256 = (getattr(leaf, "sha256_fingerprint", "") or "").lower().replace(":", "")
    serial = str(getattr(leaf, "serial_number", "") or "")
    names_blob = " ".join(s for s in chain_subjects if s).lower()
    for e in abused:
        ref = {"name": e.get("name"), "reference": e.get("reference"),
               "note": e.get("note")}
        tp = (e.get("thumbprint_sha1") or "").lower().replace(":", "")
        tp256 = (e.get("thumbprint_sha256") or "").lower().replace(":", "")
        ser = str(e.get("serial") or "")
        if (tp and tp == sha1) or (tp256 and tp256 == sha256) or (ser and ser == serial):
            hard.append({**ref, "matched_on": "thumbprint/serial"})
            continue
        nm = (e.get("signer_name") or "").lower()
        if nm and nm in names_blob:
            soft.append({**ref, "matched_on": f"signer-name substring '{e.get('signer_name')}'"})
    return hard, soft


def build_signature_record(sig, now):
    """Flatten one Authenticode signature into a JSON-safe record + per-sig flags."""
    flags = set()
    si = sig.signer_info
    certs = list(sig.certificates)

    # Locate the leaf (signing) cert by serial number.
    leaf = next((c for c in certs if c.serial_number == si.serial_number), None)

    # Digest algorithm name (e.g. openssl_sha1 / openssl_sha256).
    dalg = getattr(sig, "digest_algorithm", None)
    dalg_name = getattr(dalg, "__name__", None) or str(dalg)
    low = dalg_name.lower()
    if "sha1" in low:
        flags.add("weak_digest_sha1")
    if "md5" in low:
        flags.add("weak_digest_md5")

    signing_time = getattr(si, "signing_time", None)
    counter = getattr(si, "countersigner", None)
    counter_time = getattr(counter, "signing_time", None) if counter else None
    if not counter_time:
        flags.add("no_countersignature")

    leaf_rec = None
    chain_subjects = []
    if leaf is not None:
        vf, vt = getattr(leaf, "valid_from", None), getattr(leaf, "valid_to", None)
        # Validity-window checks (use the trusted countersignature time when present,
        # else the claimed signing time, else now).
        anchor = counter_time or signing_time
        if vt and vt < now:
            flags.add("expired_at_analysis")
        if anchor and vf and vt and not (vf <= anchor <= vt):
            flags.add("signed_outside_validity")
        # Self-signed applies to the LEAF (signing) cert only. A root CA in the
        # embedded chain is self-signed BY DESIGN (subject == issuer) — flagging
        # that would false-positive on every normally-signed binary.
        if _dn(leaf.subject) and _dn(leaf.subject) == _dn(leaf.issuer):
            flags.add("self_signed")
        leaf_rec = {
            "subject": _dn(leaf.subject),
            "subject_cn": _cn(leaf.subject),
            "issuer": _dn(leaf.issuer),
            "issuer_cn": _cn(leaf.issuer),
            "serial": str(leaf.serial_number),
            "sha1_thumbprint": getattr(leaf, "sha1_fingerprint", None),
            "sha256_thumbprint": getattr(leaf, "sha256_fingerprint", None),
            "valid_from": _iso(vf),
            "valid_to": _iso(vt),
            "signature_algorithm": str(getattr(leaf, "signature_algorithm", None)),
        }

    # Chain subjects feed the abused-cert NAME correlation (all certs, incl. CAs).
    chain_subjects = [_dn(c.subject) for c in certs]

    rec = {
        "digest_algorithm": dalg_name,
        "program_name": getattr(si, "program_name", None),
        "signing_time": _iso(signing_time),
        "countersignature_time": _iso(counter_time),
        "signer": {
            "serial": str(getattr(si, "serial_number", None)),
            "issuer": _dn(getattr(si, "issuer", None)),
            "issuer_cn": _cn(getattr(si, "issuer", None)),
        },
        "leaf_certificate": leaf_rec,
        "chain": [{"subject": _dn(c.subject), "issuer": _dn(c.issuer),
                   "serial": str(c.serial_number)} for c in certs],
        "flags": sorted(flags),
    }
    return rec, flags, leaf, chain_subjects


def analyze(sample_path):
    result = {
        "tool": "signify",
        "sample": os.path.basename(sample_path),
        "status": "not_signed",
        "verification_result": None,
        "reason": None,
        "signature_count": 0,
        "signatures": [],
        "flags": [],
        "revocation": {
            "checked": False,
            "note": "Offline triage does not perform OCSP/CRL revocation checks. "
                    "If cert provenance is decision-relevant, verify revocation out of band.",
        },
        "abused_cert_matches": [],
        "analyst_note": None,
    }

    # signify is a venv dep; treat its absence as a GAP, not as "not signed".
    try:
        from signify.authenticode import (
            AuthenticodeFile, AuthenticodeVerificationResult)
    except ImportError:
        result["status"] = "unavailable"
        result["analyst_note"] = (
            "python-signify not installed in this interpreter — cannot verify the "
            "signature. This is a GAP, not a clean result. Run tools/setup-env.sh, "
            "then re-run. (pestats.peinfo.json still reports signature PRESENCE.)")
        return result

    now = _now_utc()
    try:
        with open(sample_path, "rb") as fh:
            af = AuthenticodeFile.from_stream(fh)
            sigs = list(af.signatures)
            result["signature_count"] = len(sigs)

            if not sigs:
                result["status"] = "not_signed"
                result["verification_result"] = "NOT_SIGNED"
                result["analyst_note"] = (
                    "No Authenticode signature present. Unsigned is common and NOT "
                    "proof of malice on its own — but a binary impersonating a known "
                    "signed vendor product while being unsigned is a masquerade signal.")
                return result

            all_flags = set()
            for sig in sigs:
                rec, flags, leaf, chain_subjects = build_signature_record(sig, now)
                # Abused-cert correlation (analyst-maintained ruleset).
                abused, _ = load_abused_certs()
                if leaf is not None:
                    hard, soft = match_abused(leaf, chain_subjects, abused)
                    if hard:
                        flags.add("abused_cert")
                        result["abused_cert_matches"].extend(
                            {**h, "severity": "hard"} for h in hard)
                    if soft:
                        flags.add("abused_cert_suspected")
                        result["abused_cert_matches"].extend(
                            {**s, "severity": "suspected"} for s in soft)
                    rec["flags"] = sorted(set(rec["flags"]) | flags)
                all_flags |= flags
                result["signatures"].append(rec)

            # Dedupe abused-cert matches (dual-signed files report each twice).
            seen = set()
            deduped = []
            for m in result["abused_cert_matches"]:
                key = (m.get("name"), m.get("matched_on"), m.get("severity"))
                if key not in seen:
                    seen.add(key)
                    deduped.append(m)
            result["abused_cert_matches"] = deduped

            # Overall verification verdict (verifies all embedded signatures).
            vres, exc = af.explain_verify()
            result["verification_result"] = vres.name
            if vres == AuthenticodeVerificationResult.OK:
                result["status"] = "valid"
            else:
                result["status"] = "invalid"
                result["reason"] = str(exc) if exc else vres.name
                # Map common failure modes to flags.
                name = vres.name
                if name == "INVALID_DIGEST":
                    all_flags.add("hash_mismatch")
                elif name == "INCONSISTENT_DIGEST_ALGORITHM":
                    all_flags.add("inconsistent_digest")

            result["flags"] = sorted(all_flags)
            result["analyst_note"] = _verdict_note(result)
            return result

    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {e}"
        result["analyst_note"] = (
            "Signature parsing failed unexpectedly (recorded as a gap, not a clean "
            "result). The security directory may be malformed — itself sometimes a "
            "tamper signal. Inspect manually / cross-check with peinfo.json.")
        return result


def _verdict_note(r):
    """Compose the analyst-facing one-liner from status + flags."""
    f = set(r.get("flags", []))
    if r["status"] == "valid":
        base = ("Signature verifies (chain trusted as of signing time, digest intact). "
                "This LOWERS suspicion but does NOT prove the file is benign — confirm "
                "the signer is the expected vendor, and remember stolen-cert abuse and "
                "trojanized-legit binaries are signed-and-valid too.")
        if "abused_cert" in f:
            return ("VALID signature, but the signer matches a KNOWN-ABUSED cert in the "
                    "ruleset — treat as High: likely stolen/abused code-signing cert.")
        if "abused_cert_suspected" in f:
            return base + (" NOTE: signer name resembles a known-abused cert — Investigate "
                           "against current threat intel before trusting it.")
        if "self_signed" in f:
            return ("Signature is internally consistent but SELF-SIGNED — no real CA "
                    "vouches for the signer. Treat as effectively unsigned / suspicious.")
        if "weak_digest_md5" in f:
            return base + " Signed with MD5 (broken digest) — forgery/tamper concern."
        return base
    if r["status"] == "invalid":
        if "hash_mismatch" in f:
            return ("Signature present but the digest does NOT match the file — the binary "
                    "was modified AFTER signing. Strong indicator of a trojanized/tampered "
                    "binary (High).")
        return (f"Signature present but verification FAILED ({r.get('verification_result')}: "
                f"{r.get('reason')}). Do not trust the signer; treat as unsigned at best, "
                f"tampered at worst.")
    return r.get("analyst_note")


def main():
    if len(sys.argv) != 3:
        print("Usage: authenticode.py <sample> <out.json>", file=sys.stderr)
        return 2
    sample, out_path = sys.argv[1], sys.argv[2]
    result = analyze(sample)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    # Compact console echo for the triage dashboard.
    st = result["status"]
    flags = ",".join(result.get("flags", [])) or "-"
    signer = None
    if result.get("signatures"):
        leaf = result["signatures"][0].get("leaf_certificate")
        signer = leaf.get("subject_cn") if leaf else None
    extra = f" | signer={signer}" if signer else ""
    print(f"    authenticode: {st} (flags: {flags}){extra} -> {os.path.basename(out_path)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
