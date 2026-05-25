# Auditor Bundle Guide — Verifying a Full Evidence Period

**Audience:** senior auditor reviewing an entire audit period's evidence package.
**Use case:** Q1 SOC 2 evidence review. You received a `.dsr.bundle` file
covering an entire quarter and want to confirm every receipt is authentic.

---

## What is an evidence bundle?

An evidence bundle (`.dsr.bundle`) is a ZIP archive that packages every
receipt for an audit period together with a cryptographically signed
manifest. The manifest:

- Lists every receipt by sequence number, file name, and content hash
- Is signed by the same ed25519 key that signs the individual receipts
- Binds the complete set of receipts: adding, removing, or reordering any
  receipt breaks the manifest signature

A bundle lets you verify an entire evidence period in a single command
rather than verifying each receipt manually.

---

## What you need

From the customer:

1. **The bundle file** — a `.dsr.bundle` file, for example
   `acme-fintech-q1-soc2.dsr.bundle`
2. **The vault's public key** — the same `.pub` file used for single
   receipt verification, for example `acme-fintech-vault.pub`

---

## Step 1 — Run bundle verification

```
dsr-verifier-cli verify-bundle acme-fintech-q1-soc2.dsr.bundle \
  --key acme-fintech-vault.pub
```

For large bundles (hundreds or thousands of receipts), verification takes
a few seconds. A 10,000-receipt bundle completes in under 10 seconds on
typical hardware.

---

## Step 2 — Read the output

A successful verification looks like this:

```
┌─ DSR Verifier · v1.0.0 · Bundle Verification ───────────────────────┐
│ Bundle:   acme-fintech-q1-soc2.dsr.bundle                            │
│ Using key: acme-fintech-vault.pub                                    │
└──────────────────────────────────────────────────────────────────────┘

Bundle:     acme-fintech-q1-soc2.dsr.bundle (18.4 MB)
Vault:      vlt_acme-fintech
Period:     2026-01-01 to 2026-03-31
Frameworks: SOC 2 · NYDFS 500

Verifying 412 receipts...

  R1 (Attribution)              387/387 passed
  R1-L (Low Confidence)          18/18 passed
  R1-N (No Match)                 5/5 passed
  R2 (Resolution)                 2/2 passed
  RV (Vault Verification)       720/720 passed  (continuous integrity)

✓ Verifying bundle signature ....................................... OK
  Bundle signed by:    key_acme_2026q1
  Bundle signature:    valid

✓ Verifying sequence integrity ..................................... OK
  Sequence range:      1–2,178 (no gaps detected)

✓ Verifying causal chain consistency ............................... OK
  Cross-receipt references resolved within bundle: 38 / 38

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Bundle verified · all 412 receipts cryptographically valid

Summary:
  Pass rate:     412 / 412 (100%)
  Tampered:      0
  Missing:       0
  RV coverage:   720 vault-verification receipts · 30 days covered

Output: verification report written to ./acme-fintech-q1-soc2.verification.json
```

---

## Step 3 — Understand what each check means

### Per-receipt verification (by type)

Every receipt in the bundle is individually verified against the same four
checks as single-receipt verification (key authority, signature, content
hash, causal references). Failures are listed by receipt type:

| Receipt type | What it represents |
|-------------|-------------------|
| R1 (Attribution) | A merged pull request was attributed to a specific developer |
| R1-L (Low Confidence) | Attribution assigned with lower confidence |
| R1-N (No Match) | No attribution match found for this commit |
| R2 (Resolution) | A dispute or override of a prior attribution |
| RV (Vault Verification) | Continuous integrity check — see below |

### What the RV receipt line means

The `RV (Vault Verification)` line is often the most important for a
continuous-assurance engagement.

In the example output: **720 RV receipts = 30 days × 24 per day**.

Each RV receipt is a cryptographically signed attestation that on that
specific hour, Déjà's continuous integrity system scanned the entire vault
and found no anomalies. The RV receipts are issued hourly. For a 92-day
audit period, a complete coverage period would have:

```
92 days × 24 hours/day = 2,208 RV receipts
```

If the `DaysCovered` value matches the period length (and `TotalAnomalies`
is 0), you have cryptographic evidence of continuous integrity monitoring
for the entire audit period.

**What to check:**
- Does `DaysCovered` equal the number of days in the audit period?
- Is `TotalAnomalies` zero?
- Is the streak (longest unbroken daily sequence) equal to the full period?

### Bundle signature

The manifest signature covers the entire receipts list. If any receipt was
added, removed, or modified after the bundle was signed, this check fails.
A failed manifest signature means the bundle as a whole cannot be trusted,
even if individual receipts look valid.

### Sequence integrity

The manifest assigns every receipt a sequential number. Gaps in the sequence
(e.g., 1, 2, 4 — missing 3) indicate receipts were removed from the bundle
after it was assembled, which also causes the manifest signature to fail.

### Causal chain consistency

R1, R1-L, and R1-N receipts can reference a "parent" receipt (typically an
earlier attribution that was revised). The causal chain check verifies that
parent references within the bundle resolve correctly. References to receipts
outside the bundle scope are noted but not treated as failures — partial
bundles may legitimately omit earlier periods.

---

## Step 4 — The verification report

After every bundle verification, a JSON report is automatically written to
`<bundle-name>.verification.json` — in this example,
`acme-fintech-q1-soc2.verification.json`.

The report contains:
- All check results (passed/failed) with error details
- Per-type receipt counts
- RV coverage statistics
- The verifier version and duration

Include this file in your audit working papers as the machine-readable
record of the verification.

---

## Step 5 — Get machine-readable output

For scripting or audit management systems:

```
dsr-verifier-cli verify-bundle bundle.dsr.bundle --key vault.pub --json
```

This outputs the full verification result as JSON to stdout and also writes
the `.verification.json` report file.

Exit codes for scripting:
- `0` — all checks passed
- `1` — one or more checks failed
- `2` — bundle file is malformed
- `3` — bundle or key file not found
- `4` — key file is invalid

---

## Common questions

**Q: The bundle has 720 RV receipts but I only expected 412. Is that normal?**

Yes. The per-receipt count in "Verifying N receipts" shows the total
receipt count. The breakdown then shows how many are of each type. RV
receipts are issued hourly, so they typically make up the majority of a
large bundle. 412 might be the count of R1/R1-L/R1-N/R2 receipts while 720
are RV receipts, for a total of 1,132 receipts.

**Q: Some receipts are listed as R1-L (Low Confidence). Should I be concerned?**

Not necessarily. R1-L indicates Déjà assigned the attribution with lower
confidence — perhaps the commit pattern was ambiguous. The receipt is still
cryptographically valid. Whether low-confidence attributions are acceptable
for your audit purpose is a scope question for the engagement team.

**Q: The causal chain shows "out-of-scope references." Is that a failure?**

No. Out-of-scope references occur when an R1 receipt in this bundle
references a parent receipt that was issued in an earlier period (not
included in this bundle). This is expected for any bundle that doesn't
cover the beginning of a project's history.

**Q: The bundle verification says "tampered: 1." What should I do?**

Stop and contact the issuing organization. One or more receipts have a
valid signature but a mismatched content hash — meaning the content was
modified after signing. Do not use this bundle as audit evidence until the
discrepancy is resolved. Document the failure in your audit findings.
