# Auditor Quick Start — Verifying a Single Receipt

**Time required:** about 5 minutes.
**Audience:** junior auditor at an accounting or advisory firm.

This guide walks you through verifying a DSR receipt — a cryptographically
signed evidence record issued by Déjà on behalf of a customer. By the end
you will know whether the receipt is authentic and unmodified.

---

## What you need

Two files from the customer:

1. **The receipt file** — a `.dsr` file, for example `r_8a4f2c9e.dsr`
2. **The vault's public key** — a `.pub` file, for example `acme-fintech-vault.pub`

The customer should provide both. If you only have the receipt, ask the
issuing organization for their public key file.

---

## Step 1 — Install the CLI

**macOS (recommended):**
```
brew install deja-dev/tap/dsr-verifier-cli
```

**Linux / Windows — direct download:**

Go to https://verify.deja.dev/download and download the binary for your
platform. Verify the SHA-256 checksum against the values listed on that page
before running the binary.

After installation, confirm it works:
```
dsr-verifier-cli --version
```

You should see something like:
```
dsr-verifier-cli v1.0.0 (commit: a3f8c2e)
DSR/1.0.1 · MIT License · https://github.com/deja-dev/dsr-verifier-cli
Offline · zero network calls
```

---

## Step 2 — Verify the receipt

Open a terminal in the directory containing your two files and run:

```
dsr-verifier-cli verify r_8a4f2c9e.dsr --key acme-fintech-vault.pub
```

Replace the file names with your actual files.

---

## Step 3 — Read the output

**If the receipt is authentic**, you will see:

```
┌─ DSR Verifier · v1.0.0 ─────────────────────────────────────────────┐
│ Verifying: r_8a4f2c9e.dsr                                            │
│ Using key: acme-fintech-vault.pub                                    │
│ Mode:      offline · no network calls                                │
└──────────────────────────────────────────────────────────────────────┘

✓ Key authority check .............................................. OK
  Claimed:      key_acme_2026q2
  Provided:     key_acme_2026q2

✓ Signature verification ........................................... OK
  Algorithm:  ed25519
  Key ID:     key_acme_2026q2

✓ Content hash verification ........................................ OK
  Algorithm:  sha256
  Computed:   4d8a2c9e7b3f1a2d4c5e6f7a8b9...
  Stored:     4d8a2c9e7b3f1a2d4c5e6f7a8b9...

✓ Causal artifact structural validation ............................ OK
  PR reference:  github.com/acme-fintech/payments-api#4287 (structure valid)
  Commit SHA:    a8f3c2e9

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Result: VERIFIED  ·  4 checks passed  ·  0 failures
Trust path: key authority → signature → content hash → structural
```

**All four checks passed.** This receipt is authentic.

---

**If the receipt has been tampered with**, you will see:

```
✗ Content hash verification ..................................... FAIL
  Error class: content_hash_mismatch
  ...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Result: FAILED  ·  1 check(s) failed  ·  3 passed

Failure: content_hash_mismatch

  The hash of the receipt's current content does not match the
  content_hash field that was included in the signed payload. This
  means the content of the receipt was modified after the receipt
  was signed. ...

Recommended actions for auditor:

  • Confirm the receipt file was not modified in transit
  • Request a fresh receipt copy directly from the source organization
  • Do NOT trust the content of this receipt for audit purposes
```

---

## Step 4 — Save the result for your audit working papers

The CLI writes a local audit log entry to `./verifier.log` automatically.
To save the full output as structured JSON for your working papers:

```
dsr-verifier-cli verify r_8a4f2c9e.dsr --key acme-fintech-vault.pub --json > verification-result.json
```

The JSON output includes the receipt ID, all check results, the timestamp,
and the duration. Attach it to your audit file.

To disable the local log file if your firm has specific logging requirements:

```
dsr-verifier-cli verify r_8a4f2c9e.dsr --key acme-fintech-vault.pub --no-log
```

---

## What the four checks mean

| Check | What it verifies |
|-------|----------------|
| Key authority | The receipt was signed by the key you provided, not a different one |
| Signature | The receipt's envelope fields have not been modified since it was signed |
| Content hash | The receipt's content has not been modified since it was signed |
| Causal references | The PR URL and commit SHA in the receipt have the correct format |

All four checks run offline — **no internet connection required, and no data
is sent to Déjà or anyone else.**

---

## Common issues

**"Key file not found"**
Make sure you are running the command from the right directory, and that the
`.pub` file name exactly matches what you typed.

**"Key authority mismatch"**
You are using the wrong public key. Ask the issuing organization for the
correct key for this receipt. The receipt says which key it expects —
look for the `signing_key_id` value in the error output.

**"Receipt file not found"**
The `.dsr` file is not in the current directory. Either `cd` to the folder
containing it, or provide the full path.

**"Malformed receipt"**
The receipt file is corrupt or is not a valid DSR/1.0.1 file. Request a new
copy from the issuing organization.

For more failure codes, see `docs/troubleshooting.md` or run:
```
dsr-verifier-cli verify --help
```
