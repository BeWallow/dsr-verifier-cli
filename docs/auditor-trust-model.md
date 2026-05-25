# Auditor Trust Model

**What does `dsr-verifier-cli` actually verify? What does it trust?
Why should you trust the CLI itself?**

This document answers those questions directly, without assuming you know
how ed25519 signatures work internally.

---

## What the CLI verifies

The CLI performs four independent checks on every receipt. Each is
cryptographic — the result is mathematically determined, not a judgment call.

### 1. Key authority

The receipt contains a claim: "I was signed by key `key_acme_2026q2`."
The public key file you provide identifies itself (via the `# key_id:` comment)
as a specific key.

This check asks: **do the claimed key ID and the provided key ID match?**

If they don't match, you have the wrong public key for this receipt — the
signature check would fail for the wrong reason. The CLI surfaces this first
so you know to get the right key.

### 2. Signature verification (ed25519)

The receipt's signature is a 64-byte value produced by the private key when
the receipt was signed. The only way to produce a valid signature is to have
held the private key at the time of signing.

This check asks: **does the ed25519 signature verify against the public key
and the receipt's envelope fields (ID, type, vault, timestamp, content hash)?**

If any of those eight envelope fields were modified after signing, the
signature fails. This includes the content hash — if someone changed the
content, they would need to re-sign with the private key. Without the
private key, they cannot.

### 3. Content hash verification (SHA-256)

The receipt's `content_hash` field is the SHA-256 hash of the receipt's
content object (with JSON keys sorted alphabetically). When the receipt was
signed, the content hash was computed from the actual content and then
included in the signed payload.

This check asks: **does re-computing SHA-256 of the current content produce
the same hash that was signed?**

This detects a specific attack: modifying the content without re-signing.
An attacker who changes `commit_sha` or `pr_url` in the content field
cannot also update the content hash without re-signing — and they cannot
re-sign without the private key. So the signature passes (original hash was
valid) but the content hash fails (current content doesn't match that hash).
The CLI reports both: "Signature: OK, Content hash: FAIL — receipt was
tampered after signing."

### 4. Causal reference validation

R1, R1-L, and R1-N receipts include a GitHub PR URL and a commit SHA.

This check asks: **do these fields have the correct structure?**

Specifically:
- Does the PR URL match the format `github.com/<org>/<repo>#<number>` or
  `https://github.com/<org>/<repo>#<number>`?
- Does the commit SHA consist of 7 to 64 hexadecimal characters?
- If `merged_at` is present, is it a valid RFC 3339 timestamp?

**This check does NOT fetch the PR or commit from GitHub.** The CLI is
offline. It verifies that the fields are structurally plausible — not that
the referenced PR actually exists or was merged. The cryptographic signature
is what guarantees authenticity; this check guards against obviously malformed
receipts.

---

## What the CLI trusts

### The public key you provide

The CLI trusts that the `.pub` file you pass with `--key` is the genuine
public key for the vault that issued the receipt. The CLI cannot verify
key provenance — it can only verify that a receipt was signed by the key
you provided.

The correct workflow: the customer sends you both the receipt file and the
public key. The public key should be delivered through a channel separate
from the receipt (for example, the customer's official website or directly
from their IT department). If you received the key from the same source
as the receipts, and that source is compromised, you cannot detect forgery.

### The DSR/1.0.1 specification

The CLI implements the DSR/1.0.1 receipt format as specified. If a receipt
claims to be `version: "DSR/1.0.1"` but was actually signed under different
rules, the CLI would not detect that — it verifies according to the spec it
implements.

### Your operating system's time

The CLI does not check whether a receipt's `issued_at` timestamp is in the
expected audit period. It only verifies that the timestamp is after 2020-01-01
(a basic sanity check) and that it parses as a valid RFC 3339 timestamp.
If a receipt's timestamp is in the future or outside the audit period, the
CLI will not flag it — that is a scope review for the auditor.

---

## What the CLI does NOT do

- **No network calls.** The CLI never contacts Déjà, GitHub, or any server.
  Every byte needed for verification comes from the files you provide.
- **No trust decisions.** The CLI verifies mathematics. It does not decide
  whether a verified receipt is meaningful for your audit — that is your job.
- **No key fetching.** Public keys are local files you provide. The CLI cannot
  download keys from the internet.
- **No analytics or telemetry.** The CLI records nothing to any remote system.
  The local `./verifier.log` is the only output, and `--no-log` suppresses even
  that.

---

## Why the source is open

The source code is published at `github.com/deja-dev/dsr-verifier-cli`
under the MIT License. This is intentional and load-bearing:

- **Auditors can read the code.** If your firm's security team wants to
  confirm that the CLI does not phone home, they can read the source.
  There is nothing to hide.
- **Anyone can rebuild.** The CLI is reproducible (see below). An auditor
  who does not trust the published binary can build it from source and
  confirm they get the same binary.
- **Open source is not just a distribution choice.** It is the evidence
  for the claims on this page. "Zero network calls" is not a marketing
  statement when the source code is available and the binary is
  reproducible.

---

## How to verify the CLI binary itself

If you want to be certain the binary you downloaded matches the published
source code:

**Option A: Check the SHA-256 checksum**

Download `SHA256SUMS` and `SHA256SUMS.asc` from the GitHub Release page.
Verify the GPG signature on `SHA256SUMS` (this proves the Déjà release key
signed those checksums). Then check your binary's SHA-256 against the file.

```bash
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

**Option B: Rebuild from source**

Anyone with Go 1.22.3 installed can rebuild the binary and verify it matches
the published SHA-256. See `BUILD.md` for the exact build command. The
resulting binary should be byte-for-byte identical to the published one
because the builds are reproducible (same source + same toolchain = same
binary).

---

## Summary: the trust chain

```
You provide:    receipt.dsr  +  vault.pub
                    │                │
                    ▼                ▼
CLI verifies:   signature ← signed payload ← content_hash ← content
                    │
                    ▼
                ed25519.Verify(vault.pub, signed_payload, signature)
                    │
                Result: VERIFIED or FAILED (deterministic, offline)
```

The only trust decision you make is: "Is this `vault.pub` the genuine key
for this organization?" Everything else is math.
