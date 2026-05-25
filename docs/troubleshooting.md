# Troubleshooting — Verification Failures

The 15 most common failures, what each means, and what to do.

---

## Receipt-level failures

### 1. `content_hash_mismatch` — "content hash does not match"

**What it means:** The receipt's content was modified after the receipt was
signed. The signature covers the original content hash; the current content
produces a different hash.

**Critical case: Signature: OK but Content hash: FAIL**

If the signature passed but the content hash failed, this is strong evidence
of tampering. An attacker modified the content without re-signing.

**What to do:**
- Do NOT use this receipt as audit evidence.
- Request a new copy directly from the issuing organization.
- Document the discrepancy in your audit findings.
- Ask the issuing organization to explain the chain of custody for the file.

---

### 2. `signature_invalid` — "ed25519 signature does not verify"

**What it means:** The ed25519 signature is not valid for the receipt's
envelope fields and the key you provided.

**Possible causes:**
a) The signature bytes were corrupted in transit.
b) One of the signed fields (id, type, vault_id, issued_at, content_hash)
   was modified after signing.
c) You are using the wrong public key.

**What to do:**
- First check: does the key authority check also fail? If so, start there —
  you likely have the wrong key. See failure #3.
- If key authority passed but signature failed: the receipt or signature
  field itself is corrupt. Request a fresh copy.

---

### 3. `key_authority_mismatch` — "wrong public key"

**What it means:** The receipt claims it was signed by key `key_A`, but the
public key file you provided identifies as `key_B`. You are holding the
wrong public key.

**What to do:**
- Ask the issuing organization for the correct public key for this receipt.
  The receipt output will show both the `Receipt key ID` and the `Key file
  key ID` — ask for a key that matches the receipt's key ID.
- Confirm the `.pub` file you have corresponds to the vault that issued
  this receipt.

---

### 4. "Key authority: OK but Signature: FAIL"

**What it means:** The key IDs match (or the key file has no `key_id`
comment so no ID comparison was possible), but the signature math fails.

**Possible causes:**
a) The key file contains the wrong key material (a different key with the
   same key_id — this should not happen in a well-managed vault).
b) The receipt's signature field was corrupted.
c) The receipt's envelope fields were modified after signing.

**What to do:**
- Request the receipt and key from the issuing organization again.
- Confirm you are using the key file that corresponds to this specific vault
  and time period (organizations sometimes rotate keys — make sure you have
  the key that was active when this receipt was issued).

---

### 5. `malformed_receipt` — parse error / malformed JSON

**What it means:** The `.dsr` file is not a valid DSR/1.0.1 receipt.

**Sub-cases:**
- `truncated` — the file was cut off mid-write
- `not json` — the file is not JSON at all
- `missing required field` — a required field (`id`, `version`, `type`, etc.) is absent
- `unknown field` — the receipt has a field name the parser doesn't recognize

**What to do:**
- Verify the file was downloaded completely (check file size, re-download if needed).
- Confirm the file ends in `.dsr` and was not renamed from another format.
- Request a fresh copy from the issuing organization.

---

### 6. `malformed_receipt` — wrong DSR version

**Message example:** "The receipt declares format 'DSR/2.0.0' but this
verifier only supports 'DSR/1.0.1'"

**What it means:** This receipt was issued in a newer format not yet
supported by the version of the CLI you are running.

**What to do:**
- Download the latest version of `dsr-verifier-cli` from
  https://verify.deja.dev/download
- Older receipts will continue to work with newer versions of the CLI
  (backward compatibility is guaranteed).

---

### 7. `malformed_receipt` — unsupported receipt type

**Message example:** "Receipt type 'RX' is not a recognized DSR/1.0.1 type"

**What it means:** The receipt's `type` field contains a value not defined
in DSR/1.0.1 (valid types: R1, R1-L, R1-N, R2, RV, RV-i, RV-f).

**What to do:**
- Confirm the file is actually a DSR receipt and not some other file.
- Request a fresh copy from the issuing organization.

---

### 8. `malformed_receipt` — unsupported signing algorithm

**Message example:** "Signing algorithm 'rsa-pss' is not supported"

**What it means:** DSR/1.0.1 requires ed25519 signatures. This receipt
claims to be signed with a different algorithm.

**What to do:**
- This receipt is not a valid DSR/1.0.1 receipt.
- Contact the issuing organization.

---

### 9. `malformed_causal_ref` — invalid PR URL or commit SHA

**What it means:** The `pr_url` or `commit_sha` field in the receipt
content is not in the expected format.

- `pr_url` must be `github.com/<org>/<repo>#<number>` or with `https://`
- `commit_sha` must be 7 to 64 hexadecimal characters

This check is **structural only** — the CLI does not fetch GitHub. A
malformed causal reference means the field was set incorrectly when the
receipt was generated.

**What to do:**
- If the signature and content hash passed, the receipt is cryptographically
  authentic but has a structural issue. Report it to the issuing organization.
- Whether to accept such a receipt for audit purposes is a judgment call for
  your engagement team.

---

### 10. Error: "receipt file not found" (exit code 3)

**What it means:** The CLI cannot find the `.dsr` file at the path you
provided.

**What to do:**
- Check that you are in the right directory: `ls *.dsr`
- Provide the full path: `verify /full/path/to/receipt.dsr --key vault.pub`
- On Windows, use backslashes or quotes: `verify "C:\receipts\r_abc.dsr" --key vault.pub`

---

### 11. Error: "key file not found" (exit code 3)

**What it means:** The CLI cannot find the `.pub` file at the path you
provided.

**What to do:**
- Check the key file name and path.
- Ask the issuing organization for the correct public key file.

---

### 12. Error: "invalid key file" (exit code 4)

**What it means:** The file you passed as `--key` is not a valid ed25519
public key in PKIX PEM format.

**Sub-cases:**
- Not a PEM file (does not start with `-----BEGIN PUBLIC KEY-----`)
- Wrong PEM type (e.g., `CERTIFICATE` instead of `PUBLIC KEY`)
- The key material is not an ed25519 key

**What to do:**
- Confirm the file was provided by the issuing organization as a vault
  public key. It should look like this:
  ```
  # key_id: key_acme_2026q2
  -----BEGIN PUBLIC KEY-----
  MCowBQYDK2VwAyEA...
  -----END PUBLIC KEY-----
  ```
- Do not use a full certificate (`.crt` / `.cer` file) — the CLI needs
  the raw public key in PKIX format.

---

## Bundle-level failures

### 13. Bundle manifest signature invalid

**What it means:** The manifest's ed25519 signature does not verify. The
bundle was either not signed by the key you provided, or the manifest
fields or receipt list were modified after signing.

**What to do:**
- Do NOT treat this bundle as evidence without resolving the failure.
- Confirm you have the correct public key for this vault.
- Request a fresh bundle from the issuing organization.

---

### 14. Bundle sequence integrity failure (gaps in sequence)

**What it means:** The manifest lists receipts with sequence numbers that
are not contiguous — for example, 1, 2, 4 (missing 3). Receipts were
removed from the bundle after it was assembled.

**Note:** this failure also causes the manifest signature to fail because
the receipt list was modified.

**What to do:**
- Request a complete bundle from the issuing organization.
- Ask them to explain which receipts are missing and why.

---

### 15. One or more receipts missing from the bundle archive

**What it means:** The manifest references a receipt file (e.g.,
`receipts/00003_r_abc.dsr`) but that file is not present in the ZIP archive.

**What to do:**
- The bundle is incomplete. Request a new bundle from the issuing
  organization. Report which sequence numbers are missing (they are listed
  in the verification output).

---

## Getting more information

Run any command with `--help` for usage details:
```
dsr-verifier-cli verify --help
dsr-verifier-cli verify-bundle --help
dsr-verifier-cli info --help
```

Use `--json` to get the full machine-readable error output:
```
dsr-verifier-cli verify receipt.dsr --key vault.pub --json
```

The JSON output includes the `technical_detail` field for each failure,
which provides the raw diagnostic values (computed hash, algorithm name,
actual vs expected values) that may help the issuing organization diagnose
the problem.
