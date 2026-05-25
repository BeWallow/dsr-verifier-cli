# Security and Cryptographic Library Audit

This document records the cryptographic design of `dsr-verifier-cli` and
confirms that every dependency has been reviewed. It is intended for auditors
who want to understand what cryptographic code the CLI runs and why.

---

## Dependency manifest

`dsr-verifier-cli` has **zero external dependencies**. The `go.mod` file
contains only the Go version pin; `go.sum` is empty.

```
module github.com/deja-dev/dsr-verifier-cli
go 1.22.3
```

Every package used is either in the Go standard library or in the Go toolchain
vendor directory (which is part of the pinned Go 1.22.3 release).

---

## Cryptographic primitives used

| Primitive | Purpose | Go package | Notes |
|-----------|---------|-----------|-------|
| Ed25519 | Receipt and bundle manifest signature verification | `crypto/ed25519` | Standard library. RFC 8032. 64-byte signatures, 32-byte public keys |
| SHA-256 | Content hash verification | `crypto/sha256` | Standard library. FIPS 180-4 |
| SHA-256 (constant-time compare) | Hash comparison | `crypto/subtle.ConstantTimeCompare` | Prevents timing side-channels even in offline mode |
| PKIX public key parsing | Loading ed25519 public keys from PEM files | `crypto/x509`, `encoding/pem` | Standard library. SubjectPublicKeyInfo encoding (RFC 5480) |

No third-party cryptographic libraries are used.

---

## Signature verification design

A DSR/1.0.1 receipt's ed25519 signature covers a **canonical signed payload**
— the compact, sorted-key JSON of eight envelope fields:

```json
{
  "content_hash": "<hex>",
  "id": "<receipt-id>",
  "issued_at": "2026-01-15T10:00:00Z",
  "signing_algorithm": "ed25519",
  "signing_key_id": "<key-id>",
  "type": "R1",
  "vault_id": "<vault-id>",
  "version": "DSR/1.0.1"
}
```

The `content_hash` field is SHA-256 of the **canonical content**: the receipt's
`content` JSON object re-serialized with lexicographically sorted keys
(compact, no whitespace). Go's `encoding/json` marshals `map[string]interface{}`
keys in sorted order as of Go 1.12.

This two-level structure — content → content_hash → signed_payload → signature —
enables independent verification of each layer:

- **Signature check**: verifies the eight envelope fields were not modified
- **Content hash check**: verifies the content was not modified independently

A tampered receipt that modifies content without re-signing will have a valid
signature (the original content_hash is still correct) but a failing content
hash (the new content no longer hashes to the stored value). Both failures are
surfaced with distinct error messages.

---

## Bundle manifest verification

A DSR-BUNDLE/1.0 manifest's ed25519 signature covers a canonical payload
including a `receipts_hash` field — SHA-256 of the canonical JSON of the
manifest's complete entries array. Adding, removing, or reordering receipts
changes the hash and breaks the manifest signature.

---

## What is NOT in the import graph

Running `go list -f '{{join .Deps "\n"}}' ./cmd/dsr-verifier-cli` produces 146
packages. The following critical network packages are **absent**:

| Package | What it enables | Status |
|---------|----------------|--------|
| `net/http` | HTTP client/server | **Not imported** |
| `net/rpc` | RPC over network | **Not imported** |
| `net/smtp` | Email | **Not imported** |

**Why `net` appears in the graph**: `crypto/x509` imports `net` for IP address
types used in certificate fields (`net.IP`, `net.IPNet`). No code path in
`dsr-verifier-cli` calls `net.Dial`, `net.Listen`, or any function that opens
a socket. The `net` package's presence does not enable network calls unless a
Dial/Listen is explicitly invoked.

To verify this yourself:
```bash
go list -f '{{join .Deps "\n"}}' ./cmd/dsr-verifier-cli | grep "^net/"
# Expected output:  net  net/netip  net/url
# NOT expected:     net/http  net/rpc  net/smtp
```

---

## Offline property: proof by import graph

The CLI cannot make network calls because:

1. No package in the import graph provides a way to open a socket or send
   a DNS query without an explicit application-level call to `net.Dial` or
   similar.
2. No application-level code in `dsr-verifier-cli` calls any socket function.
3. The test `TestOfflineImportGraph` (in `internal/cli/offline_test.go`)
   asserts `net/http` and `net/rpc` are absent from the import graph on
   every CI run.

For additional confirmation, you can trace syscalls during a verification run:

```bash
# Linux
strace -e trace=network ./dsr-verifier-cli verify receipt.dsr --key vault.pub
# Expected: no network-related syscalls (no socket(), connect(), etc.)

# macOS
sudo dtrace -n 'syscall::connect:entry /pid == $target/ { @[execname] = count(); }' \
  -c './dsr-verifier-cli verify receipt.dsr --key vault.pub'
# Expected: no output (zero connect() calls)
```

---

## Constant-time comparison

Hash comparisons in `verify.ContentHash` use `crypto/subtle.ConstantTimeCompare`
rather than `bytes.Equal`. While `dsr-verifier-cli` is an offline tool with no
remote timing oracle, constant-time comparison is the correct discipline for
any cryptographic code. It costs nothing and eliminates a class of potential
future issues if the code is ever adapted.

---

## Key format and trust assumptions

- Public keys must be in PKIX PEM format (`BEGIN PUBLIC KEY`) with ed25519
  key material inside.
- The optional `# key_id: <id>` comment before the PEM block is parsed by the
  CLI; its value is compared against the receipt's `signing_key_id` field.
- **The CLI trusts the key you provide.** If you provide the wrong key, the
  signature check will fail — that is correct behaviour. If you provide a key
  that was forged, tampered, or obtained from an untrusted source, the CLI
  cannot detect this. The public key distribution is the human-process step
  that sits outside the CLI's security boundary.

---

## Threat model: what the CLI catches

| Attack | Detection |
|--------|-----------|
| Receipt content modified after signing | Content hash mismatch (`content_hash_mismatch`) |
| Receipt signature bytes replaced or corrupted | Signature invalid (`signature_invalid`) |
| Wrong public key provided (key_id present) | Key authority mismatch (`key_authority_mismatch`) |
| Wrong public key provided (no key_id in file) | Signature invalid |
| JSON field reordering in content | No false failure — canonicalization is order-independent |
| Unknown/unsupported receipt version | Parse error (`malformed_receipt`) |
| Bundle receipt swapped from another vault | Key authority mismatch on that receipt |
| Bundle receipts removed after manifest signing | Bundle manifest signature invalid |
| Bundle sequence numbers with gaps | Sequence integrity failure |

## Threat model: what the CLI does NOT catch

| Condition | Reason |
|-----------|--------|
| Receipts signed with a compromised signing key | The CLI verifies mathematical correctness, not key provenance |
| A forged public key passed to `--key` | The CLI trusts the key file you provide |
| Social engineering (a legitimate receipt for a different event) | Out of scope; the CLI verifies cryptographic integrity, not business logic |
| A receipt correctly signed but for the wrong scope (wrong PR, wrong vault) | The CLI checks structural validity of `pr_url` / `commit_sha` format; it does not fetch or verify the referenced content |
