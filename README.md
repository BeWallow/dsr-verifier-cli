# dsr-verifier-cli

A standalone, offline-only command-line tool for verifying DSR/1.0.1 receipts and evidence bundles
produced by [Déjà](https://deja.dev).

---

## Trust positioning

**Open-source. MIT-licensed. Zero network calls. Reproducible builds.**

An auditor's job is to verify evidence, not to trust tools on faith. This CLI is designed to be
auditable end-to-end:

- **Audit the source.** Every line of verification logic is published at
  `github.com/deja-dev/dsr-verifier-cli`. There is nothing to hide.
- **Rebuild from source.** The build is reproducible: same source + same Go 1.22.3 toolchain =
  byte-for-byte identical binary. See `BUILD.md`.
- **Verify our binaries with your own builds.** Every release ships a GPG-signed `SHA256SUMS`
  file. An auditor who doesn't trust the published binary can rebuild it and confirm the hashes
  match.
- **Zero external dependencies.** The `go.mod` file lists only the Go version. Every cryptographic
  primitive (`crypto/ed25519`, `crypto/sha256`, `crypto/subtle`) is Go standard library.
- **Proof of offline property.** The import graph contains no `net/http` or `net/rpc`. The
  `TestOfflineImportGraph` test asserts this on every CI run. You can verify it yourself:
  `go list -f '{{join .Deps "\n"}}' ./cmd/dsr-verifier-cli | grep net/http` should return nothing.

This positioning is not marketing. It is a design constraint: the CLI cannot verify receipts for
audit purposes if auditors cannot verify the CLI itself.

---

## Overview

The CLI verifier allows external auditors to cryptographically verify DSR receipts with zero
network calls. An auditor in an air-gapped compliance environment can confirm:

1. **Signature validity** — the receipt was signed by the claimed key
2. **Content integrity** — nothing was modified after signing
3. **Key authority** — the signing key matches the claimed vault
4. **Causal references** — PR/commit identifiers are structurally valid

No login. No account. No network access. Just the `.dsr` file and the customer's public key.

## Install

**macOS:**
```
brew install deja-dev/tap/dsr-verifier-cli
```

**Linux / Windows:** download the binary from https://verify.deja.dev/download and verify the
SHA-256 checksum listed on that page before running.

## Usage

```
dsr-verifier-cli verify <receipt.dsr> --key <pubkey>
dsr-verifier-cli verify-bundle <bundle.dsr.bundle> --key <pubkey>
dsr-verifier-cli info <receipt.dsr>
```

## Public key format

Public keys are ed25519 keys in PKIX PEM format with an optional `key_id` header comment:

```
# key_id: key_acme_2026q2
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA...
-----END PUBLIC KEY-----
```

The customer's public key should be included alongside evidence packages. The CLI never fetches
keys from the network — keys are always provided as local files.

## Receipt format

The CLI verifies DSR/1.0.1 receipts. The canonical content bytes of a receipt are computed by
re-serializing the `content` JSON object with lexicographically sorted keys (compact, no
whitespace). The `content_hash` field is SHA-256 of those bytes (hex-encoded). The `signature`
field is an ed25519 signature over the canonical signed payload (see `internal/verify/verify.go`
for the exact construction).

## Security properties

- **Zero network calls** — the binary makes no outbound connections under any circumstances
- **Standard library crypto only** — uses Go's `crypto/ed25519` and `crypto/sha256`; no
  third-party cryptographic dependencies
- **Constant-time comparison** — hash comparisons use `crypto/subtle` to prevent timing leaks
- **Reproducible builds** — pin the Go toolchain version and use `-trimpath -buildvcs=false`;
  see `BUILD.md` for instructions

## Documentation

| Document | Audience |
|----------|----------|
| [docs/auditor-quick-start.md](docs/auditor-quick-start.md) | Junior auditor — first-time single receipt verification |
| [docs/auditor-bundle-guide.md](docs/auditor-bundle-guide.md) | Senior auditor — full evidence period bundle review |
| [docs/auditor-trust-model.md](docs/auditor-trust-model.md) | Any auditor — what the CLI verifies, trusts, and doesn't do |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Any user — 15 most common verification failures |
| [docs/SECURITY.md](docs/SECURITY.md) | Security reviewer — cryptographic design and import graph audit |
| [docs/VERSIONING.md](docs/VERSIONING.md) | Any user — compatibility commitments and support window |
| [BUILD.md](BUILD.md) | Anyone building from source — reproducible build instructions |

## License

MIT — see LICENSE file.
