# Versioning Policy

`dsr-verifier-cli` follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

---

## Compatibility commitments

### Receipt format compatibility

**1.x verifies all DSR/1.0 receipts forever.**

Once a receipt passes verification under any `1.x` release, it will pass under all
future `1.x` releases — including receipts issued years earlier. An auditor reviewing
a receipt from 2026 using a `1.x` CLI released in 2030 will get the same result.

This is a hard commitment, not a best-effort goal. DSR/1.0.1 is a fixed specification;
the verification math does not change.

### Command-line interface

Within a major version, the following are stable:

- Command names (`verify`, `verify-bundle`, `info`)
- Flag names (`--key`, `--json`, `--no-color`, `--no-log`)
- Exit codes (0 verified, 1 failed, 2 parse error, 3 not found, 4 invalid key)
- JSON output field names and types

Additions (new commands, new optional flags, new JSON fields) are non-breaking and
may appear in minor releases.

### What constitutes a breaking change

Breaking changes require a major version increment:

- Removing or renaming a command
- Removing or renaming a flag
- Changing an exit code's meaning
- Removing a JSON output field
- Dropping support for a receipt format version previously verified
- Changing the canonical signed-payload or content-canonicalization rules in a way
  that would cause a previously-passing receipt to fail

---

## Support window

| Release stream | Support ends |
|---------------|-------------|
| 1.x | No earlier than 2031-01-01 (5 years from initial release) |
| 0.x | Already superseded by 1.0 — no active support |

Security fixes are backported to the supported major stream. Fixes that address a
false-negative verification result (i.e., a tampered receipt incorrectly passes)
are treated as critical and released promptly.

---

## Pre-release versions

Versions tagged `-alpha`, `-beta`, or `-rc` make no compatibility guarantees.
They are for internal testing only and should not be used in audit engagements.

---

## Receipt format versions

The CLI advertises which DSR receipt format versions it supports in the `--version`
output:

```
dsr-verifier-cli v1.0.0 (commit: a3f8c2e)
DSR/1.0.1 · MIT License · https://github.com/deja-dev/dsr-verifier-cli
```

When a new DSR format version is released (e.g., DSR/2.0.0), support for it will
appear in a minor or major release of the CLI depending on whether the new format
is backward compatible with the previous specification.

Receipts that declare an unsupported format version produce exit code 2 and a clear
error message directing the auditor to update the CLI.

---

## Go toolchain compatibility

The CLI is built and tested against the pinned Go version listed in `go.mod` (currently
Go 1.22.3). The CI pipeline also tests against the latest stable Go release. Production
binaries are always built with the pinned version for reproducibility.

The minimum Go version required to build from source will not be increased within a
major release without a deprecation notice in the release notes.
