# Release Process

How to cut a `dsr-verifier-cli` release. This document is for Déjà engineers;
auditors and external users do not need to read it.

---

## Overview

```
Engineer: bump version + tag → git push tag
                                    ↓
                    GitHub Actions: test → build (5 targets) → release
                                                                    ↓
                                        GitHub Release (binaries + SHA256SUMS + GPG sig)
                                                                    ↓
                                              Homebrew tap auto-update
```

The entire pipeline is automated after the engineer pushes a version tag.
Manual steps are limited to: version bump, tagging, and post-release verification.

---

## Pre-release checklist

- [ ] All tests pass on `main`: `go test ./...`
- [ ] Version in `internal/cli/version.go` matches the intended tag
- [ ] `go.mod` still has no external dependencies (security invariant)
- [ ] `go.sum` is committed
- [ ] CHANGELOG entry written (if maintained)
- [ ] GPG signing key accessible (stored in GitHub secret `GPG_SIGNING_KEY`)
- [ ] Homebrew tap token valid (stored in GitHub secret `HOMEBREW_TAP_TOKEN`)

---

## Step 1: Bump the version

Edit `internal/cli/version.go`:

```go
const Version = "1.0.1"   // ← new version
```

Commit:
```bash
git add internal/cli/version.go
git commit -m "chore: bump version to v1.0.1"
```

---

## Step 2: Tag the release

Tag with a signed tag (preferred) or annotated tag:

```bash
# Signed tag (recommended — requires GPG key in git config)
git tag -s v1.0.1 -m "dsr-verifier-cli v1.0.1"

# Annotated tag (if GPG signing of tags is not set up)
git tag -a v1.0.1 -m "dsr-verifier-cli v1.0.1"
```

Push the tag:
```bash
git push origin v1.0.1
```

This triggers the GitHub Actions release pipeline automatically.

---

## Step 3: Watch the pipeline

Monitor at: `https://github.com/deja-dev/dsr-verifier-cli/actions`

The pipeline runs in three stages:
1. **Test** (~1 min) — full test suite on the pinned toolchain
2. **Build** (~3 min) — parallel cross-compilation for all 5 targets
3. **Release** (~1 min) — checksums, GPG signature, GitHub Release, Homebrew dispatch

If any stage fails, the release is not created. Fix the issue, delete the tag,
and re-tag:
```bash
git tag -d v1.0.1
git push origin :refs/tags/v1.0.1
# fix the issue, then re-tag
```

---

## Step 4: Verify the release artifacts

After the pipeline completes, verify:

```bash
VERSION=v1.0.1

# Download the checksums and signature
curl -LO "https://github.com/deja-dev/dsr-verifier-cli/releases/download/${VERSION}/SHA256SUMS"
curl -LO "https://github.com/deja-dev/dsr-verifier-cli/releases/download/${VERSION}/SHA256SUMS.asc"

# Verify GPG signature
gpg --verify SHA256SUMS.asc SHA256SUMS

# Download one binary and verify its checksum
curl -LO "https://github.com/deja-dev/dsr-verifier-cli/releases/download/${VERSION}/dsr-verifier-cli-${VERSION}-linux-amd64.tar.gz"
sha256sum --check --ignore-missing SHA256SUMS

# Extract and run
tar -xzf "dsr-verifier-cli-${VERSION}-linux-amd64.tar.gz"
./dsr-verifier-cli --version
```

---

## Step 5: Verify the Homebrew tap updated

The release pipeline dispatches an update event to the
`deja-dev/homebrew-tap` repository. Confirm the formula was updated:

```bash
# Check that the tap repo has a new commit
gh api repos/deja-dev/homebrew-tap/commits/main \
  --jq '.commit.message'

# Should show something like: "chore: bump dsr-verifier-cli to v1.0.1"
```

Test the Homebrew install in a clean environment:
```bash
brew uninstall dsr-verifier-cli 2>/dev/null || true
brew install deja-dev/tap/dsr-verifier-cli
dsr-verifier-cli --version
```

---

## Step 6: Update the download page

The download page at `download/index.html` references the latest version.
Update it after each release:

1. Replace the `VERSION` placeholder with the new tag
2. Update the SHA-256 checksums from the `SHA256SUMS` file
3. Deploy to `verify.deja.dev/download` (see infrastructure docs)

Alternatively, this step can be automated as part of the release pipeline
(open task: wire `download/index.html` to CI substitution).

---

## Secrets required

| Secret name | What it contains | Rotation schedule |
|-------------|-----------------|------------------|
| `GPG_SIGNING_KEY` | Armored ed25519 or RSA GPG private key for the Déjà release key | Annually |
| `GPG_PASSPHRASE` | Passphrase for the GPG key | Matches key rotation |
| `HOMEBREW_TAP_TOKEN` | GitHub personal access token with `repo` scope for the `homebrew-tap` repo | Annually |

**The GPG private key is never committed to any repository.** It lives
exclusively in GitHub Secrets and in secure cold storage. The public key
is published at `https://deja.dev/release-key.asc` and on public keyservers.

---

## Homebrew tap structure

The `deja-dev/homebrew-tap` repository must contain:
- `Formula/dsr-verifier-cli.rb` — the formula (see `homebrew/dsr-verifier-cli.rb` in this repo for the template)
- `.github/workflows/update-formula.yml` — the workflow that receives the `new-release` dispatch and commits the updated formula (see `homebrew/tap-update-workflow.yml` in this repo for the reference implementation)

---

## Incident response: bad binary shipped

If a shipped binary has a bug or security issue:

1. **Immediately:** delete the GitHub Release assets and mark the release as
   a pre-release to prevent new downloads.
2. **Communicate:** post a notice to the GitHub repository and notify known
   enterprise users directly.
3. **Fix:** cut a patch release following this process.
4. **Homebrew:** the Homebrew formula auto-updates — but if you need to
   yank immediately, manually update the formula to point to a
   non-existent version so `brew install` fails with a clear message.

---

## Versioning policy

See `docs/VERSIONING.md` for the full semver and backward compatibility
commitment. The short version:
- **1.x.z** → backward compatible; all DSR/1.x receipts verify forever
- **1.x.0** → minor version; new features, old receipts still verify
- **1.x.z** → patch; bug fixes only
- Breaking changes require a new major version with a documented migration
