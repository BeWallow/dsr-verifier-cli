# Reproducible Build Guide

`dsr-verifier-cli` supports reproducible builds: two independent builders
starting from the same source commit will produce byte-for-byte identical
binaries. This property lets auditors verify that the binary they downloaded
matches the published source code.

---

## Prerequisites

| Tool | Required version | Notes |
|------|-----------------|-------|
| Go   | **1.22.3 exactly** | Do not use "latest" — toolchain differences break reproducibility |
| Git  | Any modern version | Only needed to read the commit hash for `BuildCommit` |
| Docker | Optional | Needed only for the maximum-isolation build path |

Download Go 1.22.3: https://go.dev/dl/#go1.22.3

Verify your Go version:
```
go version
# must print: go version go1.22.3 ...
```

---

## Quick build (local, no Docker)

```bash
git clone https://github.com/deja-dev/dsr-verifier-cli.git
cd dsr-verifier-cli
git checkout v1.0.0          # replace with the tag you are verifying

COMMIT=$(git rev-parse --short HEAD)

CGO_ENABLED=0 go build \
  -trimpath \
  -buildvcs=false \
  -ldflags="-s -w -X github.com/deja-dev/dsr-verifier-cli/internal/cli.BuildCommit=${COMMIT}" \
  -o dsr-verifier-cli \
  ./cmd/dsr-verifier-cli
```

Verify the binary works:
```
./dsr-verifier-cli --version
```

---

## Cross-compile for all targets

Replace `GOOS` and `GOARCH` as needed:

| Platform        | GOOS    | GOARCH |
|-----------------|---------|--------|
| macOS Intel     | darwin  | amd64  |
| macOS Apple Silicon | darwin | arm64 |
| Linux x86-64    | linux   | amd64  |
| Linux ARM64     | linux   | arm64  |
| Windows x86-64  | windows | amd64  |

```bash
VERSION=$(git describe --tags --exact-match)
COMMIT=$(git rev-parse --short HEAD)

for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64; do
  GOOS="${target%/*}"
  GOARCH="${target#*/}"
  EXT=""
  [ "$GOOS" = "windows" ] && EXT=".exe"

  CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH \
  go build \
    -trimpath \
    -buildvcs=false \
    -ldflags="-s -w -X github.com/deja-dev/dsr-verifier-cli/internal/cli.BuildCommit=${COMMIT}" \
    -o "dist/dsr-verifier-cli-${VERSION}-${GOOS}-${GOARCH}${EXT}" \
    ./cmd/dsr-verifier-cli
done
```

---

## Maximum-isolation build (Docker)

For the strongest reproducibility guarantee, build inside a clean Docker
container with a controlled environment. This is what the official CI uses.

```bash
VERSION=v1.0.0      # the tag you are verifying
GOOS=linux
GOARCH=amd64

docker run --rm \
  -e CGO_ENABLED=0 \
  -e GOOS=${GOOS} \
  -e GOARCH=${GOARCH} \
  -v "$(pwd):/src:ro" \
  -w /src \
  golang:1.22.3-alpine \
  sh -c '
    apk add --no-cache git
    COMMIT=$(git rev-parse --short HEAD)
    go build \
      -trimpath \
      -buildvcs=false \
      -ldflags="-s -w -X github.com/deja-dev/dsr-verifier-cli/internal/cli.BuildCommit=${COMMIT}" \
      -o /tmp/dsr-verifier-cli-out \
      ./cmd/dsr-verifier-cli
    cp /tmp/dsr-verifier-cli-out /src/dsr-verifier-cli-${GOOS}-${GOARCH}
  '
```

---

## Verify your build against published checksums

Download the `SHA256SUMS` and `SHA256SUMS.asc` files from the GitHub Release:

```bash
VERSION=v1.0.0

curl -LO "https://github.com/deja-dev/dsr-verifier-cli/releases/download/${VERSION}/SHA256SUMS"
curl -LO "https://github.com/deja-dev/dsr-verifier-cli/releases/download/${VERSION}/SHA256SUMS.asc"
```

Verify the GPG signature on `SHA256SUMS`:
```bash
# Import the Déjà release key (one-time setup)
gpg --keyserver keys.openpgp.org --recv-keys <RELEASE_KEY_FINGERPRINT>

# Verify
gpg --verify SHA256SUMS.asc SHA256SUMS
```

Compare your locally built binary against the published checksum:
```bash
sha256sum dsr-verifier-cli-linux-amd64
# Compare the output to the linux-amd64 line in SHA256SUMS
```

If the SHA-256 values match, your independently built binary is identical to the official release.

---

## Why these build flags?

| Flag | Purpose |
|------|---------|
| `CGO_ENABLED=0` | Disables C bindings → fully static binary, no libc dependency |
| `-trimpath` | Strips the build machine's file paths from the binary. Without this, paths like `/home/user/go/pkg/...` would be embedded, making the binary differ between builders |
| `-buildvcs=false` | Prevents Git metadata (dirty working tree status, etc.) from being embedded. Without this, a build with local uncommitted changes produces a different binary |
| `-s` | Strips the symbol table |
| `-w` | Strips DWARF debug info |
| `-s -w` together | Reduce binary size from ~10 MB to ~5 MB with no functional difference |
| `-X ...BuildCommit` | Injects the short commit hash explicitly. This is deterministic: the same tag always maps to the same commit hash |

---

## Expected binary sizes (approximate)

| Platform | Approximate size |
|----------|-----------------|
| darwin-amd64 | ~5–6 MB |
| darwin-arm64 | ~5–6 MB |
| linux-amd64  | ~5–6 MB |
| linux-arm64  | ~5–6 MB |
| windows-amd64 | ~5–6 MB |

---

## Frequently asked questions

**Q: Will builds from different machines really be identical?**

Yes, provided: (1) exact Go 1.22.3, (2) same source commit, (3) same
`CGO_ENABLED=0` and build flags, (4) same `GOOS`/`GOARCH`. Go's build
system is deterministic given these inputs.

**Q: What if my SHA-256 does not match?**

Common causes:
- Different Go version (check `go version` carefully — `1.22.3` ≠ `1.22.4`)
- Missing `-trimpath` flag
- Missing `-buildvcs=false` flag  
- Different source commit (check `git log -1 --format='%H'`)
- `CGO_ENABLED` was not explicitly set to `0`

**Q: Does the CI use the same flags?**

Yes. See `.github/workflows/release.yml` — the exact build command is
documented there and in this file.
