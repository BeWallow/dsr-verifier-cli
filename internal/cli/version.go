package cli

// Version is the semver release. The CLI verifier promises backward
// compatibility within a major version: any receipt produced by a Déjà
// release that was current when this version shipped will verify forever.
const Version = "1.0.0"

// BuildCommit is injected at link time:
//
//	go build -ldflags "-X github.com/deja-dev/dsr-verifier-cli/internal/cli.BuildCommit=$(git rev-parse --short HEAD)"
//
// It defaults to "dev" when built without ldflags (e.g. in tests).
var BuildCommit = "dev"
