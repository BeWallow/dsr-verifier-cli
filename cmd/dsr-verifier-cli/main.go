// dsr-verifier-cli verifies DSR/1.0.1 receipts offline.
//
// Build with reproducible flags:
//
//	go build -trimpath -buildvcs=false \
//	  -ldflags "-X github.com/deja-dev/dsr-verifier-cli/internal/cli.BuildCommit=$(git rev-parse --short HEAD)" \
//	  ./cmd/dsr-verifier-cli
package main

import (
	"os"

	"github.com/deja-dev/dsr-verifier-cli/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
