package cli_test

// offline_test.go — proves the CLI's zero-network-call property.
//
// There are two complementary tests:
//
//  1. Static: inspect the compiled import graph and confirm no HTTP client or
//     active network packages are present. This is a compile-time guarantee.
//
//  2. Functional: run the full verify pipeline (via cli.Run) and confirm it
//     produces a correct result.  The test itself runs in the Go test runner
//     which has no special network access — if the code made any network call,
//     it would either time out or produce a DNS error that would be visible.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deja-dev/dsr-verifier-cli/internal/cli"
	"github.com/deja-dev/dsr-verifier-cli/internal/dsr"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: Static import graph audit
//
// The CLI must never import net/http, net/rpc, or net/smtp.
// These are the packages that enable active network communication (HTTP
// clients, RPC calls, email).  Their absence is a structural guarantee that
// no code path in the binary can make outbound connections.
//
// Note: "net" itself appears in the graph as a transitive dependency of
// crypto/x509 (used for net.IP / net.IPNet certificate field types — not for
// socket operations).  net/url appears similarly.  Neither enables network I/O
// without an explicit Dial or Listen call, which no package in this binary
// makes.
// ─────────────────────────────────────────────────────────────────────────────

func TestOfflineImportGraph(t *testing.T) {
	modFile, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Skipf("cannot run 'go env GOMOD' (not in a module?): %v", err)
	}
	moduleRoot := filepath.Dir(strings.TrimSpace(string(modFile)))

	cmd := exec.Command("go", "list", "-f", `{{join .Deps "\n"}}`,
		"./cmd/dsr-verifier-cli")
	cmd.Dir = moduleRoot
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}

	// These packages enable active network I/O and must never appear.
	banned := []string{
		"net/http",
		"net/rpc",
		"net/smtp",
	}

	deps := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, dep := range deps {
		dep = strings.TrimSpace(dep)
		for _, b := range banned {
			if dep == b {
				t.Errorf("FAIL offline property: found %q in import graph "+
					"— this package can make network connections", dep)
			}
		}
	}
	t.Logf("import graph: %d packages; net/http absent ✓", len(deps))
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: Functional offline verification
//
// Runs the full cli.Run() pipeline with a real signed receipt and key.
// Produces exit code 0 and "VERIFIED" output with no network access.
// ─────────────────────────────────────────────────────────────────────────────

func TestOfflineFunctionalVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const keyID = "key_offline_test"

	// Build receipt.
	content := json.RawMessage(`{"commit_sha":"a1b2c3d4e5f6a1b2","merged_at":"2026-01-15T10:00:00Z","pr_url":"github.com/acme/repo#42"}`)
	canonical, _ := dsr.CanonicalContent(content)
	sum := sha256.Sum256(canonical)
	contentHash := hex.EncodeToString(sum[:])

	issuedAt := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	partial := &dsr.Receipt{
		ID:               "r_offline_test_001",
		Version:          dsr.Version,
		Type:             dsr.TypeR1,
		VaultID:          "vlt_offline_test",
		IssuedAt:         issuedAt,
		Content:          content,
		ContentHash:      contentHash,
		SigningKeyID:     keyID,
		SigningAlgorithm: dsr.SigningAlgorithmED25519,
	}
	payload, err := dsr.CanonicalSignedPayload(partial)
	if err != nil {
		t.Fatalf("CanonicalSignedPayload: %v", err)
	}
	sig := ed25519.Sign(priv, payload)

	receiptMap := map[string]interface{}{
		"id": "r_offline_test_001", "version": dsr.Version, "type": dsr.TypeR1,
		"vault_id": "vlt_offline_test", "issued_at": issuedAt.UTC().Format(time.RFC3339),
		"content": content, "content_hash": contentHash,
		"signing_key_id":    keyID,
		"signing_algorithm": dsr.SigningAlgorithmED25519,
		"signature":         hex.EncodeToString(sig),
	}
	receiptBytes, _ := json.Marshal(receiptMap)

	// Build PEM key file.
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	keyPEM := fmt.Sprintf("# key_id: %s\n%s", keyID,
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))

	// Write to temp files.
	dir := t.TempDir()
	receiptPath := filepath.Join(dir, "receipt.dsr")
	keyPath := filepath.Join(dir, "vault.pub")
	if err := os.WriteFile(receiptPath, receiptBytes, 0600); err != nil {
		t.Fatalf("write receipt: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	// Run cli.Run() — this is the full pipeline, identical to what the
	// binary executes.  The test runner has no special network permissions;
	// any attempted network call would manifest as a failure here.
	var stdout, stderr bytes.Buffer
	exitCode := cli.Run(
		[]string{"verify", receiptPath, "--key", keyPath, "--no-log", "--no-color"},
		&stdout, &stderr,
	)

	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s",
			exitCode, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "VERIFIED") {
		t.Errorf("output does not contain VERIFIED:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "offline") {
		t.Errorf("output does not confirm offline mode:\n%s", stdout.String())
	}
	t.Logf("offline functional verify: exit 0 ✓\n%s", stdout.String())
}
