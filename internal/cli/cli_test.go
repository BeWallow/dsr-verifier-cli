package cli_test

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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deja-dev/dsr-verifier-cli/internal/cli"
	"github.com/deja-dev/dsr-verifier-cli/internal/dsr"
)

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

const testKeyID = "key_acme_test_2026"

func newTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func writeKeyFile(t *testing.T, dir string, pub ed25519.PublicKey, keyID string) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	var buf []byte
	if keyID != "" {
		buf = append(buf, fmt.Sprintf("# key_id: %s\n", keyID)...)
	}
	buf = append(buf, pem.EncodeToMemory(block)...)
	path := filepath.Join(dir, "vault.pub")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return path
}

// buildAndWriteReceipt creates a fully-signed receipt and writes it to a temp file.
func buildAndWriteReceipt(t *testing.T, dir string, priv ed25519.PrivateKey, keyID, receiptType string) string {
	t.Helper()
	data := buildReceiptJSON(t, priv, keyID, receiptType)
	path := filepath.Join(dir, "receipt.dsr")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write receipt: %v", err)
	}
	return path
}

// buildReceiptJSON produces signed receipt JSON bytes.
func buildReceiptJSON(t *testing.T, priv ed25519.PrivateKey, keyID, receiptType string) []byte {
	t.Helper()

	content := map[string]interface{}{
		"commit_sha": "a8f3c2e9d4b1a6f7c2e8d4b1f6a8c3e9d4b1a6f7",
		"merged_at":  "2026-05-12T12:18:43Z",
		"pr_url":     "github.com/acme-fintech/payments-api#4287",
	}
	canonical, _ := json.Marshal(content)
	sum := sha256.Sum256(canonical)
	contentHash := hex.EncodeToString(sum[:])

	issuedAt := time.Date(2026, 5, 12, 12, 42, 8, 0, time.UTC)
	partial := &dsr.Receipt{
		ID:               "r_test_acme_payments",
		Version:          dsr.Version,
		Type:             receiptType,
		VaultID:          "vlt_acme-fintech",
		IssuedAt:         issuedAt,
		Content:          canonical,
		ContentHash:      contentHash,
		SigningKeyID:     keyID,
		SigningAlgorithm:  dsr.SigningAlgorithmED25519,
	}
	payload, err := dsr.CanonicalSignedPayload(partial)
	if err != nil {
		t.Fatalf("canonical signed payload: %v", err)
	}
	sig := ed25519.Sign(priv, payload)

	full := map[string]interface{}{
		"id":                "r_test_acme_payments",
		"version":           dsr.Version,
		"type":              receiptType,
		"vault_id":          "vlt_acme-fintech",
		"issued_at":         issuedAt.UTC().Format(time.RFC3339),
		"content":           json.RawMessage(canonical),
		"content_hash":      contentHash,
		"signing_key_id":    keyID,
		"signing_algorithm": dsr.SigningAlgorithmED25519,
		"signature":         hex.EncodeToString(sig),
	}
	b, _ := json.Marshal(full)
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// verify command — good receipt, exit 0, output structure
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyGoodReceipt(t *testing.T) {
	dir := t.TempDir()
	pub, priv := newTestKey(t)
	keyPath := writeKeyFile(t, dir, pub, testKeyID)
	receiptPath := buildAndWriteReceipt(t, dir, priv, testKeyID, dsr.TypeR1)

	var out, errout bytes.Buffer
	code := cli.Run([]string{"verify", receiptPath, "--key", keyPath, "--no-log", "--no-color"}, &out, &errout)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out.String(), errout.String())
	}

	output := out.String()
	assertContains(t, output, "VERIFIED")
	assertContains(t, output, "4 checks passed")
	assertContains(t, output, "OK")
	assertContains(t, output, "Key authority check")
	assertContains(t, output, "Signature verification")
	assertContains(t, output, "Content hash verification")
	assertContains(t, output, "Causal artifact structural validation")
	assertContains(t, output, "offline")
	assertContains(t, output, "zero network calls")
	assertNotContains(t, output, "FAIL")
	assertNotContains(t, output, "FAILED")
}

// ─────────────────────────────────────────────────────────────────────────────
// verify command — tampered receipt, exit 1, failure output
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyTamperedReceipt(t *testing.T) {
	dir := t.TempDir()
	pub, priv := newTestKey(t)
	keyPath := writeKeyFile(t, dir, pub, testKeyID)
	receiptData := buildReceiptJSON(t, priv, testKeyID, dsr.TypeR1)

	// Tamper: replace content without updating content_hash or signature.
	var raw map[string]json.RawMessage
	json.Unmarshal(receiptData, &raw)
	raw["content"] = []byte(`{"commit_sha":"0000000000000000000000000000000000000000","merged_at":"2026-05-12T12:18:43Z","pr_url":"github.com/acme-fintech/payments-api#4287"}`)
	tampered, _ := json.Marshal(raw)
	receiptPath := filepath.Join(dir, "tampered.dsr")
	os.WriteFile(receiptPath, tampered, 0o600)

	var out, errout bytes.Buffer
	code := cli.Run([]string{"verify", receiptPath, "--key", keyPath, "--no-log", "--no-color"}, &out, &errout)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s", code, out.String())
	}

	output := out.String()
	assertContains(t, output, "FAILED")
	assertContains(t, output, "FAIL")
	assertContains(t, output, "Recommended actions for auditor")
	assertContains(t, output, "Do NOT")
}

// ─────────────────────────────────────────────────────────────────────────────
// verify command — missing receipt file, exit 3
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyMissingReceiptFile(t *testing.T) {
	dir := t.TempDir()
	pub, _ := newTestKey(t)
	keyPath := writeKeyFile(t, dir, pub, testKeyID)

	var out, errout bytes.Buffer
	code := cli.Run([]string{"verify", "/nonexistent/receipt.dsr", "--key", keyPath, "--no-log"}, &out, &errout)

	if code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
	if !strings.Contains(errout.String(), "not found") {
		t.Errorf("stderr should mention 'not found', got: %s", errout.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// verify --json: output is valid JSON with required structure
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyJSONOutput(t *testing.T) {
	dir := t.TempDir()
	pub, priv := newTestKey(t)
	keyPath := writeKeyFile(t, dir, pub, testKeyID)
	receiptPath := buildAndWriteReceipt(t, dir, priv, testKeyID, dsr.TypeR1)

	var out, errout bytes.Buffer
	code := cli.Run([]string{"verify", receiptPath, "--key", keyPath, "--json", "--no-log"}, &out, &errout)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr: %s", code, errout.String())
	}

	var j map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &j); err != nil {
		t.Fatalf("output is not valid JSON: %v\nraw:\n%s", err, out.String())
	}

	// Required top-level fields.
	for _, key := range []string{"version", "receipt_id", "result", "checks", "failure_reasons", "duration_ms", "offline"} {
		if _, ok := j[key]; !ok {
			t.Errorf("JSON missing required field %q", key)
		}
	}
	if j["result"] != "verified" {
		t.Errorf("result = %v, want %q", j["result"], "verified")
	}
	if j["offline"] != true {
		t.Errorf("offline = %v, want true", j["offline"])
	}

	// Checks sub-object.
	checks, ok := j["checks"].(map[string]interface{})
	if !ok {
		t.Fatal("checks is not an object")
	}
	for _, checkName := range []string{"key_authority", "signature", "content_hash", "causal_refs"} {
		c, ok := checks[checkName].(map[string]interface{})
		if !ok {
			t.Errorf("checks.%s missing or not an object", checkName)
			continue
		}
		if c["passed"] != true {
			t.Errorf("checks.%s.passed = %v, want true", checkName, c["passed"])
		}
	}

	// failure_reasons must be empty for a verified receipt.
	reasons, _ := j["failure_reasons"].([]interface{})
	if len(reasons) != 0 {
		t.Errorf("failure_reasons = %v, want empty", reasons)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// verify --json on tampered: failure_reasons populated
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyJSONOutputFailed(t *testing.T) {
	dir := t.TempDir()
	pub, priv := newTestKey(t)
	keyPath := writeKeyFile(t, dir, pub, testKeyID)
	receiptData := buildReceiptJSON(t, priv, testKeyID, dsr.TypeR1)

	var raw map[string]json.RawMessage
	json.Unmarshal(receiptData, &raw)
	raw["content"] = []byte(`{"commit_sha":"0000000000000000000000000000000000000000","merged_at":"2026-05-12T12:18:43Z","pr_url":"github.com/acme-fintech/payments-api#4287"}`)
	tampered, _ := json.Marshal(raw)
	receiptPath := filepath.Join(dir, "tampered.dsr")
	os.WriteFile(receiptPath, tampered, 0o600)

	var out, errout bytes.Buffer
	code := cli.Run([]string{"verify", receiptPath, "--key", keyPath, "--json", "--no-log"}, &out, &errout)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	var j map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &j); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out.String())
	}
	if j["result"] != "failed" {
		t.Errorf("result = %v, want %q", j["result"], "failed")
	}
	reasons, _ := j["failure_reasons"].([]interface{})
	if len(reasons) == 0 {
		t.Error("failure_reasons must be non-empty when verification fails")
	}
	// Verify the failure has the expected class.
	found := false
	for _, r := range reasons {
		rm, _ := r.(map[string]interface{})
		if rm["error_class"] == "content_hash_mismatch" {
			found = true
		}
	}
	if !found {
		t.Errorf("failure_reasons does not contain content_hash_mismatch: %v", reasons)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// info command: metadata displayed, no verification attempted
// ─────────────────────────────────────────────────────────────────────────────

func TestInfoCommand(t *testing.T) {
	dir := t.TempDir()
	_, priv := newTestKey(t)
	receiptPath := buildAndWriteReceipt(t, dir, priv, testKeyID, dsr.TypeR1)

	var out, errout bytes.Buffer
	code := cli.Run([]string{"info", receiptPath, "--no-color"}, &out, &errout)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr: %s", code, errout.String())
	}
	output := out.String()
	assertContains(t, output, "INFO ONLY")
	assertContains(t, output, "RECEIPT NOT VERIFIED")
	assertContains(t, output, "r_test_acme_payments")
	assertContains(t, output, "vlt_acme-fintech")
	// Must NOT contain any cryptographic verification result.
	// ("RECEIPT NOT VERIFIED" is expected; "Result: VERIFIED" must not appear.)
	assertNotContains(t, output, "Result: VERIFIED")
	assertNotContains(t, output, "Result: FAILED")
	assertNotContains(t, output, "Signature verification")
}

// ─────────────────────────────────────────────────────────────────────────────
// info --json: returns valid JSON with verified=false
// ─────────────────────────────────────────────────────────────────────────────

func TestInfoJSONOutput(t *testing.T) {
	dir := t.TempDir()
	_, priv := newTestKey(t)
	receiptPath := buildAndWriteReceipt(t, dir, priv, testKeyID, dsr.TypeR1)

	var out, errout bytes.Buffer
	code := cli.Run([]string{"info", receiptPath, "--json"}, &out, &errout)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	var j map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &j); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out.String())
	}
	if j["verified"] != false {
		t.Errorf("verified = %v, want false", j["verified"])
	}
	if j["receipt_id"] != "r_test_acme_payments" {
		t.Errorf("receipt_id = %v", j["receipt_id"])
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// --version: prints version string
// ─────────────────────────────────────────────────────────────────────────────

func TestVersionFlag(t *testing.T) {
	var out bytes.Buffer
	code := cli.Run([]string{"--version"}, &out, &out)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	output := out.String()
	if !strings.Contains(output, cli.Version) {
		t.Errorf("version output does not contain %q: %s", cli.Version, output)
	}
	assertContains(t, output, "dsr-verifier-cli")
	assertContains(t, output, "DSR/1.0.1")
}

// ─────────────────────────────────────────────────────────────────────────────
// --no-color: output contains no ANSI codes
// ─────────────────────────────────────────────────────────────────────────────

func TestNoColorFlag(t *testing.T) {
	dir := t.TempDir()
	pub, priv := newTestKey(t)
	keyPath := writeKeyFile(t, dir, pub, testKeyID)
	receiptPath := buildAndWriteReceipt(t, dir, priv, testKeyID, dsr.TypeR1)

	var out bytes.Buffer
	cli.Run([]string{"verify", receiptPath, "--key", keyPath, "--no-log", "--no-color"}, &out, &out)

	if strings.Contains(out.String(), "\033[") {
		t.Error("output contains ANSI escape codes despite --no-color")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// audit log: written per verify call, one JSON line
// ─────────────────────────────────────────────────────────────────────────────

func TestAuditLogWritten(t *testing.T) {
	dir := t.TempDir()
	pub, priv := newTestKey(t)
	keyPath := writeKeyFile(t, dir, pub, testKeyID)
	receiptPath := buildAndWriteReceipt(t, dir, priv, testKeyID, dsr.TypeR1)
	logPath := filepath.Join(dir, "verifier.log")

	// Override DefaultLogFile is not possible without a parameter, so we write
	// to the current directory. Change working directory to dir for this test.
	origWd, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origWd)

	var out bytes.Buffer
	code := cli.Run([]string{"verify", receiptPath, "--key", keyPath, "--no-color"}, &out, &out)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	// Log file must exist.
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("log file not found at %s: %v", logPath, err)
	}

	// Must be a valid JSON line.
	lines := strings.Split(strings.TrimSpace(string(logData)), "\n")
	if len(lines) == 0 {
		t.Fatal("log file is empty")
	}
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("log line is not valid JSON: %v\nline: %s", err, lines[0])
	}
	for _, field := range []string{"timestamp", "command", "file", "result", "duration_ms", "verifier_version"} {
		if _, ok := entry[field]; !ok {
			t.Errorf("log entry missing field %q", field)
		}
	}
	if entry["result"] != "verified" {
		t.Errorf("log result = %v, want %q", entry["result"], "verified")
	}
	if entry["command"] != "verify" {
		t.Errorf("log command = %v, want %q", entry["command"], "verify")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// --quiet: produces no output (exit code only)
// ─────────────────────────────────────────────────────────────────────────────

func TestQuietFlag(t *testing.T) {
	dir := t.TempDir()
	pub, priv := newTestKey(t)
	keyPath := writeKeyFile(t, dir, pub, testKeyID)
	receiptPath := buildAndWriteReceipt(t, dir, priv, testKeyID, dsr.TypeR1)

	var out bytes.Buffer
	code := cli.Run([]string{"verify", receiptPath, "--key", keyPath, "--no-log", "--quiet"}, &out, &out)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if out.Len() != 0 {
		t.Errorf("--quiet should produce no output, got: %q", out.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// verify with missing --key flag: exit 4, clear error
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyMissingKeyFlag(t *testing.T) {
	dir := t.TempDir()
	_, priv := newTestKey(t)
	receiptPath := buildAndWriteReceipt(t, dir, priv, testKeyID, dsr.TypeR1)

	var errout bytes.Buffer
	code := cli.Run([]string{"verify", receiptPath}, &bytes.Buffer{}, &errout)
	if code != 4 {
		t.Fatalf("exit code = %d, want 4 (key error)", code)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// unknown command: exit 2
// ─────────────────────────────────────────────────────────────────────────────

func TestUnknownCommand(t *testing.T) {
	var errout bytes.Buffer
	code := cli.Run([]string{"frob"}, &bytes.Buffer{}, &errout)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// no arguments: shows help, exit 0
// ─────────────────────────────────────────────────────────────────────────────

func TestNoArgs(t *testing.T) {
	var out bytes.Buffer
	code := cli.Run([]string{}, &out, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	assertContains(t, out.String(), "verify")
	assertContains(t, out.String(), "info")
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func assertContains(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Errorf("expected output to contain %q\nfull output:\n%s", sub, s)
	}
}

func assertNotContains(t *testing.T, s, sub string) {
	t.Helper()
	if strings.Contains(s, sub) {
		t.Errorf("expected output NOT to contain %q\nfull output:\n%s", sub, s)
	}
}
