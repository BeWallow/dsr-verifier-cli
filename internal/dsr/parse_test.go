package dsr_test

import (
	"strings"
	"testing"

	"github.com/deja-dev/dsr-verifier-cli/internal/dsr"
	dsrerrors "github.com/deja-dev/dsr-verifier-cli/internal/errors"
)

// validReceiptJSON is a minimal but complete DSR/1.0.1 receipt for parse tests.
// The signature and content_hash values are placeholder hex strings of the
// correct lengths; parse tests do not verify cryptographic correctness.
const validReceiptJSON = `{
	"id": "r_test_001",
	"version": "DSR/1.0.1",
	"type": "R1",
	"vault_id": "vlt_test",
	"issued_at": "2026-05-12T12:42:08Z",
	"content": {"pr_url": "github.com/org/repo#1", "commit_sha": "abc1234"},
	"content_hash": "4d8a2c9e7b3f1a2d4c5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c",
	"signing_key_id": "key_test",
	"signing_algorithm": "ed25519",
	"signature": "b2e9c4a7f1d3e6a8b2e9c4a7f1d3e6a8b2e9c4a7f1d3e6a8b2e9c4a7f1d3e6a8b2e9c4a7f1d3e6a8b2e9c4a7f1d3e6a8b2e9c4a7f1d3e6a8b2e9c4a7f1d3e6a8"
}`

func TestParseValidReceipt(t *testing.T) {
	r, err := dsr.Parse([]byte(validReceiptJSON))
	if err != nil {
		t.Fatalf("Parse valid receipt: %v", err)
	}
	if r.ID != "r_test_001" {
		t.Errorf("ID = %q, want %q", r.ID, "r_test_001")
	}
	if r.Version != dsr.Version {
		t.Errorf("Version = %q, want %q", r.Version, dsr.Version)
	}
	if r.Type != dsr.TypeR1 {
		t.Errorf("Type = %q, want %q", r.Type, dsr.TypeR1)
	}
	if r.VaultID != "vlt_test" {
		t.Errorf("VaultID = %q, want %q", r.VaultID, "vlt_test")
	}
	if r.SigningKeyID != "key_test" {
		t.Errorf("SigningKeyID = %q", r.SigningKeyID)
	}
	if r.SigningAlgorithm != dsr.SigningAlgorithmED25519 {
		t.Errorf("SigningAlgorithm = %q", r.SigningAlgorithm)
	}
	if len(r.Signature) != 64 {
		t.Errorf("Signature len = %d, want 64", len(r.Signature))
	}
}

func TestParseMalformedJSON(t *testing.T) {
	inputs := []struct {
		name  string
		input string
	}{
		{"truncated", `{"id": "r_test`},
		{"not json", `not json at all`},
		{"empty", ``},
		{"just brace", `{`},
	}

	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := dsr.Parse([]byte(tc.input))
			if err == nil {
				t.Fatal("expected parse error, got nil")
			}
			if err.Class != dsrerrors.MalformedReceipt {
				t.Errorf("error class = %q, want %q", err.Class, dsrerrors.MalformedReceipt)
			}
			if err.TechnicalDetail == "" {
				t.Error("TechnicalDetail must not be empty")
			}
		})
	}
}

func TestParseUnknownFieldRejected(t *testing.T) {
	// Strict mode: unknown fields must be rejected.
	input := strings.Replace(validReceiptJSON, `"id": "r_test_001"`,
		`"id": "r_test_001", "extra_field": "should fail"`, 1)
	_, err := dsr.Parse([]byte(input))
	if err == nil {
		t.Fatal("expected rejection of unknown field, got nil error")
	}
	if err.Class != dsrerrors.MalformedReceipt {
		t.Errorf("error class = %q, want %q", err.Class, dsrerrors.MalformedReceipt)
	}
}

func TestParseMissingRequiredFields(t *testing.T) {
	cases := []struct {
		name   string
		remove string
	}{
		{"missing id", `"id": "r_test_001",`},
		{"missing version", `"version": "DSR/1.0.1",`},
		{"missing type", `"type": "R1",`},
		{"missing vault_id", `"vault_id": "vlt_test",`},
		{"missing content_hash", `"content_hash": "4d8a2c9e7b3f1a2d4c5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c",`},
		{"missing signing_key_id", `"signing_key_id": "key_test",`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.Replace(validReceiptJSON, tc.remove, "", 1)
			_, err := dsr.Parse([]byte(input))
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			if err.Class != dsrerrors.MalformedReceipt {
				t.Errorf("error class = %q, want %q", err.Class, dsrerrors.MalformedReceipt)
			}
		})
	}
}

func TestParseWrongVersion(t *testing.T) {
	input := strings.Replace(validReceiptJSON, `"DSR/1.0.1"`, `"DSR/2.0.0"`, 1)
	_, err := dsr.Parse([]byte(input))
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
	if err.Class != dsrerrors.MalformedReceipt {
		t.Errorf("error class = %q, want %q", err.Class, dsrerrors.MalformedReceipt)
	}
	if !strings.Contains(err.HumanMessage, "DSR/2.0.0") {
		t.Errorf("HumanMessage should mention the bad version, got: %s", err.HumanMessage)
	}
}

func TestParseUnknownType(t *testing.T) {
	input := strings.Replace(validReceiptJSON, `"type": "R1"`, `"type": "RX"`, 1)
	_, err := dsr.Parse([]byte(input))
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
	if err.Class != dsrerrors.MalformedReceipt {
		t.Errorf("error class = %q, want %q", err.Class, dsrerrors.MalformedReceipt)
	}
}

func TestParseWrongAlgorithm(t *testing.T) {
	// "rsa-pkcs1" is not a supported algorithm — must return UnsupportedAlgorithm,
	// not MalformedReceipt.
	input := strings.Replace(validReceiptJSON, `"ed25519"`, `"rsa-pkcs1"`, 1)
	_, err := dsr.Parse([]byte(input))
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
	if err.Class != dsrerrors.UnsupportedAlgorithm {
		t.Errorf("error class = %q, want %q", err.Class, dsrerrors.UnsupportedAlgorithm)
	}
}

func TestParseAcceptedAlgorithms(t *testing.T) {
	// All three supported BYOK algorithms must parse successfully.
	// Note: the validReceiptJSON signature is placeholder bytes — parse tests
	// do not verify cryptographic correctness, just structural acceptance.
	tests := []struct {
		name string
		algo string
	}{
		{"ed25519", "ed25519"},
		{"rsa-pss-sha256", "rsa-pss-sha256"},
		{"ecdsa-sha256", "ecdsa-sha256"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Use a longer placeholder signature to satisfy any non-zero length check;
			// rsa-pss and ecdsa sigs are variable length so we just need non-empty.
			input := strings.Replace(validReceiptJSON, `"ed25519"`, `"`+tc.algo+`"`, 1)
			_, parseErr := dsr.Parse([]byte(input))
			if parseErr != nil {
				t.Errorf("Parse(%s): unexpected error: class=%s msg=%s",
					tc.algo, parseErr.Class, parseErr.HumanMessage)
			}
		})
	}
}

func TestParseAllValidTypes(t *testing.T) {
	types := []string{"R1", "R1-L", "R1-N", "R2", "RV", "RV-i", "RV-f"}
	for _, typ := range types {
		t.Run(typ, func(t *testing.T) {
			input := strings.Replace(validReceiptJSON, `"type": "R1"`,
				`"type": "`+typ+`"`, 1)
			_, err := dsr.Parse([]byte(input))
			if err != nil {
				t.Errorf("Parse %s: %v", typ, err)
			}
		})
	}
}

func TestParseContentHashWrongLength(t *testing.T) {
	// content_hash must be exactly 64 hex chars (SHA-256).
	input := strings.Replace(validReceiptJSON,
		"4d8a2c9e7b3f1a2d4c5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c",
		"tooshort", 1)
	_, err := dsr.Parse([]byte(input))
	if err == nil {
		t.Fatal("expected error for short content_hash")
	}
	if err.Class != dsrerrors.MalformedReceipt {
		t.Errorf("error class = %q, want %q", err.Class, dsrerrors.MalformedReceipt)
	}
}
