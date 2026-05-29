package dsr_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/deja-dev/dsr-verifier-cli/internal/dsr"
)

func TestRVCanonical(t *testing.T) {
	data, err := os.ReadFile("../../testdata/protocol/rv-canonical-vector.json")
	if err != nil {
		t.Fatal(err)
	}

	var v struct {
		WireNames        json.RawMessage `json:"wire_names"`
		CanonicalJSON    string          `json:"canonical_json"`
		CanonicalSHA256  string          `json:"canonical_sha256"`
		TestPubKey       string          `json:"test_public_key_base64"`
		TestSignature    string          `json:"test_signature_base64"`
		TestSigAlgorithm string          `json:"test_signature_algorithm"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}

	// Assert 1: CLI's CanonicalContent over wire_names matches canonical_json byte-exactly.
	computed, err := dsr.CanonicalContent(v.WireNames)
	if err != nil {
		t.Fatal(err)
	}
	if string(computed) != v.CanonicalJSON {
		t.Fatalf("canonical form drift:\n  computed: %s\n  expected: %s",
			string(computed), v.CanonicalJSON)
	}

	// Assert 2: SHA-256 of canonical_json matches canonical_sha256.
	h := sha256.Sum256([]byte(v.CanonicalJSON))
	if hex.EncodeToString(h[:]) != v.CanonicalSHA256 {
		t.Fatalf("canonical SHA-256 drift:\n  computed: %x\n  expected: %s",
			h, v.CanonicalSHA256)
	}

	// Assert 3: Test signature verifies against the test public key over canonical_json.
	if v.TestSigAlgorithm != "ed25519" {
		t.Skipf("unsupported test algorithm: %s", v.TestSigAlgorithm)
	}
	pubDER, err := base64.StdEncoding.DecodeString(v.TestPubKey)
	if err != nil {
		t.Fatalf("decode test public key: %v", err)
	}
	pubAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		t.Fatalf("parse test public key: %v", err)
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("test public key is not ed25519, got %T", pubAny)
	}
	sig, err := base64.StdEncoding.DecodeString(v.TestSignature)
	if err != nil {
		t.Fatalf("decode test signature: %v", err)
	}
	if !ed25519.Verify(pub, []byte(v.CanonicalJSON), sig) {
		t.Fatal("test signature did not verify against test public key — vector is inconsistent OR CLI verify path broke")
	}
}
