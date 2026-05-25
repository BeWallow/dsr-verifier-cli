package verify_test

// adversarial_test.go — attack-scenario tests that are not already covered
// by verify_test.go.  Each test is named after the threat it exercises and
// documents which check catches it.

import (
	"encoding/json"
	"testing"
	"time"

	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"

	"github.com/deja-dev/dsr-verifier-cli/internal/dsr"
	dsrerrors "github.com/deja-dev/dsr-verifier-cli/internal/errors"
	"github.com/deja-dev/dsr-verifier-cli/internal/verify"
)

// ─────────────────────────────────────────────────────────────────────────────
// Attack: receipt signed by an unknown key (no key_id in the key file)
//
// Scenario: an auditor was given the correct .dsr file but an unrelated
// public key that has no key_id comment.  The key authority check cannot
// compare key IDs (provided.KeyID == ""), so it passes.  The signature
// check then fails because the key material is wrong.
//
// Caught by: Signature verification (check #2).
// ─────────────────────────────────────────────────────────────────────────────

func TestUnknownKeySignatureFails(t *testing.T) {
	// Receipt signed with key A.
	_, privA := newTestKey(t)
	receiptJSON := buildSignedReceipt(t, privA, testKeyID, testVaultID)

	// Key file contains key B — completely different key, no key_id comment.
	pubB, _ := newTestKey(t)
	keyPEMNoID := marshalPublicKeyPEM(t, pubB, "")

	r, parseErr := dsr.Parse(receiptJSON)
	if parseErr != nil {
		t.Fatalf("Parse: %v", parseErr)
	}
	provided, keyErr := verify.ParsePublicKeyFile(keyPEMNoID)
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile: %v", keyErr)
	}

	// KeyAuthority must PASS — provided.KeyID is empty, so no mismatch
	// is detectable at this step.  The CLI documents this: a key file
	// without a key_id comment skips the authority pre-check and relies
	// entirely on the signature check to detect the wrong key.
	authRes := verify.KeyAuthority(r, provided)
	assertValid(t, "KeyAuthority (no key_id in file)", authRes.Valid, authRes.Err)

	// Signature MUST FAIL — the wrong key cannot verify the signature.
	sigRes := verify.Signature(r, provided)
	assertInvalid(t, "Signature (wrong key material)", sigRes.Valid, sigRes.Err, dsrerrors.SignatureInvalid)

	// Confirm the diagnostic message explains the failure.
	if sigRes.Err.HumanMessage == "" {
		t.Error("HumanMessage must not be empty on signature failure")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Attack: content field reordering does NOT bypass canonicalization
//
// Scenario: an attacker modifies a receipt by shuffling the JSON key order
// inside the content field, hoping this produces a different hash. Because
// CanonicalContent sorts keys lexicographically before hashing, reordering
// produces the same canonical bytes and therefore the same SHA-256 hash.
//
// Expected outcome: ContentHash passes (robustness test — canonicalization
// is truly order-independent).  The receipt verifies correctly despite
// non-canonical field ordering in the raw JSON.
// ─────────────────────────────────────────────────────────────────────────────

func TestContentFieldReorderingVerifies(t *testing.T) {
	pub, priv := newTestKey(t)
	keyPEM := marshalPublicKeyPEM(t, pub, testKeyID)

	// Build the receipt content in canonical (sorted) order first, to get
	// the correct content_hash.  Canonical order for these three keys:
	//   commit_sha < merged_at < pr_url  (lexicographic sort).
	contentCanonical := []byte(`{"commit_sha":"a8f3c2e9d4b1a6f7c2e8d4b1f6a8c3e9d4b1a6f7","merged_at":"2026-05-12T12:18:43Z","pr_url":"github.com/test-org/payments-api#4287"}`)
	hashBytes := sha256.Sum256(contentCanonical)
	contentHash := hex.EncodeToString(hashBytes[:])

	// Build a signed payload using the canonical content.
	issuedAt := time.Date(2026, 5, 12, 12, 42, 8, 0, time.UTC)
	partial := &dsr.Receipt{
		ID:               "r_reorder_test",
		Version:          dsr.Version,
		Type:             dsr.TypeR1,
		VaultID:          testVaultID,
		IssuedAt:         issuedAt,
		Content:          contentCanonical,
		ContentHash:      contentHash,
		SigningKeyID:     testKeyID,
		SigningAlgorithm: dsr.SigningAlgorithmED25519,
	}
	payload, err := dsr.CanonicalSignedPayload(partial)
	if err != nil {
		t.Fatalf("CanonicalSignedPayload: %v", err)
	}
	sig := ed25519.Sign(priv, payload)

	// Construct the receipt JSON with the content field in NON-canonical
	// (reversed) key order: pr_url > merged_at > commit_sha.
	contentReordered := []byte(`{"pr_url":"github.com/test-org/payments-api#4287","merged_at":"2026-05-12T12:18:43Z","commit_sha":"a8f3c2e9d4b1a6f7c2e8d4b1f6a8c3e9d4b1a6f7"}`)

	receiptMap := map[string]interface{}{
		"id":                "r_reorder_test",
		"version":           dsr.Version,
		"type":              dsr.TypeR1,
		"vault_id":          testVaultID,
		"issued_at":         issuedAt.UTC().Format(time.RFC3339),
		"content":           json.RawMessage(contentReordered), // ← reordered
		"content_hash":      contentHash,                       // hash of canonical form
		"signing_key_id":    testKeyID,
		"signing_algorithm": dsr.SigningAlgorithmED25519,
		"signature":         hex.EncodeToString(sig),
	}
	receiptJSON, err := json.Marshal(receiptMap)
	if err != nil {
		t.Fatalf("json.Marshal receipt: %v", err)
	}

	r, parseErr := dsr.Parse(receiptJSON)
	if parseErr != nil {
		t.Fatalf("Parse: %v", parseErr)
	}
	provided, _ := verify.ParsePublicKeyFile(keyPEM)

	// All four checks must PASS.  The reordered content is normalised by
	// CanonicalContent before hashing, producing the same sorted bytes as
	// the original — so the stored hash matches.
	if res := verify.KeyAuthority(r, provided); !res.Valid {
		t.Errorf("KeyAuthority: %v", res.Err)
	}
	if res := verify.Signature(r, provided); !res.Valid {
		t.Errorf("Signature: %v", res.Err)
	}
	hashRes := verify.ContentHash(r)
	if !hashRes.Valid {
		t.Errorf("ContentHash failed despite reordering being canonical-equivalent: %v", hashRes.Err)
	}
	if hashRes.ComputedHash != hashRes.StoredHash {
		t.Errorf("ComputedHash %q != StoredHash %q after reordered content parsed",
			hashRes.ComputedHash, hashRes.StoredHash)
	}
}
