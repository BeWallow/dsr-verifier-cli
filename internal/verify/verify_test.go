package verify_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/deja-dev/dsr-verifier-cli/internal/dsr"
	dsrerrors "github.com/deja-dev/dsr-verifier-cli/internal/errors"
	"github.com/deja-dev/dsr-verifier-cli/internal/verify"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test fixtures
// ─────────────────────────────────────────────────────────────────────────────

const testKeyID = "key_test_2026q2"
const testVaultID = "vlt_test-org"

// newTestKey generates a fresh ed25519 key pair for testing.
func newTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return pub, priv
}

// marshalPublicKeyPEM encodes a public key as a PKIX PEM block with the
// optional # key_id: header comment.
func marshalPublicKeyPEM(t *testing.T, pub ed25519.PublicKey, keyID string) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	var buf []byte
	if keyID != "" {
		buf = append(buf, fmt.Sprintf("# key_id: %s\n", keyID)...)
	}
	buf = append(buf, pem.EncodeToMemory(block)...)
	return buf
}

// buildSignedReceipt constructs a complete, correctly-signed R1 receipt for
// the given private key.
func buildSignedReceipt(t *testing.T, priv ed25519.PrivateKey, keyID, vaultID string) []byte {
	t.Helper()

	// Build the content object.
	content := map[string]interface{}{
		"commit_sha": "a8f3c2e9d4b1a6f7c2e8d4b1f6a8c3e9d4b1a6f7",
		"merged_at":  "2026-05-12T12:18:43Z",
		"pr_url":     "github.com/test-org/payments-api#4287",
	}

	// Compute the canonical content bytes.
	canonicalContent, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("marshal content: %v", err)
	}

	// content_hash = sha256(canonical content).
	sum := sha256.Sum256(canonicalContent)
	contentHash := hex.EncodeToString(sum[:])

	issuedAt := time.Date(2026, 5, 12, 12, 42, 8, 0, time.UTC)

	// Build the partial receipt (without signature) to compute the signed payload.
	partial := &dsr.Receipt{
		ID:               "r_test_payments_2026q2",
		Version:          dsr.Version,
		Type:             dsr.TypeR1,
		VaultID:          vaultID,
		IssuedAt:         issuedAt,
		Content:          canonicalContent,
		ContentHash:      contentHash,
		SigningKeyID:     keyID,
		SigningAlgorithm:  dsr.SigningAlgorithmED25519,
	}

	payload, err := dsr.CanonicalSignedPayload(partial)
	if err != nil {
		t.Fatalf("canonical signed payload: %v", err)
	}

	sig := ed25519.Sign(priv, payload)

	// Now serialize the full receipt as JSON.
	full := map[string]interface{}{
		"id":                "r_test_payments_2026q2",
		"version":           dsr.Version,
		"type":              dsr.TypeR1,
		"vault_id":          vaultID,
		"issued_at":         issuedAt.UTC().Format(time.RFC3339),
		"content":           json.RawMessage(canonicalContent),
		"content_hash":      contentHash,
		"signing_key_id":    keyID,
		"signing_algorithm": dsr.SigningAlgorithmED25519,
		"signature":         hex.EncodeToString(sig),
	}

	b, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: known-good receipt — all checks pass
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyKnownGoodReceipt(t *testing.T) {
	pub, priv := newTestKey(t)
	keyPEM := marshalPublicKeyPEM(t, pub, testKeyID)
	receiptJSON := buildSignedReceipt(t, priv, testKeyID, testVaultID)

	r, parseErr := dsr.Parse(receiptJSON)
	if parseErr != nil {
		t.Fatalf("Parse: %v", parseErr)
	}

	provided, keyErr := verify.ParsePublicKeyFile(keyPEM)
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile: %v", keyErr)
	}

	authRes := verify.KeyAuthority(r, provided)
	assertValid(t, "KeyAuthority", authRes.Valid, authRes.Err)

	sigRes := verify.Signature(r, provided)
	assertValid(t, "Signature", sigRes.Valid, sigRes.Err)

	hashRes := verify.ContentHash(r)
	assertValid(t, "ContentHash", hashRes.Valid, hashRes.Err)

	causalRes := verify.CausalRefs(r)
	assertValid(t, "CausalRefs", causalRes.Valid, causalRes.Err)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: tamper content → content_hash_mismatch surfaces
// ─────────────────────────────────────────────────────────────────────────────

func TestTamperContent(t *testing.T) {
	pub, priv := newTestKey(t)
	keyPEM := marshalPublicKeyPEM(t, pub, testKeyID)
	receiptJSON := buildSignedReceipt(t, priv, testKeyID, testVaultID)

	// Tamper: replace the content's commit_sha with a different value.
	// The signature and content_hash fields are left unchanged — this simulates
	// an attacker modifying the content without re-signing.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(receiptJSON, &raw); err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}
	tamperedContent := []byte(`{"commit_sha":"0000000000000000000000000000000000000000","merged_at":"2026-05-12T12:18:43Z","pr_url":"github.com/test-org/payments-api#4287"}`)
	raw["content"] = tamperedContent
	tampered, _ := json.Marshal(raw)

	r, parseErr := dsr.Parse(tampered)
	if parseErr != nil {
		t.Fatalf("Parse: %v", parseErr)
	}

	provided, _ := verify.ParsePublicKeyFile(keyPEM)

	// Signature should still pass (signed payload includes original content_hash).
	sigRes := verify.Signature(r, provided)
	assertValid(t, "Signature (content tampered, envelope unchanged)", sigRes.Valid, sigRes.Err)

	// Content hash must fail with the right error class.
	hashRes := verify.ContentHash(r)
	assertInvalid(t, "ContentHash", hashRes.Valid, hashRes.Err, dsrerrors.ContentHashMismatch)

	if hashRes.ComputedHash == hashRes.StoredHash {
		t.Error("computed and stored hashes must differ after tampering")
	}
	if hashRes.ComputedHash == "" || hashRes.StoredHash == "" {
		t.Error("both hash values must be populated in the failure result")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: tamper signature bytes → signature_invalid surfaces
// ─────────────────────────────────────────────────────────────────────────────

func TestTamperSignature(t *testing.T) {
	pub, priv := newTestKey(t)
	keyPEM := marshalPublicKeyPEM(t, pub, testKeyID)
	receiptJSON := buildSignedReceipt(t, priv, testKeyID, testVaultID)

	// Flip the first byte of the signature field.
	var raw map[string]json.RawMessage
	json.Unmarshal(receiptJSON, &raw)
	var sigHex string
	json.Unmarshal(raw["signature"], &sigHex)
	sigBytes, _ := hex.DecodeString(sigHex)
	sigBytes[0] ^= 0xFF
	raw["signature"], _ = json.Marshal(hex.EncodeToString(sigBytes))
	tampered, _ := json.Marshal(raw)

	r, parseErr := dsr.Parse(tampered)
	if parseErr != nil {
		t.Fatalf("Parse: %v", parseErr)
	}

	provided, _ := verify.ParsePublicKeyFile(keyPEM)
	sigRes := verify.Signature(r, provided)
	assertInvalid(t, "Signature", sigRes.Valid, sigRes.Err, dsrerrors.SignatureInvalid)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: wrong public key → key_authority_mismatch surfaces before signature check
// ─────────────────────────────────────────────────────────────────────────────

func TestWrongPublicKey(t *testing.T) {
	_, priv := newTestKey(t)
	// Signing key has testKeyID; the "wrong" key file identifies as a different ID.
	wrongPub, _ := newTestKey(t)
	wrongKeyPEM := marshalPublicKeyPEM(t, wrongPub, "key_attacker_xyz")
	receiptJSON := buildSignedReceipt(t, priv, testKeyID, testVaultID)

	r, parseErr := dsr.Parse(receiptJSON)
	if parseErr != nil {
		t.Fatalf("Parse: %v", parseErr)
	}

	provided, keyErr := verify.ParsePublicKeyFile(wrongKeyPEM)
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile: %v", keyErr)
	}

	authRes := verify.KeyAuthority(r, provided)
	assertInvalid(t, "KeyAuthority", authRes.Valid, authRes.Err, dsrerrors.KeyAuthorityMismatch)

	// Verify that the diagnostic values are populated.
	if authRes.ClaimedKeyID != testKeyID {
		t.Errorf("ClaimedKeyID = %q, want %q", authRes.ClaimedKeyID, testKeyID)
	}
	if authRes.ProvidedKeyID != "key_attacker_xyz" {
		t.Errorf("ProvidedKeyID = %q, want %q", authRes.ProvidedKeyID, "key_attacker_xyz")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: malformed causal ref → structural validation surfaces
// ─────────────────────────────────────────────────────────────────────────────

func TestMalformedCausalRef(t *testing.T) {
	pub, priv := newTestKey(t)
	keyPEM := marshalPublicKeyPEM(t, pub, testKeyID)
	receiptJSON := buildSignedReceipt(t, priv, testKeyID, testVaultID)

	// Replace the content with one that has invalid pr_url and commit_sha.
	var raw map[string]json.RawMessage
	json.Unmarshal(receiptJSON, &raw)

	badContent := map[string]interface{}{
		"commit_sha": "not-a-hex-sha!",
		"merged_at":  "2026-05-12T12:18:43Z",
		"pr_url":     "not-a-valid-pr-url",
	}
	badContentBytes, _ := json.Marshal(badContent)

	// Recompute the content_hash and signature for the modified receipt so that
	// only the causal-ref check fails (signature and hash checks pass).
	sum := sha256.Sum256(badContentBytes)
	newContentHash := hex.EncodeToString(sum[:])

	raw["content"] = badContentBytes
	raw["content_hash"], _ = json.Marshal(newContentHash)

	// Re-sign with the partial receipt.
	issuedAt := time.Date(2026, 5, 12, 12, 42, 8, 0, time.UTC)
	partial := &dsr.Receipt{
		ID:               "r_test_payments_2026q2",
		Version:          dsr.Version,
		Type:             dsr.TypeR1,
		VaultID:          testVaultID,
		IssuedAt:         issuedAt,
		Content:          badContentBytes,
		ContentHash:      newContentHash,
		SigningKeyID:     testKeyID,
		SigningAlgorithm:  dsr.SigningAlgorithmED25519,
	}
	payload, _ := dsr.CanonicalSignedPayload(partial)
	_, privKey := newTestKey(t) // wrong priv — we want the original priv
	_ = privKey
	// Use the original priv key (passed in as priv from buildSignedReceipt's key pair).
	// We don't have access to priv here directly, so rebuild the receipt using
	// the same priv key.
	_ = pub
	sig := ed25519.Sign(priv, payload)
	raw["signature"], _ = json.Marshal(hex.EncodeToString(sig))

	modified, _ := json.Marshal(raw)

	r, parseErr := dsr.Parse(modified)
	if parseErr != nil {
		t.Fatalf("Parse: %v", parseErr)
	}

	provided, _ := verify.ParsePublicKeyFile(keyPEM)
	_ = provided

	causalRes := verify.CausalRefs(r)
	assertInvalid(t, "CausalRefs", causalRes.Valid, causalRes.Err, dsrerrors.MalformedCausalRef)

	if len(causalRes.MalformedFields) < 2 {
		t.Errorf("expected at least 2 malformed fields (pr_url, commit_sha), got %d: %v",
			len(causalRes.MalformedFields), causalRes.MalformedFields)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: R2 receipt skips causal ref check
// ─────────────────────────────────────────────────────────────────────────────

func TestR2SkipsCausalRefs(t *testing.T) {
	pub, priv := newTestKey(t)
	keyPEM := marshalPublicKeyPEM(t, pub, testKeyID)
	receiptJSON := buildSignedReceipt(t, priv, testKeyID, testVaultID)

	// Modify the type to R2.
	var raw map[string]json.RawMessage
	json.Unmarshal(receiptJSON, &raw)

	// Need to re-sign because type is part of the signed payload.
	raw["type"], _ = json.Marshal(dsr.TypeR2)
	// Recompute signature for R2 type.
	issuedAt := time.Date(2026, 5, 12, 12, 42, 8, 0, time.UTC)
	var contentHash string
	json.Unmarshal(raw["content_hash"], &contentHash)
	partial := &dsr.Receipt{
		ID:               "r_test_payments_2026q2",
		Version:          dsr.Version,
		Type:             dsr.TypeR2,
		VaultID:          testVaultID,
		IssuedAt:         issuedAt,
		ContentHash:      contentHash,
		SigningKeyID:     testKeyID,
		SigningAlgorithm:  dsr.SigningAlgorithmED25519,
	}
	payload, _ := dsr.CanonicalSignedPayload(partial)
	sig := ed25519.Sign(priv, payload)
	raw["signature"], _ = json.Marshal(hex.EncodeToString(sig))

	r2Receipt, _ := json.Marshal(raw)

	r, parseErr := dsr.Parse(r2Receipt)
	if parseErr != nil {
		t.Fatalf("Parse: %v", parseErr)
	}
	_ = keyPEM
	_ = pub

	causalRes := verify.CausalRefs(r)
	if !causalRes.Valid {
		t.Errorf("CausalRefs for R2 receipt must be Valid=true (no causal refs expected): %v", causalRes.Err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: key file without key_id comment still parses
// ─────────────────────────────────────────────────────────────────────────────

func TestKeyFileNoKeyID(t *testing.T) {
	pub, _ := newTestKey(t)
	keyPEM := marshalPublicKeyPEM(t, pub, "") // no key_id comment

	provided, keyErr := verify.ParsePublicKeyFile(keyPEM)
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile: %v", keyErr)
	}
	if provided.KeyID != "" {
		t.Errorf("KeyID = %q, want empty when comment absent", provided.KeyID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BYOK algorithm helpers
// ─────────────────────────────────────────────────────────────────────────────

// marshalAnyPublicKeyPEM encodes any supported public key (ed25519, *rsa.PublicKey,
// *ecdsa.PublicKey) as a PKIX PEM block with an optional # key_id: header.
func marshalAnyPublicKeyPEM(t *testing.T, pub interface{}, keyID string) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey(%T): %v", pub, err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	var buf []byte
	if keyID != "" {
		buf = append(buf, fmt.Sprintf("# key_id: %s\n", keyID)...)
	}
	buf = append(buf, pem.EncodeToMemory(block)...)
	return buf
}

// buildSignedReceiptWithAlgo constructs a complete, correctly-signed R1 receipt
// for the given algorithm. signerFn receives the canonical payload bytes and
// returns the raw signature bytes.
func buildSignedReceiptWithAlgo(
	t *testing.T,
	algo, keyID, vaultID string,
	signerFn func(payload []byte) []byte,
) []byte {
	t.Helper()

	content := map[string]interface{}{
		"commit_sha": "a8f3c2e9d4b1a6f7c2e8d4b1f6a8c3e9d4b1a6f7",
		"merged_at":  "2026-05-12T12:18:43Z",
		"pr_url":     "github.com/test-org/payments-api#4287",
	}
	canonicalContent, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("marshal content: %v", err)
	}
	sum := sha256.Sum256(canonicalContent)
	contentHash := hex.EncodeToString(sum[:])

	issuedAt := time.Date(2026, 5, 12, 12, 42, 8, 0, time.UTC)
	partial := &dsr.Receipt{
		ID:               "r_byok_test",
		Version:          dsr.Version,
		Type:             dsr.TypeR1,
		VaultID:          vaultID,
		IssuedAt:         issuedAt,
		Content:          canonicalContent,
		ContentHash:      contentHash,
		SigningKeyID:     keyID,
		SigningAlgorithm: algo,
	}
	payload, err := dsr.CanonicalSignedPayload(partial)
	if err != nil {
		t.Fatalf("CanonicalSignedPayload: %v", err)
	}

	sig := signerFn(payload)

	full := map[string]interface{}{
		"id":                "r_byok_test",
		"version":           dsr.Version,
		"type":              dsr.TypeR1,
		"vault_id":          vaultID,
		"issued_at":         issuedAt.UTC().Format(time.RFC3339),
		"content":           json.RawMessage(canonicalContent),
		"content_hash":      contentHash,
		"signing_key_id":    keyID,
		"signing_algorithm": algo,
		"signature":         hex.EncodeToString(sig),
	}
	b, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: RSA-PSS receipt — parse, verify, tamper-detection
// ─────────────────────────────────────────────────────────────────────────────

func TestRSAPSSVerifyAndTamper(t *testing.T) {
	// Generate a 2048-bit RSA key pair for testing.
	// Generated programmatically — no external fixture files required.
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	rsaPub := &rsaPriv.PublicKey

	keyPEM := marshalAnyPublicKeyPEM(t, rsaPub, testKeyID)

	signerFn := func(payload []byte) []byte {
		hashed := sha256.Sum256(payload)
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}
		sig, err := rsa.SignPSS(rand.Reader, rsaPriv, crypto.SHA256, hashed[:], opts)
		if err != nil {
			t.Fatalf("rsa.SignPSS: %v", err)
		}
		return sig
	}

	receiptJSON := buildSignedReceiptWithAlgo(t, dsr.SigningAlgorithmRSAPSS, testKeyID, testVaultID, signerFn)

	// Parse must succeed.
	r, parseErr := dsr.Parse(receiptJSON)
	if parseErr != nil {
		t.Fatalf("Parse RSA-PSS receipt: %v", parseErr)
	}
	if r.SigningAlgorithm != dsr.SigningAlgorithmRSAPSS {
		t.Errorf("SigningAlgorithm = %q, want %q", r.SigningAlgorithm, dsr.SigningAlgorithmRSAPSS)
	}

	// Parse public key must succeed and return an RSA key.
	provided, keyErr := verify.ParsePublicKeyFile(keyPEM)
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile (RSA): %v", keyErr)
	}

	// Signature check must pass.
	sigRes := verify.Signature(r, provided)
	assertValid(t, "RSA-PSS Signature", sigRes.Valid, sigRes.Err)

	// ── Tamper detection ──
	// Flip the first byte of the signature to produce a corrupted signature.
	var raw map[string]json.RawMessage
	json.Unmarshal(receiptJSON, &raw)
	var sigHex string
	json.Unmarshal(raw["signature"], &sigHex)
	sigBytes, _ := hex.DecodeString(sigHex)
	sigBytes[0] ^= 0xFF
	raw["signature"], _ = json.Marshal(hex.EncodeToString(sigBytes))
	tampered, _ := json.Marshal(raw)

	rTampered, _ := dsr.Parse(tampered)
	tamperedSig := verify.Signature(rTampered, provided)
	assertInvalid(t, "RSA-PSS tampered Signature", tamperedSig.Valid, tamperedSig.Err, dsrerrors.SignatureInvalid)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: ECDSA receipt — parse, verify, tamper-detection
// ─────────────────────────────────────────────────────────────────────────────

func TestECDSAVerifyAndTamper(t *testing.T) {
	// Generate a P-256 ECDSA key pair for testing.
	// AWS KMS ECDSA_SHA_256 uses P-256; generated programmatically here.
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	ecPub := &ecPriv.PublicKey

	keyPEM := marshalAnyPublicKeyPEM(t, ecPub, testKeyID)

	signerFn := func(payload []byte) []byte {
		hashed := sha256.Sum256(payload)
		// ecdsa.SignASN1 produces a DER-encoded signature — same as AWS KMS output.
		sig, err := ecdsa.SignASN1(rand.Reader, ecPriv, hashed[:])
		if err != nil {
			t.Fatalf("ecdsa.SignASN1: %v", err)
		}
		return sig
	}

	receiptJSON := buildSignedReceiptWithAlgo(t, dsr.SigningAlgorithmECDSA, testKeyID, testVaultID, signerFn)

	// Parse must succeed.
	r, parseErr := dsr.Parse(receiptJSON)
	if parseErr != nil {
		t.Fatalf("Parse ECDSA receipt: %v", parseErr)
	}
	if r.SigningAlgorithm != dsr.SigningAlgorithmECDSA {
		t.Errorf("SigningAlgorithm = %q, want %q", r.SigningAlgorithm, dsr.SigningAlgorithmECDSA)
	}

	// Parse public key must succeed and return an ECDSA key.
	provided, keyErr := verify.ParsePublicKeyFile(keyPEM)
	if keyErr != nil {
		t.Fatalf("ParsePublicKeyFile (ECDSA): %v", keyErr)
	}

	// Signature check must pass.
	sigRes := verify.Signature(r, provided)
	assertValid(t, "ECDSA Signature", sigRes.Valid, sigRes.Err)

	// ── Tamper detection ──
	var raw map[string]json.RawMessage
	json.Unmarshal(receiptJSON, &raw)
	var sigHex string
	json.Unmarshal(raw["signature"], &sigHex)
	sigBytes, _ := hex.DecodeString(sigHex)
	sigBytes[0] ^= 0xFF
	raw["signature"], _ = json.Marshal(hex.EncodeToString(sigBytes))
	tampered, _ := json.Marshal(raw)

	rTampered, _ := dsr.Parse(tampered)
	tamperedSig := verify.Signature(rTampered, provided)
	assertInvalid(t, "ECDSA tampered Signature", tamperedSig.Valid, tamperedSig.Err, dsrerrors.SignatureInvalid)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: ErrUnsupportedAlgorithm returned (not MalformedReceipt) for "rsa-pkcs1"
// ─────────────────────────────────────────────────────────────────────────────

func TestParseUnsupportedAlgorithmError(t *testing.T) {
	// Use the ed25519 receipt JSON (from offline test) but swap the algorithm
	// to "rsa-pkcs1" which is explicitly unsupported.
	pub, priv := newTestKey(t)
	_ = pub
	receiptJSON := buildSignedReceipt(t, priv, testKeyID, testVaultID)

	var raw map[string]json.RawMessage
	json.Unmarshal(receiptJSON, &raw)
	raw["signing_algorithm"], _ = json.Marshal("rsa-pkcs1")
	// Also widen the signature to a plausible RSA size so no length check fires.
	raw["signature"], _ = json.Marshal(hex.EncodeToString(make([]byte, 256)))
	modified, _ := json.Marshal(raw)

	_, parseErr := dsr.Parse(modified)
	if parseErr == nil {
		t.Fatal("expected ErrUnsupportedAlgorithm for rsa-pkcs1, got nil")
	}
	if parseErr.Class != dsrerrors.UnsupportedAlgorithm {
		t.Errorf("error class = %q, want %q (not %q)",
			parseErr.Class, dsrerrors.UnsupportedAlgorithm, dsrerrors.MalformedReceipt)
	}
	if parseErr.HumanMessage == "" {
		t.Error("HumanMessage must not be empty")
	}
	if parseErr.TechnicalDetail == "" {
		t.Error("TechnicalDetail must not be empty")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func assertValid(t *testing.T, label string, valid bool, verr *dsrerrors.VerificationError) {
	t.Helper()
	if !valid {
		t.Errorf("%s: expected Valid=true but got failure: class=%s, message=%s",
			label, verr.Class, verr.HumanMessage)
	}
}

func assertInvalid(t *testing.T, label string, valid bool, verr *dsrerrors.VerificationError, wantClass dsrerrors.ErrorClass) {
	t.Helper()
	if valid {
		t.Errorf("%s: expected Valid=false but got Valid=true", label)
		return
	}
	if verr == nil {
		t.Errorf("%s: expected non-nil VerificationError but got nil", label)
		return
	}
	if verr.Class != wantClass {
		t.Errorf("%s: error class = %q, want %q", label, verr.Class, wantClass)
	}
	if verr.HumanMessage == "" {
		t.Errorf("%s: HumanMessage must not be empty", label)
	}
	if verr.TechnicalDetail == "" {
		t.Errorf("%s: TechnicalDetail must not be empty", label)
	}
}
