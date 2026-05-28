// gen.go — fixture generator for internal/verify/testdata
//
// Run with:
//
//	go run ./internal/verify/testdata/gen
//
// from the repository root. This produces:
//
//	internal/verify/testdata/rsa_pss_receipt.dsr
//	internal/verify/testdata/rsa_pss_key.pub
//	internal/verify/testdata/ecdsa_receipt.dsr
//	internal/verify/testdata/ecdsa_key.pub
//
// How each was generated:
//   - RSA key: rsa.GenerateKey(rand.Reader, 2048)  →  PKIX PEM
//   - RSA-PSS sig: rsa.SignPSS(rand.Reader, priv, crypto.SHA256, sha256(payload), PSSSaltLengthAuto)
//   - ECDSA key: ecdsa.GenerateKey(elliptic.P256(), rand.Reader)  →  PKIX PEM
//   - ECDSA sig: ecdsa.SignASN1(rand.Reader, priv, sha256(payload))  →  DER-encoded
//
// The receipt payload is the canonical signed payload (sorted-key JSON) over a
// representative R1 receipt. The content_hash covers the canonical JSON content.
//
//go:generate go run .
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

func main() {
	// Locate the testdata directory relative to this file.
	_, filename, _, _ := runtime.Caller(0)
	outDir := filepath.Dir(filepath.Dir(filename)) // parent of gen/

	if err := genRSAPSS(outDir); err != nil {
		fmt.Fprintf(os.Stderr, "rsa-pss: %v\n", err)
		os.Exit(1)
	}
	if err := genECDSA(outDir); err != nil {
		fmt.Fprintf(os.Stderr, "ecdsa: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("fixtures written to", outDir)
}

// sharedReceiptFields returns the fields common to both fixture receipts.
func sharedReceiptFields(algo, keyID string) (content json.RawMessage, contentHash string, issuedAt time.Time) {
	content = json.RawMessage(`{"commit_sha":"fixture000000000000000000000000000000000000","merged_at":"2026-05-01T00:00:00Z","pr_url":"github.com/deja-dev/example#1"}`)
	sum := sha256.Sum256(content)
	contentHash = hex.EncodeToString(sum[:])
	issuedAt = time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	return
}

// canonicalPayload constructs the canonical signed payload JSON.
func canonicalPayload(id, algo, keyID, contentHash string, issuedAt time.Time) ([]byte, error) {
	payload := struct {
		ContentHash      string `json:"content_hash"`
		ID               string `json:"id"`
		IssuedAt         string `json:"issued_at"`
		SigningAlgorithm string `json:"signing_algorithm"`
		SigningKeyID     string `json:"signing_key_id"`
		Type             string `json:"type"`
		VaultID          string `json:"vault_id"`
		Version          string `json:"version"`
	}{
		ContentHash:      contentHash,
		ID:               id,
		IssuedAt:         issuedAt.UTC().Format("2006-01-02T15:04:05Z"),
		SigningAlgorithm: algo,
		SigningKeyID:     keyID,
		Type:             "R1",
		VaultID:          "vlt_fixture_byok",
		Version:          "DSR/1.0.1",
	}
	return json.Marshal(payload)
}

func writePEMKey(path string, pub interface{}, keyID string) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	data := fmt.Sprintf("# key_id: %s\n%s", keyID, string(block))
	return os.WriteFile(path, []byte(data), 0644)
}

func writeReceiptJSON(path string, id, algo, keyID, contentHash string, content json.RawMessage, issuedAt time.Time, sig []byte) error {
	receipt := map[string]interface{}{
		"id":                id,
		"version":           "DSR/1.0.1",
		"type":              "R1",
		"vault_id":          "vlt_fixture_byok",
		"issued_at":         issuedAt.UTC().Format(time.RFC3339),
		"content":           content,
		"content_hash":      contentHash,
		"signing_key_id":    keyID,
		"signing_algorithm": algo,
		"signature":         hex.EncodeToString(sig),
	}
	b, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func genRSAPSS(outDir string) error {
	const algo = "rsa-pss-sha256"
	const keyID = "key_fixture_rsa_pss_2026"
	const receiptID = "r_fixture_rsa_pss_001"

	// Generate RSA-2048 key pair.
	// Method: rsa.GenerateKey(rand.Reader, 2048)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("rsa.GenerateKey: %w", err)
	}

	content, contentHash, issuedAt := sharedReceiptFields(algo, keyID)

	payload, err := canonicalPayload(receiptID, algo, keyID, contentHash, issuedAt)
	if err != nil {
		return err
	}

	// Sign: rsa.SignPSS with SHA-256 digest and PSSSaltLengthAuto.
	hashed := sha256.Sum256(payload)
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, hashed[:], opts)
	if err != nil {
		return fmt.Errorf("rsa.SignPSS: %w", err)
	}

	if err := writePEMKey(filepath.Join(outDir, "rsa_pss_key.pub"), &priv.PublicKey, keyID); err != nil {
		return err
	}
	return writeReceiptJSON(filepath.Join(outDir, "rsa_pss_receipt.dsr"),
		receiptID, algo, keyID, contentHash, content, issuedAt, sig)
}

func genECDSA(outDir string) error {
	const algo = "ecdsa-sha256"
	const keyID = "key_fixture_ecdsa_2026"
	const receiptID = "r_fixture_ecdsa_001"

	// Generate P-256 ECDSA key pair.
	// Method: ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("ecdsa.GenerateKey: %w", err)
	}

	content, contentHash, issuedAt := sharedReceiptFields(algo, keyID)

	payload, err := canonicalPayload(receiptID, algo, keyID, contentHash, issuedAt)
	if err != nil {
		return err
	}

	// Sign: ecdsa.SignASN1 produces DER-encoded signature (same as AWS KMS output).
	hashed := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hashed[:])
	if err != nil {
		return fmt.Errorf("ecdsa.SignASN1: %w", err)
	}

	if err := writePEMKey(filepath.Join(outDir, "ecdsa_key.pub"), &priv.PublicKey, keyID); err != nil {
		return err
	}
	return writeReceiptJSON(filepath.Join(outDir, "ecdsa_receipt.dsr"),
		receiptID, algo, keyID, contentHash, content, issuedAt, sig)
}
