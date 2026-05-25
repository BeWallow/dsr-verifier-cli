package dsr

import (
	"encoding/json"
	"fmt"
)

// CanonicalContent returns the canonical byte representation of a receipt's
// content field. This is the input to SHA-256 when computing content_hash,
// and the input to ed25519 when constructing the signed payload.
//
// Canonical form: the content object re-serialized with lexicographically
// sorted keys at every level, compact (no extra whitespace). Go's
// encoding/json marshals map keys in sorted order as of Go 1.12, so
// unmarshaling to interface{} and re-marshaling produces the canonical form.
//
// This definition must match the canonical serialization used by the Déjà
// signing infrastructure. Both sides sort object keys lexicographically and
// produce compact JSON with no trailing newline.
func CanonicalContent(content json.RawMessage) ([]byte, error) {
	if len(content) == 0 {
		return nil, fmt.Errorf("content is empty")
	}
	var v interface{}
	if err := json.Unmarshal(content, &v); err != nil {
		return nil, fmt.Errorf("content is not valid JSON: %w", err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to re-serialize content: %w", err)
	}
	return b, nil
}

// CanonicalSignedPayload returns the bytes that are covered by the ed25519
// signature. The signed payload binds together the receipt's identity fields
// and its content_hash, so that any modification to id, version, type,
// vault_id, issued_at, or content causes signature verification to fail.
//
// Construction: sorted-key JSON of the six covered fields, compact.
//
// Covered fields (JSON keys in sort order):
//
//	content_hash, id, issued_at, signing_algorithm, signing_key_id, type,
//	vault_id, version
//
// issued_at is serialized as an RFC3339 UTC timestamp ("Z" suffix).
func CanonicalSignedPayload(r *Receipt) ([]byte, error) {
	// Construct only the covered fields. Use a struct with explicit JSON tags
	// so the key names are stable regardless of field order in the source.
	payload := struct {
		ContentHash      string `json:"content_hash"`
		ID               string `json:"id"`
		IssuedAt         string `json:"issued_at"`
		SigningAlgorithm  string `json:"signing_algorithm"`
		SigningKeyID     string `json:"signing_key_id"`
		Type             string `json:"type"`
		VaultID          string `json:"vault_id"`
		Version          string `json:"version"`
	}{
		ContentHash:      r.ContentHash,
		ID:               r.ID,
		IssuedAt:         r.IssuedAt.UTC().Format("2006-01-02T15:04:05Z"),
		SigningAlgorithm:  r.SigningAlgorithm,
		SigningKeyID:     r.SigningKeyID,
		Type:             r.Type,
		VaultID:          r.VaultID,
		Version:          r.Version,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize signed payload: %w", err)
	}
	return b, nil
}
