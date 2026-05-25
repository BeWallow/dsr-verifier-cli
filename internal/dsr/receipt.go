// Package dsr parses DSR/1.0.1 receipts.
//
// The canonical receipt format is a JSON object with the following top-level
// fields. Strict parsing is enforced: unknown fields are rejected and all
// required fields must be present.
package dsr

import (
	"encoding/json"
	"time"
)

// Version is the only receipt format version this CLI supports.
const Version = "DSR/1.0.1"

// Valid receipt types in DSR/1.0.1.
const (
	TypeR1   = "R1"   // Attribution
	TypeR1L  = "R1-L" // Low Confidence
	TypeR1N  = "R1-N" // No Match
	TypeR2   = "R2"   // Resolution
	TypeRV   = "RV"   // Vault Verification (continuous integrity)
	TypeRVi  = "RV-i" // Vault Verification (interval start)
	TypeRVf  = "RV-f" // Vault Verification (interval end)
)

// validTypes is the complete set of accepted receipt type values.
var validTypes = map[string]bool{
	TypeR1:  true,
	TypeR1L: true,
	TypeR1N: true,
	TypeR2:  true,
	TypeRV:  true,
	TypeRVi: true,
	TypeRVf: true,
}

// ValidType reports whether t is a recognized DSR/1.0.1 receipt type.
func ValidType(t string) bool { return validTypes[t] }

// SigningAlgorithmED25519 is the only signing algorithm accepted by this verifier.
const SigningAlgorithmED25519 = "ed25519"

// Receipt is the parsed, validated representation of a DSR/1.0.1 receipt.
//
// The Signature field holds the raw 64-byte ed25519 signature decoded from
// the hex string stored in the JSON. The Content field is the raw JSON bytes
// of the receipt body, preserved verbatim for canonical hash computation.
type Receipt struct {
	ID               string          `json:"id"`
	Version          string          `json:"version"`
	Type             string          `json:"type"`
	VaultID          string          `json:"vault_id"`
	IssuedAt         time.Time       `json:"issued_at"`
	Content          json.RawMessage `json:"content"`
	ContentHash      string          `json:"content_hash"`
	SigningKeyID     string          `json:"signing_key_id"`
	SigningAlgorithm  string          `json:"signing_algorithm"`
	Signature        HexBytes        `json:"signature"`
}

// HexBytes is a []byte that marshals to/from a lowercase hex string in JSON.
type HexBytes []byte

// UnmarshalJSON decodes a JSON hex string into bytes.
func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	b, err := hexDecode(s)
	if err != nil {
		return err
	}
	*h = b
	return nil
}

// MarshalJSON encodes bytes as a lowercase hex string.
func (h HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hexEncode(h))
}

// R1Content is the parsed body of R1, R1-L, and R1-N receipts.
// These types carry causal artifact references that the verifier validates structurally.
type R1Content struct {
	PRURL     string `json:"pr_url"`
	CommitSHA string `json:"commit_sha"`
	MergedAt  string `json:"merged_at"`
}
