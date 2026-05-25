// Package bundle parses and verifies DSR evidence bundles (.dsr.bundle files).
//
// A .dsr.bundle file is a ZIP archive containing:
//
//	manifest.json              signed by the vault's ed25519 key
//	receipts/NNNNN_<id>.dsr   individual DSR receipts (zero-padded seq prefix)
//
// The manifest signature covers a canonical payload that includes a hash of
// the receipts list, binding the complete set of receipts to the signature.
// Any receipt added, removed, or reordered breaks the manifest signature.
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/deja-dev/dsr-verifier-cli/internal/dsr"
)

// BundleFormat is the only manifest format version this verifier accepts.
const BundleFormat = "DSR-BUNDLE/1.0"

// Manifest is the parsed, validated content of manifest.json in a bundle.
type Manifest struct {
	Format       string          `json:"format"`
	BundleID     string          `json:"bundle_id"`
	VaultID      string          `json:"vault_id"`
	IssuedAt     time.Time       `json:"issued_at"`
	PeriodStart  string          `json:"period_start"`
	PeriodEnd    string          `json:"period_end"`
	Frameworks   []string        `json:"frameworks"`
	IssuerKeyID  string          `json:"issuer_key_id"`
	Entries      []ManifestEntry `json:"receipts"`
	ReceiptCount int             `json:"receipt_count"`
	SeqRange     SeqRange        `json:"seq_range"`
	Signature    dsr.HexBytes    `json:"signature"`
}

// ManifestEntry describes one receipt in the bundle.
type ManifestEntry struct {
	Seq         int    `json:"seq"`
	ReceiptID   string `json:"receipt_id"`
	Type        string `json:"type"`
	Filename    string `json:"filename"`     // path within ZIP, e.g. "receipts/00001_r_xxx.dsr"
	ContentHash string `json:"content_hash"` // must match the receipt's own content_hash field
}

// SeqRange is the inclusive [min, max] sequence range declared in the manifest.
type SeqRange struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// CanonicalManifestPayload constructs the canonical bytes covered by the
// manifest's ed25519 signature.
//
// The payload is the sorted-key JSON of nine covered fields. The
// receipts_hash field is SHA-256 of the canonical JSON of the entries
// array, binding the complete receipt list to the signature without
// including potentially large arrays directly.
func CanonicalManifestPayload(m *Manifest) ([]byte, error) {
	// Canonical receipts hash: sha256(json.Marshal(entries)).
	// json.Marshal on a slice preserves order, which is intentional:
	// the order of receipts in the manifest is part of the signed content.
	entriesBytes, err := json.Marshal(m.Entries)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest entries: %w", err)
	}
	sum := sha256.Sum256(entriesBytes)
	receiptsHash := hex.EncodeToString(sum[:])

	// Sort frameworks so the payload is deterministic regardless of the order
	// they appear in the manifest.
	frameworks := make([]string, len(m.Frameworks))
	copy(frameworks, m.Frameworks)
	sort.Strings(frameworks)

	payload := struct {
		BundleID     string   `json:"bundle_id"`
		Format       string   `json:"format"`
		Frameworks   []string `json:"frameworks"`
		IssuedAt     string   `json:"issued_at"`
		IssuerKeyID  string   `json:"issuer_key_id"`
		PeriodEnd    string   `json:"period_end"`
		PeriodStart  string   `json:"period_start"`
		ReceiptCount int      `json:"receipt_count"`
		ReceiptsHash string   `json:"receipts_hash"`
		VaultID      string   `json:"vault_id"`
	}{
		BundleID:     m.BundleID,
		Format:       m.Format,
		Frameworks:   frameworks,
		IssuedAt:     m.IssuedAt.UTC().Format("2006-01-02T15:04:05Z"),
		IssuerKeyID:  m.IssuerKeyID,
		PeriodEnd:    m.PeriodEnd,
		PeriodStart:  m.PeriodStart,
		ReceiptCount: m.ReceiptCount,
		ReceiptsHash: receiptsHash,
		VaultID:      m.VaultID,
	}
	return json.Marshal(payload)
}
