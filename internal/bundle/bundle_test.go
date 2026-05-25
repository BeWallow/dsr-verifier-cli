package bundle_test

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/deja-dev/dsr-verifier-cli/internal/bundle"
	"github.com/deja-dev/dsr-verifier-cli/internal/dsr"
	dsrerrors "github.com/deja-dev/dsr-verifier-cli/internal/errors"
	"github.com/deja-dev/dsr-verifier-cli/internal/verify"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

// testKey holds a generated key pair for use within a single test.
type testKey struct {
	Pub  ed25519.PublicKey
	Priv ed25519.PrivateKey
	ID   string
}

func newTestKey(t *testing.T) *testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sum := sha256.Sum256(pub)
	return &testKey{Pub: pub, Priv: priv, ID: "key_test_" + hex.EncodeToString(sum[:4])}
}

func (k *testKey) PublicKeyWithID() *verify.PublicKeyWithID {
	return &verify.PublicKeyWithID{Key: k.Pub, KeyID: k.ID}
}

// buildReceipt creates a valid, fully-signed DSR receipt JSON.
// content must be valid JSON. receiptType must be a valid DSR type.
func buildReceipt(t *testing.T, k *testKey, id, receiptType, vaultID string, content json.RawMessage) []byte {
	t.Helper()

	canonical, err := dsr.CanonicalContent(content)
	if err != nil {
		t.Fatalf("canonical content: %v", err)
	}
	sum := sha256.Sum256(canonical)
	contentHash := hex.EncodeToString(sum[:])

	issuedAt := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

	r := &dsr.Receipt{
		ID:               id,
		Version:          dsr.Version,
		Type:             receiptType,
		VaultID:          vaultID,
		IssuedAt:         issuedAt,
		Content:          content,
		ContentHash:      contentHash,
		SigningKeyID:     k.ID,
		SigningAlgorithm: dsr.SigningAlgorithmED25519,
	}

	payload, err := dsr.CanonicalSignedPayload(r)
	if err != nil {
		t.Fatalf("canonical signed payload: %v", err)
	}
	sig := ed25519.Sign(k.Priv, payload)
	r.Signature = dsr.HexBytes(sig)

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	return data
}

// r1Content returns a valid R1 content JSON.
func r1Content() json.RawMessage {
	return json.RawMessage(`{"pr_url":"https://github.com/acme/repo#1","commit_sha":"abc1234def5678","merged_at":"2026-01-15T09:00:00Z"}`)
}

// rvContent returns a valid RV content JSON.
func rvContentJSON(day int) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"interval_start":"2026-01-%02dT00:00:00Z","interval_end":"2026-01-%02dT23:59:59Z","anomalies":0,"scan_at":"2026-01-%02dT00:00:00Z"}`, day, day, day))
}

// buildBundleZIP assembles a ZIP archive containing manifest.json and receipt files.
// entries must correspond 1-1 with receiptFiles (keyed by Filename).
func buildBundleZIP(t *testing.T, k *testKey, entries []bundle.ManifestEntry, receiptFiles map[string][]byte) []byte {
	t.Helper()

	issuedAt := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)

	m := &bundle.Manifest{
		Format:       bundle.BundleFormat,
		BundleID:     "bndl_test_001",
		VaultID:      "vlt_test",
		IssuedAt:     issuedAt,
		PeriodStart:  "2026-01-01",
		PeriodEnd:    "2026-03-31",
		Frameworks:   []string{"SOC 2"},
		IssuerKeyID:  k.ID,
		Entries:      entries,
		ReceiptCount: len(entries),
		SeqRange: bundle.SeqRange{
			Min: entries[0].Seq,
			Max: entries[len(entries)-1].Seq,
		},
	}

	// Sign the manifest.
	payload, err := bundle.CanonicalManifestPayload(m)
	if err != nil {
		t.Fatalf("canonical manifest payload: %v", err)
	}
	sig := ed25519.Sign(k.Priv, payload)
	m.Signature = dsr.HexBytes(sig)

	manifestJSON, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	// Build ZIP.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	mf, err := zw.Create("manifest.json")
	if err != nil {
		t.Fatalf("zip create manifest.json: %v", err)
	}
	if _, err := mf.Write(manifestJSON); err != nil {
		t.Fatalf("zip write manifest.json: %v", err)
	}

	for name, data := range receiptFiles {
		rf, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := rf.Write(data); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// buildSimpleBundle builds a bundle with n R1 receipts.
func buildSimpleBundle(t *testing.T, k *testKey, n int) []byte {
	t.Helper()
	entries := make([]bundle.ManifestEntry, n)
	receiptFiles := make(map[string][]byte, n)

	for i := 0; i < n; i++ {
		seq := i + 1
		id := fmt.Sprintf("r_%016x", uint64(seq))
		data := buildReceipt(t, k, id, dsr.TypeR1, "vlt_test", r1Content())
		filename := fmt.Sprintf("receipts/%05d_%s.dsr", seq, id)
		receiptFiles[filename] = data

		// Parse just to get content_hash.
		r, verr := dsr.Parse(data)
		if verr != nil {
			t.Fatalf("parse receipt seq %d: %v", seq, verr)
		}

		entries[i] = bundle.ManifestEntry{
			Seq:         seq,
			ReceiptID:   id,
			Type:        dsr.TypeR1,
			Filename:    filename,
			ContentHash: r.ContentHash,
		}
	}
	return buildBundleZIP(t, k, entries, receiptFiles)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyValidBundle(t *testing.T) {
	k := newTestKey(t)
	data := buildSimpleBundle(t, k, 5)

	b, verr := bundle.ParseBundleFromBytes(data)
	if verr != nil {
		t.Fatalf("ParseBundleFromBytes: %v", verr)
	}
	if len(b.Receipts) != 5 {
		t.Fatalf("got %d receipts, want 5", len(b.Receipts))
	}

	res := bundle.VerifyBundle(b, k.PublicKeyWithID())

	if !res.ManifestSig.Valid {
		t.Errorf("ManifestSig: want valid, got error: %v", res.ManifestSig.Err)
	}
	if !res.SequenceInteg.Valid {
		t.Errorf("SequenceInteg: want valid, got error: %v", res.SequenceInteg.Err)
	}
	if res.PerReceipt.Failed != 0 {
		t.Errorf("PerReceipt.Failed: want 0, got %d", res.PerReceipt.Failed)
	}
	if res.PerReceipt.Passed != 5 {
		t.Errorf("PerReceipt.Passed: want 5, got %d", res.PerReceipt.Passed)
	}
	if !res.CausalChain.Valid {
		t.Errorf("CausalChain: want valid")
	}
	if !res.AllPassed() {
		t.Errorf("AllPassed: want true")
	}
}

func TestVerifyTamperedReceipt(t *testing.T) {
	k := newTestKey(t)

	// Build a 3-receipt bundle, then tamper with receipt 2's content.
	entries := make([]bundle.ManifestEntry, 3)
	receiptFiles := make(map[string][]byte, 3)

	for i := 0; i < 3; i++ {
		seq := i + 1
		id := fmt.Sprintf("r_%016x", uint64(seq))
		data := buildReceipt(t, k, id, dsr.TypeR1, "vlt_test", r1Content())
		filename := fmt.Sprintf("receipts/%05d_%s.dsr", seq, id)

		r, verr := dsr.Parse(data)
		if verr != nil {
			t.Fatalf("parse receipt: %v", verr)
		}

		// Tamper receipt 2: replace content with different JSON but keep original content_hash.
		// This makes the content hash check fail while signature may still appear valid.
		if seq == 2 {
			var rawMap map[string]interface{}
			if err := json.Unmarshal(data, &rawMap); err != nil {
				t.Fatalf("unmarshal for tampering: %v", err)
			}
			rawMap["content"] = map[string]interface{}{
				"pr_url":    "https://github.com/evil/repo#999",
				"commit_sha": "deadbeefdeadbeefdead",
				"merged_at": "2026-01-15T09:00:00Z",
			}
			tampered, err := json.Marshal(rawMap)
			if err != nil {
				t.Fatalf("marshal tampered: %v", err)
			}
			receiptFiles[filename] = tampered
		} else {
			receiptFiles[filename] = data
		}

		entries[i] = bundle.ManifestEntry{
			Seq:         seq,
			ReceiptID:   id,
			Type:        dsr.TypeR1,
			Filename:    filename,
			ContentHash: r.ContentHash,
		}
	}

	zipData := buildBundleZIP(t, k, entries, receiptFiles)
	b, verr := bundle.ParseBundleFromBytes(zipData)
	if verr != nil {
		t.Fatalf("ParseBundleFromBytes: %v", verr)
	}

	res := bundle.VerifyBundle(b, k.PublicKeyWithID())

	if res.PerReceipt.Failed == 0 {
		t.Error("PerReceipt.Failed: want > 0 for tampered receipt")
	}
	if res.Tampered() == 0 {
		t.Error("Tampered(): want > 0")
	}
	// Only receipt 2 should fail.
	if res.PerReceipt.Passed != 2 {
		t.Errorf("PerReceipt.Passed: want 2, got %d", res.PerReceipt.Passed)
	}

	// Confirm the failure class.
	found := false
	for _, f := range res.PerReceipt.Failures {
		for _, e := range f.Errors {
			if e.Class == dsrerrors.ContentHashMismatch {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected content_hash_mismatch in failures")
	}
}

func TestVerifySequenceGap(t *testing.T) {
	k := newTestKey(t)

	// Build entries for seqs 1, 2, 4 (gap at 3).
	seqs := []int{1, 2, 4}
	entries := make([]bundle.ManifestEntry, len(seqs))
	receiptFiles := make(map[string][]byte, len(seqs))

	for i, seq := range seqs {
		id := fmt.Sprintf("r_%016x", uint64(seq))
		data := buildReceipt(t, k, id, dsr.TypeR1, "vlt_test", r1Content())
		filename := fmt.Sprintf("receipts/%05d_%s.dsr", seq, id)
		receiptFiles[filename] = data

		r, verr := dsr.Parse(data)
		if verr != nil {
			t.Fatalf("parse receipt: %v", verr)
		}
		entries[i] = bundle.ManifestEntry{
			Seq:         seq,
			ReceiptID:   id,
			Type:        dsr.TypeR1,
			Filename:    filename,
			ContentHash: r.ContentHash,
		}
	}

	zipData := buildBundleZIP(t, k, entries, receiptFiles)
	b, verr := bundle.ParseBundleFromBytes(zipData)
	if verr != nil {
		t.Fatalf("ParseBundleFromBytes: %v", verr)
	}

	res := bundle.VerifyBundle(b, k.PublicKeyWithID())

	if res.SequenceInteg.Valid {
		t.Error("SequenceInteg.Valid: want false (gap at seq 3)")
	}
	if len(res.SequenceInteg.Gaps) == 0 {
		t.Error("SequenceInteg.Gaps: want non-empty")
	}
	// Gap should be at seq 3.
	found := false
	for _, g := range res.SequenceInteg.Gaps {
		if g == 3 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected gap at seq 3, got gaps: %v", res.SequenceInteg.Gaps)
	}
}

func TestVerifyBrokenManifestSignature(t *testing.T) {
	k := newTestKey(t)

	// Build a valid bundle, then flip one byte of the manifest signature.
	entries := make([]bundle.ManifestEntry, 2)
	receiptFiles := make(map[string][]byte, 2)
	for i := 0; i < 2; i++ {
		seq := i + 1
		id := fmt.Sprintf("r_%016x", uint64(seq))
		data := buildReceipt(t, k, id, dsr.TypeR1, "vlt_test", r1Content())
		filename := fmt.Sprintf("receipts/%05d_%s.dsr", seq, id)
		receiptFiles[filename] = data
		r, verr := dsr.Parse(data)
		if verr != nil {
			t.Fatalf("parse receipt: %v", verr)
		}
		entries[i] = bundle.ManifestEntry{
			Seq:         seq,
			ReceiptID:   id,
			Type:        dsr.TypeR1,
			Filename:    filename,
			ContentHash: r.ContentHash,
		}
	}

	issuedAt := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	m := &bundle.Manifest{
		Format:       bundle.BundleFormat,
		BundleID:     "bndl_broken_sig",
		VaultID:      "vlt_test",
		IssuedAt:     issuedAt,
		PeriodStart:  "2026-01-01",
		PeriodEnd:    "2026-03-31",
		Frameworks:   []string{"SOC 2"},
		IssuerKeyID:  k.ID,
		Entries:      entries,
		ReceiptCount: 2,
		SeqRange:     bundle.SeqRange{Min: 1, Max: 2},
	}
	payload, err := bundle.CanonicalManifestPayload(m)
	if err != nil {
		t.Fatalf("canonical manifest payload: %v", err)
	}
	sig := ed25519.Sign(k.Priv, payload)
	sig[0] ^= 0xFF // flip first byte
	m.Signature = dsr.HexBytes(sig)

	manifestJSON, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	mf, _ := zw.Create("manifest.json")
	mf.Write(manifestJSON)
	for name, data := range receiptFiles {
		rf, _ := zw.Create(name)
		rf.Write(data)
	}
	zw.Close()

	b, verr := bundle.ParseBundleFromBytes(buf.Bytes())
	if verr != nil {
		t.Fatalf("ParseBundleFromBytes: %v", verr)
	}

	res := bundle.VerifyBundle(b, k.PublicKeyWithID())

	if res.ManifestSig.Valid {
		t.Error("ManifestSig.Valid: want false (signature was flipped)")
	}
	if res.ManifestSig.Err == nil {
		t.Error("ManifestSig.Err: want non-nil")
	}
	if res.AllPassed() {
		t.Error("AllPassed: want false")
	}
}

func TestVerifyLargeBundle(t *testing.T) {
	// Product target: 10k receipts in <10s without -race; see perf_limit_*.go for CI (-race).
	const n = 10_000

	k := newTestKey(t)
	start := time.Now()

	data := buildSimpleBundle(t, k, n)

	b, verr := bundle.ParseBundleFromBytes(data)
	if verr != nil {
		t.Fatalf("ParseBundleFromBytes: %v", verr)
	}
	if len(b.Receipts) != n {
		t.Fatalf("expected %d receipts, got %d", n, len(b.Receipts))
	}

	res := bundle.VerifyBundle(b, k.PublicKeyWithID())

	elapsed := time.Since(start)
	t.Logf("10k bundle: parse+verify in %v (limit %v)", elapsed, bundlePerfLimit)

	if elapsed > bundlePerfLimit {
		t.Errorf("performance: 10k bundle took %v, want < %v", elapsed, bundlePerfLimit)
	}
	if !res.AllPassed() {
		t.Errorf("AllPassed: want true, PerReceipt.Failed=%d", res.PerReceipt.Failed)
	}
}
