package bundle

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/deja-dev/dsr-verifier-cli/internal/dsr"
	dsrerrors "github.com/deja-dev/dsr-verifier-cli/internal/errors"
	"github.com/deja-dev/dsr-verifier-cli/internal/verify"
)

// ─────────────────────────────────────────────────────────────────────────────
// Result types
// ─────────────────────────────────────────────────────────────────────────────

// BundleVerifyResult aggregates the results of all bundle-level checks.
type BundleVerifyResult struct {
	BundleID    string
	VaultID     string
	PeriodStart string
	PeriodEnd   string
	Frameworks  []string
	IssuerKeyID string

	ManifestSig   ManifestSigResult
	SequenceInteg SeqIntegResult
	PerReceipt    PerReceiptResult
	CausalChain   CausalChainResult
	RVCoverage    RVCoverageResult

	DurationMS int64
	ReportFile string
}

// AllPassed reports whether all bundle-level checks passed.
func (r *BundleVerifyResult) AllPassed() bool {
	return r.ManifestSig.Valid &&
		r.SequenceInteg.Valid &&
		r.PerReceipt.Failed == 0 &&
		r.CausalChain.Valid
}

// Tampered returns the count of receipts with signature or content-hash failures.
func (r *BundleVerifyResult) Tampered() int {
	count := 0
	for _, f := range r.PerReceipt.Failures {
		for _, e := range f.Errors {
			if e.Class == dsrerrors.SignatureInvalid || e.Class == dsrerrors.ContentHashMismatch {
				count++
				break
			}
		}
	}
	return count
}

// Missing returns the count of receipts declared in the manifest but absent
// from the archive or unparseable.
func (r *BundleVerifyResult) Missing() int {
	count := 0
	for _, f := range r.PerReceipt.Failures {
		for _, e := range f.Errors {
			if e.Class == dsrerrors.MalformedReceipt {
				count++
				break
			}
		}
	}
	return count
}

// ManifestSigResult is returned by VerifyManifestSignature.
type ManifestSigResult struct {
	Valid   bool
	KeyID   string
	Err     *dsrerrors.VerificationError
}

// SeqIntegResult is returned by VerifySequenceIntegrity.
type SeqIntegResult struct {
	Valid  bool
	MinSeq int
	MaxSeq int
	Count  int
	Gaps   []int // seq numbers that are missing
	Err    *dsrerrors.VerificationError
}

// PerReceiptResult aggregates per-receipt verification across the bundle.
type PerReceiptResult struct {
	Total    int
	Passed   int
	Failed   int
	ByType   map[string]*TypeResult
	Failures []ReceiptFailure
}

// TypeResult counts passed/failed within one receipt type.
type TypeResult struct {
	Total  int
	Passed int
	Failed int
}

// ReceiptFailure holds the failure details for one receipt.
type ReceiptFailure struct {
	Seq       int
	ReceiptID string
	Type      string
	Errors    []*dsrerrors.VerificationError
}

// CausalChainResult is returned by VerifyCausalChain.
type CausalChainResult struct {
	Valid         bool
	Total         int // cross-bundle references found
	Resolved      int // references resolved within this bundle
	Unresolvable  []string // IDs referenced but not in bundle (not a failure — may be out-of-scope)
	Err           *dsrerrors.VerificationError
}

// RVCoverageResult summarises the RV receipt coverage.
type RVCoverageResult struct {
	TotalRV      int
	TotalRVi     int
	TotalRVf     int
	DaysCovered  int
	Streak       int // longest contiguous daily streak
	TotalAnomalies int
}

// ─────────────────────────────────────────────────────────────────────────────
// VerifyBundle runs all four bundle checks and returns the aggregate result.
// ─────────────────────────────────────────────────────────────────────────────

func VerifyBundle(b *Bundle, provided *verify.PublicKeyWithID) *BundleVerifyResult {
	res := &BundleVerifyResult{
		BundleID:    b.Manifest.BundleID,
		VaultID:     b.Manifest.VaultID,
		PeriodStart: b.Manifest.PeriodStart,
		PeriodEnd:   b.Manifest.PeriodEnd,
		Frameworks:  b.Manifest.Frameworks,
		IssuerKeyID: b.Manifest.IssuerKeyID,
	}

	// Bundles are ed25519-only in v1; extract the ed25519 key for manifest verification.
	ed25519Key, ok := provided.Key.(ed25519.PublicKey)
	if !ok {
		res.ManifestSig = ManifestSigResult{
			Valid: false,
			KeyID: b.Manifest.IssuerKeyID,
			Err: dsrerrors.New(
				dsrerrors.SignatureInvalid,
				"Bundle manifests require an ed25519 public key. "+
					"BYOK (RSA/ECDSA) keys are not supported for bundle manifest verification.",
				fmt.Sprintf("key type: %T, expected: ed25519.PublicKey", provided.Key),
			),
		}
	} else {
		res.ManifestSig = VerifyManifestSignature(b.Manifest, ed25519Key)
	}
	res.SequenceInteg = VerifySequenceIntegrity(b.Manifest)
	res.PerReceipt = VerifyPerReceipt(b.Receipts, provided)
	res.CausalChain = VerifyCausalChain(b.Receipts)
	res.RVCoverage = AnalyseRVCoverage(b.Receipts)

	return res
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Manifest signature verification
// ─────────────────────────────────────────────────────────────────────────────

func VerifyManifestSignature(m *Manifest, pubKey ed25519.PublicKey) ManifestSigResult {
	res := ManifestSigResult{KeyID: m.IssuerKeyID}

	payload, err := CanonicalManifestPayload(m)
	if err != nil {
		res.Valid = false
		res.Err = dsrerrors.New(
			dsrerrors.SignatureInvalid,
			"The verifier could not construct the canonical manifest payload. "+
				"The manifest may have malformed fields.",
			fmt.Sprintf("CanonicalManifestPayload error: %s", err.Error()),
		)
		return res
	}

	if !ed25519.Verify(pubKey, payload, m.Signature) {
		res.Valid = false
		res.Err = dsrerrors.New(
			dsrerrors.SignatureInvalid,
			fmt.Sprintf(
				"The bundle manifest's ed25519 signature does not verify against key %q. "+
					"This means either: (1) the bundle was not signed by this key, "+
					"(2) the manifest fields or receipt list were modified after signing, or "+
					"(3) the signature is corrupt. "+
					"Do not treat this bundle as evidence without resolving this failure.",
				m.IssuerKeyID,
			),
			fmt.Sprintf("ed25519.Verify returned false for manifest; key_id=%s", m.IssuerKeyID),
		)
		return res
	}

	res.Valid = true
	return res
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Sequence integrity
// ─────────────────────────────────────────────────────────────────────────────

func VerifySequenceIntegrity(m *Manifest) SeqIntegResult {
	if len(m.Entries) == 0 {
		return SeqIntegResult{Valid: true}
	}

	// Build a set of observed seq numbers.
	seqSet := make(map[int]bool, len(m.Entries))
	minSeq, maxSeq := m.Entries[0].Seq, m.Entries[0].Seq
	for _, e := range m.Entries {
		seqSet[e.Seq] = true
		if e.Seq < minSeq {
			minSeq = e.Seq
		}
		if e.Seq > maxSeq {
			maxSeq = e.Seq
		}
	}

	// Check for gaps in [minSeq, maxSeq].
	var gaps []int
	for s := minSeq; s <= maxSeq; s++ {
		if !seqSet[s] {
			gaps = append(gaps, s)
		}
	}

	// Also check consistency with declared seq_range.
	declaredMin := m.SeqRange.Min
	declaredMax := m.SeqRange.Max
	if declaredMin != 0 && declaredMin != minSeq {
		gaps = append(gaps, -1) // sentinel for declared-vs-actual mismatch
	}
	_ = declaredMax

	res := SeqIntegResult{
		MinSeq: minSeq,
		MaxSeq: maxSeq,
		Count:  len(m.Entries),
		Gaps:   gaps,
	}

	if len(gaps) > 0 {
		res.Valid = false
		gapDisplay := gaps
		if len(gapDisplay) > 5 {
			gapDisplay = gapDisplay[:5]
		}
		res.Err = dsrerrors.New(
			dsrerrors.MalformedReceipt,
			fmt.Sprintf(
				"The bundle has %d missing sequence number(s) in the range %d–%d. "+
					"This may indicate that receipts were removed from the bundle after it was assembled, "+
					"which would also cause the manifest signature to fail. "+
					"A complete bundle must include every receipt in its declared sequence range.",
				len(gaps), minSeq, maxSeq,
			),
			fmt.Sprintf("missing seq numbers (first 5): %v", gapDisplay),
		)
	} else {
		res.Valid = true
	}

	return res
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Per-receipt verification
// ─────────────────────────────────────────────────────────────────────────────

func VerifyPerReceipt(receipts []*ParsedReceipt, provided *verify.PublicKeyWithID) PerReceiptResult {
	res := PerReceiptResult{
		Total:  len(receipts),
		ByType: make(map[string]*TypeResult),
	}

	for _, pr := range receipts {
		// Ensure type bucket exists.
		typ := pr.Entry.Type
		if typ == "" && pr.Receipt != nil {
			typ = pr.Receipt.Type
		}
		if _, ok := res.ByType[typ]; !ok {
			res.ByType[typ] = &TypeResult{}
		}
		res.ByType[typ].Total++

		// If parsing failed, count as failed and continue.
		if pr.ParseErr != nil {
			res.ByType[typ].Failed++
			res.Failed++
			res.Failures = append(res.Failures, ReceiptFailure{
				Seq:       pr.Entry.Seq,
				ReceiptID: pr.Entry.ReceiptID,
				Type:      typ,
				Errors:    []*dsrerrors.VerificationError{pr.ParseErr},
			})
			continue
		}

		// Run the four checks.
		authRes := verify.KeyAuthority(pr.Receipt, provided)
		sigRes := verify.Signature(pr.Receipt, provided)
		hashRes := verify.ContentHash(pr.Receipt)
		causalRes := verify.CausalRefs(pr.Receipt)

		var errs []*dsrerrors.VerificationError
		if authRes.Err != nil {
			errs = append(errs, authRes.Err)
		}
		if sigRes.Err != nil {
			errs = append(errs, sigRes.Err)
		}
		if hashRes.Err != nil {
			errs = append(errs, hashRes.Err)
		}
		if causalRes.Err != nil {
			errs = append(errs, causalRes.Err)
		}

		if len(errs) > 0 {
			res.ByType[typ].Failed++
			res.Failed++
			res.Failures = append(res.Failures, ReceiptFailure{
				Seq:       pr.Entry.Seq,
				ReceiptID: pr.Receipt.ID,
				Type:      typ,
				Errors:    errs,
			})
		} else {
			res.ByType[typ].Passed++
			res.Passed++
		}
	}

	return res
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Causal chain consistency
// ─────────────────────────────────────────────────────────────────────────────

// receiptParentRef is used to extract an optional parent_receipt_id from content.
type receiptParentRef struct {
	ParentReceiptID string `json:"parent_receipt_id"`
}

func VerifyCausalChain(receipts []*ParsedReceipt) CausalChainResult {
	// Build an index of receipt IDs in this bundle.
	bundleIDs := make(map[string]bool, len(receipts))
	for _, pr := range receipts {
		if pr.Receipt != nil {
			bundleIDs[pr.Receipt.ID] = true
		}
	}

	res := CausalChainResult{Valid: true}

	for _, pr := range receipts {
		if pr.Receipt == nil {
			continue
		}
		// Only R1, R1-L, R1-N carry parent references.
		switch pr.Receipt.Type {
		case dsr.TypeR1, dsr.TypeR1L, dsr.TypeR1N:
		default:
			continue
		}

		var ref receiptParentRef
		if err := json.Unmarshal(pr.Receipt.Content, &ref); err != nil {
			continue // content may not have the field; that's fine
		}
		if ref.ParentReceiptID == "" {
			continue
		}

		res.Total++
		if bundleIDs[ref.ParentReceiptID] {
			res.Resolved++
		} else {
			// Parent not in bundle — this is allowed (partial bundles may
			// legitimately reference receipts outside their scope).
			res.Unresolvable = append(res.Unresolvable, ref.ParentReceiptID)
		}
	}

	// A causal chain failure only occurs if a resolved reference is
	// inconsistent — i.e., the parent exists in the bundle but its
	// type is incompatible. For v1 we just count and report.
	// (In-bundle inconsistency detection is a v2 concern.)

	return res
}

// ─────────────────────────────────────────────────────────────────────────────
// RV coverage analysis
// ─────────────────────────────────────────────────────────────────────────────

// rvContent is used to extract interval fields from RV receipt content.
type rvContent struct {
	IntervalStart string `json:"interval_start"`
	IntervalEnd   string `json:"interval_end"`
	Anomalies     int    `json:"anomalies"`
	ScanAt        string `json:"scan_at"`
}

// AnalyseRVCoverage counts RV receipts and computes coverage statistics.
func AnalyseRVCoverage(receipts []*ParsedReceipt) RVCoverageResult {
	var res RVCoverageResult
	daySet := make(map[string]bool)

	for _, pr := range receipts {
		if pr.Receipt == nil {
			continue
		}
		switch pr.Receipt.Type {
		case dsr.TypeRV, dsr.TypeRVi, dsr.TypeRVf:
		default:
			continue
		}

		res.TotalRV++
		switch pr.Receipt.Type {
		case dsr.TypeRVi:
			res.TotalRVi++
		case dsr.TypeRVf:
			res.TotalRVf++
		}

		var c rvContent
		if err := json.Unmarshal(pr.Receipt.Content, &c); err != nil {
			continue
		}
		res.TotalAnomalies += c.Anomalies

		ts := c.IntervalStart
		if ts == "" {
			ts = c.ScanAt
		}
		if ts != "" {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				day := t.UTC().Format("2006-01-02")
				daySet[day] = true
			}
		}
	}

	res.DaysCovered = len(daySet)

	// Compute the longest contiguous streak.
	if len(daySet) > 0 {
		days := make([]string, 0, len(daySet))
		for d := range daySet {
			days = append(days, d)
		}
		sort.Strings(days)
		streak, best := 1, 1
		for i := 1; i < len(days); i++ {
			t0, _ := time.Parse("2006-01-02", days[i-1])
			t1, _ := time.Parse("2006-01-02", days[i])
			if t1.Sub(t0) == 24*time.Hour {
				streak++
			} else {
				streak = 1
			}
			if streak > best {
				best = streak
			}
		}
		res.Streak = best
	}

	return res
}
