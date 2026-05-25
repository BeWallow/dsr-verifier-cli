package bundle_test

// adversarial_test.go — bundle-level attack scenarios beyond the baseline
// tests in bundle_test.go.

import (
	"fmt"
	"testing"

	"github.com/deja-dev/dsr-verifier-cli/internal/bundle"
	"github.com/deja-dev/dsr-verifier-cli/internal/dsr"
	dsrerrors "github.com/deja-dev/dsr-verifier-cli/internal/errors"
)

// ─────────────────────────────────────────────────────────────────────────────
// Attack: one receipt in a bundle was swapped in from a different vault
//
// Scenario: an attacker modifies an evidence bundle by replacing one of the
// legitimate receipts with a receipt signed by a completely different vault's
// key.  The swapped receipt is cryptographically self-consistent (its own
// signature and content_hash are valid), but it was NOT signed by the key the
// auditor provided — so it fails the key_authority check.
//
// Caught by: KeyAuthority check on the swapped receipt (check #1 of per-receipt
// verification).  The bundle-level manifest signature also fails because the
// entries list was modified.
// ─────────────────────────────────────────────────────────────────────────────

func TestBundleReceiptFromWrongVault(t *testing.T) {
	// Legitimate vault key — what the auditor has.
	legitKey := newTestKey(t)
	// Foreign vault key — used to sign the swapped receipt.
	foreignKey := newTestKey(t)

	entries := make([]bundle.ManifestEntry, 3)
	receiptFiles := make(map[string][]byte, 3)

	for i := 0; i < 3; i++ {
		seq := i + 1
		id := fmt.Sprintf("r_%016x", uint64(seq))

		// Receipt at seq=2 is swapped in from the foreign vault.
		var sigKey *testKey
		if seq == 2 {
			sigKey = foreignKey
		} else {
			sigKey = legitKey
		}

		data := buildReceipt(t, sigKey, id, dsr.TypeR1, "vlt_test", r1Content())
		filename := fmt.Sprintf("receipts/%05d_%s.dsr", seq, id)
		receiptFiles[filename] = data

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

	// The attacker re-signs the bundle manifest with the legit key to conceal
	// the swap.  In a realistic attack they cannot do this, but we build the
	// bundle with the legit key here to test that per-receipt key authority
	// is checked independently of the manifest signature.
	zipData := buildBundleZIP(t, legitKey, entries, receiptFiles)
	b, verr := bundle.ParseBundleFromBytes(zipData)
	if verr != nil {
		t.Fatalf("ParseBundleFromBytes: %v", verr)
	}

	res := bundle.VerifyBundle(b, legitKey.PublicKeyWithID())

	// Exactly one receipt (the swapped one at seq=2) must fail.
	if res.PerReceipt.Passed != 2 {
		t.Errorf("Passed = %d, want 2 (only the swapped receipt should fail)", res.PerReceipt.Passed)
	}
	if res.PerReceipt.Failed == 0 {
		t.Fatal("expected at least one receipt to fail for the wrong-vault receipt")
	}

	// The failure list for the swapped receipt must contain key_authority_mismatch.
	// (VerifyPerReceipt runs all four checks; signature_invalid will also appear
	// because the wrong key cannot verify the signature.  We assert key authority
	// is present because that is the primary diagnostic — the auditor is told
	// "wrong key" before "bad signature".)
	found := false
	for _, f := range res.PerReceipt.Failures {
		for _, e := range f.Errors {
			if e.Class == dsrerrors.KeyAuthorityMismatch {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("key_authority_mismatch not found in failures; got: %v",
			func() []string {
				var classes []string
				for _, f := range res.PerReceipt.Failures {
					for _, e := range f.Errors {
						classes = append(classes, string(e.Class))
					}
				}
				return classes
			}())
	}

	// AllPassed must be false.
	if res.AllPassed() {
		t.Error("AllPassed: want false — swapped receipt must fail")
	}
}
