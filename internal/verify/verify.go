// Package verify implements the four independent verification checks for a
// DSR/1.0.1 receipt. Each function is stateless and pure: given the same
// inputs they produce the same output, with no side effects.
//
// Verification order mandated by the spec (key authority before signature):
//
//  1. KeyAuthority   — wrong key file is caught before we waste time on crypto
//  2. Signature      — ed25519 signature over the canonical signed payload
//  3. ContentHash    — SHA-256 of canonical content vs. content_hash field
//  4. CausalRefs     — structural validation of PR/commit identifiers
//
// Each function returns a result struct containing a boolean Valid flag plus
// all diagnostic fields. Failures are represented as *dsrerrors.VerificationError
// values so callers can access both the typed class and the human message.
package verify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"

	"github.com/deja-dev/dsr-verifier-cli/internal/dsr"
	dsrerrors "github.com/deja-dev/dsr-verifier-cli/internal/errors"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1. Key authority check
// ─────────────────────────────────────────────────────────────────────────────

// KeyAuthorityResult is returned by KeyAuthority.
type KeyAuthorityResult struct {
	Valid          bool
	ClaimedKeyID   string
	ProvidedKeyID  string
	Err            *dsrerrors.VerificationError
}

// KeyAuthority compares the receipt's signing_key_id field against the key_id
// extracted from the provided public key file. A mismatch means the auditor
// is holding the wrong key for this receipt — the signature check would fail
// with a confusing message, so we surface the root cause first.
//
// A receipt with an empty provided key ID (the key file has no # key_id:
// comment) passes this check; the caller is responsible for out-of-band key
// confirmation in that case.
func KeyAuthority(r *dsr.Receipt, provided *PublicKeyWithID) *KeyAuthorityResult {
	res := &KeyAuthorityResult{
		ClaimedKeyID:  r.SigningKeyID,
		ProvidedKeyID: provided.KeyID,
	}

	if provided.KeyID != "" && r.SigningKeyID != provided.KeyID {
		res.Valid = false
		res.Err = dsrerrors.New(
			dsrerrors.KeyAuthorityMismatch,
			fmt.Sprintf(
				"The receipt claims it was signed by key %q, but the public key file identifies as %q. "+
					"You are likely using the wrong public key for this receipt. "+
					"Request the correct public key from the customer who issued this receipt.",
				r.SigningKeyID, provided.KeyID,
			),
			fmt.Sprintf(
				"receipt.signing_key_id=%q, key_file.key_id=%q",
				r.SigningKeyID, provided.KeyID,
			),
		)
		return res
	}

	res.Valid = true
	return res
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Signature verification
// ─────────────────────────────────────────────────────────────────────────────

// SignatureResult is returned by Signature.
type SignatureResult struct {
	Valid           bool
	Algorithm       string
	KeyID           string
	PublicKeyDigest string // sha256:<hex prefix> of the public key bytes
	SignatureHex    string // first 8 and last 8 hex chars of the 64-byte sig
	Err             *dsrerrors.VerificationError
}

// Signature verifies the ed25519 signature on r using the provided public key.
//
// The signed payload is the canonical representation of the receipt's envelope
// fields (id, version, type, vault_id, issued_at, content_hash, signing_key_id,
// signing_algorithm) — see dsr.CanonicalSignedPayload for the exact construction.
// This binds all identity fields and the content hash to the signature, so that
// any modification to any of those fields is detected here.
func Signature(r *dsr.Receipt, provided *PublicKeyWithID) *SignatureResult {
	pubKey := provided.Key

	// Compute the public key's fingerprint for the output (not for security).
	sum := sha256.Sum256(pubKey)
	keyDigest := fmt.Sprintf("sha256:%s", hex.EncodeToString(sum[:])[:16])

	sigHex := hex.EncodeToString(r.Signature)
	sigDisplay := sigHex[:8] + "..." + sigHex[len(sigHex)-8:]

	res := &SignatureResult{
		Algorithm:       dsr.SigningAlgorithmED25519,
		KeyID:           r.SigningKeyID,
		PublicKeyDigest: keyDigest,
		SignatureHex:    sigDisplay,
	}

	payload, err := dsr.CanonicalSignedPayload(r)
	if err != nil {
		res.Valid = false
		res.Err = dsrerrors.New(
			dsrerrors.SignatureInvalid,
			"The verifier could not construct the canonical signed payload for this receipt. "+
				"The receipt may have malformed envelope fields.",
			fmt.Sprintf("CanonicalSignedPayload error: %s", err.Error()),
		)
		return res
	}

	if !ed25519.Verify(pubKey, payload, r.Signature) {
		res.Valid = false
		res.Err = dsrerrors.New(
			dsrerrors.SignatureInvalid,
			fmt.Sprintf(
				"The ed25519 signature on this receipt does not verify against key %q. "+
					"This means either: (1) the receipt was not signed by this key, "+
					"(2) the receipt's envelope fields (id, version, type, vault_id, "+
					"issued_at, content_hash) were modified after signing, or "+
					"(3) the signature bytes are corrupt. "+
					"Do not treat this receipt as evidence without resolving this failure.",
				r.SigningKeyID,
			),
			fmt.Sprintf(
				"ed25519.Verify returned false; algorithm=%s, key_id=%s, payload_len=%d",
				dsr.SigningAlgorithmED25519, r.SigningKeyID, len(payload),
			),
		)
		return res
	}

	res.Valid = true
	return res
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Content hash verification
// ─────────────────────────────────────────────────────────────────────────────

// ContentHashResult is returned by ContentHash.
type ContentHashResult struct {
	Valid        bool
	Algorithm    string
	ComputedHash string
	StoredHash   string
	Err          *dsrerrors.VerificationError
}

// ContentHash recomputes the SHA-256 of the canonical content bytes and
// compares the result to the receipt's content_hash field using a
// constant-time comparison.
//
// A mismatch with a valid signature (check #2 passed) means the content was
// modified after the receipt was signed — the signature covered the original
// content_hash, not the current content.
func ContentHash(r *dsr.Receipt) *ContentHashResult {
	res := &ContentHashResult{
		Algorithm:  "sha256",
		StoredHash: r.ContentHash,
	}

	canonical, err := dsr.CanonicalContent(r.Content)
	if err != nil {
		res.Valid = false
		res.Err = dsrerrors.New(
			dsrerrors.ContentHashMismatch,
			"The receipt's content field could not be canonicalized for hash verification. "+
				"The content field may contain invalid JSON.",
			fmt.Sprintf("CanonicalContent error: %s", err.Error()),
		)
		return res
	}

	sum := sha256.Sum256(canonical)
	computed := hex.EncodeToString(sum[:])
	res.ComputedHash = computed

	storedBytes, decErr := hex.DecodeString(r.ContentHash)
	if decErr != nil {
		res.Valid = false
		res.Err = dsrerrors.New(
			dsrerrors.ContentHashMismatch,
			"The receipt's content_hash field is not a valid hex string and cannot be compared. "+
				"The field may be corrupt.",
			fmt.Sprintf("hex.DecodeString error: %s", decErr.Error()),
		)
		return res
	}

	computedBytes := sum[:]
	// constant-time comparison to prevent timing side-channels.
	if subtle.ConstantTimeCompare(computedBytes, storedBytes) != 1 {
		res.Valid = false
		res.Err = dsrerrors.New(
			dsrerrors.ContentHashMismatch,
			"The hash of the receipt's current content does not match the content_hash field "+
				"that was included in the signed payload. "+
				"This means the content of the receipt was modified after the receipt was signed. "+
				"The signature may still be valid for the original content — if so, the receipt was "+
				"authentic at issuance but has been tampered with since. "+
				"Do not accept this receipt as audit evidence in its current form.",
			fmt.Sprintf(
				"algorithm=sha256, computed=%s, stored=%s",
				computed, r.ContentHash,
			),
		)
		return res
	}

	res.Valid = true
	return res
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Causal artifact structural validation
// ─────────────────────────────────────────────────────────────────────────────

// CausalRefsResult is returned by CausalRefs.
type CausalRefsResult struct {
	Valid           bool
	MalformedFields []string
	PRURL           string
	CommitSHA       string
	MergedAt        string
	Err             *dsrerrors.VerificationError
}

// prURLPattern matches GitHub PR URLs in the forms:
//   - github.com/org/repo#1234
//   - https://github.com/org/repo#1234
//   - http://github.com/org/repo#1234
var prURLPattern = regexp.MustCompile(
	`^(https?://)?github\.com/[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+#[0-9]+$`,
)

// commitSHAPattern matches abbreviated or full git commit SHAs (7–64 hex chars).
var commitSHAPattern = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

// CausalRefs validates the structural integrity of causal artifact references
// in R1, R1-L, and R1-N receipts. For other receipt types the result is always
// Valid=true with a note that no causal refs are expected.
//
// This check is STRUCTURAL ONLY — no network calls are made, and no attempt
// is made to fetch or verify the referenced PR or commit.
func CausalRefs(r *dsr.Receipt) *CausalRefsResult {
	res := &CausalRefsResult{Valid: true}

	switch r.Type {
	case dsr.TypeR1, dsr.TypeR1L, dsr.TypeR1N:
		// fall through to validation below
	default:
		// R2, RV, RV-i, RV-f do not carry causal PR/commit references.
		return res
	}

	var content dsr.R1Content
	if err := jsonUnmarshal(r.Content, &content); err != nil {
		res.Valid = false
		res.MalformedFields = []string{"content"}
		res.Err = dsrerrors.New(
			dsrerrors.MalformedCausalRef,
			"The receipt's content field could not be parsed as an R1 content object. "+
				"Fields pr_url, commit_sha, and merged_at could not be extracted for validation.",
			fmt.Sprintf("json.Unmarshal error: %s", err.Error()),
		)
		return res
	}

	res.PRURL = content.PRURL
	res.CommitSHA = content.CommitSHA
	res.MergedAt = content.MergedAt

	var malformed []string

	if content.PRURL == "" {
		malformed = append(malformed, "pr_url (missing)")
	} else if !prURLPattern.MatchString(content.PRURL) {
		malformed = append(malformed, fmt.Sprintf(
			"pr_url (value %q does not match expected GitHub PR URL format, e.g. github.com/org/repo#1234)",
			content.PRURL,
		))
	}

	if content.CommitSHA == "" {
		malformed = append(malformed, "commit_sha (missing)")
	} else if !commitSHAPattern.MatchString(content.CommitSHA) {
		malformed = append(malformed, fmt.Sprintf(
			"commit_sha (value %q is not a valid git SHA: must be 7–64 hexadecimal characters)",
			content.CommitSHA,
		))
	}

	if content.MergedAt != "" {
		if _, err := time.Parse(time.RFC3339, content.MergedAt); err != nil {
			malformed = append(malformed, fmt.Sprintf(
				"merged_at (value %q is not a valid RFC3339 timestamp)",
				content.MergedAt,
			))
		}
	}

	if len(malformed) > 0 {
		res.Valid = false
		res.MalformedFields = malformed
		res.Err = dsrerrors.New(
			dsrerrors.MalformedCausalRef,
			fmt.Sprintf(
				"The receipt's causal artifact references contain %d malformed field(s). "+
					"Note: this check validates format only — no network calls were made to verify "+
					"the referenced PR or commit actually exists.",
				len(malformed),
			),
			fmt.Sprintf("malformed fields: %v", malformed),
		)
	}

	return res
}

// jsonUnmarshal is a package-local alias to avoid a direct encoding/json import
// conflict with the json used in dsr. It's identical to json.Unmarshal.
func jsonUnmarshal(data []byte, v interface{}) error {
	return unmarshal(data, v)
}
