package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/deja-dev/dsr-verifier-cli/internal/verify"
	dsrerrors "github.com/deja-dev/dsr-verifier-cli/internal/errors"
)

// JSONOutput is the top-level --json output document.
type JSONOutput struct {
	Version        string        `json:"version"`
	ReceiptID      string        `json:"receipt_id"`
	ReceiptType    string        `json:"receipt_type"`
	VaultID        string        `json:"vault_id"`
	Result         string        `json:"result"`
	Checks         JSONChecks    `json:"checks"`
	FailureReasons []JSONFailure `json:"failure_reasons"`
	DurationMS     int64         `json:"duration_ms"`
	Offline        bool          `json:"offline"`
}

// JSONChecks holds the per-check result summary.
type JSONChecks struct {
	KeyAuthority JSONCheckResult `json:"key_authority"`
	Signature    JSONCheckResult `json:"signature"`
	ContentHash  JSONCheckResult `json:"content_hash"`
	CausalRefs   JSONCheckResult `json:"causal_refs"`
}

// JSONCheckResult is the result of a single verification check.
type JSONCheckResult struct {
	Passed  bool            `json:"passed"`
	Details json.RawMessage `json:"details,omitempty"`
}

// JSONFailure is one entry in failure_reasons.
type JSONFailure struct {
	Check           string `json:"check"`
	ErrorClass      string `json:"error_class"`
	HumanMessage    string `json:"human_message"`
	TechnicalDetail string `json:"technical_detail"`
}

// WriteJSON emits the JSON output document to w.
func WriteJSON(w io.Writer, r *VerifyResults) error {
	out := buildJSONOutput(r)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func buildJSONOutput(r *VerifyResults) *JSONOutput {
	result := "verified"
	if !r.AllPassed() {
		result = "failed"
	}

	out := &JSONOutput{
		Version:     Version,
		ReceiptID:   r.ReceiptID,
		ReceiptType: r.ReceiptType,
		VaultID:     r.VaultID,
		Result:      result,
		DurationMS:  r.DurationMS,
		Offline:     true,
	}

	out.Checks.KeyAuthority = checkResult(r.KeyAuthority.Valid, keyAuthorityDetails(r.KeyAuthority))
	out.Checks.Signature = checkResult(r.Sig.Valid, signatureDetails(r.Sig))
	out.Checks.ContentHash = checkResult(r.Hash.Valid, contentHashDetails(r.Hash))
	out.Checks.CausalRefs = checkResult(r.Causal.Valid, causalRefsDetails(r.Causal))

	// Collect failure reasons in check order.
	for _, f := range []struct {
		name string
		err  *dsrerrors.VerificationError
	}{
		{"key_authority", r.KeyAuthority.Err},
		{"signature", r.Sig.Err},
		{"content_hash", r.Hash.Err},
		{"causal_refs", r.Causal.Err},
	} {
		if f.err != nil {
			out.FailureReasons = append(out.FailureReasons, JSONFailure{
				Check:           f.name,
				ErrorClass:      string(f.err.Class),
				HumanMessage:    f.err.HumanMessage,
				TechnicalDetail: f.err.TechnicalDetail,
			})
		}
	}
	if out.FailureReasons == nil {
		out.FailureReasons = []JSONFailure{}
	}

	return out
}

func checkResult(passed bool, details interface{}) JSONCheckResult {
	b, _ := json.Marshal(details)
	return JSONCheckResult{Passed: passed, Details: json.RawMessage(b)}
}

func keyAuthorityDetails(r *verify.KeyAuthorityResult) interface{} {
	return map[string]string{
		"claimed_key_id":  r.ClaimedKeyID,
		"provided_key_id": r.ProvidedKeyID,
	}
}

func signatureDetails(r *verify.SignatureResult) interface{} {
	return map[string]string{
		"algorithm":        r.Algorithm,
		"key_id":           r.KeyID,
		"public_key_sha256": r.PublicKeyDigest,
		"signature_hex":    r.SignatureHex,
	}
}

func contentHashDetails(r *verify.ContentHashResult) interface{} {
	return map[string]string{
		"algorithm": r.Algorithm,
		"computed":  r.ComputedHash,
		"stored":    r.StoredHash,
	}
}

func causalRefsDetails(r *verify.CausalRefsResult) interface{} {
	if r.PRURL == "" && r.CommitSHA == "" {
		return map[string]interface{}{
			"applicable": false,
			"note":       "receipt type does not carry causal references",
		}
	}
	d := map[string]interface{}{
		"pr_url":    r.PRURL,
		"commit_sha": r.CommitSHA,
	}
	if r.MergedAt != "" {
		d["merged_at"] = r.MergedAt
	}
	if len(r.MalformedFields) > 0 {
		d["malformed_fields"] = r.MalformedFields
	}
	return d
}

// JSONInfoOutput is the --json output for the info command.
type JSONInfoOutput struct {
	Version     string          `json:"version"`
	ReceiptID   string          `json:"receipt_id"`
	ReceiptType string          `json:"receipt_type"`
	VaultID     string          `json:"vault_id"`
	IssuedAt    string          `json:"issued_at"`
	SigningKeyID string          `json:"signing_key_id"`
	Algorithm   string          `json:"signing_algorithm"`
	ContentHash string          `json:"content_hash"`
	Content     json.RawMessage `json:"content"`
	Verified    bool            `json:"verified"`
	Note        string          `json:"note"`
}

// WriteJSONInfo emits the info JSON document to w.
func WriteJSONInfo(w io.Writer, info *JSONInfoOutput) error {
	info.Verified = false
	info.Note = "INFO ONLY — receipt not verified; no signature check was performed"
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(info); err != nil {
		return fmt.Errorf("encode json info: %w", err)
	}
	return nil
}
