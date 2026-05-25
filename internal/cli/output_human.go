package cli

import (
	"fmt"
	"strings"

	"github.com/deja-dev/dsr-verifier-cli/internal/verify"
	dsrerrors "github.com/deja-dev/dsr-verifier-cli/internal/errors"
)

// VerifyResults aggregates the output of all four verification checks plus
// the metadata needed for output formatting.
type VerifyResults struct {
	ReceiptID   string
	ReceiptType string
	VaultID     string
	IssuedAt    string

	KeyAuthority *verify.KeyAuthorityResult
	Sig          *verify.SignatureResult
	Hash         *verify.ContentHashResult
	Causal       *verify.CausalRefsResult

	DurationMS int64
	LogFile    string
}

// AllPassed reports whether all four checks passed.
func (r *VerifyResults) AllPassed() bool {
	return r.KeyAuthority.Valid && r.Sig.Valid && r.Hash.Valid && r.Causal.Valid
}

// FailureCount returns the number of checks that did not pass.
func (r *VerifyResults) FailureCount() int {
	count := 0
	for _, ok := range []bool{r.KeyAuthority.Valid, r.Sig.Valid, r.Hash.Valid, r.Causal.Valid} {
		if !ok {
			count++
		}
	}
	return count
}

// PrintVerifyResults writes the full human-readable verification output to p.
func PrintVerifyResults(p *Printer, r *VerifyResults) {
	// Key authority
	p.CheckLine(r.KeyAuthority.Valid, "Key authority check", statusLabel(r.KeyAuthority.Valid))
	if r.KeyAuthority.Valid {
		p.Detail("Claimed", r.KeyAuthority.ClaimedKeyID)
		p.Detail("Provided", r.KeyAuthority.ProvidedKeyID)
	} else {
		printFailDetails(p, r.KeyAuthority.Err, map[string]string{
			"Receipt key ID":  r.KeyAuthority.ClaimedKeyID,
			"Key file key ID": r.KeyAuthority.ProvidedKeyID,
		})
	}
	p.Println("")

	// Signature
	p.CheckLine(r.Sig.Valid, "Signature verification", statusLabel(r.Sig.Valid))
	if r.Sig.Valid {
		p.Detail("Algorithm", r.Sig.Algorithm)
		p.Detail("Key ID", r.Sig.KeyID)
		p.Detail("Public key", r.Sig.PublicKeyDigest)
		p.Detail("Signature", r.Sig.SignatureHex)
	} else {
		printFailDetails(p, r.Sig.Err, map[string]string{
			"Algorithm": r.Sig.Algorithm,
			"Key ID":    r.Sig.KeyID,
		})
	}
	p.Println("")

	// Content hash
	p.CheckLine(r.Hash.Valid, "Content hash verification", statusLabel(r.Hash.Valid))
	if r.Hash.Valid {
		p.Detail("Algorithm", r.Hash.Algorithm)
		p.Detail("Computed", truncateHash(r.Hash.ComputedHash))
		p.Detail("Stored", truncateHash(r.Hash.StoredHash))
	} else {
		printFailDetails(p, r.Hash.Err, map[string]string{
			"Algorithm":     r.Hash.Algorithm,
			"Stored hash":   r.Hash.StoredHash,
			"Computed hash": r.Hash.ComputedHash,
		})
	}
	p.Println("")

	// Causal refs
	p.CheckLine(r.Causal.Valid, "Causal artifact structural validation", statusLabel(r.Causal.Valid))
	if r.Causal.Valid {
		if r.Causal.PRURL != "" {
			p.Detail("PR reference", r.Causal.PRURL+" (structure valid)")
		}
		if r.Causal.CommitSHA != "" {
			p.Detail("Commit SHA", r.Causal.CommitSHA)
		}
		if r.Causal.PRURL == "" {
			p.Indent(p.Dim("not applicable for receipt type " + r.ReceiptType))
		}
	} else {
		details := map[string]string{}
		if r.Causal.PRURL != "" {
			details["pr_url"] = r.Causal.PRURL
		}
		if r.Causal.CommitSHA != "" {
			details["commit_sha"] = r.Causal.CommitSHA
		}
		printFailDetails(p, r.Causal.Err, details)
		if len(r.Causal.MalformedFields) > 0 {
			p.Indent("Malformed fields:")
			for _, f := range r.Causal.MalformedFields {
				p.Printf("    • %s\n", f)
			}
		}
	}
	p.Println("")

	// Summary separator
	p.Separator()

	if r.AllPassed() {
		p.Println(p.Green(p.Bold("Result: VERIFIED")) +
			fmt.Sprintf("  ·  4 checks passed  ·  0 failures"))
		p.Printf("Trust path: %s → %s → %s → %s\n",
			p.Dim("key authority"), p.Dim("signature"),
			p.Dim("content hash"), p.Dim("structural"))
	} else {
		fc := r.FailureCount()
		p.Println(p.Red(p.Bold("Result: FAILED")) +
			fmt.Sprintf("  ·  %d check(s) failed  ·  %d passed", fc, 4-fc))
		p.Println("")

		// Print the human message from each failed check.
		for _, f := range collectFailures(r) {
			p.Println(p.Red("Failure: ") + string(f.Class))
			p.Println("")
			// Word-wrap the human message at lineWidth-2 chars.
			for _, line := range wrapText(f.HumanMessage, lineWidth-2) {
				p.Indent(line)
			}
			p.Println("")
		}

		p.Println(p.Bold("Recommended actions for auditor:"))
		p.Println("")
		p.Indent("• Confirm the receipt file was not modified in transit")
		p.Indent("  (compare its SHA-256 to the hash on record with the issuing organization)")
		p.Indent("• Request a fresh receipt copy directly from the source organization's vault")
		p.Indent("• " + p.Red("Do NOT") + " trust the content of this receipt for audit purposes")
		p.Indent("• Report the discrepancy to the issuing organization and document in your audit")
		p.Println("")
	}

	p.Println("")
	p.Printf("%s · %s · duration %dms\n",
		p.Dim("offline"), p.Dim("zero network calls"), r.DurationMS)
	if r.LogFile != "" {
		p.Printf("Logged to: %s\n", p.Cyan(r.LogFile))
	}
	p.Separator()
}

// PrintInfo writes the human-readable info output (no verification).
func PrintInfo(p *Printer, id, receiptType, vaultID, issuedAt, keyID, algorithm, contentHash string, contentSummary map[string]string) {
	p.Separator()
	p.Println(p.Yellow(p.Bold("INFO ONLY — RECEIPT NOT VERIFIED")))
	p.Println(p.Dim("No signature verification was performed. Run 'verify' to verify."))
	p.Separator()
	p.Println("")

	p.Printf("Receipt:     %s\n", p.Bold(id))
	p.Printf("Format:      %s\n", "DSR/1.0.1")
	p.Printf("Type:        %s\n", p.Bold(receiptType)+" · "+receiptTypeLabel(receiptType))
	p.Printf("Vault:       %s\n", vaultID)
	p.Printf("Issued:      %s\n", issuedAt)
	p.Println("")
	p.Printf("Signing key: %s\n", keyID)
	p.Printf("Algorithm:   %s\n", algorithm)
	p.Printf("Content hash (stored):  %s\n", truncateHash(contentHash))
	p.Println("")

	if len(contentSummary) > 0 {
		p.Println("Content fields:")
		for k, v := range contentSummary {
			p.Printf("  %-14s %s\n", k+":", v)
		}
		p.Println("")
	}
	p.Println(p.Dim("To verify this receipt cryptographically, run:"))
	p.Println(p.Dim("  dsr-verifier-cli verify <receipt.dsr> --key <pubkey>"))
}

// statusLabel returns "OK" or "FAIL".
func statusLabel(passed bool) string {
	if passed {
		return "OK"
	}
	return "FAIL"
}

// receiptTypeLabel returns a human-readable label for a receipt type.
func receiptTypeLabel(t string) string {
	switch t {
	case "R1":
		return "Attribution"
	case "R1-L":
		return "Low Confidence"
	case "R1-N":
		return "No Match"
	case "R2":
		return "Resolution"
	case "RV":
		return "Vault Verification"
	case "RV-i":
		return "Vault Verification (interval start)"
	case "RV-f":
		return "Vault Verification (interval end)"
	default:
		return t
	}
}

// truncateHash returns the first 32 chars + "..." for display.
func truncateHash(h string) string {
	if len(h) > 32 {
		return h[:32] + "..."
	}
	return h
}

// printFailDetails prints the short diagnostic block under a FAIL check line.
func printFailDetails(p *Printer, verr *dsrerrors.VerificationError, fields map[string]string) {
	if verr != nil {
		p.Indent(p.Dim("Error class: " + string(verr.Class)))
	}
	for k, v := range fields {
		if v != "" {
			p.Detail(k, v)
		}
	}
}

// collectFailures returns errors from all failed checks in order.
func collectFailures(r *VerifyResults) []*dsrerrors.VerificationError {
	var out []*dsrerrors.VerificationError
	for _, e := range []*dsrerrors.VerificationError{
		r.KeyAuthority.Err, r.Sig.Err, r.Hash.Err, r.Causal.Err,
	} {
		if e != nil {
			out = append(out, e)
		}
	}
	return out
}

// wrapText hard-wraps text at maxWidth characters, breaking at spaces.
func wrapText(text string, maxWidth int) []string {
	if maxWidth <= 0 {
		return []string{text}
	}
	words := strings.Fields(text)
	var lines []string
	var current strings.Builder

	for _, word := range words {
		need := current.Len()
		if need > 0 {
			need++ // space before word
		}
		need += len(word)

		if current.Len() > 0 && need > maxWidth {
			lines = append(lines, current.String())
			current.Reset()
		}
		if current.Len() > 0 {
			current.WriteByte(' ')
		}
		current.WriteString(word)
	}
	if current.Len() > 0 {
		lines = append(lines, current.String())
	}
	return lines
}
