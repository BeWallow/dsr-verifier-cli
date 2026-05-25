package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/deja-dev/dsr-verifier-cli/internal/bundle"
	dsrerrors "github.com/deja-dev/dsr-verifier-cli/internal/errors"
)

// ─────────────────────────────────────────────────────────────────────────────
// Human-readable bundle output
// ─────────────────────────────────────────────────────────────────────────────

// BundleHeader prints the header box for bundle verification.
func (p *Printer) BundleHeader(bundleFile, keyFile string) {
	title := fmt.Sprintf("DSR Verifier · v%s · Bundle Verification", Version)
	titleRunes := utf8.RuneCountInString(title)
	dashCount := lineWidth - 3 - titleRunes - 2
	if dashCount < 1 {
		dashCount = 1
	}
	top := "┌─ " + p.Bold(title) + " " + strings.Repeat("─", dashCount) + "┐"
	p.Println(top)

	inner := lineWidth - 4
	p.Println("│ " + padRight("Bundle:   "+filepath.Base(bundleFile), inner) + " │")
	if keyFile != "" {
		p.Println("│ " + padRight("Using key: "+keyFile, inner) + " │")
	}
	p.Println("└" + strings.Repeat("─", lineWidth-2) + "┘")
	p.Println("")
}

// PrintBundleResults writes the full human-readable bundle verification output.
func PrintBundleResults(p *Printer, res *bundle.BundleVerifyResult, bundleFile string, sizeBytes int64, reportFile string) {
	// Bundle metadata block.
	p.Printf("Bundle:     %s", filepath.Base(bundleFile))
	if sizeBytes > 0 {
		p.Printf(" (%s)\n", formatBytes(sizeBytes))
	} else {
		p.Println("")
	}
	p.Printf("Vault:      %s\n", res.VaultID)
	if res.PeriodStart != "" || res.PeriodEnd != "" {
		p.Printf("Period:     %s to %s\n", res.PeriodStart, res.PeriodEnd)
	}
	if len(res.Frameworks) > 0 {
		p.Printf("Frameworks: %s\n", strings.Join(res.Frameworks, " · "))
	}
	p.Println("")

	// Per-receipt breakdown.
	total := res.PerReceipt.Total
	p.Printf("%s\n", p.Bold(fmt.Sprintf("Verifying %d receipts...", total)))
	p.Println("")
	printTypeBreakdown(p, res)
	p.Println("")

	// Bundle signature.
	p.CheckLine(res.ManifestSig.Valid, "Verifying bundle signature", statusLabel(res.ManifestSig.Valid))
	if res.ManifestSig.Valid {
		p.Detail("Bundle signed by", res.IssuerKeyID)
		p.Detail("Bundle signature", "valid")
	} else if res.ManifestSig.Err != nil {
		p.Indent(p.Dim("Error class: " + string(res.ManifestSig.Err.Class)))
		for _, line := range wrapText(res.ManifestSig.Err.HumanMessage, lineWidth-4) {
			p.Indent(line)
		}
	}
	p.Println("")

	// Sequence integrity.
	p.CheckLine(res.SequenceInteg.Valid, "Verifying sequence integrity", statusLabel(res.SequenceInteg.Valid))
	if res.SequenceInteg.Valid {
		p.Detail("Sequence range",
			fmt.Sprintf("%d–%d (no gaps detected)",
				res.SequenceInteg.MinSeq, res.SequenceInteg.MaxSeq))
	} else if res.SequenceInteg.Err != nil {
		p.Indent(p.Dim("Error class: " + string(res.SequenceInteg.Err.Class)))
		gapDisplay := res.SequenceInteg.Gaps
		if len(gapDisplay) > 5 {
			gapDisplay = gapDisplay[:5]
		}
		p.Indent(fmt.Sprintf("Missing sequences (first %d): %v", len(gapDisplay), gapDisplay))
	}
	p.Println("")

	// Causal chain.
	p.CheckLine(res.CausalChain.Valid, "Verifying causal chain consistency", statusLabel(res.CausalChain.Valid))
	if res.CausalChain.Total > 0 {
		p.Detail("Cross-receipt references resolved",
			fmt.Sprintf("%d / %d", res.CausalChain.Resolved, res.CausalChain.Total))
	} else {
		p.Indent(p.Dim("No cross-receipt causal references found"))
	}
	if len(res.CausalChain.Unresolvable) > 0 {
		p.Indent(p.Dim(fmt.Sprintf("Out-of-scope references (not a failure): %d", len(res.CausalChain.Unresolvable))))
	}
	p.Println("")

	// Summary separator.
	p.Separator()

	if res.AllPassed() {
		p.Println(p.Green(p.Bold(fmt.Sprintf("✓ Bundle verified · all %d receipts cryptographically valid", total))))
	} else {
		failCount := 0
		if !res.ManifestSig.Valid {
			failCount++
		}
		if !res.SequenceInteg.Valid {
			failCount++
		}
		if res.PerReceipt.Failed > 0 {
			failCount++
		}
		p.Println(p.Red(p.Bold(fmt.Sprintf("✗ Bundle verification FAILED · %d check(s) failed", failCount))))
		p.Println("")

		// Print failure details.
		if !res.ManifestSig.Valid && res.ManifestSig.Err != nil {
			printBundleFailure(p, "Bundle signature", res.ManifestSig.Err)
		}
		if !res.SequenceInteg.Valid && res.SequenceInteg.Err != nil {
			printBundleFailure(p, "Sequence integrity", res.SequenceInteg.Err)
		}
		if res.PerReceipt.Failed > 0 {
			p.Println(p.Red("Receipt failures:"))
			limit := 5
			shown := 0
			for _, f := range res.PerReceipt.Failures {
				if shown >= limit {
					remaining := len(res.PerReceipt.Failures) - shown
					p.Indent(p.Dim(fmt.Sprintf("... and %d more failure(s)", remaining)))
					break
				}
				p.Indent(fmt.Sprintf("seq %d · %s · %s", f.Seq, f.ReceiptID, formatErrors(f.Errors)))
				shown++
			}
			p.Println("")
		}

		p.Println(p.Bold("Recommended actions for auditor:"))
		p.Println("")
		p.Indent("• Do NOT treat this bundle as verified evidence")
		p.Indent("• Request a fresh bundle directly from the issuing organization")
		p.Indent("• Document this discrepancy in your audit findings")
		p.Println("")
	}

	// Summary block.
	p.Printf("%s\n", p.Bold("Summary:"))
	passRate := fmt.Sprintf("%d / %d (100%%)", total, total)
	if total > 0 && res.PerReceipt.Passed < total {
		pct := res.PerReceipt.Passed * 100 / total
		passRate = fmt.Sprintf("%d / %d (%d%%)", res.PerReceipt.Passed, total, pct)
	}
	p.Detail("  Pass rate", passRate)
	p.Detail("  Tampered", fmt.Sprintf("%d", res.Tampered()))
	p.Detail("  Missing", fmt.Sprintf("%d", res.Missing()))
	if res.RVCoverage.TotalRV > 0 {
		p.Detail("  RV coverage", fmt.Sprintf("%d vault-verification receipts · %d days covered",
			res.RVCoverage.TotalRV, res.RVCoverage.DaysCovered))
	}
	p.Println("")

	p.Printf("%s · %s\n", p.Dim("offline"), p.Dim("zero network calls"))
	if reportFile != "" {
		p.Printf("Output: verification report written to %s\n", p.Cyan(reportFile))
	}
	p.Separator()
}

// printTypeBreakdown prints the per-type receipt counts.
func printTypeBreakdown(p *Printer, res *bundle.BundleVerifyResult) {
	// Print types in a fixed display order.
	order := []struct {
		key   string
		label string
	}{
		{"R1", "R1 (Attribution)"},
		{"R1-L", "R1-L (Low Confidence)"},
		{"R1-N", "R1-N (No Match)"},
		{"R2", "R2 (Resolution)"},
		{"RV", "RV (Vault Verification)"},
		{"RV-i", "RV-i (Interval Start)"},
		{"RV-f", "RV-f (Interval End)"},
	}

	for _, o := range order {
		tr, ok := res.PerReceipt.ByType[o.key]
		if !ok || tr.Total == 0 {
			continue
		}
		label := padRight("  "+o.label, 34)
		counts := fmt.Sprintf("%d/%d passed", tr.Passed, tr.Total)
		var suffix string
		if o.key == "RV" || o.key == "RV-i" || o.key == "RV-f" {
			suffix = "  " + p.Dim("(continuous integrity)")
		}
		if tr.Failed > 0 {
			p.Printf("%s  %s%s\n", label, p.Red(counts), suffix)
		} else {
			p.Printf("%s  %s%s\n", label, p.Green(counts), suffix)
		}
	}

	// Print any types not in the fixed list.
	for typ, tr := range res.PerReceipt.ByType {
		known := false
		for _, o := range order {
			if o.key == typ {
				known = true
				break
			}
		}
		if known || tr.Total == 0 {
			continue
		}
		label := padRight("  "+typ, 34)
		counts := fmt.Sprintf("%d/%d passed", tr.Passed, tr.Total)
		if tr.Failed > 0 {
			p.Printf("%s  %s\n", label, p.Red(counts))
		} else {
			p.Printf("%s  %s\n", label, p.Green(counts))
		}
	}
}

func printBundleFailure(p *Printer, checkName string, verr *dsrerrors.VerificationError) {
	p.Println(p.Red("Failure: ") + checkName + " · " + string(verr.Class))
	p.Println("")
	for _, line := range wrapText(verr.HumanMessage, lineWidth-4) {
		p.Indent(line)
	}
	p.Println("")
}

func formatErrors(errs []*dsrerrors.VerificationError) string {
	classes := make([]string, 0, len(errs))
	for _, e := range errs {
		classes = append(classes, string(e.Class))
	}
	return strings.Join(classes, ", ")
}

func formatBytes(n int64) string {
	const mb = 1 << 20
	const kb = 1 << 10
	switch {
	case n >= mb:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(mb))
	case n >= kb:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(kb))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON bundle report
// ─────────────────────────────────────────────────────────────────────────────

// BundleJSONReport is the structure written to <bundle>.verification.json.
type BundleJSONReport struct {
	Version     string `json:"version"`
	BundleID    string `json:"bundle_id"`
	VaultID     string `json:"vault_id"`
	PeriodStart string `json:"period_start"`
	PeriodEnd   string `json:"period_end"`
	IssuerKeyID string `json:"issuer_key_id"`

	Result string `json:"result"` // "verified" | "failed"

	Checks BundleJSONChecks `json:"checks"`

	PerReceipt BundleJSONPerReceipt `json:"per_receipt"`
	RVCoverage BundleJSONRVCoverage `json:"rv_coverage"`

	Failures []BundleJSONFailure `json:"failures"`

	DurationMS int64 `json:"duration_ms"`
	Offline    bool  `json:"offline"`
}

type BundleJSONChecks struct {
	ManifestSignature JSONCheckResult `json:"manifest_signature"`
	SequenceIntegrity JSONCheckResult `json:"sequence_integrity"`
	CausalChain       JSONCheckResult `json:"causal_chain"`
}

type BundleJSONPerReceipt struct {
	Total  int                        `json:"total"`
	Passed int                        `json:"passed"`
	Failed int                        `json:"failed"`
	ByType map[string]*bundle.TypeResult `json:"by_type"`
}

type BundleJSONRVCoverage struct {
	TotalRV      int `json:"total_rv"`
	TotalRVi     int `json:"total_rvi"`
	TotalRVf     int `json:"total_rvf"`
	DaysCovered  int `json:"days_covered"`
	Streak       int `json:"streak"`
	TotalAnomalies int `json:"total_anomalies"`
}

type BundleJSONFailure struct {
	Seq             int    `json:"seq,omitempty"`
	ReceiptID       string `json:"receipt_id,omitempty"`
	Check           string `json:"check"`
	ErrorClass      string `json:"error_class"`
	HumanMessage    string `json:"human_message"`
	TechnicalDetail string `json:"technical_detail"`
}

// WriteBundleJSONReport encodes the bundle verification result as a JSON report.
func WriteBundleJSONReport(w io.Writer, res *bundle.BundleVerifyResult, durationMS int64) error {
	result := "verified"
	if !res.AllPassed() {
		result = "failed"
	}

	report := &BundleJSONReport{
		Version:     Version,
		BundleID:    res.BundleID,
		VaultID:     res.VaultID,
		PeriodStart: res.PeriodStart,
		PeriodEnd:   res.PeriodEnd,
		IssuerKeyID: res.IssuerKeyID,
		Result:      result,
		DurationMS:  durationMS,
		Offline:     true,
	}

	report.Checks.ManifestSignature = bundleCheckResult(res.ManifestSig.Valid, res.ManifestSig.Err)
	report.Checks.SequenceIntegrity = bundleCheckResult(res.SequenceInteg.Valid, res.SequenceInteg.Err)
	report.Checks.CausalChain = bundleCheckResult(res.CausalChain.Valid, res.CausalChain.Err)

	report.PerReceipt = BundleJSONPerReceipt{
		Total:  res.PerReceipt.Total,
		Passed: res.PerReceipt.Passed,
		Failed: res.PerReceipt.Failed,
		ByType: res.PerReceipt.ByType,
	}

	report.RVCoverage = BundleJSONRVCoverage{
		TotalRV:        res.RVCoverage.TotalRV,
		TotalRVi:       res.RVCoverage.TotalRVi,
		TotalRVf:       res.RVCoverage.TotalRVf,
		DaysCovered:    res.RVCoverage.DaysCovered,
		Streak:         res.RVCoverage.Streak,
		TotalAnomalies: res.RVCoverage.TotalAnomalies,
	}

	// Bundle-level failures.
	if !res.ManifestSig.Valid && res.ManifestSig.Err != nil {
		report.Failures = append(report.Failures, bundleJSONFailure("manifest_signature", res.ManifestSig.Err))
	}
	if !res.SequenceInteg.Valid && res.SequenceInteg.Err != nil {
		report.Failures = append(report.Failures, bundleJSONFailure("sequence_integrity", res.SequenceInteg.Err))
	}

	// Per-receipt failures.
	for _, f := range res.PerReceipt.Failures {
		for _, e := range f.Errors {
			report.Failures = append(report.Failures, BundleJSONFailure{
				Seq:             f.Seq,
				ReceiptID:       f.ReceiptID,
				Check:           "per_receipt",
				ErrorClass:      string(e.Class),
				HumanMessage:    e.HumanMessage,
				TechnicalDetail: e.TechnicalDetail,
			})
		}
	}

	if report.Failures == nil {
		report.Failures = []BundleJSONFailure{}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func bundleCheckResult(valid bool, verr *dsrerrors.VerificationError) JSONCheckResult {
	if verr == nil {
		b, _ := json.Marshal(map[string]bool{"passed": valid})
		return JSONCheckResult{Passed: valid, Details: json.RawMessage(b)}
	}
	b, _ := json.Marshal(map[string]string{
		"error_class":      string(verr.Class),
		"human_message":    verr.HumanMessage,
		"technical_detail": verr.TechnicalDetail,
	})
	return JSONCheckResult{Passed: valid, Details: json.RawMessage(b)}
}

func bundleJSONFailure(check string, verr *dsrerrors.VerificationError) BundleJSONFailure {
	return BundleJSONFailure{
		Check:           check,
		ErrorClass:      string(verr.Class),
		HumanMessage:    verr.HumanMessage,
		TechnicalDetail: verr.TechnicalDetail,
	}
}
