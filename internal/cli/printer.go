package cli

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// lineWidth is the visual width used for box drawing and separator lines.
const lineWidth = 75

// ANSI escape codes. All are no-ops when color is disabled.
const (
	ansiReset  = "\033[0m"
	ansiGreen  = "\033[32m"
	ansiRed    = "\033[31m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiCyan   = "\033[36m"
	ansiYellow = "\033[33m"
)

// Printer writes formatted output to a writer with optional ANSI color.
// All output goes through Printer so that --no-color is honored everywhere.
type Printer struct {
	w     io.Writer
	color bool
}

// NewPrinter returns a Printer that writes to w. If color is false, no ANSI
// escape codes are emitted.
func NewPrinter(w io.Writer, color bool) *Printer {
	return &Printer{w: w, color: color}
}

func (p *Printer) c(code, text string) string {
	if !p.color {
		return text
	}
	return code + text + ansiReset
}

func (p *Printer) Green(s string) string  { return p.c(ansiGreen, s) }
func (p *Printer) Red(s string) string    { return p.c(ansiRed, s) }
func (p *Printer) Bold(s string) string   { return p.c(ansiBold, s) }
func (p *Printer) Dim(s string) string    { return p.c(ansiDim, s) }
func (p *Printer) Cyan(s string) string   { return p.c(ansiCyan, s) }
func (p *Printer) Yellow(s string) string { return p.c(ansiYellow, s) }

func (p *Printer) Printf(format string, args ...interface{}) {
	fmt.Fprintf(p.w, format, args...)
}

func (p *Printer) Println(s string) {
	fmt.Fprintln(p.w, s)
}

// Header prints the top box with the verifier banner and input details.
//
//	┌─ DSR Verifier · v1.0.0 ──────────────────────────────────────────────┐
//	│ Verifying: receipt.dsr                                                │
//	│ Using key: vault.pub                                                  │
//	└───────────────────────────────────────────────────────────────────────┘
func (p *Printer) Header(receiptFile, keyFile string) {
	title := fmt.Sprintf("DSR Verifier · v%s", Version)
	titleRunes := utf8.RuneCountInString(title)
	// top: ┌─ <title> <dashes>┐
	dashCount := lineWidth - 3 - titleRunes - 2 // "┌─ " + title + " " + dashes + "┐"
	if dashCount < 1 {
		dashCount = 1
	}
	top := "┌─ " + p.Bold(title) + " " + strings.Repeat("─", dashCount) + "┐"
	p.Println(top)

	inner := lineWidth - 4 // "│ " + content + " │"
	p.Println("│ " + padRight("Verifying: "+receiptFile, inner) + " │")
	if keyFile != "" {
		p.Println("│ " + padRight("Using key: "+keyFile, inner) + " │")
	}
	p.Println("│ " + padRight("Mode:      offline · no network calls", inner) + " │")
	p.Println("└" + strings.Repeat("─", lineWidth-2) + "┘")
	p.Println("")
}

// Separator prints a heavy horizontal rule.
func (p *Printer) Separator() {
	p.Println(strings.Repeat("━", lineWidth))
}

// CheckLine prints a check result line with dot-fill padding:
//
//	✓ Signature verification ........................................... OK
//	✗ Content hash verification ...................................... FAIL
func (p *Printer) CheckLine(passed bool, label, result string) {
	var icon, coloredResult string
	if passed {
		icon = p.Green("✓")
		coloredResult = p.Green(result)
	} else {
		icon = p.Red("✗")
		coloredResult = p.Red(result)
	}

	// Calculate visible rune counts, ignoring color codes.
	prefixText := "  " + label + " "
	prefixRunes := utf8.RuneCountInString(prefixText)
	resultRunes := utf8.RuneCountInString(result)
	dotCount := lineWidth - prefixRunes - resultRunes - 2 // gap before result
	if dotCount < 3 {
		dotCount = 3
	}

	p.Printf("%s %s %s %s\n", icon, label, p.Dim(strings.Repeat(".", dotCount)), coloredResult)
}

// Detail prints a key-value detail line indented under a check result.
func (p *Printer) Detail(key, value string) {
	p.Printf("  %-12s %s\n", key+":", value)
}

// Indent prints a line indented 2 spaces.
func (p *Printer) Indent(s string) {
	p.Printf("  %s\n", s)
}

// padRight pads s with spaces on the right until it is at least width runes wide.
func padRight(s string, width int) string {
	n := utf8.RuneCountInString(s)
	if n >= width {
		return s
	}
	return s + strings.Repeat(" ", width-n)
}
