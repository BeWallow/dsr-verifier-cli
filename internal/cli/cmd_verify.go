package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/deja-dev/dsr-verifier-cli/internal/dsr"
	"github.com/deja-dev/dsr-verifier-cli/internal/verify"
)

// verifyOpts holds parsed flags for the verify command.
type verifyOpts struct {
	keyFile string
	json    bool
	quiet   bool
	noLog   bool
	noColor bool
}

// parseVerifyArgs scans args in any order (flags may come before or after the
// receipt path). Returns the receipt path, parsed options, a help-requested
// boolean, and any parse error.
func parseVerifyArgs(args []string, stderr io.Writer) (receipt string, opts verifyOpts, help bool, err error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--key", "-key":
			i++
			if i >= len(args) {
				fmt.Fprintln(stderr, "error: --key requires a file path")
				err = fmt.Errorf("--key requires a value")
				return
			}
			opts.keyFile = args[i]
		case "--json", "-json":
			opts.json = true
		case "--quiet", "-quiet", "-q":
			opts.quiet = true
		case "--no-log", "-no-log":
			opts.noLog = true
		case "--no-color", "-no-color":
			opts.noColor = true
		case "--help", "-help", "-h":
			help = true
			return
		default:
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(stderr, "error: unknown flag for verify: %s\n", arg)
				err = fmt.Errorf("unknown flag: %s", arg)
				return
			}
			if receipt != "" {
				fmt.Fprintf(stderr, "error: unexpected argument: %s\n", arg)
				err = fmt.Errorf("unexpected argument: %s", arg)
				return
			}
			receipt = arg
		}
	}
	return
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	receiptPath, opts, help, parseArgErr := parseVerifyArgs(args, stderr)
	if help {
		fmt.Fprint(stdout, verifyHelp)
		return exitSuccess
	}
	if parseArgErr != nil {
		return exitParseError
	}
	if receiptPath == "" {
		fmt.Fprintln(stderr, "error: verify requires a receipt file argument")
		fmt.Fprintln(stderr, "usage: dsr-verifier-cli verify <receipt.dsr> --key <pubkey>")
		return exitParseError
	}
	if opts.keyFile == "" {
		fmt.Fprintln(stderr, "error: --key <pubkey> is required for verify")
		fmt.Fprintln(stderr, "usage: dsr-verifier-cli verify <receipt.dsr> --key <pubkey>")
		return exitKeyError
	}

	// Read receipt file.
	receiptData, err := os.ReadFile(receiptPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(stderr, "error: receipt file not found: %s\n", receiptPath)
			return exitMissingFile
		}
		fmt.Fprintf(stderr, "error: cannot read receipt file %s: %v\n", receiptPath, err)
		return exitMissingFile
	}

	// Read key file.
	keyData, err := os.ReadFile(opts.keyFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(stderr, "error: key file not found: %s\n", opts.keyFile)
			return exitMissingFile
		}
		fmt.Fprintf(stderr, "error: cannot read key file %s: %v\n", opts.keyFile, err)
		return exitMissingFile
	}

	// Parse receipt.
	receipt, parseErr := dsr.Parse(receiptData)
	if parseErr != nil {
		fmt.Fprintf(stderr, "error: malformed receipt: %s\n", parseErr.HumanMessage)
		fmt.Fprintf(stderr, "detail: %s\n", parseErr.TechnicalDetail)
		return exitParseError
	}

	// Parse public key.
	providedKey, keyErr := verify.ParsePublicKeyFile(keyData)
	if keyErr != nil {
		fmt.Fprintf(stderr, "error: invalid key file: %s\n", keyErr.HumanMessage)
		fmt.Fprintf(stderr, "detail: %s\n", keyErr.TechnicalDetail)
		return exitKeyError
	}

	// Run all four checks.
	start := time.Now()
	authResult := verify.KeyAuthority(receipt, providedKey)
	sigResult := verify.Signature(receipt, providedKey)
	hashResult := verify.ContentHash(receipt)
	causalResult := verify.CausalRefs(receipt)
	durationMS := time.Since(start).Milliseconds()

	results := &VerifyResults{
		ReceiptID:    receipt.ID,
		ReceiptType:  receipt.Type,
		VaultID:      receipt.VaultID,
		IssuedAt:     receipt.IssuedAt.UTC().Format(time.RFC3339),
		KeyAuthority: authResult,
		Sig:          sigResult,
		Hash:         hashResult,
		Causal:       causalResult,
		DurationMS:   durationMS,
	}

	exitCode := exitSuccess
	if !results.AllPassed() {
		exitCode = exitVerifyFailed
	}

	logResult := "verified"
	if exitCode != exitSuccess {
		logResult = "failed"
	}

	// Write audit log unless suppressed.
	if !opts.noLog {
		results.LogFile = DefaultLogFile
		if lerr := WriteLogEntry(DefaultLogFile, "verify", receiptPath, logResult, durationMS); lerr != nil {
			fmt.Fprintf(stderr, "warning: audit log write failed: %v\n", lerr)
		}
	}

	if opts.quiet {
		return exitCode
	}

	if opts.json {
		if encErr := WriteJSON(stdout, results); encErr != nil {
			fmt.Fprintf(stderr, "error: JSON encode failed: %v\n", encErr)
			return exitParseError
		}
		return exitCode
	}

	// Human-readable output.
	p := NewPrinter(stdout, !opts.noColor)
	p.Header(receiptPath, opts.keyFile)
	PrintVerifyResults(p, results)
	return exitCode
}

// parseInfoFromContent extracts a display-friendly string map from content JSON.
func parseInfoFromContent(raw json.RawMessage) map[string]string {
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		switch sv := v.(type) {
		case string:
			out[k] = sv
		case float64:
			out[k] = fmt.Sprintf("%g", sv)
		case bool:
			if sv {
				out[k] = "true"
			} else {
				out[k] = "false"
			}
		default:
			b, _ := json.Marshal(v)
			out[k] = string(b)
		}
	}
	return out
}

const verifyHelp = `
Usage: dsr-verifier-cli verify <receipt.dsr> --key <pubkey> [flags]

Verify a DSR/1.0.1 receipt's signature, content integrity, key authority,
and structural causal references. All checks run offline with zero network calls.

Arguments:
  <receipt.dsr>   path to the .dsr receipt file to verify

Flags:
  --key <file>    path to the PEM-encoded ed25519 public key (required)
  --json          machine-readable JSON output
  --quiet         minimal output; rely on exit code
  --no-log        disable the local audit log (./verifier.log by default)
  --no-color      disable ANSI color codes in output
  --help          this help

Exit codes:
  0   all checks passed
  1   one or more verification checks failed
  2   receipt file is malformed or cannot be parsed
  3   receipt or key file not found
  4   key file is not a valid ed25519 public key
`
