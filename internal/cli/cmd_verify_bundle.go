package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/deja-dev/dsr-verifier-cli/internal/bundle"
	"github.com/deja-dev/dsr-verifier-cli/internal/verify"
)

// bundleVerifyOpts holds parsed flags for the verify-bundle command.
type bundleVerifyOpts struct {
	keyFile string
	json    bool
	quiet   bool
	noLog   bool
	noColor bool
}

// parseBundleVerifyArgs scans args in any order.
func parseBundleVerifyArgs(args []string, stderr io.Writer) (bundlePath string, opts bundleVerifyOpts, help bool, err error) {
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
				fmt.Fprintf(stderr, "error: unknown flag for verify-bundle: %s\n", arg)
				err = fmt.Errorf("unknown flag: %s", arg)
				return
			}
			if bundlePath != "" {
				fmt.Fprintf(stderr, "error: unexpected argument: %s\n", arg)
				err = fmt.Errorf("unexpected argument: %s", arg)
				return
			}
			bundlePath = arg
		}
	}
	return
}

func runVerifyBundle(args []string, stdout, stderr io.Writer) int {
	bundlePath, opts, help, parseArgErr := parseBundleVerifyArgs(args, stderr)
	if help {
		fmt.Fprint(stdout, verifyBundleHelp)
		return exitSuccess
	}
	if parseArgErr != nil {
		return exitParseError
	}
	if bundlePath == "" {
		fmt.Fprintln(stderr, "error: verify-bundle requires a bundle file argument")
		fmt.Fprintln(stderr, "usage: dsr-verifier-cli verify-bundle <bundle.dsr.bundle> --key <pubkey>")
		return exitParseError
	}
	if opts.keyFile == "" {
		fmt.Fprintln(stderr, "error: --key <pubkey> is required for verify-bundle")
		fmt.Fprintln(stderr, "usage: dsr-verifier-cli verify-bundle <bundle.dsr.bundle> --key <pubkey>")
		return exitKeyError
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

	providedKey, keyErr := verify.ParsePublicKeyFile(keyData)
	if keyErr != nil {
		fmt.Fprintf(stderr, "error: invalid key file: %s\n", keyErr.HumanMessage)
		fmt.Fprintf(stderr, "detail: %s\n", keyErr.TechnicalDetail)
		return exitKeyError
	}

	// Parse bundle.
	start := time.Now()
	b, bundleErr := bundle.ParseBundle(bundlePath)
	if bundleErr != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(stderr, "error: bundle file not found: %s\n", bundlePath)
			return exitMissingFile
		}
		fmt.Fprintf(stderr, "error: malformed bundle: %s\n", bundleErr.HumanMessage)
		fmt.Fprintf(stderr, "detail: %s\n", bundleErr.TechnicalDetail)
		return exitParseError
	}

	// Verify.
	res := bundle.VerifyBundle(b, providedKey)
	durationMS := time.Since(start).Milliseconds()
	res.DurationMS = durationMS

	exitCode := exitSuccess
	if !res.AllPassed() {
		exitCode = exitVerifyFailed
	}

	logResult := "verified"
	if exitCode != exitSuccess {
		logResult = "failed"
	}

	// Always write the JSON verification report alongside the bundle file.
	reportFile := reportFilename(bundlePath)
	if f, ferr := os.Create(reportFile); ferr == nil {
		if encErr := WriteBundleJSONReport(f, res, durationMS); encErr != nil {
			fmt.Fprintf(stderr, "warning: could not write verification report: %v\n", encErr)
			reportFile = ""
		}
		f.Close()
	} else {
		fmt.Fprintf(stderr, "warning: could not create verification report %s: %v\n", reportFile, ferr)
		reportFile = ""
	}

	// Write audit log unless suppressed.
	if !opts.noLog {
		if lerr := WriteLogEntry(DefaultLogFile, "verify-bundle", bundlePath, logResult, durationMS); lerr != nil {
			fmt.Fprintf(stderr, "warning: audit log write failed: %v\n", lerr)
		}
	}

	if opts.quiet {
		return exitCode
	}

	if opts.json {
		if encErr := WriteBundleJSONReport(stdout, res, durationMS); encErr != nil {
			fmt.Fprintf(stderr, "error: JSON encode failed: %v\n", encErr)
			return exitParseError
		}
		return exitCode
	}

	// Human-readable output.
	p := NewPrinter(stdout, !opts.noColor)
	p.BundleHeader(bundlePath, opts.keyFile)
	PrintBundleResults(p, res, bundlePath, b.SizeBytes, reportFile)
	return exitCode
}

// reportFilename derives the verification report path from the bundle path.
// "foo/bar.dsr.bundle" → "foo/bar.verification.json"
// "plain.dsr.bundle"   → "plain.verification.json"
func reportFilename(bundlePath string) string {
	base := bundlePath
	if strings.HasSuffix(base, ".dsr.bundle") {
		base = base[:len(base)-len(".dsr.bundle")]
	} else if strings.HasSuffix(base, ".bundle") {
		base = base[:len(base)-len(".bundle")]
	}
	return base + ".verification.json"
}

const verifyBundleHelp = `
Usage: dsr-verifier-cli verify-bundle <bundle.dsr.bundle> --key <pubkey> [flags]

Verify every receipt in a DSR evidence bundle, plus the bundle's manifest
signature and sequence integrity. All checks run offline with zero network calls.
A JSON verification report is always written to <bundle>.verification.json.

Arguments:
  <bundle.dsr.bundle>  path to the .dsr.bundle archive to verify

Flags:
  --key <file>    path to the PEM-encoded ed25519 public key (required)
  --json          machine-readable JSON output (also writes .verification.json)
  --quiet         minimal output; rely on exit code
  --no-log        disable the local audit log (./verifier.log by default)
  --no-color      disable ANSI color codes in output
  --help          this help

Exit codes:
  0   all checks passed
  1   one or more verification checks failed
  2   bundle file is malformed or cannot be parsed
  3   bundle or key file not found
  4   key file is not a valid ed25519 public key
`
