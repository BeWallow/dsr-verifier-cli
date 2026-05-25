package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/deja-dev/dsr-verifier-cli/internal/dsr"
)

// infoOpts holds parsed flags for the info command.
type infoOpts struct {
	json    bool
	noColor bool
}

func parseInfoArgs(args []string, stderr io.Writer) (receipt string, opts infoOpts, help bool, err error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--json", "-json":
			opts.json = true
		case "--no-color", "-no-color":
			opts.noColor = true
		case "--help", "-help", "-h":
			help = true
			return
		default:
			if strings.HasPrefix(arg, "-") {
				fmt.Fprintf(stderr, "error: unknown flag for info: %s\n", arg)
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

func runInfo(args []string, stdout, stderr io.Writer) int {
	receiptPath, opts, help, parseArgErr := parseInfoArgs(args, stderr)
	if help {
		fmt.Fprint(stdout, infoHelp)
		return exitSuccess
	}
	if parseArgErr != nil {
		return exitParseError
	}
	if receiptPath == "" {
		fmt.Fprintln(stderr, "error: info requires a receipt file argument")
		fmt.Fprintln(stderr, "usage: dsr-verifier-cli info <receipt.dsr>")
		return exitParseError
	}

	receiptData, err := os.ReadFile(receiptPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(stderr, "error: receipt file not found: %s\n", receiptPath)
			return exitMissingFile
		}
		fmt.Fprintf(stderr, "error: cannot read receipt file %s: %v\n", receiptPath, err)
		return exitMissingFile
	}

	receipt, parseErr := dsr.Parse(receiptData)
	if parseErr != nil {
		fmt.Fprintf(stderr, "error: malformed receipt: %s\n", parseErr.HumanMessage)
		fmt.Fprintf(stderr, "detail: %s\n", parseErr.TechnicalDetail)
		return exitParseError
	}

	issuedAt := receipt.IssuedAt.UTC().Format(time.RFC3339)

	if opts.json {
		out := &JSONInfoOutput{
			Version:      Version,
			ReceiptID:    receipt.ID,
			ReceiptType:  receipt.Type,
			VaultID:      receipt.VaultID,
			IssuedAt:     issuedAt,
			SigningKeyID:  receipt.SigningKeyID,
			Algorithm:    receipt.SigningAlgorithm,
			ContentHash:  receipt.ContentHash,
			Content:      receipt.Content,
		}
		if encErr := WriteJSONInfo(stdout, out); encErr != nil {
			fmt.Fprintf(stderr, "error: %v\n", encErr)
			return exitParseError
		}
		return exitSuccess
	}

	p := NewPrinter(stdout, !opts.noColor)
	contentSummary := parseInfoFromContent(receipt.Content)
	PrintInfo(p, receipt.ID, receipt.Type, receipt.VaultID, issuedAt,
		receipt.SigningKeyID, receipt.SigningAlgorithm, receipt.ContentHash,
		contentSummary)
	return exitSuccess
}

const infoHelp = `
Usage: dsr-verifier-cli info <receipt.dsr> [flags]

Display receipt metadata without performing verification. Useful for quick
inspection when the public key is not available. This command does NOT verify
the signature or content integrity.

Arguments:
  <receipt.dsr>   path to the .dsr receipt file to inspect

Flags:
  --json          machine-readable JSON output
  --no-color      disable ANSI color codes in output
  --help          this help
`
