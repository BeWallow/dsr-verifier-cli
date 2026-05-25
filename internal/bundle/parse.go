package bundle

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/deja-dev/dsr-verifier-cli/internal/dsr"
	dsrerrors "github.com/deja-dev/dsr-verifier-cli/internal/errors"
)

// Bundle holds the fully-parsed contents of a .dsr.bundle file.
type Bundle struct {
	Manifest *Manifest
	Receipts []*ParsedReceipt // parallel to Manifest.Entries; nil if parse failed
	SizeBytes int64
}

// ParsedReceipt pairs a manifest entry with its parsed receipt (or a parse error).
type ParsedReceipt struct {
	Entry   ManifestEntry
	Receipt *dsr.Receipt            // nil if ParseErr is set
	ParseErr *dsrerrors.VerificationError
}

// ParseBundle opens and parses a .dsr.bundle ZIP file from disk.
func ParseBundle(path string) (*Bundle, *dsrerrors.VerificationError) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, dsrerrors.New(
			dsrerrors.MalformedReceipt,
			fmt.Sprintf("The bundle file %q could not be opened as a ZIP archive. "+
				"The file may be corrupt or not a valid .dsr.bundle.", path),
			fmt.Sprintf("zip.OpenReader error: %s", err.Error()),
		)
	}
	defer zr.Close()

	var totalSize int64
	for _, f := range zr.File {
		totalSize += int64(f.UncompressedSize64)
	}

	return parseBundleFromZip(&zr.Reader, totalSize)
}

// ParseBundleFromBytes parses a .dsr.bundle from an in-memory byte slice.
// Used in tests to avoid writing temp files.
func ParseBundleFromBytes(data []byte) (*Bundle, *dsrerrors.VerificationError) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, dsrerrors.New(
			dsrerrors.MalformedReceipt,
			"The bundle data could not be parsed as a ZIP archive.",
			fmt.Sprintf("zip.NewReader error: %s", err.Error()),
		)
	}
	return parseBundleFromZip(zr, int64(len(data)))
}

func parseBundleFromZip(zr *zip.Reader, sizeBytes int64) (*Bundle, *dsrerrors.VerificationError) {
	// Index files by name for fast lookup.
	fileIndex := make(map[string]*zip.File, len(zr.File))
	for _, f := range zr.File {
		fileIndex[f.Name] = f
	}

	// Parse manifest.json.
	manifestFile, ok := fileIndex["manifest.json"]
	if !ok {
		return nil, dsrerrors.New(
			dsrerrors.MalformedReceipt,
			"The bundle does not contain a manifest.json file. "+
				"A valid .dsr.bundle must include manifest.json at the archive root.",
			"manifest.json not found in ZIP",
		)
	}

	manifestData, err := readZipFile(manifestFile)
	if err != nil {
		return nil, dsrerrors.New(
			dsrerrors.MalformedReceipt,
			"The manifest.json file in the bundle could not be read.",
			fmt.Sprintf("read manifest.json: %s", err.Error()),
		)
	}

	manifest, verr := parseManifest(manifestData)
	if verr != nil {
		return nil, verr
	}

	// Parse each receipt referenced in the manifest.
	parsed := make([]*ParsedReceipt, len(manifest.Entries))
	for i, entry := range manifest.Entries {
		zf, found := fileIndex[entry.Filename]
		if !found {
			parsed[i] = &ParsedReceipt{
				Entry: entry,
				ParseErr: dsrerrors.New(
					dsrerrors.MalformedReceipt,
					fmt.Sprintf("Bundle manifest references receipt file %q (seq %d) "+
						"but that file is missing from the archive.", entry.Filename, entry.Seq),
					fmt.Sprintf("missing file: %q", entry.Filename),
				),
			}
			continue
		}

		receiptData, err := readZipFile(zf)
		if err != nil {
			parsed[i] = &ParsedReceipt{
				Entry: entry,
				ParseErr: dsrerrors.New(
					dsrerrors.MalformedReceipt,
					fmt.Sprintf("Receipt file %q (seq %d) could not be read from the bundle.", entry.Filename, entry.Seq),
					fmt.Sprintf("read %q: %s", entry.Filename, err.Error()),
				),
			}
			continue
		}

		receipt, parseErr := dsr.Parse(receiptData)
		parsed[i] = &ParsedReceipt{Entry: entry, Receipt: receipt, ParseErr: parseErr}
	}

	return &Bundle{
		Manifest:  manifest,
		Receipts:  parsed,
		SizeBytes: sizeBytes,
	}, nil
}

// parseManifest parses and validates manifest.json bytes.
func parseManifest(data []byte) (*Manifest, *dsrerrors.VerificationError) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, dsrerrors.New(
			dsrerrors.MalformedReceipt,
			"The bundle's manifest.json could not be parsed. "+
				"The file may be corrupt or not a valid DSR bundle manifest.",
			fmt.Sprintf("JSON parse error: %s", err.Error()),
		)
	}

	if err := validateManifest(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// validateManifest checks that all required manifest fields are present and valid.
func validateManifest(m *Manifest) *dsrerrors.VerificationError {
	var missing []string
	if m.Format == "" {
		missing = append(missing, "format")
	}
	if m.BundleID == "" {
		missing = append(missing, "bundle_id")
	}
	if m.VaultID == "" {
		missing = append(missing, "vault_id")
	}
	if m.IssuedAt.IsZero() {
		missing = append(missing, "issued_at")
	}
	if m.IssuerKeyID == "" {
		missing = append(missing, "issuer_key_id")
	}
	if len(m.Entries) == 0 {
		missing = append(missing, "receipts (empty)")
	}
	if len(m.Signature) == 0 {
		missing = append(missing, "signature")
	}
	if len(missing) > 0 {
		return dsrerrors.New(
			dsrerrors.MalformedReceipt,
			fmt.Sprintf("The bundle manifest is missing required fields: %v", missing),
			fmt.Sprintf("missing fields: %v", missing),
		)
	}

	if m.Format != BundleFormat {
		return dsrerrors.New(
			dsrerrors.MalformedReceipt,
			fmt.Sprintf("The bundle manifest declares format %q but this verifier only supports %q.",
				m.Format, BundleFormat),
			fmt.Sprintf("manifest.format=%q, expected=%q", m.Format, BundleFormat),
		)
	}

	if len(m.Signature) != 64 {
		return dsrerrors.New(
			dsrerrors.MalformedReceipt,
			fmt.Sprintf("The bundle manifest's signature field is %d bytes but ed25519 signatures are exactly 64 bytes.",
				len(m.Signature)),
			fmt.Sprintf("signature length: %d, expected: 64", len(m.Signature)),
		)
	}

	return nil
}

func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}
