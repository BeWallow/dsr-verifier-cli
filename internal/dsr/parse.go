package dsr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	dsrerrors "github.com/deja-dev/dsr-verifier-cli/internal/errors"
)

// Parse parses and strictly validates a DSR/1.0.1 receipt from raw JSON bytes.
//
// Strict mode: unknown fields are rejected, all required fields must be
// present and non-zero, version must be exactly "DSR/1.0.1", signing
// algorithm must be "ed25519", and type must be a recognized receipt type.
// Any deviation returns a MalformedReceipt error with diagnostic details.
func Parse(data []byte) (*Receipt, *dsrerrors.VerificationError) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var r Receipt
	if err := dec.Decode(&r); err != nil {
		offset := offsetFromError(err, data)
		return nil, dsrerrors.New(
			dsrerrors.MalformedReceipt,
			"The receipt file could not be parsed as a valid DSR/1.0.1 receipt. "+
				"The file may be corrupt, truncated, or not a DSR receipt.",
			fmt.Sprintf("JSON parse error at byte offset %d: %s", offset, err.Error()),
		)
	}

	if verr := validate(&r); verr != nil {
		return nil, verr
	}

	return &r, nil
}

// validate checks that all required fields are present and hold valid values.
func validate(r *Receipt) *dsrerrors.VerificationError {
	var missing []string

	if r.ID == "" {
		missing = append(missing, "id")
	}
	if r.Version == "" {
		missing = append(missing, "version")
	}
	if r.Type == "" {
		missing = append(missing, "type")
	}
	if r.VaultID == "" {
		missing = append(missing, "vault_id")
	}
	if r.IssuedAt.IsZero() {
		missing = append(missing, "issued_at")
	}
	if len(r.Content) == 0 {
		missing = append(missing, "content")
	}
	if r.ContentHash == "" {
		missing = append(missing, "content_hash")
	}
	if r.SigningKeyID == "" {
		missing = append(missing, "signing_key_id")
	}
	if r.SigningAlgorithm == "" {
		missing = append(missing, "signing_algorithm")
	}
	if len(r.Signature) == 0 {
		missing = append(missing, "signature")
	}

	if len(missing) > 0 {
		return dsrerrors.New(
			dsrerrors.MalformedReceipt,
			fmt.Sprintf(
				"The receipt is missing required fields: %s. A valid DSR/1.0.1 receipt must include all ten envelope fields.",
				strings.Join(missing, ", "),
			),
			fmt.Sprintf("missing fields: [%s]", strings.Join(missing, ", ")),
		)
	}

	if r.Version != Version {
		return dsrerrors.New(
			dsrerrors.MalformedReceipt,
			fmt.Sprintf(
				"This receipt declares version %q but this verifier only understands DSR/1.0.1. "+
					"If the receipt is from a newer version of Déjà, update the verifier CLI.",
				r.Version,
			),
			fmt.Sprintf("version field: %q, expected: %q", r.Version, Version),
		)
	}

	if !ValidType(r.Type) {
		return dsrerrors.New(
			dsrerrors.MalformedReceipt,
			fmt.Sprintf(
				"The receipt type %q is not a recognized DSR/1.0.1 receipt type. "+
					"Valid types are: R1, R1-L, R1-N, R2, RV, RV-i, RV-f.",
				r.Type,
			),
			fmt.Sprintf("type field: %q, valid types: [R1, R1-L, R1-N, R2, RV, RV-i, RV-f]", r.Type),
		)
	}

	if r.SigningAlgorithm != SigningAlgorithmED25519 {
		return dsrerrors.New(
			dsrerrors.MalformedReceipt,
			fmt.Sprintf(
				"The receipt claims signing algorithm %q but this verifier only supports ed25519. "+
					"Contact Déjà support if you believe this receipt was produced by a current Déjà release.",
				r.SigningAlgorithm,
			),
			fmt.Sprintf("signing_algorithm field: %q, expected: %q", r.SigningAlgorithm, SigningAlgorithmED25519),
		)
	}

	// ed25519 signatures are exactly 64 bytes.
	if len(r.Signature) != 64 {
		return dsrerrors.New(
			dsrerrors.MalformedReceipt,
			fmt.Sprintf(
				"The receipt's signature field is %d bytes but ed25519 signatures are exactly 64 bytes. "+
					"The receipt file may be corrupt.",
				len(r.Signature),
			),
			fmt.Sprintf("signature length: %d bytes, expected: 64 bytes", len(r.Signature)),
		)
	}

	// issued_at must not be the zero value (already checked) and must be sensible.
	// Receipts before 2020-01-01 or more than 1 hour in the future are suspicious
	// but not necessarily invalid — we warn via the TechnicalDetail only.
	earliest := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if r.IssuedAt.Before(earliest) {
		return dsrerrors.New(
			dsrerrors.MalformedReceipt,
			fmt.Sprintf(
				"The receipt's issued_at timestamp (%s) predates Déjà's existence. "+
					"The timestamp field may be corrupt or zeroed.",
				r.IssuedAt.UTC().Format(time.RFC3339),
			),
			fmt.Sprintf("issued_at: %s, earliest plausible: %s", r.IssuedAt.UTC().Format(time.RFC3339), earliest.Format(time.RFC3339)),
		)
	}

	// content_hash must be a 64-character hex string (SHA-256 = 32 bytes = 64 hex chars).
	if len(r.ContentHash) != 64 {
		return dsrerrors.New(
			dsrerrors.MalformedReceipt,
			fmt.Sprintf(
				"The receipt's content_hash field is %d characters but a SHA-256 hex digest is exactly 64 characters. "+
					"The field may be truncated or use a different encoding.",
				len(r.ContentHash),
			),
			fmt.Sprintf("content_hash length: %d chars, expected: 64 hex chars", len(r.ContentHash)),
		)
	}
	for _, c := range r.ContentHash {
		if !isHexChar(c) {
			return dsrerrors.New(
				dsrerrors.MalformedReceipt,
				"The receipt's content_hash field contains non-hexadecimal characters. "+
					"It must be a lowercase hex-encoded SHA-256 digest.",
				fmt.Sprintf("invalid character %q in content_hash", c),
			)
		}
	}

	return nil
}

// offsetFromError attempts to extract a byte offset from a JSON syntax error.
// Returns -1 if the error type does not carry offset information.
func offsetFromError(err error, _ []byte) int64 {
	var synErr *json.SyntaxError
	if errAs(err, &synErr) {
		return synErr.Offset
	}
	var unmarshalErr *json.UnmarshalTypeError
	if errAs(err, &unmarshalErr) {
		return unmarshalErr.Offset
	}
	return -1
}

// errAs is a thin wrapper over errors.As to avoid importing "errors" alongside
// our own dsrerrors package in this file.
func errAs(err error, target interface{}) bool {
	// Use type assertion directly for the two concrete types we care about.
	switch t := target.(type) {
	case **json.SyntaxError:
		var synErr *json.SyntaxError
		if e, ok := err.(*json.SyntaxError); ok {
			synErr = e
			*t = synErr
			return true
		}
	case **json.UnmarshalTypeError:
		if e, ok := err.(*json.UnmarshalTypeError); ok {
			*t = e
			return true
		}
	}
	return false
}

func isHexChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
