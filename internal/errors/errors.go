// Package dsrerrors defines auditor-friendly typed errors for verification failures.
//
// Every failure carries three things:
//   - Class: a stable machine-readable identifier (safe to match in scripts)
//   - HumanMessage: why the failure matters in plain language
//   - TechnicalDetail: algorithm names, computed values, expected values
//
// Error messages are written for a CPA or compliance professional reading an
// audit report — not for the developer who built the CLI.
package dsrerrors

// ErrorClass is a stable, machine-readable identifier for a failure category.
// Callers may switch on these values; they will not change within a major version.
type ErrorClass string

const (
	// SignatureInvalid means the ed25519 signature does not verify against the
	// provided public key and the receipt's signed payload. The receipt may have
	// been produced by a different key, or the signature bytes were corrupted.
	SignatureInvalid ErrorClass = "signature_invalid"

	// ContentHashMismatch means the SHA-256 hash of the receipt's current content
	// does not match the content_hash field that was signed. The content was
	// modified after the receipt was issued.
	ContentHashMismatch ErrorClass = "content_hash_mismatch"

	// KeyAuthorityMismatch means the key_id embedded in the receipt does not
	// match the key_id declared in the provided public key file. The auditor
	// is using the wrong key for this receipt.
	KeyAuthorityMismatch ErrorClass = "key_authority_mismatch"

	// MalformedReceipt means the receipt file could not be parsed as a valid
	// DSR/1.0.1 receipt. The file may be corrupt, truncated, or not a DSR receipt.
	MalformedReceipt ErrorClass = "malformed_receipt"

	// MalformedCausalRef means one or more causal artifact references in the
	// receipt content (PR identifiers, commit SHAs) do not match the expected
	// format for their type.
	MalformedCausalRef ErrorClass = "malformed_causal_ref"

	// KeyParseError means the public key file could not be parsed as a valid
	// public key in PEM or DER format.
	KeyParseError ErrorClass = "key_parse_error"

	// UnsupportedAlgorithm means the receipt declares a signing algorithm that
	// this verifier does not implement. Supported algorithms are ed25519,
	// rsa-pss-sha256, and ecdsa-sha256.
	UnsupportedAlgorithm ErrorClass = "unsupported_algorithm"
)

// VerificationError is a typed, auditor-friendly verification failure.
type VerificationError struct {
	// Class is the stable machine-readable error category.
	Class ErrorClass `json:"error_class"`

	// HumanMessage explains why the failure matters in plain language.
	// Written for a CPA or compliance professional, not a developer.
	HumanMessage string `json:"human_message"`

	// TechnicalDetail provides algorithm names, computed values, and expected
	// values so the failure is reproducible and self-documenting.
	TechnicalDetail string `json:"technical_detail"`
}

func (e *VerificationError) Error() string { return e.HumanMessage }

// New constructs a VerificationError.
func New(class ErrorClass, human, detail string) *VerificationError {
	return &VerificationError{
		Class:           class,
		HumanMessage:    human,
		TechnicalDetail: detail,
	}
}

// ParseErrorDetail carries line and column information for JSON parse failures.
type ParseErrorDetail struct {
	// Offset is the byte offset in the input where parsing failed.
	Offset int64
	// Msg is the underlying parser message.
	Msg string
}
