package verify

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	dsrerrors "github.com/deja-dev/dsr-verifier-cli/internal/errors"
)

// PublicKeyWithID bundles a parsed public key with the key_id extracted
// from the PEM comment header. The Key field holds one of:
//
//   - ed25519.PublicKey
//   - *rsa.PublicKey
//   - *ecdsa.PublicKey
type PublicKeyWithID struct {
	Key   interface{}
	KeyID string
}

// ParsePublicKeyFile parses a public key from PEM-encoded bytes.
// The file may contain an optional header comment in the form:
//
//	# key_id: <id>
//
// placed before the PEM block. If the comment is absent, KeyID is empty.
// The PEM block must use the PKIX SubjectPublicKeyInfo encoding
// ("BEGIN PUBLIC KEY"). Supported key types: ed25519, RSA, ECDSA.
func ParsePublicKeyFile(data []byte) (*PublicKeyWithID, *dsrerrors.VerificationError) {
	keyID := extractKeyID(data)

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, dsrerrors.New(
			dsrerrors.KeyParseError,
			"The public key file does not contain a PEM-encoded key block. "+
				"Expected a file beginning with '-----BEGIN PUBLIC KEY-----'.",
			"pem.Decode returned nil; no PEM block found in key file",
		)
	}

	if block.Type != "PUBLIC KEY" {
		return nil, dsrerrors.New(
			dsrerrors.KeyParseError,
			fmt.Sprintf(
				"The public key file contains a %q PEM block but this verifier expects a %q block "+
					"(PKIX SubjectPublicKeyInfo encoding).",
				block.Type, "PUBLIC KEY",
			),
			fmt.Sprintf("pem block type: %q, expected: %q", block.Type, "PUBLIC KEY"),
		)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, dsrerrors.New(
			dsrerrors.KeyParseError,
			"The public key file could not be parsed. The PEM block may be corrupt or use "+
				"an encoding other than PKIX SubjectPublicKeyInfo.",
			fmt.Sprintf("x509.ParsePKIXPublicKey error: %s", err.Error()),
		)
	}

	switch k := pub.(type) {
	case ed25519.PublicKey:
		return &PublicKeyWithID{Key: k, KeyID: keyID}, nil
	case *rsa.PublicKey:
		return &PublicKeyWithID{Key: k, KeyID: keyID}, nil
	case *ecdsa.PublicKey:
		return &PublicKeyWithID{Key: k, KeyID: keyID}, nil
	default:
		return nil, dsrerrors.New(
			dsrerrors.KeyParseError,
			fmt.Sprintf(
				"The public key file contains a %T key but this verifier supports only "+
					"ed25519, RSA, and ECDSA keys for DSR/1.0.1 receipts.",
				pub,
			),
			fmt.Sprintf("key type: %T, supported: ed25519.PublicKey, *rsa.PublicKey, *ecdsa.PublicKey", pub),
		)
	}
}

// extractKeyID scans the lines before the first PEM block for a comment of
// the form "# key_id: <value>" and returns the trimmed value.
// Returns an empty string if no such comment is found.
func extractKeyID(data []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "-----BEGIN") {
			break
		}
		if strings.HasPrefix(line, "#") {
			rest := strings.TrimPrefix(line, "#")
			rest = strings.TrimSpace(rest)
			if strings.HasPrefix(rest, "key_id:") {
				id := strings.TrimPrefix(rest, "key_id:")
				return strings.TrimSpace(id)
			}
		}
	}
	return ""
}
