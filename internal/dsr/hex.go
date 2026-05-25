package dsr

import (
	"encoding/hex"
	"fmt"
)

func hexDecode(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}
	return b, nil
}

func hexEncode(b []byte) string {
	return hex.EncodeToString(b)
}
