package verify

import (
	"crypto/x509"
	"encoding/json"
)

// unmarshal is a package-local alias so verify.go can call it without
// importing encoding/json twice alongside the dsr package.
func unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// marshalPKIX is a package-local alias for x509.MarshalPKIXPublicKey so that
// verify.go can call it without a direct x509 import (key.go already imports it
// within the same package; this avoids a duplicate-import lint concern).
func marshalPKIX(pub interface{}) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}
