package verify

import "encoding/json"

// unmarshal is a package-local alias so verify.go can call it without
// importing encoding/json twice alongside the dsr package.
func unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
