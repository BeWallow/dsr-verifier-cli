//go:build race

package bundle_test

import "time"

// bundlePerfLimit is relaxed under -race; CI runs go test -race and is much slower.
const bundlePerfLimit = 90 * time.Second
