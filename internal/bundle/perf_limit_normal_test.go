//go:build !race

package bundle_test

import "time"

// bundlePerfLimit is the 10k-receipt budget on release builds (no race detector).
const bundlePerfLimit = 10 * time.Second
