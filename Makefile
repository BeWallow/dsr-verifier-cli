.PHONY: test vet build verify-vector-parity

test:
	go test -race -count=1 -timeout=120s ./...

vet:
	go vet ./...

build:
	go build -trimpath -buildvcs=false ./cmd/dsr-verifier-cli

# verify-vector-parity — diff the vendored RV canonical vector against the
# authoritative copy in the wallow repo. Requires WALLOW_REPO to point at
# the root of the wallow repository checkout (default: ../wallow).
WALLOW_REPO ?= ../wallow

verify-vector-parity:
	@diff -q testdata/protocol/rv-canonical-vector.json \
	  $(WALLOW_REPO)/docs/dsr/rv-canonical-vector.json || \
	  (echo "ERROR: RV vector copies have diverged — sync required" && exit 1)
	@echo "vector-parity OK"
