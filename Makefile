BINARY  := coraza-waf-mod
DIST    := dist

# Version is the nearest git tag; falls back to the commit hash if no tag exists.
# Override with: make dist VERSION=v1.2.3
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  := -s -w -X main.version=$(VERSION)

.PHONY: build generate run test clean dist checksums tag

build: generate
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) .

generate:
	go generate ./...

run: build
	./$(BINARY)

test:
	go test ./...

clean:
	rm -f $(BINARY)
	rm -f static/js/dist/*.min.js
	rm -rf $(DIST)

# Cross-compiled, stripped release binaries (no CGO, so this works without
# any target toolchain installed). -s -w drop debug symbols/DWARF — smaller
# download, and end users never need to attach a debugger to this binary.
dist: generate
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-arm64 .
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY)-windows-amd64.exe .

# Run after `make dist`. Produces dist/checksums.txt for users to verify
# their download with `sha256sum --check checksums.txt`.
checksums:
	cd $(DIST) && sha256sum $(BINARY)-linux-amd64 $(BINARY)-linux-arm64 $(BINARY)-windows-amd64.exe > checksums.txt

# Create and push a version tag to trigger the CI release pipeline.
# Usage: make tag VERSION=v1.0.0
tag:
	@test -n "$(VERSION)" || (echo "Usage: make tag VERSION=v1.0.0" && exit 1)
	@echo "==> Tagging $(VERSION)"
	git tag -a $(VERSION) -m "Release $(VERSION)"
	git push origin $(VERSION)
	@echo "==> GitHub Actions release workflow started — watch it at:"
	@echo "    https://github.com/sinhaparth5/coraza-waf-mod/actions"
