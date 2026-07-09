BINARY  := coraza-waf-mod
DIST    := dist

# Version is the nearest git tag; falls back to the commit hash if no tag exists.
# Override with: make dist VERSION=v1.2.3
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  := -s -w -X main.version=$(VERSION)

# Keep in sync with .github/workflows/ci.yml's golangci-lint-action `version:`
# input, so a clean local `make lint` and CI never disagree on results.
LINT_VERSION := v2.12.2

.PHONY: build generate run test lint hooks clean dist checksums tag

build: hooks generate
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) .

generate:
	go generate ./...

run: build
	./$(BINARY)

test: hooks
	go test ./...

# Requires golangci-lint $(LINT_VERSION) — https://golangci-lint.run/welcome/install/
# Config lives in .golangci.yml. Same command CI and the pre-commit hook run.
lint:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint not found. Install $(LINT_VERSION):"; \
		echo "  https://golangci-lint.run/welcome/install/"; \
		exit 1; \
	}
	golangci-lint run ./...

# Points git at the versioned hooks in .githooks/ instead of the untracked,
# per-clone .git/hooks/ directory — there's no way to ship that config in a
# commit, git deliberately never version-controls .git/hooks/. A prerequisite
# of build/test so it's enabled the first time anyone runs either, without
# needing to know this target exists; idempotent and silent once already set,
# so it doesn't nag on every subsequent build.
hooks:
	@if [ "$$(git config --get core.hooksPath 2>/dev/null)" != ".githooks" ]; then \
		git config core.hooksPath .githooks; \
		echo "==> git hooks enabled (.githooks) — golangci-lint runs before every commit"; \
	fi

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
