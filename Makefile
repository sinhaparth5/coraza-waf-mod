BINARY := coraza-waf-mod
DIST   := dist

.PHONY: build generate run test clean dist checksums

build: generate
	go build -o $(BINARY) .

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
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(DIST)/$(BINARY)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $(DIST)/$(BINARY)-linux-arm64 .

# Run after `make dist`. Produces dist/checksums.txt for users to verify
# their download with `sha256sum --check checksums.txt`.
checksums:
	cd $(DIST) && sha256sum $(BINARY)-linux-amd64 $(BINARY)-linux-arm64 > checksums.txt
