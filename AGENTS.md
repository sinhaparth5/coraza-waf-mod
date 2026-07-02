# Repository Guidelines

## Project Structure & Module Organization

This is a single-binary Go WAF and reverse proxy with an embedded admin UI. `main.go` wires startup, config, TLS, pruning, and server modes. Core packages include `config/`, `waf/`, `proxy/`, `services/`, `storage/`, and `metrics/`. Blocking and detection logic lives in `blocklist/`, `geo/`, `asn/`, `bot/`, `ja3/`, `ratelimit/`, and `threatintel/`. The dashboard lives in `ui/handlers.go` and `ui/templates/`. Frontend sources are in `static/js/src/`; generated files go to `static/js/dist/`.

## Build, Test, and Development Commands

- `make build`: runs `go generate ./...` and builds `./coraza-waf-mod`.
- `make generate`: regenerates embedded/minified assets without building.
- `make run`: builds and starts the binary.
- `make test`: runs `go test ./...`.
- `make clean`: removes the binary, generated minified JS, and `dist/`.
- `make dist`: creates stripped release binaries in `dist/`.
- `make checksums`: writes `dist/checksums.txt` after `make dist`.
- `make tag VERSION=v1.0.0`: creates and pushes an annotated release tag.

After editing `static/js/src/*.js`, run `make generate` or `make build` before any direct `go build`.

## Coding Style & Naming Conventions

Use standard Go formatting: run `gofmt` on changed Go files and keep package names short, lowercase, and role-based. Export names only for cross-package APIs. Prefer table-driven tests for routing, blocking, and config behavior. Templates use Tailwind utilities from `ui/templates/base.html`; avoid adding a Node build pipeline, inline `style` attributes, or separate CSS for utilities Tailwind can express.

## Testing Guidelines

Tests exist in `proxy/`, `ratelimit/`, `ja3/`, and `ui/`. Add tests next to the package being changed, using Go’s standard `testing` package and names like `TestRegistryMatchPrefixPriority`. Run `make test` before submitting. For focused work, use `go test ./proxy -run TestName -v` with the relevant package path.

## Commit & Pull Request Guidelines

Recent commits use short, imperative or descriptive summaries such as `ci: run go generate before go test to produce embedded JS assets`. Keep commits focused and mention the affected area when useful. Pull requests should include a brief description, test results, config or migration notes, and screenshots for dashboard UI changes. Call out behavior affecting routing, TLS, storage, or blocking decisions.

## Security & Configuration Tips

Do not commit real admin credentials, TLS private keys, GeoIP databases, or production `waf.db` files. Use `deploy/config.yaml.example` for documented defaults and keep local secrets in `config.yaml`.

## Agent-Specific Instructions

Before editing, check the worktree and preserve unrelated user changes. After changing Go or frontend source, run the narrowest relevant test or generation command.
