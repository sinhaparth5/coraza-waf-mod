# Repository Guidelines

## Project Structure & Module Organization

This is a single-binary Go WAF and reverse proxy with an embedded admin UI. `main.go` wires startup, config, TLS, pruning, and server modes. Core packages are split by responsibility: `config/` for YAML loading, `waf/` for Coraza setup, `proxy/` for the request pipeline, `services/` for DB-backed routing and TLS, `storage/` for SQLite, `blocklist/` and `geo/` for blocking rules, and `metrics/` for Prometheus output. The admin dashboard lives in `ui/handlers.go` and `ui/templates/`. Frontend sources are in `static/js/src/`; generated minified files go to `static/js/dist/` and are embedded through `assets.go`. Deployment assets are under `deploy/`.

## Build, Test, and Development Commands

- `make build`: runs `go generate ./...` and builds `./coraza-waf-mod`.
- `make run`: builds, then starts the binary.
- `make test`: runs `go test ./...`.
- `make clean`: removes the binary, generated minified JS, and `dist/`.
- `make dist`: creates stripped Linux `amd64` and `arm64` release binaries in `dist/`.
- `make checksums`: writes `dist/checksums.txt` after `make dist`.

After editing `static/js/src/*.js`, use `make build` or run `go generate ./...` before any direct `go build`.

## Coding Style & Naming Conventions

Use standard Go formatting: run `gofmt` on changed Go files and keep package names short, lowercase, and role-based. Export names only for cross-package APIs. Templates use Tailwind utilities loaded from the CDN in `ui/templates/base.html`; avoid adding a Node build pipeline, inline `style` attributes, or separate CSS for utilities Tailwind can express.

## Testing Guidelines

There are currently no checked-in `*_test.go` files. Add tests next to the package being changed, using Go’s standard `testing` package and names like `TestRegistryMatchPrefixPriority`. Run `make test` before submitting. For focused work, use `go test ./proxy -run TestName -v` with the relevant package path.

## Commit & Pull Request Guidelines

Recent commits use short, imperative or descriptive lowercase summaries such as `added metrics api` and `migrated to tailwindcss`. Keep commits focused and mention the affected area when useful. Pull requests should include a brief description, test results, config or migration notes, and screenshots for dashboard UI changes. Link issues when available and call out behavior affecting routing, TLS, storage, or blocking decisions.

## Security & Configuration Tips

Do not commit real admin credentials, TLS private keys, GeoIP databases, or production `waf.db` files. Use `deploy/config.yaml.example` for documented configuration defaults and keep local secrets in `config.yaml` out of shared changes.
