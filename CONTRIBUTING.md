# Contributing to Coraza WAF Mod

Thanks for your interest in improving Coraza WAF Mod — a single-binary Go WAF +
reverse proxy with an embedded HTMX/Tailwind admin dashboard. This guide covers
how to build, test, and submit changes.

By contributing, you agree that your contributions are licensed under the
project's [Apache License 2.0](LICENSE).

## Prerequisites

- **Go 1.25+** (the module targets `go 1.25`).
- That's it. Every dependency is pure Go — the SQLite driver is
  `modernc.org/sqlite` (no CGO), and there is **no Node/npm toolchain**. The
  admin UI's JS is minified by a small pure-Go tool in `tools/minify`, run via
  `go:generate`.

## Getting started

```bash
git clone https://gitlab.com/sinhaparth5/coraza-waf-mod.git
cd coraza-waf-mod
make build      # go generate (minifies JS) + go build -> ./coraza-waf-mod
make test       # go test ./...
```

Run a single package's tests while iterating:

```bash
go test ./proxy/ -run TestName -v
```

Tests live alongside the code they cover — `proxy/`, `ratelimit/`, `ja3/`,
`ja4/`, `storage/`, `mailer/`, `autoban/`, `challenge/`, `services/`, `ui/`.

## Build rules that will bite you

- **After editing any `static/js/src/*.js`, never run bare `go build`.** The
  minifier only runs through `go:generate`, which fires via `make build` /
  `make dist` — not `go build`. If you must use `go build` directly, run
  `go generate ./...` first, otherwise the embedded `*.min.js` served by the
  binary will be stale.
- Don't start the server as part of routine work. Verify behaviour with
  `go test` (throwaway tests are fine — delete them once they pass) rather than
  running `make run` / `go run .`.

## Coding conventions

- Run **`gofmt`** on every changed Go file. Keep package names short, lowercase,
  and role-based; export only what crosses a package boundary.
- Prefer **table-driven tests** (e.g. `TestRegistryMatchPrefixPriority`), and add
  cases next to the package you changed.
- **Frontend:** styling is Tailwind via the CDN Play script — there is no
  `tailwind.config.js`, PostCSS, or purge step. Use `class="..."` utilities
  (including arbitrary-value syntax like `w-[34px]`); do **not** add
  `style="..."` attributes or `<style>` blocks for anything Tailwind can
  express, and toggle visibility with `classList`, not `element.style.*`.
- **Templates:** Go `html/template` content outside a `{{define}}` block is never
  rendered — keep modal/partial markup inside the right block.
- **Config direction:** there is no config file. Bootstrap settings (listen
  addresses, TLS binding, WAF rules dir, DB path, retention) are CLI flags —
  see `coraza-waf-mod --help`-equivalent flag list in `main.go`'s `main()`. All
  runtime knobs (bot protection, Redis, ACME email, per-service overrides,
  etc.) are stored in the SQLite `meta` table / per-service columns and
  managed from the admin UI.

See [`CLAUDE.md`](CLAUDE.md) for a deep architecture tour (request pipeline,
hot-reload pattern, SQLite concurrency and date/time gotchas, cache sandwich,
etc.) before making non-trivial changes.

## Security & secret hygiene

Never commit any of the following:

- Real admin credentials, TLS private keys, or Cloudflare/API tokens.
- A production `waf.db`, or bundled GeoIP/ASN databases beyond what the repo
  already ships.

Admin credentials are seeded via `coraza-waf-mod setup` (password read from
stdin, never a flag or file — see `--help`). When adding a new configurable
secret, follow the existing pattern: store it in the `meta` table, enter it
from the Settings page, and never echo it back to the UI or ship it in the
binary/installer.

Found a security vulnerability? Please **do not** open a public issue — report it
privately to the maintainer (see `git log` for the contact address) so it can be
fixed before disclosure.

## Submitting changes

This project is hosted on **GitLab**; changes are proposed as **merge requests**.

1. Branch off `main` (e.g. `git checkout -b 42-fix-threat-intel-delete`).
2. Make focused commits with short, imperative or descriptive summaries — match
   the existing history (e.g. `ci: run go generate before go test to produce
   embedded JS assets`). Mention the affected area when useful.
3. Run `make test` (and `gofmt`) before pushing.
4. Open a merge request that includes:
   - a brief description of the change and its motivation;
   - test results, plus any config or migration notes;
   - screenshots for dashboard/UI changes;
   - an explicit call-out for anything affecting routing, TLS, storage, or
     blocking decisions.
5. Add a `## [Unreleased]` entry to [`CHANGELOG.md`](CHANGELOG.md) for anything
   user-visible.

Preserve unrelated changes in the working tree, and keep each MR scoped to one
logical change.

## Releases

Releases are cut by the maintainer with `make tag VERSION=vX.Y.Z`, which pushes
an annotated tag and triggers the GitLab release pipeline. The project follows
[Semantic Versioning](https://semver.org/). Contributors don't need to tag —
just land your `Unreleased` changelog entry and it will roll into the next tag.
