# Docker image release plan (issue #47)

Status: **implemented, pending Docker Hub secret setup + first tagged release.**
Registry decision: **both** GHCR and Docker Hub. Docker Hub push will fail
until `vars.DOCKERHUB_USERNAME` (repo variable) and `secrets.DOCKERHUB_TOKEN`
(repo secret, a Docker Hub access token) are added in GitHub repo settings —
the GHCR half needs no setup and will work on the first tag regardless.

## What exists today

- `Dockerfile` (repo root): multi-stage `golang:1.26-alpine` builder → `FROM
  scratch` final, `CGO_ENABLED=0`, runs `go generate` (JS minify) then `go
  build`. Entrypoint is the bare binary.
- `docker-compose.yml`: local-dev only (`build: .`, maps `/data` for `--db`/
  `--certs`), not part of any CI/release path.
- `.github/workflows/ci.yml` has a `release` job (`needs: [lint, test]`,
  triggers on `v*` tags) that runs `make dist` + `make checksums` and attaches
  the resulting linux/amd64, linux/arm64, and windows/amd64 binaries to a
  GitHub Release via `softprops/action-gh-release`. It does **not** build or
  push a Docker image anywhere.
- No `.dockerignore`.
- No registry references (GHCR or Docker Hub) anywhere in the repo.

## Problems to fix, not just gaps to fill

- **`FROM scratch` has no CA certificate bundle.** Several subsystems make
  outbound HTTPS/TLS calls that need to verify a server certificate against a
  root CA store: ACME (`autocert.Manager`), the Cloudflare mailer
  (`smtp.mx.cloudflare.net:465` implicit TLS), `threatintel`'s block-list
  downloads, and webhook POSTs to `https://` Slack/Discord/generic endpoints.
  None of these currently have a cert store to validate against in the
  built image — this needs `COPY --from=builder
  /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt`
  (present in the alpine builder stage via `apk add ca-certificates`, alpine
  doesn't ship it by default either) before this is safe to publish.
- **No `.dockerignore`.** `COPY . .` in the builder stage currently sends
  the whole working tree as build context, including `.git/`, any local
  `waf.db`/`certs/` a developer has sitting in the repo root, `dist/`, and
  `.cache/` (the Tailwind CLI download dir) — slow and a minor data-hygiene
  risk for anyone building locally with leftover state.

## Decisions needed before implementing (ask the user, don't assume)

- Registry target: GHCR (`ghcr.io/<org>/coraza-waf-mod`, free, tied to the
  GitHub repo, no separate account) vs. Docker Hub vs. both.
- Multi-arch: mirror `make dist`'s linux/amd64 + linux/arm64 (matches the
  binary release matrix) via `docker buildx build --platform`.
  Windows has no meaningful Docker story here — skip.
- Tag scheme: `vX.Y.Z` + `latest` on the default branch's most recent tag,
  or also a floating `vX.Y` / `vX` per common convention.
- Where persistent data goes in the image contract: document `/data` as the
  expected volume mount (matches `docker-compose.yml`'s existing convention)
  and default `--db`/`--certs` flags in `ENTRYPOINT`/`CMD` to paths under it.

## Implementation steps

1. [x] Add `.dockerignore` (`.git`, `.githooks`, `.cache`, `dist`, `*.db`/
       `*.db-wal`/`*.db-shm`, `waf.db*`, `certs`, `coraza-waf-mod` binary).
2. [x] Fix `Dockerfile`: `apk add ca-certificates` in the builder stage,
       `COPY --from=builder /etc/ssl/certs/ca-certificates.crt ...` into the
       `scratch` final stage. `ARG VERSION=dev` baked via
       `-ldflags "-X main.version=${VERSION}"`, same convention `make dist`
       uses for native binaries.
3. [x] `/data` volume convention: `VOLUME ["/data"]`, `EXPOSE 8080`, default
       `CMD ["--db", "/data/waf.db", "--certs", "/data/certs"]` on the image
       so `docker run` works with zero extra args. `docker-compose.yml`
       simplified to drop its now-redundant explicit `command:`.
4. [x] Added a `docker` job to `.github/workflows/ci.yml` (`needs: [lint,
       test]`, `if: startsWith(github.ref, 'refs/tags/v')` — same gate as
       `release`), using `docker/setup-qemu-action` +
       `docker/setup-buildx-action` + `docker/login-action` (GHCR via
       `github.actor`/`GITHUB_TOKEN`, Docker Hub via
       `vars.DOCKERHUB_USERNAME`/`secrets.DOCKERHUB_TOKEN`) +
       `docker/metadata-action` + `docker/build-push-action`.
5. [x] Multi-arch build via buildx (`linux/amd64,linux/arm64`).
6. [x] Release-notes heredoc in `ci.yml` now has a "## Docker" section with a
       `docker run` quick-start pointing at the GHCR tag.
7. [x] Smoke-tested locally end-to-end (see Findings below) — caught and
       fixed a real crash-loop bug, not just "it built."
8. [x] `CHANGELOG.md` entry under `[Unreleased]`.
9. [x] `CLAUDE.md`'s "Distribution" section rewritten to describe the image
       as a first-class release artifact, the CA-bundle and `TMPDIR` fixes,
       and the `docker` CI job.

## Findings from local smoke-testing

- `docker build` succeeds; final image is **73.5 MB** (bundled GeoLite2 +
  DB-IP ASN mmdb databases plus the CRS ruleset account for most of that on
  top of a scratch base).
- `--version` correctly reports the baked `VERSION` build-arg instead of
  `dev`.
- CA bundle confirmed present at `/etc/ssl/certs/ca-certificates.crt` inside
  the image.
- **Caught a real crash-loop bug during smoke-testing, now fixed**: Coraza's
  engine-init filesystem-access check does `os.CreateTemp(os.TempDir(), ...)`
  — `scratch` has no `/tmp` directory at all, so every container startup
  failed with `waf init: ... open /tmp/checkfsfile...: no such file or
  directory` before a single request could be served. Fixed by setting
  `ENV TMPDIR=/data` in the final stage (`/data` always exists via the
  declared volume) rather than trying to fabricate an empty `/tmp` via a
  `COPY --from=builder /tmp /tmp` trick.
- After the fix: container starts cleanly, logs show the normal startup
  sequence (geo/ASN DB load, cache-return listener, `coraza-waf listening on
  :8080`), and `GET /admin/login` returns `200` through a published port.

## Remaining before this is actually "released"

- [ ] User needs to add `DOCKERHUB_USERNAME` (repo **variable**, not secret —
      a username isn't sensitive) and `DOCKERHUB_TOKEN` (repo **secret**, a
      Docker Hub access token, not the account password) in GitHub repo
      Settings → Secrets and variables → Actions, before the first tag push,
      or the `docker` job's Docker Hub half will fail (GHCR half is
      unaffected either way).
- [ ] First real tagged release to confirm the `docker` job passes in CI
      exactly as it did locally (buildx multi-arch in CI can occasionally
      surface QEMU-emulation issues that a native-arch local build won't).

## Explicitly out of scope

- Any change to how config is supplied (still CLI flags + DB-backed
  settings, no env-var config layer) — a container is just a packaging
  target, not a reason to add a config file per "No config file, by design."
