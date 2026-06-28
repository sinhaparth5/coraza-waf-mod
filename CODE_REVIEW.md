# Code Review — Production Readiness Findings

> Generated 2026-06-28. Whole-application audit (no code diff under review — `HEAD == origin/main`).
> Scope: find unused code to delete, things to add, and places that can break in production.
>
> Each finding below is written to be copy-pasted into a GitLab issue. Severity legend:
> 🔴 breakdown risk · 🟠 missing / production-readiness gap · 🧹 cleanup.
>
> **Already actioned in this review** (committed as dead-code removal, build verified):
> - `challenge/challenge.go` — removed unused `GenerateSecret()`
> - `ui/broadcast.go` — removed unused `SubscriberCount()` and `Recent()`
> - `proxy/security.go` — removed unused `BackendSecurityHeaders` var (stale; `services/registry.go` hardcodes its own copy)

---

## 🔴 1. JA3 `connStore` grows without bound — memory leak

- **File:** `ja3/ja3.go:27` (`var connStore sync.Map`), write at `main.go:379-385`, read at `proxy/handler.go:153`
- **Problem:** `connStore` is keyed by `remoteAddr` (`host:ephemeral-port`, unique per connection) and written on every TLS handshake. There is **no `Delete`, no TTL, no eviction** anywhere in the package. `Get` reads but never removes.
- **Failure scenario:** Any TLS-enabled deployment accumulates one map entry per connection forever. Under real traffic (millions of connections/day) the map grows until OOM. Unlike the rate limiter, which has a janitor, this store has zero cleanup.
- **Suggested fix:** Delete the entry in the handler right after `Get` (the fingerprint is only needed once per request), or add a TTL janitor goroutine mirroring the rate-limiter pattern.

## 🔴 2. No graceful shutdown — log queue and rate-limit state lost on SIGTERM/SIGINT

- **File:** `main.go:264-291` (only `SIGHUP` trapped; `e.Start()` blocks at :288)
- **Problem:** `defer db.Close()` / `rl.Stop()` / `webhookPusher.Stop()` / `intelWorker.Stop()` only run on normal `main` return, which never happens. `systemctl stop` / container stop sends SIGTERM, which terminates the process **without running defers**.
- **Failure scenario:** On every restart/deploy: `DB.Close()` (drains the 10k-deep `logQueue`) never runs → queued request logs silently dropped; `Limiter` final state save never fires → last ≤10s of token-bucket state lost; in-flight requests cut rather than drained.
- **Suggested fix:** `signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)`; on receipt call `e.Shutdown(ctx)` with a timeout, then run the cleanup that the defers do.

## 🔴 3. `X-Forwarded-For` / `X-Real-IP` trusted from any source → rate-limit & IP-block bypass

- **File:** `proxy/handler.go:582-591` (`realIP`)
- **Decision (from review):** deployment is **both / configurable** — WAF may sit behind Cloudflare/LB *or* be directly internet-facing.
- **Problem:** `CF-Connecting-IP` is correctly gated to Cloudflare ranges, but `X-Forwarded-For` and `X-Real-IP` are trusted **unconditionally** otherwise. `realIP()` feeds the IP blocklist, geo block, and rate limiter.
- **Failure scenario:** Direct-origin access → attacker sends a unique forged `X-Forwarded-For` per request → fresh token bucket with full burst every time (global + per-service rate limiter fully bypassed), and the limiter's bucket map balloons before the janitor reclaims it. A forged IP can also evade an IP block or poison logs/blocking of a victim IP.
- **Suggested fix:** Add a configurable **trusted-proxy CIDR allowlist**. Only honor `X-Forwarded-For` / `X-Real-IP` when `RemoteAddr` is within an allowlisted range; otherwise use the real socket peer. Default to **not** trusting forwarded headers.

## 🔴 4. `log.Fatalf` in the HTTP redirect goroutine kills the whole server

- **File:** `main.go:341-347`
- **Problem:** The plain-HTTP listener (ACME challenge + HTTPS redirect) runs in a goroutine that calls `log.Fatalf` if `ListenAndServe` returns a non-`ErrServerClosed` error. `log.Fatalf` calls `os.Exit`.
- **Failure scenario:** TLS is up and serving, but port :80 is taken / transiently unbindable → `os.Exit` tears down the healthy HTTPS server too.
- **Suggested fix:** Log the error (non-fatal); the HTTPS listener should keep serving.

## 🔴 5. `RedisBackend.Allow` indexes the reply slice without a length check

- **File:** `ratelimit/redis.go:102-111`
- **Problem:** On `err == nil` it accesses `vals[0]`, `vals[1]`, `vals[2]` directly with no `len(vals) >= 3` check.
- **Failure scenario:** A short/unexpected Lua reply (script reloaded oddly, Redis proxy mangling the reply, a future script edit) → index-out-of-range panic → Echo Recover turns it into a 500. Every affected request fails instead of failing open like the error path does.
- **Suggested fix:** Check `len(vals) >= 3` before indexing; on mismatch, fail open (allow) like the existing `err != nil` path.

## 🔴 6. Unbounded request-body read into memory on the WAF hot path

- **File:** `waf/engine.go:110-115`
- **Problem:** `io.ReadAll(r.Body)` buffers the **entire** body into RAM before `WriteRequestBody` enforces `SecRequestBodyLimit` (13 MB). No `http.MaxBytesReader` in front.
- **Failure scenario:** A client POSTs a multi-GB or chunked (no Content-Length) body. The full payload is allocated before the limit is consulted; a few concurrent large uploads exhaust memory. Every proxied request with a body also pays full in-memory buffering (no streaming).
- **Suggested fix:** Wrap `r.Body` with `http.MaxBytesReader` (or check Content-Length) capped at the WAF body limit before reading; consider streaming for bodies under the limit.

## 🔴 7. `sessions` table is never pruned

- **File:** `storage/db.go:1292-1306` (`ValidateSession`)
- **Problem:** TTL (24h) is checked in Go at read time, but expired rows are never deleted (only explicit logout / credential change removes rows).
- **Failure scenario:** Long-lived deployment accumulates dead session rows indefinitely, slowly bloating the DB.
- **Suggested fix:** Add a periodic delete of expired sessions (piggyback on the existing prune CLI/timer, or a lightweight startup/interval sweep).

---

## 🟠 8. Default admin credentials seeded and printed on every startup

- **File:** `main.go:117-120`; `storage/db.go` `SeedTestAdmin()`
- **Problem:** `SeedTestAdmin()` creates `admin@localhost` / `admin123` whenever no admin exists, and `log.Printf("admin login: admin@localhost / admin123 ...")` logs it on **every** boot regardless. A deploy that skips the `setup` subcommand ships publicly-known admin credentials.
- **Failure scenario:** Full admin takeover — disable WAF, add IP allow rules, exfiltrate DB.
- **Suggested fix:** Gate seeding behind a dev build tag or remove it; require the `setup` subcommand to create the first admin; never log the password.

## 🟠 9. Session and challenge cookies missing the `Secure` flag

- **File:** `ui/handlers.go:270-277` (session), `challenge/challenge.go:156-163` (bot-bypass)
- **Problem:** Both set `HttpOnly` + `SameSite=Lax` + `Path:"/"` but never `Secure: true`.
- **Failure scenario:** On a TLS deployment the cookie rides the initial plain-HTTP request (before redirect), exposing it to network MITM.
- **Suggested fix:** Set `Secure: true` when TLS is enabled.

## 🟠 10. SSRF: server-side fetch of admin-supplied URLs with no validation or timeout

- **File:** `threatintel/worker.go:119` (`fetchIPs`), `webhook/pusher.go:78` (`deliver`); storage at `ui/handlers.go:1422` (`SaveWebhookConfig`), `ui/handlers.go:853` (`AddThreatIntelSource`)
- **Problem:** Outbound GET/POST to arbitrary admin-supplied URLs with no scheme allowlist, no block of private/link-local ranges (e.g. `http://169.254.169.254/...` cloud metadata), and no per-request context timeout. URLs are stored with zero validation (not even an `http(s)://` check).
- **Failure scenario:** SSRF pivot to internal services / cloud metadata; a hanging endpoint ties up the worker/pusher.
- **Suggested fix:** Validate scheme (`http`/`https` only) on save; reject URLs resolving to private/loopback/link-local ranges; add `context.WithTimeout` to both requests.

## 🟠 11. No CSRF protection on admin mutations; DB backup is a GET

- **File:** admin routes in `ui/handlers.go`; backup at `ui/handlers.go:238,1542` (`GET /admin/settings/backup`)
- **Problem:** No CSRF token middleware anywhere; only `SameSite=Lax` defends mutations. `GET /admin/settings/backup` streams the entire SQLite DB (bcrypt admin hash + challenge secret), and Lax permits top-level cross-site GET navigation.
- **Failure scenario:** Cross-site request forges admin mutations; a crafted link exfiltrates the full DB.
- **Suggested fix:** Add CSRF tokens to all POST/DELETE forms; make backup a POST.

## 🟠 12. No brute-force throttle on the login endpoint

- **File:** `ui/handlers.go:253` (`LoginPost`)
- **Problem:** No rate limit / lockout / backoff. The proxy rate limiter runs only inside `proxy.Handle` (catch-all proxy route), not on the Echo admin group, so `/admin/login` accepts unlimited password guesses.
- **Failure scenario:** Online password brute force is feasible.
- **Suggested fix:** Per-IP attempt throttle / temporary lockout on the login route.

## 🟠 13. No request-body size limit on admin / upload / login endpoints

- **File:** admin Echo group (`ui/handlers.go`); cert uploads `AddCertificate` / `UploadServiceTLS`
- **Problem:** No `middleware.BodyLimit` / `http.MaxBytesReader` on admin handlers (the only limit is `SecRequestBodyLimit` in the WAF, which covers proxied traffic, not admin routes). Cert uploads and even unauthenticated `LoginPost` read the whole body into memory.
- **Failure scenario:** Unauthenticated large POST → memory exhaustion / DoS.
- **Suggested fix:** Add `middleware.BodyLimit` to the admin group with sensible caps (larger for cert upload).

## 🟠 14. No health / readiness endpoint

- **File:** routing in `main.go`
- **Problem:** No `/healthz` / `/readyz` / liveness route exists. systemd / LB / orchestrator cannot probe whether the proxy is up and the DB reachable.
- **Suggested fix:** Add a lightweight unauthenticated health endpoint (optionally pinging the DB).

## 🟠 15. Challenge verify endpoint: unbounded JSON body + replayable nonce

- **File:** `challenge/challenge.go:116-136`
- **Problem:** `json.NewDecoder(r.Body).Decode` has no size cap; a solved `(nonce, exp, sig)` tuple is valid until `exp` (~2 min) with no single-use enforcement.
- **Failure scenario:** `/_cz/verify` accepts an arbitrarily large body (minor DoS); a captured valid solution can be replayed within the ~2-minute window to mint multiple bypass cookies.
- **Suggested fix:** Cap the body size; track used nonces (e.g. short-lived set) to enforce single use.

---

## 🟠 16. Silent error swallowing in state-changing paths

- **Files:**
  - `ui/handlers.go:1106` (`DeleteCertificate`) ignores `registry.Reload` error (`//nolint`) → a deleted cert can keep being served.
  - `ui/handlers.go:997-998` (`AddService`) discards rps/burst parse errors.
  - `ui/handlers.go:597` (`LogDetail`) ignores `json.Unmarshal` of stored headers.
  - `challenge.ServePage` / `ServeVerify` ignore template execute errors.
- **Suggested fix:** Surface or log these failures so operators can see them; at minimum log the `Reload` error in `DeleteCertificate`.

---

## 🧹 Dead config not yet removed (needs a decision)

Both are populated in `config.Defaults()` but never read anywhere (bot settings live in the DB `meta` table per CLAUDE.md):

- `config/config.go:25` — `type App` + `config/config.go:15` `Config.Apps` field. The real migration calls `db.MigrateConfigApps(nil)` with `storage.ConfigApp`, not `config.App`. (Keep `storage.ConfigApp` — still used.)
- `config/config.go:62` — `type BotProtectionConfig` (`Enabled`, `AnomalyThreshold`, `ChallengeTTLSeconds`) + `config/config.go:22` `Config.BotProtection` field — write-only dead config.

**Suggested fix:** Remove both structs and their `Config` fields plus their lines in `Defaults()`.

---

## Notes — checked and found OK (not issues)

- `asn.Lookup` has a nil-receiver guard, so the `asnLookup = nil` path is safe.
- The SQLite `date()`/`strftime()` ban is respected everywhere — all bucketing done in Go.
- The log queue drops-on-full rather than blocking the request path.
- Prune runs in batches with pauses (no long write-lock hold).
- Path traversal on cert dirs is handled (`unsafeNameChars` sanitization + numeric pool ID).
- Hot-path locking uses the read-snapshot-then-release `RWMutex` pattern correctly throughout `Handle`.
- `go build ./...` and `go vet ./...` are clean; `staticcheck` reports only one S1005 style nit at `ui/handlers.go:1427`.

## Test coverage gaps (for later)

Only `proxy/handler_test.go` and `ratelimit/ratelimit_test.go` exist. Highest-value untested critical paths: session auth / login (`ui`), challenge HMAC/PoW verify (`challenge`), threat-intel + cert parsing.

---

## Additional findings from follow-up review (2026-06-28)

## 🔴 17. Global in-memory rate limiting is disabled by default and the UI cannot enable it

- **File:** `config/config.go:78`, `ratelimit/ratelimit.go:83-91`, `main.go:549-563`
- **Problem:** `Defaults()` sets `RequestsPerSecond` and `Burst`, but leaves `RateLimit.Enabled` as Go's zero value (`false`). The in-memory backend is built with `ratelimit.New(cfg.RateLimit)`, and `Allow()` immediately allows everything when `enabled == false`. The admin settings page only switches between memory and Redis; it does not persist or set the global enabled/RPS/burst values.
- **Failure scenario:** A default install using the advertised "memory+SQLite" backend has **no global rate limiting at all**, even though the defaults imply 10 rps / burst 20 and the dashboard can show rate-limit controls. Redis mode does enforce because `RedisBackend` ignores `Enabled`, so behavior changes unexpectedly depending on backend choice.
- **Suggested fix:** Either set `Enabled: true` in defaults for the global limiter, or move global enabled/RPS/burst into DB/UI settings and pass those values into `buildRateLimit()`.

## 🔴 18. Path-prefix services match partial path segments and can route the wrong backend

- **File:** `services/registry.go:260-265`, strip at `proxy/handler.go:299-304`
- **Problem:** Prefix matching uses raw `strings.HasPrefix(path, s.Prefix)` and forwarding strips that same string. A service configured for `/api` therefore matches `/apiary`, `/api-v2`, etc., then forwards `/apiary` as `ary` (or similar) to the API backend.
- **Failure scenario:** With a prefix service `/api` plus a host/fallback service, requests for unrelated paths that merely start with those bytes are routed to the wrong service and have their paths corrupted before proxying. This can break production routes and, in mixed-backend deployments, expose requests to the wrong application.
- **Suggested fix:** Normalize prefixes and require a path-segment boundary: match when `path == prefix` or `strings.HasPrefix(path, prefix + "/")`; strip only after that boundary check.

## 🟠 19. Hot-swapping rate-limit backends can double-close an in-memory limiter

- **File:** `main.go:144-145`, reload at `main.go:236-239`, `ratelimit/ratelimit.go:153-157`
- **Problem:** Startup defers `rl.Stop()` for the original backend, while `ReloadRateLimit()` also stops the old backend during a settings hot-swap. `Limiter.Stop()` closes `l.stop` without `sync.Once`, so a backend that was already stopped by a UI reload will panic with `close of closed channel` if it is stopped again later (for example when `e.Start` returns or after graceful shutdown is added).
- **Failure scenario:** An operator changes rate-limit backend/settings, then the server exits through a path that runs defers; the process panics during shutdown instead of saving state cleanly. The same idempotency issue can bite any future code that calls `Stop()` twice on a limiter.
- **Suggested fix:** Make `Limiter.Stop()` idempotent (e.g. add `sync.Once`) and avoid deferring a stop for a backend that can be transferred into the handler and stopped by hot reload.

## 🧹 Additional dead code

- `storage/db.go:458` — `(*DB).UpdateService()` is not referenced anywhere in non-test or test code (`rg "UpdateService"` only finds the definition). The UI supports add/delete plus TLS/rate-limit/bot updates, but no service edit path calls this method.

## Follow-up verification notes

- `GOCACHE=/tmp/go-build-cache go vet ./...` completed cleanly.
- `go test ./...` could not complete in this sandbox: the default Go build cache under `/home/parth/.cache` is read-only, and `httptest.NewServer` cannot bind loopback sockets here (`operation not permitted`).
