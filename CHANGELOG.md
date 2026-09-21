# Changelog

All notable changes to **Coraza WAF Mod** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file deliberately keeps only two sections: **[Unreleased]**, where changes
accumulate, and the **most recently published version**, kept so the current
release is readable without leaving the repo. `make tag VERSION=vX.Y.Z` promotes
Unreleased into a new version section, drops the previous one, and opens a fresh
Unreleased — older entries stay available in their git tags and GitHub releases
rather than growing this file forever.

## [Unreleased]

## [1.9.5] - 2026-09-21

### Added

- **Opt-in TypeSafe refinement for ASN/hosting threat-score classification**
  (issue #71). The hosting/ASN component of the per-IP threat score has
  always come from a small hardcoded heuristic — a non-exhaustive ASN
  allowlist plus an org-name keyword match, admittedly "not an authoritative
  classification". With a TypeSafe API key configured (Settings, off by
  default), an unrecognized ASN/org is now also judged asynchronously via
  TypeSafe's Noul primitive and the result is cached per ASN going forward.
  The heuristic answer is still returned immediately on every request — the
  score is computed on the single SQLite log-worker goroutine, which must
  never block on network I/O — so this only ever sharpens future
  classifications, never adds latency to the current one.

- **Webhook payloads are now HMAC-signed.** Every webhook delivery carries an
  `X-WAF-Signature-256: sha256=<hex>` header computed over the raw body with
  the configured webhook secret, so a receiver can verify a payload actually
  came from this WAF instead of trusting an unauthenticated POST to a public
  URL. No header is sent when no secret is configured, matching the existing
  generic/Slack/Discord payload behavior for that case.

- **Read-only API keys.** Keys created from the Settings API Keys card can
  now be scoped read-only; mutating REST endpoints (service, IP-rule, and ban
  create/update/delete) reject a read-only key with 403 while GETs continue
  to work. Previously every key was full read-write with no narrower option.

- **Per-stage request-pipeline latency metrics.** `coraza_stage_duration_seconds`
  is a new Prometheus histogram, labeled by stage (`enrich`, `blocklist`,
  `challenge`, `ratelimit`, `waf`, `proxy`), recorded at each exit point of
  the request pipeline (issue #73). `coraza_http_request_duration_seconds`
  could only ever answer "was this request slow"; this answers "which stage
  was it slow in" — a request blocked or redirected early contributes only
  to the stages it actually reached.

[Unreleased]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v1.9.5...main
[1.9.5]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v1.9.0...v1.9.5
