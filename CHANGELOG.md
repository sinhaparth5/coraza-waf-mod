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

## [2.2.4] - 2026-09-25

### Security

- **Bot challenge redirect could be pointed off-site or at `javascript:`** (CodeQL `js/xss-through-dom`). The `r` parameter on `/_cz/challenge` wasn't covered by the challenge signature, and the page navigated to it after the proof-of-work was solved. An attacker could take a freshly signed challenge link, swap `r` for `javascript:…` or `//evil.com`, and send it to a victim. Solving is automatic, so the victim only had to click: the result was XSS on the protected service's own domain, or an open redirect. The page now accepts only a same-origin path (one leading `/`, no `//` or `/\`, no control characters) and falls back to `/` for anything else.

[Unreleased]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.2.4...main
[2.2.4]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.2.3...v2.2.4
