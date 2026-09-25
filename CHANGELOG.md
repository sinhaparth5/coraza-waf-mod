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

### Fixed

- Varnish passed nearly every page view: the VCL now also drops Cloudflare (`__cf_bm`, `cf_clearance`, `_cfuvid`) and analytics (`_ga`, `_gid`, `_fbp`, Hotjar, Clarity…) cookies before its cookie check, and strips `Set-Cookie` from static-asset responses so a framework cookie on every response no longer makes assets uncacheable. Re-run `install.sh` or copy `deploy/varnish/default.vcl` to `/etc/varnish/` and `systemctl reload varnish`.

## [2.2.1] - 2026-09-25

### Fixed

- Settings → Registered devices no longer adds a new row every time the same browser logs in; a `cz_device` cookie ties logins to one row per device.

[Unreleased]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.2.1...main
[2.2.1]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.2.0...v2.2.1
