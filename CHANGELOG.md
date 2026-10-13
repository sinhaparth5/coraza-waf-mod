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

## [2.4.1] - 2026-10-13

### Fixed

- `install.sh` hung (or exited silently) right after the database prompt when run as `curl | bash`: `exec < /dev/tty` replaced the pipe bash was reading the script from. Stdin is now saved and restored around the prompts.

[Unreleased]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.4.1...main
[2.4.1]: https://github.com/sinhaparth5/coraza-waf-mod/compare/v2.4.0...v2.4.1
