# Security Policy

## Supported Versions

Security fixes are provided for the latest released minor version of
Coraza WAF Mod. Older minor versions are not normally backported unless a
maintainer explicitly announces an exception in a release note.

| Version | Supported |
| ------- | --------- |
| 1.4.x   | Yes       |
| < 1.4   | No        |

Users should upgrade to the newest published release before reporting an issue
that may already be fixed.

## Reporting a Vulnerability

Please do not report security vulnerabilities in public GitHub issues,
discussions, pull requests, or social channels.

Report vulnerabilities privately through GitHub Security Advisories for this
repository:

https://github.com/sinhaparth5/coraza-waf-mod/security/advisories/new

Include enough detail for the issue to be reproduced and assessed:

- Affected version or commit.
- Deployment mode, such as native binary, systemd install, Docker, or source
  build.
- Configuration relevant to the issue, excluding secrets and private keys.
- Clear reproduction steps, proof of concept, logs, or request samples.
- Expected impact, such as authentication bypass, WAF bypass, SSRF, data
  exposure, denial of service, privilege escalation, or unsafe TLS behavior.

## Response Process

Maintainers will triage private reports as soon as practical. If the report is
accepted, the fix will be developed privately when appropriate, released in a
patched version, and documented in the changelog or advisory. If the report is
declined, the maintainer will explain why it is not considered a project
vulnerability.

Please give maintainers reasonable time to investigate and release a fix before
public disclosure.

## Security Scope

In scope:

- Vulnerabilities in the WAF, reverse proxy, admin dashboard, authentication,
  request logging, TLS handling, installer, release artifacts, or bundled
  assets.
- Issues that meaningfully weaken expected blocking, routing, isolation, or
  administrative access controls.

Out of scope:

- Vulnerabilities caused only by an insecure local deployment, weak admin
  credentials, exposed SQLite files, leaked TLS keys, or disabled protections.
- Denial-of-service reports that rely on unrealistic traffic volume without a
  specific application flaw.
- Findings already fixed in the latest supported release.

## Operational Guidance

Use strong admin credentials, keep `waf.db`, TLS keys, and GeoIP databases
private, and restrict access to the admin dashboard. Production installations
should use the signed release artifacts and verify checksums published with each
GitHub release.
