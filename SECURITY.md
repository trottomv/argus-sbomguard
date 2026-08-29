# Security Policy

Argus SBOM Guard is a security product and we take security issues seriously. If
you believe you have found a vulnerability, please report it to us as described
below.

## Supported Versions

We provide security updates for the latest stable release and the current
development release. Older releases are not patched; please upgrade to a
supported version.

| Version     | Supported          |
| ----------- | ------------------ |
| latest      | :white_check_mark: |
| < latest    | :x:                |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities privately so we can prepare and release a fix
before details are made public.

To report a vulnerability, open a private security advisory at
https://github.com/trottomv/argus-sbomguard/security/advisories/new

Please include the following information to help us triage the report quickly:

1. The affected version(s) and deployment setup (e.g. Docker Compose, Caddy,
   PostgreSQL version).
2. A description of the vulnerability and the impact you believe it has.
3. Steps to reproduce it, ideally with a minimal proof of concept.
4. Any relevant logs, configuration excerpts, or SBOMs used to trigger it.

### What to expect

- **Acknowledgement**: We will acknowledge your report within **48 hours**.
- **Triage**: We will investigate and provide an initial assessment, including
  whether the report is accepted or declined, within **5 business days**.
- **Updates**: You can expect a status update at least every **7 days** while the
  issue remains open.
- **Disclosure**: If accepted, we will work on a fix and coordinate a public
  disclosure with you. We ask that you keep the report private until a fix has
  been released. Credit will be given to reporters who wish it.
- **Declined reports**: We will explain why a report was not accepted and may
  still ask you to file a public issue if it represents a general bug rather
  than a security concern.
