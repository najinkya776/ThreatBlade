# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.x | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability in ThreatBlade, please **do not open a public issue**.

Instead, email the details to: najinkya776@gmail.com

Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact

You can expect a response within 72 hours. If the issue is confirmed, a fix will be prioritized and you'll be credited in the release notes.

## Security Notes for Users

- API keys are stored in `config/keys.json` which is gitignored — never commit this file
- ThreatBlade is designed to run locally; do not expose it to the public internet without adding authentication
- The password breach check uses k-anonymity — only the first 5 characters of the SHA1 hash are sent to HaveIBeenPwned, your password is never transmitted in full
