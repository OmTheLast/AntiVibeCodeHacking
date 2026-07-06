# Security Policy

VibeShield is a defensive scanner for websites you own or are explicitly authorized to test.

## Built-In Guardrails

- Domain ownership verification is required before scanning.
- Localhost and private network targets are blocked.
- Active probes are lightweight and non-destructive.
- Full reports are not persisted by the app.
- Audit logs store minimal metadata in `data/audit.jsonl`.
- Likely secrets are redacted from evidence samples.
- Hosted instances can require `SCANNER_ACCESS_TOKEN`.

## Production Checklist

- Deploy behind HTTPS.
- Set `SCANNER_ACCESS_TOKEN`.
- Restrict network egress if your platform supports it.
- Put the app behind an identity provider if multiple users need access.
- Rotate audit logs and protect the `data/` directory.
- Review legal/authorization language before offering public scans.

## Reporting Vulnerabilities

Open a private security advisory or contact the repository owner. Do not include live third-party secrets in reports.
