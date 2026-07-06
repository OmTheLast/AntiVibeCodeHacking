# VibeShield

A small defensive scanner for builders who want quick, plain-English security feedback for a public website.

## Run

```bash
npm start
```

Open `http://localhost:4173`.

For a hosted deployment, set an access token:

```bash
SCANNER_ACCESS_TOKEN="change-me" npm start
```

The browser UI will ask for that token before calling API routes.

## What It Checks

- HTTPS and TLS certificate basics
- Security headers
- Cookie flags
- CORS behavior
- Exposed files and source maps
- Same-origin crawl surface
- Forms, inputs, scripts, and discovered API-like paths
- Stack hints for Next.js, Vercel, Supabase, Firebase, Stripe, Clerk, and common servers
- Safe active probes for reflected input and open redirects

The scanner is designed for authorized testing of public websites. It blocks local/private network targets, requires domain verification before scanning, redacts likely secrets in evidence, writes minimal audit logs to `data/audit.jsonl`, and keeps active probing lightweight.
