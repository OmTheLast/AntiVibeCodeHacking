<h1 align="center">VibeShield</h1>

**Check a website’s public launch surface and get evidence with fixes you can take back to your code.**

Node.js 20+. Local Node server. Hosted scans require an access token and domain verification.

By Om Patnaik · repository created July 2026.

[![License: MIT](https://img.shields.io/badge/license-MIT-176b75?style=flat-square)](LICENSE)

## Install

| Platform / path | Start here |
| --- | --- |
| From source | `npm start` (no npm dependencies) |

Open http://localhost:4173 and verify a domain you control before scanning. To inspect it without sending probes, start the app and read its checks first.

```bash
npm start
```

## Why

You are ready to launch a web app, but missing headers, exposed files, and permissive browser policies are easy to overlook. VibeShield checks that public surface and explains the evidence. Its lightweight probes do not establish that an application is secure.

## Run a scoped check

Verify ownership, select the target, and inspect HTTPS, cookies, CORS, source maps, and discovered forms. Local and private network targets are blocked; likely secrets are redacted in evidence.

## Host the scanner

Set `SCANNER_ACCESS_TOKEN` before exposing a deployment. See [deployment instructions](DEPLOYMENT.md) and [security boundaries](SECURITY.md).

## Notes from building it

I scoped the scanner around checks a builder can act on before launch. Domain verification and bounded probes keep that workflow explicit. The next improvement would be stronger evidence that each reported issue is reproducible.

## Commands

```bash
npm start                       # start the scanner at localhost:4173
npm run check                   # syntax-check the server
```

## Verify it yourself

```bash
npm run check
```

This checks JavaScript syntax only. Manually verify a domain you control and inspect each reported request; there is no automated security-accuracy or end-to-end test suite.

## Credits, license and pointers

Built with Node.js and browser APIs. Source: [MIT](LICENSE).

[Full setup, original notes, and project history](README-DETAILS.md).
