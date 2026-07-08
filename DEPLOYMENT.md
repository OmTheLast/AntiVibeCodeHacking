# Deploy VibeShield

VibeShield needs a Node server, so deploy it to a Node host such as Render, Railway, Fly.io, or a VPS. GitHub Pages can host documentation, but it cannot run the scanner backend.

## Render

1. Open Render and create a new Blueprint or Web Service from:

   `https://github.com/OmTheLast/AntiVibeCodeHacking`

2. Use the included `render.yaml` blueprint, or configure manually:

   - Runtime: Node
   - Build command: `npm install`
   - Start command: `npm start`
   - Health check path: `/healthz`

3. Set environment variables:

   - `SCANNER_ACCESS_TOKEN`: a long random secret
   - `MAX_CONCURRENT_SCANS`: `2`
   - `NODE_ENV`: `production`

4. Deploy.

5. Open the deployed URL, paste the same `SCANNER_ACCESS_TOKEN` into the UI token field, and generate a domain verification token before scanning.

## Production Notes

- Keep `SCANNER_ACCESS_TOKEN` private. Do not commit it.
- Deploy behind HTTPS.
- Review `data/audit.jsonl` retention if using persistent disks.
- Start with private/beta access. The scanner is intentionally defensive, but public scanners still need abuse monitoring.
- Increase `MAX_CONCURRENT_SCANS` only after adding a durable job queue.
