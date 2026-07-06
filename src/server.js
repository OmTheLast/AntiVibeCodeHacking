import dns from "node:dns/promises";
import fs from "node:fs/promises";
import http from "node:http";
import crypto from "node:crypto";
import net from "node:net";
import path from "node:path";
import tls from "node:tls";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.resolve(__dirname, "..", "public");
const PORT = Number(process.env.PORT || 4173);
const REQUEST_TIMEOUT_MS = 9000;
const MAX_BODY_BYTES = 900_000;
const MAX_CRAWL_PAGES = 25;
const MAX_CONCURRENT_SCANS = Number(process.env.MAX_CONCURRENT_SCANS || 2);
const USER_AGENT = "WebsiteSecurityChecker/0.1 (+defensive-authorized-scanner)";
const ACCESS_TOKEN = process.env.SCANNER_ACCESS_TOKEN || "";
const VERIFY_PATH = "/.well-known/vibeshield-verification.txt";
const DATA_DIR = path.resolve(__dirname, "..", "data");
const AUDIT_LOG = path.join(DATA_DIR, "audit.jsonl");
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT_MAX = 30;
const verifiedTargets = new Map();
const verificationTokens = new Map();
const rateBuckets = new Map();
let activeScans = 0;

const SECURITY_HEADERS = [
  {
    name: "content-security-policy",
    severity: "High",
    title: "Missing Content Security Policy",
    why: "A CSP limits where scripts, frames, images, and connections can load from. Without one, XSS and content injection bugs have more room to become account-impacting issues.",
    fix: "Add a production Content-Security-Policy. Start with default-src 'self', define script/connect/image sources used by your app, and use frame-ancestors to prevent clickjacking."
  },
  {
    name: "strict-transport-security",
    severity: "Medium",
    title: "Missing HSTS",
    why: "HSTS tells browsers to always use HTTPS for your domain after the first secure visit.",
    fix: "Return Strict-Transport-Security with a max-age value. Use includeSubDomains and preload only after verifying every subdomain supports HTTPS."
  },
  {
    name: "x-content-type-options",
    severity: "Low",
    title: "Missing X-Content-Type-Options",
    why: "Without nosniff, some browsers may interpret files as a different type than intended.",
    fix: "Return X-Content-Type-Options: nosniff on all responses."
  },
  {
    name: "referrer-policy",
    severity: "Low",
    title: "Missing Referrer-Policy",
    why: "Browsers may send full URLs as referrers to third parties, leaking routes or query strings.",
    fix: "Return Referrer-Policy: strict-origin-when-cross-origin or stricter."
  },
  {
    name: "permissions-policy",
    severity: "Low",
    title: "Missing Permissions-Policy",
    why: "A Permissions-Policy narrows browser features such as camera, microphone, geolocation, and payment APIs.",
    fix: "Return a Permissions-Policy that disables unused features."
  }
];

const SENSITIVE_PATHS = [
  "/.env",
  "/.env.local",
  "/.git/config",
  "/.svn/entries",
  "/package.json",
  "/composer.json",
  "/backup.zip",
  "/db.sql",
  "/debug",
  "/phpinfo.php",
  "/server-status",
  "/_next/static/chunks/main.js.map"
];

const SEVERITY_WEIGHT = {
  Critical: 100,
  High: 70,
  Medium: 40,
  Low: 15,
  Info: 0
};

const APP_SECURITY_HEADERS = {
  "content-security-policy": [
    "default-src 'self'",
    "base-uri 'none'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "upgrade-insecure-requests"
  ].join("; "),
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "origin-agent-cluster": "?1",
  "referrer-policy": "no-referrer",
  "strict-transport-security": "max-age=15552000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "x-permitted-cross-domain-policies": "none"
};

function secureHeaders(extra = {}) {
  return {
    ...APP_SECURITY_HEADERS,
    ...extra
  };
}

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, secureHeaders({
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload)
  }));
  res.end(payload);
}

function clientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) return forwarded.split(",")[0].trim();
  return req.socket.remoteAddress || "unknown";
}

function requireAccess(req) {
  if (!ACCESS_TOKEN) return;
  const header = req.headers["x-scanner-token"];
  if (header !== ACCESS_TOKEN) {
    const error = new Error("Invalid or missing scanner access token.");
    error.statusCode = 401;
    throw error;
  }
}

function enforceRateLimit(key) {
  const now = Date.now();
  const bucket = rateBuckets.get(key) || { resetAt: now + RATE_LIMIT_WINDOW_MS, count: 0 };
  if (bucket.resetAt <= now) {
    bucket.resetAt = now + RATE_LIMIT_WINDOW_MS;
    bucket.count = 0;
  }
  bucket.count += 1;
  rateBuckets.set(key, bucket);
  if (bucket.count > RATE_LIMIT_MAX) {
    const error = new Error("Too many requests. Try again after the rate-limit window resets.");
    error.statusCode = 429;
    throw error;
  }
}

async function audit(event, fields = {}) {
  const entry = {
    at: new Date().toISOString(),
    event,
    ...fields
  };
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
    await fs.appendFile(AUDIT_LOG, `${JSON.stringify(entry)}\n`, "utf8");
  } catch {
    // Audit logging should never break scans.
  }
}

function hostKey(url) {
  return `${url.protocol}//${url.hostname}${url.port ? `:${url.port}` : ""}`;
}

function makeVerificationToken(url) {
  const random = crypto.randomBytes(18).toString("base64url");
  return `vibeshield-verify=${url.hostname}:${random}`;
}

function isTargetVerified(url) {
  const verified = verifiedTargets.get(hostKey(url));
  return Boolean(verified && verified.expiresAt > Date.now());
}

function markTargetVerified(url) {
  verifiedTargets.set(hostKey(url), {
    verifiedAt: Date.now(),
    expiresAt: Date.now() + 24 * 60 * 60 * 1000
  });
}

function redactSensitive(value) {
  let text = String(value || "");
  const replacements = [
    /\b(sk|rk|pk)_(live|test)_[A-Za-z0-9_]+/g,
    /\bAKIA[0-9A-Z]{16}\b/g,
    /\b[A-Za-z0-9_=-]{20,}\.[A-Za-z0-9_=-]{20,}\.[A-Za-z0-9_=-]{20,}\b/g,
    /\b(?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key)\s*[:=]\s*["']?[^"'\s,;]+/gi,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g
  ];
  for (const pattern of replacements) text = text.replace(pattern, "[REDACTED]");
  return text;
}

function sanitizeFinding(finding) {
  return {
    ...finding,
    evidence: (finding.evidence || []).map((item) => redactSensitive(item)),
    fixPrompt: finding.fixPrompt ? redactSensitive(finding.fixPrompt) : finding.fixPrompt
  };
}

function normalizeTarget(input) {
  const trimmed = String(input || "").trim();
  if (!trimmed) throw new Error("Enter a website URL.");
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  const url = new URL(withScheme);
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP and HTTPS websites can be scanned.");
  url.hash = "";
  return url;
}

function isPrivateIp(address) {
  if (net.isIPv4(address)) {
    const parts = address.split(".").map(Number);
    return parts[0] === 10 ||
      parts[0] === 127 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      (parts[0] === 169 && parts[1] === 254) ||
      parts[0] === 0;
  }
  if (net.isIPv6(address)) {
    const lower = address.toLowerCase();
    return lower === "::1" || lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("fe80:");
  }
  return true;
}

async function assertPublicTarget(url) {
  const hostname = url.hostname;
  if (hostname === "localhost" || hostname.endsWith(".localhost")) {
    throw new Error("Localhost targets are blocked by the hosted scanner guardrail.");
  }

  const records = await dns.lookup(hostname, { all: true, verbatim: false });
  if (!records.length || records.some((record) => isPrivateIp(record.address))) {
    throw new Error("This target resolves to a local or private network address, so it was not scanned.");
  }
}

async function fetchLimited(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const started = Date.now();
  try {
    const response = await fetch(url, {
      redirect: options.redirect || "manual",
      method: options.method || "GET",
      headers: {
        "user-agent": USER_AGENT,
        "accept": options.accept || "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ...(options.headers || {})
      },
      signal: controller.signal
    });

    const chunks = [];
    let total = 0;
    if (response.body) {
      const reader = response.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total <= MAX_BODY_BYTES) chunks.push(value);
        if (total > MAX_BODY_BYTES) {
          await reader.cancel();
          break;
        }
      }
    }

    const body = Buffer.concat(chunks).toString("utf8");
    return {
      url: response.url || String(url),
      status: response.status,
      ok: response.ok,
      redirected: response.redirected,
      headers: Object.fromEntries(response.headers.entries()),
      body,
      truncated: total > MAX_BODY_BYTES,
      durationMs: Date.now() - started
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function getTlsInfo(url) {
  if (url.protocol !== "https:") return null;
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: url.hostname,
      port: Number(url.port || 443),
      servername: url.hostname,
      timeout: REQUEST_TIMEOUT_MS
    }, () => {
      const cert = socket.getPeerCertificate();
      const protocol = socket.getProtocol();
      socket.end();
      resolve({
        validTo: cert.valid_to,
        issuer: cert.issuer?.O || cert.issuer?.CN || "Unknown",
        subject: cert.subject?.CN || url.hostname,
        protocol
      });
    });
    socket.on("timeout", () => {
      socket.destroy();
      resolve({ error: "TLS check timed out." });
    });
    socket.on("error", (error) => resolve({ error: error.message }));
  });
}

function addFinding(findings, finding) {
  const id = finding.id || finding.title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  if (findings.some((existing) => existing.id === id && existing.url === finding.url)) return;
  findings.push({
    id,
    confidence: "Medium",
    evidence: [],
    ...finding
  });
}

function analyzeHeaders(findings, targetUrl, headers, isHttps) {
  for (const header of SECURITY_HEADERS) {
    if (!headers[header.name]) {
      if (header.name === "strict-transport-security" && !isHttps) continue;
      addFinding(findings, {
        id: `missing-${header.name}`,
        severity: header.severity,
        confidence: "High",
        title: header.title,
        category: "Headers",
        url: targetUrl,
        evidence: [`${header.name} header was not present on the homepage response.`],
        why: header.why,
        fix: header.fix
      });
    }
  }

  if (!headers["x-frame-options"] && !(headers["content-security-policy"] || "").includes("frame-ancestors")) {
    addFinding(findings, {
      id: "missing-clickjacking-protection",
      severity: "Medium",
      confidence: "High",
      title: "Missing Clickjacking Protection",
      category: "Headers",
      url: targetUrl,
      evidence: ["No X-Frame-Options header or CSP frame-ancestors directive was found."],
      why: "Attackers may be able to embed the app in another page and trick users into clicking sensitive UI.",
      fix: "Add frame-ancestors 'none' or frame-ancestors 'self' to your CSP. X-Frame-Options: DENY or SAMEORIGIN is a useful legacy fallback."
    });
  }

  const csp = headers["content-security-policy"] || "";
  if (csp && (csp.includes("unsafe-inline") || csp.includes("unsafe-eval") || csp.includes("*"))) {
    addFinding(findings, {
      id: "weak-content-security-policy",
      severity: "Medium",
      confidence: "Medium",
      title: "Weak Content Security Policy",
      category: "Headers",
      url: targetUrl,
      evidence: [`CSP contains a broad directive: ${shorten(csp, 220)}`],
      why: "A CSP with unsafe-inline, unsafe-eval, or broad wildcards may not meaningfully reduce script injection risk.",
      fix: "Replace broad sources with specific domains, remove unsafe-eval where possible, and migrate inline scripts to nonces or hashes."
    });
  }
}

function analyzeCookies(findings, targetUrl, headers, isHttps) {
  const setCookie = headers["set-cookie"];
  if (!setCookie) return;
  const cookieLines = Array.isArray(setCookie) ? setCookie : String(setCookie).split(/,(?=\s*[^;,]+=)/);
  cookieLines.forEach((cookie, index) => {
    const lower = cookie.toLowerCase();
    const name = cookie.split("=")[0]?.trim() || `cookie ${index + 1}`;
    if (isHttps && !lower.includes("secure")) {
      addFinding(findings, {
        id: `cookie-missing-secure-${name}`,
        severity: "Medium",
        title: "Cookie Missing Secure Flag",
        category: "Cookies",
        url: targetUrl,
        evidence: [`${name} did not include the Secure attribute.`],
        why: "Session or auth-related cookies without Secure may be sent over plain HTTP if a downgrade path exists.",
        fix: "Set Secure on all session, auth, and CSRF cookies in production."
      });
    }
    if (!lower.includes("httponly") && /(session|auth|token|jwt|sid)/i.test(name)) {
      addFinding(findings, {
        id: `cookie-missing-httponly-${name}`,
        severity: "High",
        title: "Auth-Looking Cookie Missing HttpOnly",
        category: "Cookies",
        url: targetUrl,
        evidence: [`${name} looks sensitive but did not include HttpOnly.`],
        why: "JavaScript can read cookies without HttpOnly, which makes XSS more damaging.",
        fix: "Set HttpOnly on server-managed session cookies. Store access tokens server-side where possible."
      });
    }
    if (!lower.includes("samesite")) {
      addFinding(findings, {
        id: `cookie-missing-samesite-${name}`,
        severity: "Low",
        title: "Cookie Missing SameSite",
        category: "Cookies",
        url: targetUrl,
        evidence: [`${name} did not include SameSite.`],
        why: "SameSite helps reduce cross-site request forgery risk for cookie-authenticated apps.",
        fix: "Use SameSite=Lax for most session cookies. Use SameSite=None only when cross-site embedding is required, and pair it with Secure."
      });
    }
  });
}

function fingerprint(response) {
  const headers = response.headers;
  const body = response.body;
  const hints = new Set();
  const poweredBy = headers["x-powered-by"] || "";
  const server = headers.server || "";

  if (body.includes("/_next/") || headers["x-nextjs-cache"] || poweredBy.toLowerCase().includes("next")) hints.add("Next.js");
  if (headers["x-vercel-id"] || server.toLowerCase().includes("vercel")) hints.add("Vercel");
  if (/supabase\.co|supabase\.in|createClient\(/i.test(body)) hints.add("Supabase");
  if (/firebaseapp\.com|firestore|firebaseConfig|googleapis\.com\/identitytoolkit/i.test(body)) hints.add("Firebase");
  if (/js\.stripe\.com|stripe\.com\/checkout/i.test(body)) hints.add("Stripe");
  if (/clerk\.|__clerk|clerk-js/i.test(body)) hints.add("Clerk");
  if (/wp-content|wp-json/i.test(body)) hints.add("WordPress");
  if (/shopify|myshopify/i.test(body)) hints.add("Shopify");
  if (poweredBy) hints.add(`X-Powered-By: ${poweredBy}`);
  if (server) hints.add(`Server: ${server}`);

  return [...hints];
}

function extractLinks(baseUrl, html) {
  const links = new Set();
  const attrs = html.matchAll(/\b(?:href|src|action)=["']([^"'#]+)["']/gi);
  for (const match of attrs) {
    try {
      const url = new URL(match[1], baseUrl);
      url.hash = "";
      if (url.origin === new URL(baseUrl).origin) links.add(url.toString());
    } catch {
      // Ignore malformed links.
    }
  }
  return [...links];
}

function extractSurface(baseUrl, html) {
  const forms = [...html.matchAll(/<form\b[^>]*>/gi)].map((match) => {
    const tag = match[0];
    return {
      action: attr(tag, "action") || baseUrl,
      method: (attr(tag, "method") || "GET").toUpperCase()
    };
  });
  const inputs = [...html.matchAll(/<(?:input|textarea|select)\b[^>]*>/gi)].map((match) => ({
    name: attr(match[0], "name") || attr(match[0], "id") || "unnamed",
    type: attr(match[0], "type") || match[0].slice(1).split(/\s/)[0]
  }));
  const scripts = [...html.matchAll(/<script\b[^>]*src=["']([^"']+)["'][^>]*>/gi)]
    .map((match) => safeUrl(match[1], baseUrl))
    .filter(Boolean);
  const apiPaths = new Set();
  const endpointPatterns = html.matchAll(/["'`](\/(?:api|auth|admin|graphql|trpc|rest|v1|v2)\/[^"'`\s<>{}\\]+)["'`]/gi);
  for (const match of endpointPatterns) apiPaths.add(match[1]);
  return { forms, inputs, scripts, apiPaths: [...apiPaths] };
}

function attr(tag, name) {
  const match = tag.match(new RegExp(`\\b${name}=["']([^"']+)["']`, "i"));
  return match?.[1] || "";
}

function safeUrl(value, base) {
  try {
    return new URL(value, base).toString();
  } catch {
    return "";
  }
}

async function crawl(startUrl, findings) {
  const origin = startUrl.origin;
  const queue = [startUrl.toString()];
  const seen = new Set();
  const pages = [];
  const allForms = [];
  const allInputs = [];
  const allScripts = new Set();
  const allApiPaths = new Set();

  while (queue.length && seen.size < MAX_CRAWL_PAGES) {
    const current = queue.shift();
    if (!current || seen.has(current)) continue;
    seen.add(current);
    let response;
    try {
      response = await fetchLimited(current);
    } catch {
      continue;
    }
    const type = response.headers["content-type"] || "";
    pages.push({ url: current, status: response.status, title: getTitle(response.body), bytes: response.body.length });
    if (response.status >= 500) {
      addFinding(findings, {
        id: `server-error-${new URL(current).pathname}`,
        severity: "Medium",
        title: "Server Error During Crawl",
        category: "Reliability",
        url: current,
        evidence: [`The page returned HTTP ${response.status}.`],
        why: "Unexpected server errors can leak implementation details and may point to unstable routes.",
        fix: "Review server logs for this route and return a generic error page in production."
      });
    }
    if (!type.includes("text/html")) continue;
    const surface = extractSurface(current, response.body);
    allForms.push(...surface.forms.map((form) => ({ ...form, page: current })));
    allInputs.push(...surface.inputs.map((input) => ({ ...input, page: current })));
    surface.scripts.forEach((script) => allScripts.add(script));
    surface.apiPaths.forEach((apiPath) => allApiPaths.add(apiPath));
    for (const link of extractLinks(current, response.body)) {
      const url = new URL(link);
      if (url.origin === origin && !seen.has(url.toString()) && queue.length < MAX_CRAWL_PAGES * 2) {
        queue.push(url.toString());
      }
    }
  }

  return {
    pages,
    forms: allForms.slice(0, 80),
    inputs: allInputs.slice(0, 120),
    scripts: [...allScripts].slice(0, 120),
    apiPaths: [...allApiPaths].slice(0, 120)
  };
}

async function checkSensitivePaths(baseUrl, findings) {
  const exposed = [];
  for (const candidate of SENSITIVE_PATHS) {
    const url = new URL(candidate, baseUrl);
    try {
      const response = await fetchLimited(url.toString());
      const text = response.body.trim();
      if (response.status >= 200 && response.status < 300 && text.length > 0 && !looksLikeGenericHtml(text)) {
        exposed.push({ path: candidate, status: response.status, sample: shorten(redactSensitive(text.replace(/\s+/g, " ")), 140) });
      }
    } catch {
      // Ignore individual probe errors.
    }
  }

  exposed.forEach((item) => {
    const highRisk = /env|git|sql|backup/i.test(item.path);
    addFinding(findings, {
      id: `exposed${item.path.replace(/[^a-z0-9]+/gi, "-")}`,
      severity: highRisk ? "Critical" : "High",
      confidence: "High",
      title: "Sensitive Public File Exposed",
      category: "Exposure",
      url: new URL(item.path, baseUrl).toString(),
      evidence: [`${item.path} returned HTTP ${item.status}. Sample: ${item.sample}`],
      why: "Public config, repository, source map, or backup files may reveal secrets, source code, internal endpoints, or deployment details.",
      fix: "Remove the file from the public web root, rotate exposed secrets, and add deny rules for dotfiles, backups, dumps, and production source maps."
    });
  });
}

function looksLikeGenericHtml(text) {
  const lower = text.toLowerCase();
  return lower.includes("<!doctype html") && (lower.includes("not found") || lower.includes("404"));
}

async function checkCors(baseUrl, findings) {
  try {
    const response = await fetchLimited(baseUrl.toString(), {
      method: "OPTIONS",
      headers: {
        "origin": "https://security-checker.example",
        "access-control-request-method": "POST"
      }
    });
    const allowOrigin = response.headers["access-control-allow-origin"] || "";
    const allowCredentials = response.headers["access-control-allow-credentials"] || "";
    if (allowOrigin === "*" && allowCredentials.toLowerCase() === "true") {
      addFinding(findings, {
        id: "cors-wildcard-with-credentials",
        severity: "High",
        confidence: "High",
        title: "Unsafe CORS Credentials Policy",
        category: "CORS",
        url: baseUrl.toString(),
        evidence: ["Access-Control-Allow-Origin was * and Access-Control-Allow-Credentials was true."],
        why: "Credentialed CORS should not be open to every origin. Browsers reject this exact pairing, but similar reflective policies often indicate a risky CORS implementation.",
        fix: "Allow only trusted origins and avoid credentialed CORS unless the endpoint genuinely needs browser cross-origin authenticated access."
      });
    } else if (allowOrigin === "https://security-checker.example" && allowCredentials.toLowerCase() === "true") {
      addFinding(findings, {
        id: "cors-reflects-arbitrary-origin",
        severity: "High",
        confidence: "Medium",
        title: "CORS Reflects Arbitrary Origin",
        category: "CORS",
        url: baseUrl.toString(),
        evidence: ["The response reflected the scanner Origin and allowed credentials."],
        why: "Reflecting arbitrary origins with credentials can let attacker-controlled sites read authenticated API responses.",
        fix: "Use an explicit allowlist for trusted origins and reject unknown origins."
      });
    }
  } catch {
    // CORS checks are best-effort.
  }
}

async function activeProbes(baseUrl, findings) {
  const marker = "wsc_marker_9417";
  const params = ["q", "search", "next", "redirect", "returnTo", "url"];
  for (const param of params) {
    const url = new URL(baseUrl.toString());
    url.searchParams.set(param, param.includes("next") || param.includes("redirect") || param === "url" ? "https://example.com/" : marker);
    try {
      const response = await fetchLimited(url.toString());
      const location = response.headers.location || "";
      if (location.startsWith("https://example.com")) {
        addFinding(findings, {
          id: `open-redirect-${param}`,
          severity: "Medium",
          confidence: "Medium",
          title: "Possible Open Redirect",
          category: "Active Probe",
          url: url.toString(),
          evidence: [`Parameter ${param} caused a redirect to an external URL.`],
          why: "Open redirects are often used in phishing flows and can weaken OAuth or magic-link redirect handling.",
          fix: "Only allow relative redirect paths or validate redirect destinations against a strict allowlist."
        });
      }
      if (response.body.includes(marker)) {
        addFinding(findings, {
          id: `reflected-input-${param}`,
          severity: "Medium",
          confidence: "Low",
          title: "Reflected Input Observed",
          category: "Active Probe",
          url: url.toString(),
          evidence: [`The marker value sent in ${param} appeared in the response body.`],
          why: "Reflected input is not automatically XSS, but it is a place to verify output encoding and template safety.",
          fix: "Ensure reflected values are HTML-escaped by default and never inserted into script, style, or URL contexts without context-aware encoding."
        });
      }
    } catch {
      // Continue probing other parameters.
    }
  }
}

function stackGuidance(hints, findings, targetUrl, surface) {
  if (hints.includes("Next.js")) {
    const sourceMaps = surface.scripts.filter((script) => script.endsWith(".map") || script.includes(".js.map"));
    if (sourceMaps.length) {
      addFinding(findings, {
        id: "nextjs-source-maps-linked",
        severity: "High",
        confidence: "High",
        title: "Production Source Maps Linked",
        category: "Stack",
        url: targetUrl,
        evidence: sourceMaps.slice(0, 3),
        why: "Source maps can expose original source, comments, internal route names, and implementation details.",
        fix: "Disable public production source maps or serve them only to authenticated internal users."
      });
    }
  }

  if (hints.includes("Supabase")) {
    addFinding(findings, {
      id: "supabase-rls-reminder",
      severity: "Info",
      confidence: "High",
      title: "Supabase Detected",
      category: "Stack",
      url: targetUrl,
      evidence: ["Supabase references were detected in public assets."],
      why: "The public anon key is expected in browser apps, but database safety depends heavily on Row Level Security and storage policies.",
      fix: "Verify RLS is enabled on every table with client access, add least-privilege policies, and check public storage buckets."
    });
  }

  if (hints.includes("Firebase")) {
    addFinding(findings, {
      id: "firebase-rules-reminder",
      severity: "Info",
      confidence: "High",
      title: "Firebase Detected",
      category: "Stack",
      url: targetUrl,
      evidence: ["Firebase references were detected in public assets."],
      why: "Firebase client config is normally public, but Firestore, Realtime Database, and Storage rules decide what attackers can read or write.",
      fix: "Review production security rules and test with an unauthenticated user and a normal authenticated user."
    });
  }

  if (hints.includes("Stripe")) {
    addFinding(findings, {
      id: "stripe-webhook-reminder",
      severity: "Info",
      confidence: "High",
      title: "Stripe Detected",
      category: "Stack",
      url: targetUrl,
      evidence: ["Stripe browser assets or checkout references were detected."],
      why: "Stripe public keys are expected in the browser. Secret keys and webhook signature verification need server-side review.",
      fix: "Make sure webhook handlers verify Stripe signatures and no sk_live or rk_live keys are present in public JavaScript."
    });
  }
}

function getTitle(html) {
  return shorten(html.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1]?.trim() || "Untitled", 90);
}

function shorten(value, length) {
  const text = String(value || "");
  return text.length > length ? `${text.slice(0, length - 1)}...` : text;
}

function score(findings) {
  const weighted = findings.reduce((sum, finding) => sum + (SEVERITY_WEIGHT[finding.severity] || 0), 0);
  const scoreValue = Math.max(0, 100 - Math.min(90, Math.round(weighted / 4)));
  let label = "Strong";
  if (scoreValue < 40) label = "Needs urgent attention";
  else if (scoreValue < 70) label = "Needs work";
  else if (scoreValue < 86) label = "Reasonable";
  return { value: scoreValue, label };
}

function makeFixPrompt(finding, target) {
  return `I scanned ${target} and found: ${finding.title}. Evidence: ${finding.evidence.join(" ")} Please fix this defensively. Context: ${finding.fix}`;
}

async function verifyTarget(input, providedToken) {
  const url = normalizeTarget(input);
  await assertPublicTarget(url);
  const expected = verificationTokens.get(hostKey(url));
  if (!expected || expected.token !== providedToken || expected.expiresAt <= Date.now()) {
    throw new Error("Verification token is missing or expired. Generate a fresh token and publish it first.");
  }
  const verifyUrl = new URL(VERIFY_PATH, url);
  const response = await fetchLimited(verifyUrl.toString(), { accept: "text/plain,*/*" });
  if (response.status < 200 || response.status >= 300 || !response.body.includes(providedToken)) {
    throw new Error(`Could not verify ownership. Publish the token at ${verifyUrl.toString()} and try again.`);
  }
  markTargetVerified(url);
  return {
    target: hostKey(url),
    verified: true,
    expiresAt: new Date(verifiedTargets.get(hostKey(url)).expiresAt).toISOString()
  };
}

async function scan(input) {
  const url = normalizeTarget(input);
  await assertPublicTarget(url);
  if (!isTargetVerified(url)) {
    throw new Error(`Verify ownership first by publishing a token at ${new URL(VERIFY_PATH, url).toString()}.`);
  }
  if (activeScans >= MAX_CONCURRENT_SCANS) {
    throw new Error("Scanner is busy. Try again in a moment.");
  }
  activeScans += 1;
  const startedAt = new Date().toISOString();
  const findings = [];

  try {
    const [homepage, tlsInfo] = await Promise.all([
      fetchLimited(url.toString()),
      getTlsInfo(url)
    ]);

    if (url.protocol !== "https:") {
      addFinding(findings, {
        id: "site-not-https",
        severity: "Critical",
        confidence: "High",
        title: "Site Does Not Use HTTPS",
        category: "Transport",
        url: url.toString(),
        evidence: ["The scanned URL used plain HTTP."],
        why: "Plain HTTP exposes traffic to interception and modification.",
        fix: "Serve the site over HTTPS and redirect all HTTP traffic to HTTPS."
      });
    }

    analyzeHeaders(findings, url.toString(), homepage.headers, url.protocol === "https:");
    analyzeCookies(findings, url.toString(), homepage.headers, url.protocol === "https:");
    const hints = fingerprint(homepage);

    const [surface] = await Promise.all([
      crawl(url, findings),
      checkSensitivePaths(url, findings),
      checkCors(url, findings),
      activeProbes(url, findings)
    ]);
    stackGuidance(hints, findings, url.toString(), surface);

    findings.sort((a, b) => (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0));
    const finalScore = score(findings);
    findings.forEach((finding) => {
      finding.fixPrompt = makeFixPrompt(finding, url.toString());
    });
    const safeFindings = findings.map(sanitizeFinding);

    return {
      target: url.toString(),
      startedAt,
      completedAt: new Date().toISOString(),
      score: finalScore,
      tls: tlsInfo,
      homepage: {
        status: homepage.status,
        durationMs: homepage.durationMs,
        finalUrl: homepage.url,
        headers: homepage.headers,
        truncated: homepage.truncated
      },
      stackHints: hints,
      surface,
      findings: safeFindings,
      counts: {
        critical: safeFindings.filter((item) => item.severity === "Critical").length,
        high: safeFindings.filter((item) => item.severity === "High").length,
        medium: safeFindings.filter((item) => item.severity === "Medium").length,
        low: safeFindings.filter((item) => item.severity === "Low").length,
        info: safeFindings.filter((item) => item.severity === "Info").length
      }
    };
  } finally {
    activeScans -= 1;
  }
}

async function serveStatic(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const requested = url.pathname === "/" ? "/index.html" : url.pathname;
  const filePath = path.resolve(publicDir, `.${requested}`);
  if (!filePath.startsWith(publicDir)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }
  try {
    const body = await fs.readFile(filePath);
    const ext = path.extname(filePath);
    const type = ext === ".css" ? "text/css" : ext === ".js" ? "application/javascript" : "text/html";
    res.writeHead(200, secureHeaders({ "content-type": `${type}; charset=utf-8` }));
    res.end(body);
  } catch {
    res.writeHead(404, secureHeaders({ "content-type": "text/plain; charset=utf-8" }));
    res.end("Not found");
  }
}

const server = http.createServer(async (req, res) => {
  try {
    const ip = clientIp(req);
    if (req.url?.startsWith("/api/")) {
      requireAccess(req);
      enforceRateLimit(ip);
    }

    if (req.method === "POST" && req.url === "/api/verification-token") {
      let raw = "";
      req.on("data", (chunk) => {
        raw += chunk;
        if (raw.length > 20_000) req.destroy();
      });
      req.on("end", async () => {
        try {
          const body = JSON.parse(raw || "{}");
          const url = normalizeTarget(body.url);
          await assertPublicTarget(url);
          const token = makeVerificationToken(url);
          verificationTokens.set(hostKey(url), {
            token,
            expiresAt: Date.now() + 30 * 60 * 1000
          });
          await audit("verification_token_created", { ip, target: hostKey(url) });
          json(res, 200, {
            target: hostKey(url),
            token,
            path: VERIFY_PATH,
            url: new URL(VERIFY_PATH, url).toString(),
            expiresInMinutes: 30
          });
        } catch (error) {
          await audit("verification_token_failed", { ip, error: redactSensitive(error.message) });
          json(res, error.statusCode || 400, { error: error.message || "Could not create verification token." });
        }
      });
      return;
    }

    if (req.method === "POST" && req.url === "/api/verify") {
      let raw = "";
      req.on("data", (chunk) => {
        raw += chunk;
        if (raw.length > 20_000) req.destroy();
      });
      req.on("end", async () => {
        try {
          const body = JSON.parse(raw || "{}");
          const result = await verifyTarget(body.url, body.token);
          await audit("target_verified", { ip, target: result.target });
          json(res, 200, result);
        } catch (error) {
          await audit("target_verification_failed", { ip, error: redactSensitive(error.message) });
          json(res, error.statusCode || 400, { error: error.message || "Verification failed." });
        }
      });
      return;
    }

    if (req.method === "POST" && req.url === "/api/scan") {
      let raw = "";
      req.on("data", (chunk) => {
        raw += chunk;
        if (raw.length > 20_000) req.destroy();
      });
      req.on("end", async () => {
        try {
          const body = JSON.parse(raw || "{}");
          if (!body.authorized) {
            json(res, 400, { error: "Confirm that you own or are authorized to test this website." });
            return;
          }
          const target = normalizeTarget(body.url);
          await audit("scan_started", { ip, target: hostKey(target) });
          const report = await scan(body.url);
          await audit("scan_completed", {
            ip,
            target: hostKey(target),
            score: report.score.value,
            counts: report.counts
          });
          json(res, 200, report);
        } catch (error) {
          await audit("scan_failed", { ip, error: redactSensitive(error.message) });
          json(res, error.statusCode || 400, { error: error.message || "Scan failed." });
        }
      });
      return;
    }
    await serveStatic(req, res);
  } catch (error) {
    json(res, error.statusCode || 500, { error: error.message || "Unexpected server error." });
  }
});

server.listen(PORT, () => {
  console.log(`VibeShield running at http://localhost:${PORT}`);
});
