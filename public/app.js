const form = document.querySelector("#scan-form");
const tokenButton = document.querySelector("#token-button");
const verifyButton = document.querySelector("#verify-button");
const scanButton = document.querySelector("#scan-button");
const statusBox = document.querySelector("#status");
const statusText = document.querySelector("#status-text");
const errorBox = document.querySelector("#error");
const reportBox = document.querySelector("#report");
const findingsBox = document.querySelector("#findings");
const filters = document.querySelector("#filters");
const verificationBox = document.querySelector("#verification");
const verifyUrl = document.querySelector("#verify-url");
const verifyToken = document.querySelector("#verify-token");

let currentReport = null;
let currentFilter = "all";
let statusTimer = null;
let currentToken = "";
let verifiedTarget = "";

const statusMessages = [
  "Fetching the homepage and checking security basics.",
  "Looking at headers, cookies, CORS, and transport settings.",
  "Crawling same-origin links and collecting forms, scripts, and API-looking paths.",
  "Checking for exposed public files and production source maps.",
  "Running safe reflected-input and redirect probes.",
  "Prioritizing findings and writing builder-friendly fixes."
];

tokenButton.addEventListener("click", async () => {
  const url = document.querySelector("#url").value;
  showWorking("Creating a domain verification token.");
  try {
    const payload = await apiPost("/api/verification-token", { url });
    currentToken = payload.token;
    verifiedTarget = "";
    verifyUrl.textContent = payload.url;
    verifyToken.textContent = payload.token;
    verificationBox.classList.remove("hidden");
    scanButton.disabled = true;
    clearError();
  } catch (error) {
    showError(error.message);
  } finally {
    stopWorking();
  }
});

verifyButton.addEventListener("click", async () => {
  const url = document.querySelector("#url").value;
  showWorking("Checking the verification token on your domain.");
  try {
    const payload = await apiPost("/api/verify", { url, token: currentToken });
    verifiedTarget = payload.target;
    scanButton.disabled = false;
    clearError();
    verifyButton.textContent = "Verified";
    setTimeout(() => {
      verifyButton.textContent = "Verify ownership";
    }, 1600);
  } catch (error) {
    showError(error.message);
  } finally {
    stopWorking();
  }
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = document.querySelector("#url").value;
  const authorized = document.querySelector("#authorized").checked;
  startLoading();

  try {
    if (!verifiedTarget) throw new Error("Verify ownership before running the scan.");
    const payload = await apiPost("/api/scan", { url, authorized });
    currentReport = payload;
    currentFilter = "all";
    renderReport(payload);
  } catch (error) {
    showError(error.message);
  } finally {
    stopLoading();
  }
});

document.querySelector("#url").addEventListener("input", () => {
  currentToken = "";
  verifiedTarget = "";
  scanButton.disabled = true;
  verificationBox.classList.add("hidden");
});

filters.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-filter]");
  if (!button || !currentReport) return;
  currentFilter = button.dataset.filter;
  document.querySelectorAll("#filters button").forEach((item) => item.classList.toggle("active", item === button));
  renderFindings(currentReport.findings);
});

function startLoading() {
  errorBox.classList.add("hidden");
  reportBox.classList.add("hidden");
  statusBox.classList.remove("hidden");
  let index = 0;
  statusText.textContent = statusMessages[index];
  clearInterval(statusTimer);
  statusTimer = setInterval(() => {
    index = (index + 1) % statusMessages.length;
    statusText.textContent = statusMessages[index];
  }, 2300);
  scanButton.disabled = true;
}

function stopLoading() {
  clearInterval(statusTimer);
  statusBox.classList.add("hidden");
  scanButton.disabled = !verifiedTarget;
}

function showWorking(message) {
  errorBox.classList.add("hidden");
  statusBox.classList.remove("hidden");
  statusText.textContent = message;
  tokenButton.disabled = true;
  verifyButton.disabled = true;
}

function stopWorking() {
  statusBox.classList.add("hidden");
  tokenButton.disabled = false;
  verifyButton.disabled = false;
}

function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove("hidden");
}

function clearError() {
  errorBox.textContent = "";
  errorBox.classList.add("hidden");
}

async function apiPost(path, body) {
  const accessToken = document.querySelector("#access-token").value.trim();
  const headers = { "content-type": "application/json" };
  if (accessToken) headers["x-scanner-token"] = accessToken;
  const response = await fetch(path, {
    method: "POST",
    headers,
    body: JSON.stringify(body)
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || "Request failed.");
  return payload;
}

function renderReport(report) {
  document.querySelector("#report-target").textContent = report.target;
  document.querySelector("#score-value").textContent = report.score.value;
  document.querySelector("#score-label").textContent = report.score.label;
  document.querySelector("#critical-count").textContent = report.counts.critical;
  document.querySelector("#high-count").textContent = report.counts.high;
  document.querySelector("#medium-count").textContent = report.counts.medium;
  document.querySelector("#low-count").textContent = report.counts.low;

  renderDefinitionList("#surface-list", {
    Pages: report.surface.pages.length,
    Forms: report.surface.forms.length,
    Inputs: report.surface.inputs.length,
    Scripts: report.surface.scripts.length,
    "API paths": report.surface.apiPaths.length
  });

  renderDefinitionList("#tls-list", report.tls?.error ? {
    Status: report.tls.error
  } : {
    Protocol: report.tls?.protocol || "Not checked",
    "Valid to": report.tls?.validTo || "Not checked",
    Issuer: report.tls?.issuer || "Not checked"
  });

  const stackHints = document.querySelector("#stack-hints");
  stackHints.innerHTML = "";
  const hints = report.stackHints.length ? report.stackHints : ["No clear stack hints"];
  hints.forEach((hint) => {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.textContent = hint;
    stackHints.append(chip);
  });

  document.querySelectorAll("#filters button").forEach((item) => item.classList.toggle("active", item.dataset.filter === "all"));
  renderFindings(report.findings);
  reportBox.classList.remove("hidden");
  reportBox.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderDefinitionList(selector, entries) {
  const list = document.querySelector(selector);
  list.innerHTML = "";
  Object.entries(entries).forEach(([term, description]) => {
    const dt = document.createElement("dt");
    const dd = document.createElement("dd");
    dt.textContent = term;
    dd.textContent = description;
    list.append(dt, dd);
  });
}

function renderFindings(findings) {
  findingsBox.innerHTML = "";
  const visible = findings.filter((finding) => currentFilter === "all" || finding.severity === currentFilter);

  if (!visible.length) {
    const empty = document.createElement("article");
    empty.className = "finding";
    empty.innerHTML = "<h4>No findings in this filter</h4><p>Try a different severity filter.</p>";
    findingsBox.append(empty);
    return;
  }

  visible.forEach((finding) => {
    const article = document.createElement("article");
    article.className = `finding ${finding.severity}`;
    article.innerHTML = `
      <div class="finding-head">
        <div>
          <h4>${escapeHtml(finding.title)}</h4>
          <div class="meta">${escapeHtml(finding.category)} · ${escapeHtml(finding.confidence)} confidence · ${escapeHtml(finding.url)}</div>
        </div>
        <span class="badge">${escapeHtml(finding.severity)}</span>
      </div>
      <p><strong>Why it matters:</strong> ${escapeHtml(finding.why)}</p>
      <p><strong>Fix:</strong> ${escapeHtml(finding.fix)}</p>
      ${finding.evidence?.length ? `<ul>${finding.evidence.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>` : ""}
      <div class="prompt">${escapeHtml(finding.fixPrompt)}</div>
      <button class="copy" type="button">Copy fix prompt</button>
    `;
    article.querySelector(".copy").addEventListener("click", async () => {
      await navigator.clipboard.writeText(finding.fixPrompt);
      article.querySelector(".copy").textContent = "Copied";
      setTimeout(() => {
        article.querySelector(".copy").textContent = "Copy fix prompt";
      }, 1400);
    });
    findingsBox.append(article);
  });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
