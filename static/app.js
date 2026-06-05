const artifactInput = document.querySelector("#artifactInput");
const analyzeButton = document.querySelector("#analyzeButton");
const useLlm = document.querySelector("#useLlm");
const llmStatus = document.querySelector("#llmStatus");
const reportOutput = document.querySelector("#reportOutput");
const riskScore = document.querySelector("#riskScore");
const findingCount = document.querySelector("#findingCount");
const iocCount = document.querySelector("#iocCount");
const findingsPanel = document.querySelector("#findingsPanel");
const iocsPanel = document.querySelector("#iocsPanel");
const timelinePanel = document.querySelector("#timelinePanel");
const fileInput = document.querySelector("#fileInput");
const inputTitle = document.querySelector("#input-title");

let currentReport = "";
let currentMode = "log";

const samples = {
  auth: "/samples/auth_bruteforce.log",
  web: "/samples/web_probe.log",
  email: "/samples/phishing_email.eml",
};

const placeholders = {
  log: "貼上 SSH、Nginx、EDR、Nmap、Trivy、OpenVAS、Windows Event 等內容",
  email: "貼上完整 .eml 原文，包含 From、Reply-To、Authentication-Results、Received、Subject 和信件內容",
};

function setStatus(text, state = "") {
  llmStatus.textContent = text;
  llmStatus.className = `status-pill ${state}`.trim();
}

function countIocs(iocs) {
  return Object.values(iocs || {}).reduce((total, values) => total + values.length, 0);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderFindings(findings) {
  if (!findings || findings.length === 0) {
    findingsPanel.innerHTML = '<div class="empty-state">尚無 findings。</div>';
    return;
  }

  findingsPanel.innerHTML = findings
    .map((finding) => {
      const examples = (finding.examples || [])
        .map(
          (example) =>
            `<div class="example">Line ${example.line}: ${escapeHtml(example.text)}</div>`,
        )
        .join("");
      return `
        <article class="finding">
          <header>
            <h3>${escapeHtml(finding.name)}</h3>
            <span class="badge ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
          </header>
          <p>${escapeHtml(finding.category)} · ${finding.count} matches</p>
          <p>${escapeHtml(finding.recommendation)}</p>
          ${examples}
        </article>
      `;
    })
    .join("");
}

function renderIocs(iocs) {
  const groups = Object.entries(iocs || {}).filter(([, values]) => values.length > 0);
  if (groups.length === 0) {
    iocsPanel.innerHTML = '<div class="empty-state">尚無 IOCs。</div>';
    return;
  }

  iocsPanel.innerHTML = groups
    .map(
      ([type, values]) => `
        <article class="ioc-group">
          <h3>${escapeHtml(type)}</h3>
          <div class="ioc-list">${values.map(escapeHtml).join("<br />")}</div>
        </article>
      `,
    )
    .join("");
}

function renderTimeline(timeline) {
  if (!timeline || timeline.length === 0) {
    timelinePanel.innerHTML = '<div class="empty-state">尚無 timeline。</div>';
    return;
  }

  timelinePanel.innerHTML = timeline
    .map(
      (event) => `
        <article class="timeline-event">
          <header>
            <strong>${escapeHtml(event.timestamp)}</strong>
            <span class="badge ${escapeHtml(event.severity)}">${escapeHtml(event.severity)}</span>
          </header>
          <p>${escapeHtml(event.event)}</p>
          <div class="example">${escapeHtml(event.detail)}</div>
        </article>
      `,
    )
    .join("");
}

function renderResult(result) {
  const analysis = result.analysis;
  currentReport = result.report || "";
  reportOutput.textContent = currentReport || "沒有報告內容。";
  riskScore.textContent = `${analysis.risk_score}`;
  riskScore.style.color =
    analysis.risk_label === "critical" || analysis.risk_label === "high"
      ? "var(--danger)"
      : analysis.risk_label === "medium"
        ? "var(--warning)"
        : "var(--good)";
  findingCount.textContent = `${analysis.findings.length}`;
  iocCount.textContent = `${countIocs(analysis.iocs)}`;
  renderFindings(analysis.findings);
  renderIocs(analysis.iocs);
  renderTimeline(analysis.timeline);

  if (result.llm?.used) {
    setStatus(`LLM ${result.llm.latency_ms}ms`, "live");
  } else if (result.llm?.error) {
    setStatus("Local fallback", "warn");
  } else {
    setStatus("Local only");
  }
}

async function analyze() {
  const content = artifactInput.value.trim();
  if (!content) {
    reportOutput.textContent = currentMode === "email" ? "請先貼上或載入 email 原文。" : "請先貼上或載入 log / 掃描結果。";
    return;
  }

  analyzeButton.disabled = true;
  analyzeButton.textContent = "分析中";
  setStatus(useLlm.checked ? "LLM 分析中" : "Local 分析中", "live");

  try {
    const endpoint = currentMode === "email" ? "/api/analyze-email" : "/api/analyze";
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, use_llm: useLlm.checked }),
    });
    const result = await response.json();
    if (!response.ok) {
      throw new Error(result.error || "Analysis request failed");
    }
    renderResult(result);
  } catch (error) {
    setStatus("分析失敗", "warn");
    reportOutput.textContent = `Error: ${error.message}`;
  } finally {
    analyzeButton.disabled = false;
    analyzeButton.textContent = "分析";
  }
}

async function loadSample(kind) {
  const response = await fetch(samples[kind]);
  artifactInput.value = await response.text();
}

function setMode(mode) {
  currentMode = mode;
  document.querySelectorAll(".mode-button").forEach((button) => {
    button.classList.toggle("active", button.dataset.mode === mode);
  });
  inputTitle.textContent = mode === "email" ? "Email 輸入" : "事件輸入";
  artifactInput.placeholder = placeholders[mode];
  reportOutput.textContent = mode === "email" ? "等待 Email 分析。" : "等待分析。";
  riskScore.textContent = "--";
  riskScore.style.color = "";
  findingCount.textContent = "--";
  iocCount.textContent = "--";
  findingsPanel.innerHTML = '<div class="empty-state">尚無 findings。</div>';
  iocsPanel.innerHTML = '<div class="empty-state">尚無 IOCs。</div>';
  timelinePanel.innerHTML = '<div class="empty-state">尚無 timeline。</div>';
  currentReport = "";
  setStatus("LLM 待命");
}

document.querySelector("#loadAuthSample").addEventListener("click", () => loadSample("auth"));
document.querySelector("#loadWebSample").addEventListener("click", () => loadSample("web"));
document.querySelector("#loadEmailSample").addEventListener("click", () => {
  setMode("email");
  loadSample("email");
});
analyzeButton.addEventListener("click", analyze);
document.querySelectorAll(".mode-button").forEach((button) => {
  button.addEventListener("click", () => setMode(button.dataset.mode));
});

fileInput.addEventListener("change", async () => {
  const [file] = fileInput.files;
  if (!file) return;
  artifactInput.value = await file.text();
});

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((tab) => tab.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.remove("active"));
    button.classList.add("active");
    document.querySelector(`#${button.dataset.tab}Panel`).classList.add("active");
  });
});

document.querySelector("#copyReport").addEventListener("click", async () => {
  if (!currentReport) return;
  await navigator.clipboard.writeText(currentReport);
  setStatus("Copied", "live");
});

document.querySelector("#downloadReport").addEventListener("click", () => {
  if (!currentReport) return;
  const blob = new Blob([currentReport], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "ai-soc-analyst-report.md";
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
});
