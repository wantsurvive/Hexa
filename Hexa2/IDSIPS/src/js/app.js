const API_BASE_CANDIDATES = buildApiBaseCandidates();
let activeApiBase = null;
const API_BASE_STORAGE_KEY = "idsipsApiBase";

const els = {
  systemToggle: document.getElementById("systemToggle"),
  engineStatus: document.getElementById("engineStatus"),
  blockedCount: document.getElementById("blockedCount"),
  suspiciousCount: document.getElementById("suspiciousCount"),
  sslDaysLeft: document.getElementById("sslDaysLeft"),
  resourceCards: document.getElementById("resourceCards"),
  ipTableBody: document.getElementById("ipTableBody"),
  ipSearch: document.getElementById("ipSearch"),
  manualBlockForm: document.getElementById("manualBlockForm"),
  manualIpInput: document.getElementById("manualIpInput"),
  manualReasonInput: document.getElementById("manualReasonInput"),
  manualUnblockBtn: document.getElementById("manualUnblockBtn"),
  newUserIp: document.getElementById("newUserIp"),
  newUserRole: document.getElementById("newUserRole"),
  addUserBtn: document.getElementById("addUserBtn"),
  pendingList: document.getElementById("pendingList"),
  portPolicyForm: document.getElementById("portPolicyForm"),
  allowPortsInput: document.getElementById("allowPortsInput"),
  portPolicyText: document.getElementById("portPolicyText"),
  simulatePermissionChangeBtn: document.getElementById("simulatePermissionChangeBtn"),
  simulateCoreFileChangeBtn: document.getElementById("simulateCoreFileChangeBtn"),
  allLogsList: document.getElementById("allLogsList"),
  suspiciousLogsList: document.getElementById("suspiciousLogsList"),
  alertBanner: document.getElementById("alertBanner"),
  logItemTemplate: document.getElementById("logItemTemplate"),
  exportAllLogsBtn: document.getElementById("exportAllLogsBtn"),
  exportSuspiciousLogsBtn: document.getElementById("exportSuspiciousLogsBtn")
};

async function fetchData() {
  try {
    const data = await apiJson("/api/status");
    render(data);
  } catch (err) {
    console.error("Failed to fetch status:", err);
    showConnectionError(err);
  }
}

function render(data) {
  els.engineStatus.textContent = data.engineOn ? "ON" : "OFF";
  els.blockedCount.textContent = data.blockedCount;
  els.suspiciousCount.textContent = data.suspiciousCount;
  els.systemToggle.textContent = data.engineOn ? "IPS ON" : "IPS OFF";
  
  renderResources(data.resources);
  renderLogs(data.logs, data.suspiciousLogs);
  renderIpTable(data.blockedIps);
}

function renderResources(resources) {
  const pairs = [
    ["CPU", resources.cpu],
    ["MEMORY", resources.memory],
    ["DISK", resources.disk],
    ["NETWORK", resources.network]
  ];

  els.resourceCards.innerHTML = "";
  for (const [label, value] of pairs) {
    const card = document.createElement("article");
    card.className = "resource-card";
    const overThreshold = value >= 80;
    card.innerHTML = `
      <div class="meta">
        <strong>${label}</strong>
        <span>${value}%</span>
      </div>
      <div class="progress ${overThreshold ? "danger" : ""}">
        <span style="width: ${value}%"></span>
      </div>
    `;
    els.resourceCards.appendChild(card);
  }
}

function renderLogs(logs, suspiciousLogs) {
  renderLogList(els.allLogsList, logs);
  renderLogList(els.suspiciousLogsList, suspiciousLogs);
}

function renderLogList(target, logs) {
  target.innerHTML = "";
  const recent = [...logs].reverse();
  for (const item of recent) {
    const node = els.logItemTemplate.content.firstElementChild.cloneNode(true);
    
    //  toLocaleTimeString()을 toLocaleString('ko-KR')로 변경!
    node.querySelector(".time").textContent = new Date(item.ts).toLocaleString('ko-KR');
    
    node.querySelector(".message").textContent = `[${item.category}] ${item.message}`;
    target.appendChild(node);
  }
}

function renderIpTable(blockedIps) {
  els.ipTableBody.innerHTML = "";
  const searchTerm = els.ipSearch?.value?.toLowerCase() || "";
  
  Object.keys(blockedIps).forEach(ip => {
    if (searchTerm && !ip.toLowerCase().includes(searchTerm)) {
      return;
    }
    
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${ip}</td>
      <td><span class="badge badge-user">blocked</span></td>
      <td colspan="4">${blockedIps[ip].reason}</td>
      <td><span class="badge badge-blocked">blocked</span></td>
      <td>
        <button class="btn" onclick="unblockIp('${ip}')">해제</button>
      </td>
    `;
    els.ipTableBody.appendChild(tr);
  });
}

async function toggleEngine() {
  try {
    const result = await apiJson("/api/toggle", { method: "POST" });
    els.engineStatus.textContent = result.engineOn ? "ON" : "OFF";
    els.systemToggle.textContent = result.engineOn ? "IPS ON" : "IPS OFF";
    fetchData();
  } catch (err) {
    console.error("Failed to toggle engine:", err);
    showConnectionError(err);
  }
}

async function blockIp(ip, reason) {
  try {
    await apiJson("/api/block", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, reason })
    });
    fetchData();
  } catch (err) {
    console.error("Failed to block IP:", err);
    showConnectionError(err);
  }
}

async function unblockIp(ip) {
  try {
    await apiJson("/api/unblock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip })
    });
    fetchData();
  } catch (err) {
    console.error("Failed to unblock IP:", err);
    showConnectionError(err);
  }
}

async function addUser() {
  try {
    const ip = els.newUserIp.value;
    const role = els.newUserRole.value;
    
    if (!ip) {
      alert("IP를 입력해주세요");
      return;
    }
    
    await apiJson("/api/add-user", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, role })
    });
    
    els.newUserIp.value = "";
    els.newUserRole.value = "user";
    fetchUsers();
    fetchData();
  } catch (err) {
    console.error("Failed to add user:", err);
    alert("사용자 등록 실패: " + err.message);
  }
}

async function fetchUsers() {
  try {
    const result = await apiJson("/api/users");
    renderUsers(result.users);
  } catch (err) {
    console.error("Failed to fetch users:", err);
  }
}

function renderUsers(users) {
  if (!els.pendingList) return;
  
  els.pendingList.innerHTML = "";
  users.forEach(user => {
    const li = document.createElement("li");
    li.textContent = `${user.ip} (${user.role})`;
    els.pendingList.appendChild(li);
  });
}

async function setPortPolicy() {
  try {
    const portsInput = els.allowPortsInput.value;
    const ports = portsInput.split(",").map(p => p.trim()).filter(p => p);
    
    if (ports.length === 0) {
      alert("포트를 입력해주세요 (쉼표로 구분)");
      return;
    }
    
    await apiJson("/api/port-policy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ports })
    });
    
    els.portPolicyText.textContent = `허용 포트: ${ports.join(", ")}`;
    fetchData();
  } catch (err) {
    console.error("Failed to set port policy:", err);
    alert("포트 정책 설정 실패: " + err.message);
  }
}

async function getPortPolicy() {
  try {
    const result = await apiJson("/api/port-policy");
    els.allowPortsInput.value = result.allowedPorts.join(",");
    els.portPolicyText.textContent = `허용 포트: ${result.allowedPorts.join(", ")}`;
  } catch (err) {
    console.error("Failed to fetch port policy:", err);
  }
}

async function simulatePermissionChange() {
  try {
    await apiJson("/api/simulate-permission-change", { method: "POST" });
    alert("권한 변경 이벤트 시뮬레이션 완료");
    fetchData();
  } catch (err) {
    console.error("Failed to simulate permission change:", err);
    alert("시뮬레이션 실패: " + err.message);
  }
}

async function simulateCoreFileChange() {
  try {
    await apiJson("/api/simulate-core-file-change", { method: "POST" });
    alert("핵심 파일 변경 이벤트 시뮬레이션 완료");
    fetchData();
  } catch (err) {
    console.error("Failed to simulate core file change:", err);
    alert("시뮬레이션 실패: " + err.message);
  }
}

async function exportAllLogs() {
  try {
    window.location.href = getApiUrl("/api/export-logs");
  } catch (err) {
    console.error("Failed to export logs:", err);
    alert("로그 내보내기 실패: " + err.message);
  }
}

async function exportSuspiciousLogs() {
  try {
    window.location.href = getApiUrl("/api/export-suspicious-logs");
  } catch (err) {
    console.error("Failed to export suspicious logs:", err);
    alert("의심 로그 내보내기 실패: " + err.message);
  }
}

function normalizeApiBase(base) {
  if (!base) {
    return "";
  }

  return `${base}`.trim().replace(/\/+$/, "");
}

function getConfiguredApiBase() {
  const params = new URLSearchParams(window.location.search);
  const queryBase = normalizeApiBase(params.get("apiBase"));
  if (queryBase) {
    return queryBase;
  }

  try {
    const storedBase = normalizeApiBase(window.localStorage.getItem(API_BASE_STORAGE_KEY));
    if (storedBase) {
      return storedBase;
    }
  } catch (err) {
    // Ignore storage access failures in hardened browser contexts.
  }

  const metaBase = normalizeApiBase(document.querySelector('meta[name="idsips-api-base"]')?.content);
  if (metaBase) {
    return metaBase;
  }

  return normalizeApiBase(window.__IDSIPS_API_BASE__);
}

function buildApiBaseCandidates() {
  const candidates = [];
  const { protocol, hostname, port } = window.location;
  const configuredBase = getConfiguredApiBase();

  if (configuredBase) {
    candidates.push(configuredBase);
  }

  // Prefer same-origin first when app is served by backend or reverse proxy.
  if (protocol !== "file:") {
    candidates.push("");
    candidates.push(window.location.origin);
  }

  // Explicit backend port candidate for local multi-port dev.
  if (!(protocol === "http:" && hostname === "localhost" && port === "4000")) {
    candidates.push(`${protocol}//${hostname || "localhost"}:4000`);
  }

  if (!(protocol === "http:" && hostname === "127.0.0.1" && port === "4000")) {
    candidates.push(`${protocol}//127.0.0.1:4000`);
  }

  // Final local fallback for file:// or unexpected host setups.
  if (!candidates.includes("http://localhost:4000")) {
    candidates.push("http://localhost:4000");
  }

  if (!candidates.includes("http://127.0.0.1:4000")) {
    candidates.push("http://127.0.0.1:4000");
  }

  return [...new Set(candidates)];
}

function getApiUrl(path) {
  return activeApiBase ? `${activeApiBase}${path}` : path;
}

function rememberApiBase(base) {
  if (!base) {
    return;
  }

  try {
    window.localStorage.setItem(API_BASE_STORAGE_KEY, base);
  } catch (err) {
    // Ignore storage access failures in hardened browser contexts.
  }
}

async function apiJson(path, options = {}) {
  const basesToTry = activeApiBase
    ? [activeApiBase, ...API_BASE_CANDIDATES.filter((base) => base !== activeApiBase)]
    : [...API_BASE_CANDIDATES];

  let lastError = null;

  for (const base of basesToTry) {
    try {
      const response = await fetch(`${base}${path}`, options);
      if (!response.ok) {
        throw new Error(`${response.status} ${response.statusText}`);
      }

      activeApiBase = base;
      rememberApiBase(base);
      return response.json();
    } catch (err) {
      lastError = err;
    }
  }

  throw lastError || new Error("API 요청 실패");
}

function showConnectionError(err) {
  if (!els.alertBanner) {
    return;
  }
  els.alertBanner.classList.add("danger");
  els.alertBanner.textContent = `백엔드 연결 실패: ${err.message} (서버 4000 포트 확인)`;
}

// Event listeners
if (els.systemToggle) {
  els.systemToggle.addEventListener("click", toggleEngine);
}

if (els.manualBlockForm) {
  els.manualBlockForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const ip = els.manualIpInput.value;
    const reason = els.manualReasonInput.value;
    blockIp(ip, reason);
    els.manualBlockForm.reset();
  });
}

if (els.manualUnblockBtn) {
  els.manualUnblockBtn.addEventListener("click", () => {
    const ip = els.manualIpInput.value;
    if (!ip) {
      alert("IP를 입력해주세요");
      return;
    }
    unblockIp(ip);
    els.manualBlockForm.reset();
  });
}

if (els.ipSearch) {
  els.ipSearch.addEventListener("input", () => {
    fetchData();
  });
}

if (els.addUserBtn) {
  els.addUserBtn.addEventListener("click", addUser);
}

if (els.portPolicyForm) {
  els.portPolicyForm.addEventListener("submit", (e) => {
    e.preventDefault();
    setPortPolicy();
  });
}

if (els.simulatePermissionChangeBtn) {
  els.simulatePermissionChangeBtn.addEventListener("click", simulatePermissionChange);
}

if (els.simulateCoreFileChangeBtn) {
  els.simulateCoreFileChangeBtn.addEventListener("click", simulateCoreFileChange);
}

if (els.exportAllLogsBtn) {
  els.exportAllLogsBtn.addEventListener("click", exportAllLogs);
}

if (els.exportSuspiciousLogsBtn) {
  els.exportSuspiciousLogsBtn.addEventListener("click", exportSuspiciousLogs);
}

// Check if current client IP is blocked
async function checkIfBlocked() {
  try {
    // Make a request to /api/status - if we get a 403, we're blocked
    const response = await fetch(getApiUrl("/api/status"));
    
    if (response.status === 403) {
      const errorData = await response.json();
      showBlockedAlert(errorData);
      return true;
    }
    
    return false;
  } catch (err) {
    console.error("Error checking if blocked:", err);
    return false;
  }
}

function showBlockedAlert(errorData) {
  const alertDiv = document.createElement("div");
  alertDiv.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.8);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 9999;
  `;
  
  const contentDiv = document.createElement("div");
  contentDiv.style.cssText = `
    background: white;
    padding: 40px;
    border-radius: 8px;
    text-align: center;
    max-width: 500px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  `;
  
  contentDiv.innerHTML = `
    <h2 style="color: #dc2626; margin-top: 0;">접근 차단됨</h2>
    <p style="font-size: 16px; color: #333; margin: 20px 0;">
      귀하의 IP 주소(${errorData.ip})는 차단되었습니다.
    </p>
    <p style="font-size: 14px; color: #666; margin: 20px 0;">
      <strong>차단 사유:</strong> ${errorData.reason}
    </p>
    <p style="font-size: 12px; color: #999; margin: 20px 0;">
      관리자에게 문의하시기 바랍니다.
    </p>
  `;
  
  alertDiv.appendChild(contentDiv);
  document.body.appendChild(alertDiv);
}

// Initial load and periodic update
checkIfBlocked().then((isBlocked) => {
  if (!isBlocked) {
    fetchData();
    getPortPolicy();
    fetchUsers();
    setInterval(fetchData, 3000);
  }
});
