const express = require("express");
const cors = require("cors");
const os = require("os");
const osUtils = require("os-utils");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const { v4: uuidv4 } = require("uuid");
const fs = require("fs");
const { exec } = require("child_process");

const app = express();
const PORT = process.env.IDSIPS_PORT || 4000;
const HOST = process.env.IDSIPS_HOST || "0.0.0.0";

app.set("trust proxy", true);

const dataDir = path.join(__dirname, "data");
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}
const dbPath = path.join(dataDir, "idsips.db");

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error("Database connection error:", err.message);
  else {
    console.log("Connected to SQLite database at:", dbPath);
    initializeDatabase();
  }
});

app.use(cors());
app.use(express.json());

function normalizeClientIp(ip) {
  if (!ip) return "0.0.0.0";
  const trimmedIp = Array.isArray(ip) ? ip[0] : `${ip}`.split(",")[0].trim();
  if (trimmedIp === "::1") return "127.0.0.1";
  if (trimmedIp.startsWith("::ffff:")) return trimmedIp.slice(7);
  return trimmedIp;
}

app.use((req, res, next) => {
  req.clientIp = normalizeClientIp(
    req.headers["x-forwarded-for"] || req.headers["x-real-ip"] || req.ip || req.socket.remoteAddress || req.connection.remoteAddress
  );
  next();
});

app.use(express.static(path.join(__dirname, "src")));

function initializeDatabase() {
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS blocked_ips (id TEXT PRIMARY KEY, ip TEXT UNIQUE NOT NULL, reason TEXT NOT NULL, blocked_at TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
    db.run(`CREATE TABLE IF NOT EXISTS logs (id TEXT PRIMARY KEY, category TEXT NOT NULL, message TEXT NOT NULL, is_suspicious INTEGER DEFAULT 0, ts TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
    db.run(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, ip TEXT UNIQUE NOT NULL, role TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
    db.run(`CREATE TABLE IF NOT EXISTS system_state (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT DEFAULT CURRENT_TIMESTAMP)`, () => {
      db.run("INSERT OR IGNORE INTO system_state (key, value) VALUES (?, ?)", ["engineOn", "true"]);
      db.run("INSERT OR IGNORE INTO system_state (key, value) VALUES (?, ?)", ["allowedPorts", "22,80,443,3000,4000"]);
    });
  });
}

function addLog(category, message, isSuspicious = false) {
  const id = uuidv4();
  const now = new Date();
  const utc = now.getTime() + (now.getTimezoneOffset() * 60000);
  const kst = new Date(utc + (9 * 3600000));
  
  const yyyy = kst.getFullYear();
  const mm = String(kst.getMonth() + 1).padStart(2, '0');
  const dd = String(kst.getDate()).padStart(2, '0');
  const hh = String(kst.getHours()).padStart(2, '0');
  const min = String(kst.getMinutes()).padStart(2, '0');
  const ss = String(kst.getSeconds()).padStart(2, '0');
  const ts = `${yyyy}-${mm}-${dd} ${hh}:${min}:${ss}`;

  db.run("INSERT INTO logs (id, category, message, is_suspicious, ts) VALUES (?, ?, ?, ?, ?)", [id, category, message, isSuspicious ? 1 : 0, ts]);
}

function getState(callback) {
  db.all("SELECT key, value FROM system_state", (err, rows) => {
    if (err) return callback(err, null);
    const state = { engineOn: true, allowedPorts: [22, 80, 443, 3000, 4000] };
    if (rows) {
      rows.forEach(row => {
        if (row.key === "engineOn") state.engineOn = row.value === "true";
        else if (row.key === "allowedPorts") state.allowedPorts = row.value.split(",").map(p => parseInt(p));
      });
    }
    callback(null, state);
  });
}

function checkIfBlocked(clientIp, callback) {
  db.get("SELECT reason FROM blocked_ips WHERE ip = ?", [clientIp], (err, row) => {
    if (err) return callback(err, false);
    callback(null, !!row, row ? row.reason : null);
  });
}

function sendBlockedResponse(res, clientIp, reason) {
  return res.status(403).json({ error: "Forbidden - Your IP address has been blocked", reason: reason, ip: clientIp });
}

app.get("/api/status", (req, res) => {
  checkIfBlocked(req.clientIp, (err, isBlocked, reason) => {
    if (isBlocked) return sendBlockedResponse(res, req.clientIp, reason);
    
    osUtils.cpuUsage((v) => {
      db.get("SELECT COUNT(*) as count FROM blocked_ips", (err, countIps) => {
        db.get("SELECT COUNT(*) as count FROM logs WHERE is_suspicious = 1", (err, countSuspicious) => {
          db.all("SELECT ip, reason, blocked_at FROM blocked_ips", (err, blockedIps) => {
            db.all("SELECT category, message, ts FROM logs ORDER BY ts DESC LIMIT 20", (err, logs) => {
              db.all("SELECT category, message, ts FROM logs WHERE is_suspicious = 1 ORDER BY ts DESC LIMIT 20", (err, suspiciousLogs) => {
                getState((err, state) => {
                  const blockedIpsMap = {};
                  if (blockedIps) blockedIps.forEach(row => { blockedIpsMap[row.ip] = { reason: row.reason, blockedAt: row.blocked_at }; });
                  res.json({
                    engineOn: state.engineOn,
                    blockedCount: countIps?.count || 0,
                    suspiciousCount: countSuspicious?.count || 0,
                    resources: { cpu: Math.round(v * 100), memory: Math.round((1 - osUtils.freememPercentage()) * 100), disk: 45, network: 15 },
                    blockedIps: blockedIpsMap,
                    logs: logs || [],
                    suspiciousLogs: suspiciousLogs || [],
                  });
                });
              });
            });
          });
        });
      });
    });
  });
});

app.post("/api/toggle", (req, res) => {
  checkIfBlocked(req.clientIp, (err, isBlocked, reason) => {
    if (isBlocked) return sendBlockedResponse(res, req.clientIp, reason);
    db.get("SELECT value FROM system_state WHERE key = ?", ["engineOn"], (err, row) => {
      const newValue = row && row.value === "true" ? "false" : "true";
      db.run("UPDATE system_state SET value = ? WHERE key = ?", [newValue, "engineOn"], () => {
        addLog("ENGINE", `IDS/IPS 엔진 ${newValue === "true" ? "ON" : "OFF"}`);
        res.json({ engineOn: newValue === "true" });
      });
    });
  });
});

app.post("/api/block", (req, res) => {
  checkIfBlocked(req.clientIp, (err, isBlocked, reason) => {
    if (isBlocked) return sendBlockedResponse(res, req.clientIp, reason);
    
    // [수정] 수동 차단 시에도 IP 정제
    const ip = normalizeClientIp(req.body.ip);
    const blockReason = req.body.reason;
    
    if (!ip) return res.status(400).json({ error: "IP is required" });
    const id = uuidv4();
    const blockedAt = new Date().toISOString();
    
    db.run("INSERT OR REPLACE INTO blocked_ips (id, ip, reason, blocked_at) VALUES (?, ?, ?, ?)", [id, ip, blockReason, blockedAt], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      addLog("BLOCK", `${ip} 차단됨 - ${blockReason}`, true);
      res.json({ message: "Blocked successfully" });
    });
  });
});

app.post("/api/unblock", (req, res) => {
  checkIfBlocked(req.clientIp, (err, isBlocked, reason) => {
    if (isBlocked) return sendBlockedResponse(res, req.clientIp, reason);
    
    // [수정] 수동 해제 시에도 IP 정제
    const ip = normalizeClientIp(req.body.ip);
    
    db.run("DELETE FROM blocked_ips WHERE ip = ?", [ip], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      addLog("UNBLOCK", `${ip} 관제 센터에서 차단 해제됨`);
      res.json({ message: "Unblocked successfully" });
    });
  });
});

// ==========================================
// ★ [수정됨] 차단 해제 로직 (8080번 통신 불필요! 8080은 이제 상태를 저장하지 않음)
app.post("/api/unblock", (req, res) => {
  checkIfBlocked(req.clientIp, (err, isBlocked, reason) => {
    if (isBlocked) return sendBlockedResponse(res, req.clientIp, reason);
    
    const { ip } = req.body;
    db.run("DELETE FROM blocked_ips WHERE ip = ?", [ip], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      addLog("UNBLOCK", `${ip} 관제 센터에서 차단 해제됨`);
      res.json({ message: "Unblocked successfully" });
    });
  });
});

// ==========================================
// ★ [보안 강화 1] 철통 보안 문지기 (엔진이 꺼져도 기존 범죄자는 막음)
app.get("/api/check-ip/:ip", (req, res) => {
  // [수정] 8080에서 넘어오는 IP도 동일하게 정제 (::ffff: 꼬리표 제거)
  const ip = normalizeClientIp(req.params.ip);
  
  db.get("SELECT reason FROM blocked_ips WHERE ip = ?", [ip], (err, row) => {
    const isBlocked = !!row;
    // 엔진 상태(engineOn)와 무관하게 DB에 있으면 무조건 막습니다.
    res.json({ blocked: isBlocked, reason: isBlocked ? row.reason : null });
  });
});

// ==========================================
// ★ [보안 강화 2] 위협 탐지 센서 (엔진이 꺼져 있으면 새로운 놈을 가두지 않음)
app.post("/api/report-event", (req, res) => {
  // [수정] 여기서도 IP 정제 적용!
  const ip = normalizeClientIp(req.body.ip);
  const { category, message, shouldBlock } = req.body;
  
  // [수정] 문자열 "false"가 true로 잘못 인식되는 자바스크립트 함정 방어
  const isBlockTarget = (shouldBlock === true || shouldBlock === "true");
  
  getState((err, state) => {
    const logMsg = state.engineOn 
      ? `[WAF 탐지 및 차단] ${ip}: ${message}` 
      : `[WAF 탐지 (차단 스킵-엔진OFF)] ${ip}: ${message}`;
    
    addLog(category, logMsg, isBlockTarget);
    
    // 엔진이 켜져 있고(engineOn === true), 차단 요청(isBlockTarget)이 왔을 때만 가둠!
    if (isBlockTarget && state.engineOn) {
      const id = uuidv4();
      const blockedAt = new Date().toISOString();
      
      // [수정] DB 저장이 '완전히 끝난 후'에 응답을 보내도록 수정 (비동기 엇박자 해결)
      db.run(
        "INSERT OR IGNORE INTO blocked_ips (id, ip, reason, blocked_at) VALUES (?, ?, ?, ?)",
        [id, ip, message, blockedAt],
        (err) => {
          if (err) {
            console.error("DB Insert Error:", err);
            return res.status(500).json({ error: err.message });
          }
          res.json({ status: "Event recorded and IP blocked" });
        }
      );
    } else {
      res.json({ status: "Event recorded (No block applied due to Engine OFF or Info Log)" });
    }
  });
});
// --- 아래는 엑셀 추출 등 기존 코드 원형 그대로 유지 ---
app.get("/api/export-logs", (req, res) => {
  db.all("SELECT category, message, ts FROM logs ORDER BY ts DESC", (err, logs) => {
    if (err) return res.status(500).json({ error: err.message });
    let csvContent = "\uFEFF분류,메시지,시간\n";
    if (logs) logs.forEach(log => { csvContent += `"${log.category}","${log.message.replace(/"/g, '""')}","${log.ts}"\n`; });
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", "attachment; filename=idsips_logs.csv");
    res.send(csvContent);
  });
});

app.get("/api/export-suspicious-logs", (req, res) => {
  db.all("SELECT category, message, ts FROM logs WHERE is_suspicious = 1 ORDER BY ts DESC", (err, logs) => {
    if (err) return res.status(500).json({ error: err.message });
    let csvContent = "\uFEFF분류,메시지,시간\n";
    if (logs) logs.forEach(log => { csvContent += `"${log.category}","${log.message.replace(/"/g, '""')}","${log.ts}"\n`; });
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", "attachment; filename=idsips_suspicious_logs.csv");
    res.send(csvContent);
  });
});

app.post("/api/add-user", (req, res) => {
  checkIfBlocked(req.clientIp, (err, isBlocked, reason) => {
    if (isBlocked) return sendBlockedResponse(res, req.clientIp, reason);
    const { ip, role } = req.body;
    if (!ip || !role) return res.status(400).json({ error: "IP and role are required" });
    const id = uuidv4();
    db.run("INSERT INTO users (id, ip, role) VALUES (?, ?, ?)", [id, ip, role], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      addLog("USER_ADDED", `사용자 ${ip} (${role}) 추가됨`);
      res.json({ message: "User added successfully" });
    });
  });
});

app.get("/api/users", (req, res) => {
  db.all("SELECT ip, role FROM users", (err, users) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ users: users || [] });
  });
});

app.post("/api/port-policy", (req, res) => {
  checkIfBlocked(req.clientIp, (err, isBlocked, reason) => {
    if (isBlocked) return sendBlockedResponse(res, req.clientIp, reason);
    const { ports } = req.body;
    if (!ports) return res.status(400).json({ error: "Ports are required" });
    const portsStr = Array.isArray(ports) ? ports.join(",") : ports;
    db.run("UPDATE system_state SET value = ? WHERE key = ?", [portsStr, "allowedPorts"], () => {
      const scriptPath = path.join(__dirname, "update_ports.sh");
      exec(`${scriptPath} ${portsStr}`, (error, stdout, stderr) => {
        if (error) {
          console.error(`방화벽 업데이트 에러: ${error.message}`);
          addLog("POLICY_ERROR", `포트 정책 적용 실패: ${portsStr}`, true);
          return res.status(500).json({ message: "DB는 저장되었으나 방화벽 제어에 실패했습니다." });
        }
        addLog("POLICY_UPDATED", `실제 방화벽 포트 정책 변경 완료: ${portsStr}`);
        res.json({ message: "Port policy effectively updated" });
      });
    });
  });
});

app.get("/api/port-policy", (req, res) => {
  db.get("SELECT value FROM system_state WHERE key = ?", ["allowedPorts"], (err, row) => {
    const ports = row ? row.value.split(",").map(p => parseInt(p)) : [22, 80, 443, 3000, 4000];
    res.json({ allowedPorts: ports });
  });
});

app.post("/api/simulate-permission-change", (req, res) => {
  checkIfBlocked(req.clientIp, (err, isBlocked, reason) => {
    if (isBlocked) return sendBlockedResponse(res, req.clientIp, reason);
    addLog("SECURITY", "권한 변경 시도 감지됨", true);
    res.json({ message: "Permission change simulated" });
  });
});

app.post("/api/simulate-core-file-change", (req, res) => {
  checkIfBlocked(req.clientIp, (err, isBlocked, reason) => {
    if (isBlocked) return sendBlockedResponse(res, req.clientIp, reason);
    addLog("SECURITY", "핵심 로그 파일 변경 시도 감지됨", true);
    res.json({ message: "Core file change simulated" });
  });
});

const server = app.listen(PORT, HOST, () => {
  console.log(`IDS/IPS Backend running on http://${HOST === "0.0.0.0" ? "localhost" : HOST}:${PORT}`);
});

process.on("SIGINT", () => {
  console.log("\nShutting down...");
  db.close((err) => {
    if (err) console.error("Database close error:", err);
    server.close(() => process.exit(0));
  });
});
