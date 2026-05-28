const express = require("express");
const cors = require("cors");
const os = require("os");
const osUtils = require("os-utils");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const { v4: uuidv4 } = require("uuid");
const fs = require("fs");
const { exec } = require("child_process"); //update_ports_sh

const app = express();
const PORT = process.env.IDSIPS_PORT || 4000;
const HOST = process.env.IDSIPS_HOST || "0.0.0.0";

app.set("trust proxy", true);

// Cross-platform database path
const dataDir = path.join(__dirname, "data");
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}
const dbPath = path.join(dataDir, "idsips.db");

// SQLite Database initialization
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error("Database connection error:", err.message);
  } else {
    console.log("Connected to SQLite database at:", dbPath);
    initializeDatabase();
  }
});

app.use(cors());
app.use(express.json());

function normalizeClientIp(ip) {
  if (!ip) {
    return "0.0.0.0";
  }

  const trimmedIp = Array.isArray(ip) ? ip[0] : `${ip}`.split(",")[0].trim();

  if (trimmedIp === "::1") {
    return "127.0.0.1";
  }

  if (trimmedIp.startsWith("::ffff:")) {
    return trimmedIp.slice(7);
  }

  return trimmedIp;
}

// Middleware: Extract client IP
app.use((req, res, next) => {
  req.clientIp = normalizeClientIp(
    req.headers["x-forwarded-for"] ||
    req.headers["x-real-ip"] ||
    req.ip ||
    req.socket.remoteAddress ||
    req.connection.remoteAddress
  );
  
  next();
});

app.use(express.static(path.join(__dirname, "src")));

function initializeDatabase() {
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS blocked_ips (
      id TEXT PRIMARY KEY,
      ip TEXT UNIQUE NOT NULL,
      reason TEXT NOT NULL,
      blocked_at TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS logs (
      id TEXT PRIMARY KEY,
      category TEXT NOT NULL,
      message TEXT NOT NULL,
      is_suspicious INTEGER DEFAULT 0,
      ts TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      ip TEXT UNIQUE NOT NULL,
      role TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS system_state (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`, () => {
      db.run("INSERT OR IGNORE INTO system_state (key, value) VALUES (?, ?)", ["engineOn", "true"]);
      db.run("INSERT OR IGNORE INTO system_state (key, value) VALUES (?, ?)", ["allowedPorts", "22,80,443,3000,4000"]);
    });
  });
}

function addLog(category, message, isSuspicious = false) {
  const id = uuidv4();
  
  // 1. 한국 시간(KST)으로 정확하게 계산
  const now = new Date();
  const utc = now.getTime() + (now.getTimezoneOffset() * 60000);
  const kst = new Date(utc + (9 * 3600000));
  
  // 2. YYYY-MM-DD HH:mm:ss 형태로 예쁘게 조립
  const yyyy = kst.getFullYear();
  const mm = String(kst.getMonth() + 1).padStart(2, '0');
  const dd = String(kst.getDate()).padStart(2, '0');
  const hh = String(kst.getHours()).padStart(2, '0');
  const min = String(kst.getMinutes()).padStart(2, '0');
  const ss = String(kst.getSeconds()).padStart(2, '0');
  
  const ts = `${yyyy}-${mm}-${dd} ${hh}:${min}:${ss}`;

  // 3. 조립된 예쁜 시간으로 DB에 저장!
  db.run(
    "INSERT INTO logs (id, category, message, is_suspicious, ts) VALUES (?, ?, ?, ?, ?)",
    [id, category, message, isSuspicious ? 1 : 0, ts],
    (err) => {
      if (err) console.error("Error adding log:", err);
    }
  );
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

// Helper: Check if IP is blocked and block access
function checkIfBlocked(clientIp, callback) {
  db.get("SELECT reason FROM blocked_ips WHERE ip = ?", [clientIp], (err, row) => {
    if (err) return callback(err, false);
    callback(null, !!row, row ? row.reason : null);
  });
}

// Middleware: Send blocked response helper
function sendBlockedResponse(res, clientIp, reason) {
  return res.status(403).json({
    error: "Forbidden - Your IP address has been blocked",
    reason: reason,
    ip: clientIp
  });
}


// API: Get System Status
app.get("/api/status", (req, res) => {
  checkIfBlocked(req.clientIp, (err, isBlocked, reason) => {
    if (isBlocked) {
      console.log(`[IP BLOCKED] ${req.clientIp}가 /api/status 접근 시도`);
      return sendBlockedResponse(res, req.clientIp, reason);
    }
    
    osUtils.cpuUsage((v) => {
      db.get("SELECT COUNT(*) as count FROM blocked_ips", (err, countIps) => {
        db.get("SELECT COUNT(*) as count FROM logs WHERE is_suspicious = 1", (err, countSuspicious) => {
          db.all("SELECT ip, reason, blocked_at FROM blocked_ips", (err, blockedIps) => {
            db.all("SELECT category, message, ts FROM logs ORDER BY ts DESC LIMIT 20", (err, logs) => {
              db.all("SELECT category, message, ts FROM logs WHERE is_suspicious = 1 ORDER BY ts DESC LIMIT 20", (err, suspiciousLogs) => {
                getState((err, state) => {
                  const blockedIpsMap = {};
                  if (blockedIps) {
                    blockedIps.forEach(row => {
                      blockedIpsMap[row.ip] = { reason: row.reason, blockedAt: row.blocked_at };
                    });
                  }
                  res.json({
                    engineOn: state.engineOn,
                    blockedCount: countIps?.count || 0,
                    suspiciousCount: countSuspicious?.count || 0,
                    resources: {
                      cpu: Math.round(v * 100),
                      memory: Math.round((1 - osUtils.freememPercentage()) * 100),
                      disk: 45,
                      network: 15,
                    },
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

// API: Toggle Engine
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

// API: Block IP
app.post("/api/block", (req, res) => {
  checkIfBlocked(req.clientIp, (err, isBlocked, reason) => {
    if (isBlocked) return sendBlockedResponse(res, req.clientIp, reason);
    
    const { ip, reason: blockReason } = req.body;
    if (!ip) return res.status(400).json({ error: "IP is required" });
    
    const id = uuidv4();
    const blockedAt = new Date().toISOString();
    
    db.run(
      "INSERT OR REPLACE INTO blocked_ips (id, ip, reason, blocked_at) VALUES (?, ?, ?, ?)",
      [id, ip, blockReason, blockedAt],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });
        addLog("BLOCK", `${ip} 차단됨 - ${blockReason}`, true);
        res.json({ message: "Blocked successfully" });
      }
    );
  });
});

// API: Unblock IP
app.post("/api/unblock", (req, res) => {
  checkIfBlocked(req.clientIp, (err, isBlocked, reason) => {
    if (isBlocked) return sendBlockedResponse(res, req.clientIp, reason);
    
    const { ip } = req.body;
    db.run("DELETE FROM blocked_ips WHERE ip = ?", [ip], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      addLog("UNBLOCK", `${ip} 차단 해제됨`);
      res.json({ message: "Unblocked successfully" });
    });
  });
});

// API: Check if IP is blocked
app.get("/api/check-ip/:ip", (req, res) => {
  const ip = req.params.ip;
  db.get("SELECT reason FROM blocked_ips WHERE ip = ?", [ip], (err, row) => {
    const isBlocked = !!row;
    res.json({ blocked: isBlocked, reason: isBlocked ? row.reason : null });
  });
});

// API: Report Security Event
app.post("/api/report-event", (req, res) => {
  const { ip, category, message, shouldBlock } = req.body;
  addLog(category, `[EVENT FROM WEB] ${ip}: ${message}`, shouldBlock);
  
  if (shouldBlock) {
    getState((err, state) => {
      if (state.engineOn) {
        const id = uuidv4();
        const blockedAt = new Date().toISOString();
        db.run(
          "INSERT OR REPLACE INTO blocked_ips (id, ip, reason, blocked_at) VALUES (?, ?, ?, ?)",
          [id, ip, message, blockedAt]
        );
      }
      res.json({ status: "Event recorded" });
    });
  } else {
    res.json({ status: "Event recorded" });
  }
});

// API: Export logs
app.get("/api/export-logs", (req, res) => {
  db.all("SELECT category, message, ts FROM logs ORDER BY ts DESC", (err, logs) => {
    if (err) return res.status(500).json({ error: err.message });
    
    let csvContent = "\uFEFF분류,메시지,시간\n";
    if (logs) {
      logs.forEach(log => {
        csvContent += `"${log.category}","${log.message.replace(/"/g, '""')}","${log.ts}"\n`;
      });
    }
    
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", "attachment; filename=idsips_logs.csv");
    res.send(csvContent);
  });
});

// API: Export suspicious logs
app.get("/api/export-suspicious-logs", (req, res) => {
  db.all("SELECT category, message, ts FROM logs WHERE is_suspicious = 1 ORDER BY ts DESC", (err, logs) => {
    if (err) return res.status(500).json({ error: err.message });
    
    let csvContent = "\uFEFF분류,메시지,시간\n";
    if (logs) {
      logs.forEach(log => {
        csvContent += `"${log.category}","${log.message.replace(/"/g, '""')}","${log.ts}"\n`;
      });
    }
    
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", "attachment; filename=idsips_suspicious_logs.csv");
    res.send(csvContent);
  });
});

// API: Add user
app.post("/api/add-user", (req, res) => {
  checkIfBlocked(req.clientIp, (err, isBlocked, reason) => {
    if (isBlocked) return sendBlockedResponse(res, req.clientIp, reason);
    
    const { ip, role } = req.body;
    if (!ip || !role) return res.status(400).json({ error: "IP and role are required" });
    
    const id = uuidv4();
    db.run(
      "INSERT INTO users (id, ip, role) VALUES (?, ?, ?)",
      [id, ip, role],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });
        addLog("USER_ADDED", `사용자 ${ip} (${role}) 추가됨`);
        res.json({ message: "User added successfully" });
      }
    );
  });
});

// API: Get users
app.get("/api/users", (req, res) => {
  db.all("SELECT ip, role FROM users", (err, users) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ users: users || [] });
  });
});

// API: Set port policy
// API: Set port policy (실제 시스템 방화벽 연동)
app.post("/api/port-policy", (req, res) => {
  checkIfBlocked(req.clientIp, (err, isBlocked, reason) => {
    if (isBlocked) return sendBlockedResponse(res, req.clientIp, reason);
    
    const { ports } = req.body;
    if (!ports) return res.status(400).json({ error: "Ports are required" });
    
    const portsStr = Array.isArray(ports) ? ports.join(",") : ports;
    
    // 1. DB에 상태 저장
    db.run("UPDATE system_state SET value = ? WHERE key = ?", [portsStr, "allowedPorts"], () => {
      
      // 2. 쉘 스크립트 실행하여 실제 iptables 방화벽 제어!
      // 스크립트 파일 위치는 환경에 맞게 조정 (도커 내부 기준 경로)
      const scriptPath = path.join(__dirname, "update_ports.sh");
      
      exec(`${scriptPath} ${portsStr}`, (error, stdout, stderr) => {
        if (error) {
          console.error(`방화벽 업데이트 에러: ${error.message}`);
          addLog("POLICY_ERROR", `포트 정책 적용 실패: ${portsStr}`, true);
          // 에러가 나도 웹 통신은 정상적으로 종료해줌
          return res.status(500).json({ message: "DB는 저장되었으나 방화벽 제어에 실패했습니다." });
        }
        
        console.log(`방화벽 쉘 스크립트 출력: ${stdout}`);
        
        // 3. 성공 로그 남기기
        addLog("POLICY_UPDATED", `실제 방화벽 포트 정책 변경 완료: ${portsStr}`);
        res.json({ message: "Port policy effectively updated" });
      });
    });
  });
});

// API: Get port policy
app.get("/api/port-policy", (req, res) => {
  db.get("SELECT value FROM system_state WHERE key = ?", ["allowedPorts"], (err, row) => {
    const ports = row ? row.value.split(",").map(p => parseInt(p)) : [22, 80, 443, 3000, 4000];
    res.json({ allowedPorts: ports });
  });
});

// API: Simulate permission change event
app.post("/api/simulate-permission-change", (req, res) => {
  checkIfBlocked(req.clientIp, (err, isBlocked, reason) => {
    if (isBlocked) return sendBlockedResponse(res, req.clientIp, reason);
    addLog("SECURITY", "권한 변경 시도 감지됨", true);
    res.json({ message: "Permission change simulated" });
  });
});

// API: Simulate core file change event
app.post("/api/simulate-core-file-change", (req, res) => {
  checkIfBlocked(req.clientIp, (err, isBlocked, reason) => {
    if (isBlocked) return sendBlockedResponse(res, req.clientIp, reason);
    addLog("SECURITY", "핵심 로그 파일 변경 시도 감지됨", true);
    res.json({ message: "Core file change simulated" });
  });
});

// Start server
const server = app.listen(PORT, HOST, () => {
  console.log(`IDS/IPS Backend running on http://${HOST === "0.0.0.0" ? "localhost" : HOST}:${PORT}`);
  console.log(`Database: ${dbPath}`);
  console.log(`Server hosting: ${HOST === "0.0.0.0" ? "All interfaces (0.0.0.0)" : HOST}`);
});

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("\nShutting down...");
  db.close((err) => {
    if (err) console.error("Database close error:", err);
    server.close(() => {
      console.log("Server closed");
      process.exit(0);
    });
  });
});
