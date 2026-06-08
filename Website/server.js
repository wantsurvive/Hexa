const path = require("path");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const PORT = process.env.PORT || 3000;
const IDSIPS_URL = process.env.IDSIPS_URL || "http://idsips:4000";

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 공통 IP 추출 함수
function getClientIp(req) {
  let ip = req.headers["x-forwarded-for"] || req.headers["x-real-ip"] || req.socket.remoteAddress;
  if (ip && ip.includes(',')) ip = ip.split(',')[0].trim();
  if (ip && ip.startsWith('::ffff:')) ip = ip.replace('::ffff:', '');
  return ip || "Unknown";
}

// IDS/IPS 관제 센터로 보고하는 함수
async function reportToIDS(ip, category, message, shouldBlock = false) {
  try {
    await fetch(`${IDSIPS_URL}/api/report-event`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, category, message, shouldBlock })
    });
  } catch (err) {}
}

// ==========================================
// ★ [WAF 1] 칼리 리눅스 스캐너 & 악성 페이로드 완벽 방어막
// ==========================================
app.use((req, res, next) => {
  const sqlInjectionPattern = /(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|--|'\s*OR\s*1=1|'\s*OR\s*true|'\s*OR\s*'\d'='\d|' OR)/i;
  const xssPattern = /(<script.*?>|javascript:|onerror\s*=|onload\s*=|alert\s*\(|<iframe)/i;
  const osCommandPattern = /(\.\.\/|\.\.\\|\/etc\/passwd|\/bin\/bash|\/bin\/sh|wget\s|curl\s|;\s*ls\s|\|\s*cat\s)/i;
  const scannerAgentPattern = /(sqlmap|nikto|dirb|nmap|zgrab|masscan|hydra|acunetix)/i;

  const clientIp = getClientIp(req);
  const userAgent = req.headers['user-agent'] || "";
  const rawUrl = req.originalUrl;

  // 데이터 긁어모으기
  let requestData = "";
  try { requestData = decodeURIComponent(rawUrl) + JSON.stringify(req.body || {}) + JSON.stringify(req.query || {}); } 
  catch(e) { requestData = rawUrl; }

  // 🚨 [최신 감시창] 모든 접근을 터미널에 상세히 찍어봅니다.
  console.log(`[WAF 감시창 👀] IP: ${clientIp} | UA: ${userAgent} | Data: ${requestData}`);

  // 1. 해킹 툴 스캐너 차단!
  if (scannerAgentPattern.test(userAgent)) {
    console.log(`[WAF 🚨] ${clientIp} 해킹 툴(${userAgent}) 접근 감지! 즉시 차단!`);
    reportToIDS(clientIp, "WAF", `해킹 툴 스캐너 접근: ${userAgent}`, true);
    return res.status(403).send(`<html><body style="background:#1a1a1a; color:#ff4444; text-align:center; padding:100px;"><h1 style="font-size:50px;">🚨 SYSTEM LOCKDOWN 🚨</h1><h2>비정상적인 스캐너 접근이 감지되었습니다.</h2></body></html>`);
  }

  // 2. 경로 탐색(LFI) & OS 명령어 차단!
  if (osCommandPattern.test(requestData)) {
    console.log(`[WAF 🚨] ${clientIp} LFI/OS 명령어 주입 공격 감지! URL: ${rawUrl}`);
    reportToIDS(clientIp, "WAF", "OS Command Injection / LFI 공격 감지", true);
    return res.status(403).send(`<html><body style="background:black; color:red; text-align:center; padding:50px;"><h1>🚨 SYSTEM LOCKDOWN 🚨</h1><h3>시스템 파일 접근 및 명령어 주입 공격이 감지되어 영구 차단되었습니다.</h3></body></html>`);
  }

  // 3. SQL 인젝션 차단!
  if (sqlInjectionPattern.test(requestData)) {
    console.log(`[WAF 🚨] ${clientIp} SQL 인젝션 공격 감지!`);
    reportToIDS(clientIp, "WAF", "SQL Injection 공격 감지", true);
    return res.status(403).send(`<html><body style="background:black; color:red; text-align:center; padding:50px;"><h1>🚨 SYSTEM LOCKDOWN 🚨</h1><h3>SQL Injection 공격이 감지되어 영구 차단되었습니다.</h3></body></html>`);
  }

  // 4. XSS 차단!
  if (xssPattern.test(requestData)) {
    console.log(`[WAF 🚨] ${clientIp} XSS 공격 감지!`);
    reportToIDS(clientIp, "WAF", "XSS 공격 감지", true);
    return res.status(403).send(`<html><body style="background:black; color:red; text-align:center; padding:50px;"><h1>🚨 SYSTEM LOCKDOWN 🚨</h1><h3>XSS 공격이 감지되어 영구 차단되었습니다.</h3></body></html>`);
  }

  next(); 
});

// ==========================================
// ★ [WAF 2] 트래픽 폭주(DoS/DDoS) 방어막
// ==========================================
const requestTracker = {};
const TIME_WINDOW = 5000;
const MAX_REQUESTS = 15;

app.use((req, res, next) => {
  // CSS, JS 필터링으로 정상 새로고침 오탐지 방지
  if (req.url.match(/\.(css|js|ico|png|jpg)$/)) return next();

  const clientIp = getClientIp(req);
  const currentTime = Date.now();

  if (!requestTracker[clientIp]) {
    requestTracker[clientIp] = { count: 1, startTime: currentTime };
  } else {
    const timeElapsed = currentTime - requestTracker[clientIp].startTime;
    if (timeElapsed < TIME_WINDOW) {
      requestTracker[clientIp].count++;
      if (requestTracker[clientIp].count > MAX_REQUESTS) {
        console.log(`[WAF 🚨] ${clientIp} 트래픽 폭주(DDoS) 감지!`);
        reportToIDS(clientIp, "WAF", "트래픽 폭주(DoS/DDoS) 공격 감지", true);
        return res.status(403).send(`<html><body style="background:black; color:red; text-align:center; padding:100px;"><h1 style="font-size:50px;">🚨 SYSTEM LOCKDOWN 🚨</h1><h2>트래픽 폭주(DoS/DDoS)가 감지되었습니다.</h2></body></html>`);
      }
    } else {
      requestTracker[clientIp] = { count: 1, startTime: currentTime };
    }
  }
  next();
});

// ==========================================
// ★ 안내데스크 (정적 파일 제공) - 반드시 WAF 검사 뒤에!
// ==========================================
app.use(express.static(path.join(__dirname, "public")));

// ==========================================
// ★ IDS/IPS Middleware: 관제 센터에 차단 여부 확인
// ==========================================
app.use(async (req, res, next) => {
  const clientIp = getClientIp(req);
  try {
    const response = await fetch(`${IDSIPS_URL}/api/check-ip/${clientIp}`);
    const data = await response.json();
    if (data.blocked) {
      return res.status(403).send(`<html><body style="text-align:center; margin-top:50px;"><h1 style="color:red;">🚨 접근 차단됨 🚨</h1><p>IDS/IPS 정책에 의해 귀하의 IP(<b>${clientIp}</b>)는 영구 차단되었습니다.</p><p>사유: ${data.reason}</p></body></html>`);
    }
  } catch (err) {}
  next();
});

// ==========================================
// ★ 데이터베이스 및 세션 세팅
// ==========================================
const db = new sqlite3.Database(path.join(__dirname, "hexa.db"));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (user_id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  db.run(`CREATE TABLE IF NOT EXISTS profiles (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL UNIQUE, full_name TEXT, phone TEXT, bio TEXT, updated_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(user_id))`);
  db.run(`CREATE TABLE IF NOT EXISTS preferences (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL UNIQUE, interests TEXT, notifications INTEGER DEFAULT 0, theme TEXT DEFAULT 'light', updated_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(user_id))`);
});

app.use(session({ secret: process.env.SESSION_SECRET || "change-this-secret", resave: false, saveUninitialized: false, cookie: { maxAge: 1000 * 60 * 60 * 12, httpOnly: true, sameSite: "lax" } }));

function isAuthenticated(req, res, next) {
  if (!req.session.user) return res.status(401).json({ message: "인증이 필요합니다." });
  next();
}

// ==========================================
// ★ 라우터 (로그인/회원가입 등 기능 로직)
// ==========================================
const loginAttempts = {};

app.post("/api/signup", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: "아이디와 비밀번호를 입력해 주세요." });
  if (username.length < 4 || password.length < 6) return res.status(400).json({ message: "아이디는 4자 이상, 비밀번호는 6자 이상이어야 합니다." });

  db.get("SELECT user_id FROM users WHERE username = ?", [username], async (err, row) => {
    if (err) return res.status(500).json({ message: "데이터베이스 오류가 발생했습니다." });
    if (row) return res.status(409).json({ message: "이미 사용 중인 아이디입니다." });

    try {
      const passwordHash = await bcrypt.hash(password, 10);
      db.run("INSERT INTO users (username, password_hash) VALUES (?, ?)", [username, passwordHash], function onInsert(insertErr) {
        if (insertErr) return res.status(500).json({ message: "회원가입 처리에 실패했습니다." });
        req.session.user = { userId: this.lastID, username };
        return res.status(201).json({ message: "회원가입이 완료되었습니다.", user: req.session.user });
      });
    } catch (hashErr) {
      return res.status(500).json({ message: "비밀번호 처리에 실패했습니다." });
    }
  });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const clientIp = getClientIp(req);

  if (!username || !password) return res.status(400).json({ message: "아이디와 비밀번호를 입력해 주세요." });

  db.get("SELECT user_id, username, password_hash FROM users WHERE username = ?", [username], async (err, userRow) => {
    if (err) return res.status(500).json({ message: "데이터베이스 오류가 발생했습니다." });

    const handleFailedLogin = async (reason) => {
      loginAttempts[clientIp] = (loginAttempts[clientIp] || 0) + 1;
      if (loginAttempts[clientIp] >= 5) {
        console.log(`[WAF 경고] ${clientIp} 무차별 대입 감지! 관제 센터에 차단 요청 발송.`);
        await reportToIDS(clientIp, "AUTH", `무차별 대입 공격 (로그인 5회 실패) - 대상: ${username}`, true);
        loginAttempts[clientIp] = 0; 
        return res.status(401).json({ message: "로그인 시도 횟수 초과. 보안 정책에 따라 즉시 차단 처리됩니다." });
      }
      reportToIDS(clientIp, "AUTH", `로그인 실패 (${reason}, 누적 ${loginAttempts[clientIp]}회): ${username}`, false);
      return res.status(401).json({ message: `아이디 또는 비밀번호가 올바르지 않습니다. (실패 ${loginAttempts[clientIp]}/5)` });
    };

    if (!userRow) return handleFailedLogin("아이디 없음");
    const isPasswordValid = await bcrypt.compare(password, userRow.password_hash);
    if (!isPasswordValid) return handleFailedLogin("비밀번호 불일치");

    loginAttempts[clientIp] = 0;
    req.session.user = { userId: userRow.user_id, username: userRow.username };
    return res.json({ message: "로그인되었습니다.", user: req.session.user });
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ message: "로그아웃에 실패했습니다." });
    return res.json({ message: "로그아웃되었습니다." });
  });
});

app.get("/api/me", (req, res) => {
  if (!req.session.user) return res.status(401).json({ message: "인증이 필요합니다." });
  return res.json({ user: req.session.user });
});

app.get("/api/profile", isAuthenticated, (req, res) => {
  db.get("SELECT full_name, phone, bio FROM profiles WHERE user_id = ?", [req.session.user.userId], (err, row) => {
    if (err) return res.status(500).json({ message: "개인정보 조회에 실패했습니다." });
    return res.json({ profile: row || { full_name: "", phone: "", bio: "" } });
  });
});

app.post("/api/profile", isAuthenticated, (req, res) => {
  const { fullName = "", phone = "", bio = "" } = req.body;
  db.run(`INSERT INTO profiles (user_id, full_name, phone, bio, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET full_name=excluded.full_name, phone=excluded.phone, bio=excluded.bio, updated_at=CURRENT_TIMESTAMP`, [req.session.user.userId, fullName, phone, bio], (err) => {
    if (err) return res.status(500).json({ message: "개인정보 저장에 실패했습니다." });
    return res.json({ message: "개인정보가 저장되었습니다." });
  });
});

app.get("/api/preferences", isAuthenticated, (req, res) => {
  db.get("SELECT interests, notifications, theme FROM preferences WHERE user_id = ?", [req.session.user.userId], (err, row) => {
    if (err) return res.status(500).json({ message: "선호 정보 조회에 실패했습니다." });
    return res.json({ preferences: row || { interests: "", notifications: 0, theme: "light" } });
  });
});

app.post("/api/preferences", isAuthenticated, (req, res) => {
  const { interests = "", notifications = false, theme = "light" } = req.body;
  const notificationsInt = notifications ? 1 : 0;
  db.run(`INSERT INTO preferences (user_id, interests, notifications, theme, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET interests=excluded.interests, notifications=excluded.notifications, theme=excluded.theme, updated_at=CURRENT_TIMESTAMP`, [req.session.user.userId, interests, notificationsInt, theme], (err) => {
    if (err) return res.status(500).json({ message: "선호 정보 저장에 실패했습니다." });
    return res.json({ message: "선호 정보가 저장되었습니다." });
  });
});

app.get("/dashboard", (req, res) => { res.sendFile(path.join(__dirname, "public", "dashboard.html")); });
app.get("*", (req, res) => { res.sendFile(path.join(__dirname, "public", "index.html")); });

app.listen(PORT, () => {
  console.log(`Hexa app is running on http://localhost:${PORT}`);
});
