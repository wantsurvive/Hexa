const path = require("path");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const PORT = process.env.PORT || 3000;
// 1. 도커 컴포즈 네트워크 이름(idsips)을 기본값으로 사용하게 변경!
const IDSIPS_URL = process.env.IDSIPS_URL || "http://idsips:4000";

// IDS/IPS Middleware: Check if IP is blocked
app.use(async (req, res, next) => {
  // 2. ngrok 등을 통해 쉼표로 여러 IP가 들어올 경우, 가장 앞의 '진짜 IP'만 추출!
  let clientIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  if (clientIp && clientIp.includes(',')) {
      clientIp = clientIp.split(',')[0].trim(); 
  }

  try {
    const response = await fetch(`${IDSIPS_URL}/api/check-ip/${clientIp}`);
    const data = await response.json();
    if (data.blocked) {
      // 3. 차단되었을 때 확실하게 403 에러를 던짐
      return res.status(403).send(`
        <html>
          <head><title>403 Forbidden</title></head>
          <body style="text-align:center; margin-top:50px;">
            <h1 style="color:red;">접근 차단됨</h1>
            <p>IDS/IPS 정책에 의해 귀하의 IP(${clientIp})는 차단되었습니다.</p>
            <p>사유: ${data.reason}</p>
          </body>
        </html>
      `);
    }
  } catch (err) {
    console.error("IDS/IPS check failed (4000번 서버 연결 오류):", err.message);
  }
  next();
});

// Helper to report events to IDS/IPS
async function reportToIDS(ip, category, message, shouldBlock = false) {
  try {
    await fetch(`${IDSIPS_URL}/api/report-event`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, category, message, shouldBlock })
    });
  } catch (err) {
    console.error("Failed to report to IDS/IPS");
  }
}

const db = new sqlite3.Database(path.join(__dirname, "hexa.db"));

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      user_id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS profiles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL UNIQUE,
      full_name TEXT,
      phone TEXT,
      bio TEXT,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(user_id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS preferences (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL UNIQUE,
      interests TEXT,
      notifications INTEGER DEFAULT 0,
      theme TEXT DEFAULT 'light',
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(user_id)
    )
  `);
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-this-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 12,
      httpOnly: true,
      sameSite: "lax"
    }
  })
);

app.use(express.static(path.join(__dirname, "public")));

function isAuthenticated(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ message: "인증이 필요합니다." });
  }
  next();
}

app.post("/api/signup", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "아이디와 비밀번호를 입력해 주세요." });
  }

  if (username.length < 4 || password.length < 6) {
    return res.status(400).json({ message: "아이디는 4자 이상, 비밀번호는 6자 이상이어야 합니다." });
  }

  db.get("SELECT user_id FROM users WHERE username = ?", [username], async (err, row) => {
    if (err) {
      return res.status(500).json({ message: "데이터베이스 오류가 발생했습니다." });
    }

    if (row) {
      return res.status(409).json({ message: "이미 사용 중인 아이디입니다." });
    }

    try {
      const passwordHash = await bcrypt.hash(password, 10);

      db.run(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        [username, passwordHash],
        function onInsert(insertErr) {
          if (insertErr) {
            return res.status(500).json({ message: "회원가입 처리에 실패했습니다." });
          }

          req.session.user = { userId: this.lastID, username };
          return res.status(201).json({ message: "회원가입이 완료되었습니다.", user: req.session.user });
        }
      );
    } catch (hashErr) {
      return res.status(500).json({ message: "비밀번호 처리에 실패했습니다." });
    }
  });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "아이디와 비밀번호를 입력해 주세요." });
  }

  db.get(
    "SELECT user_id, username, password_hash FROM users WHERE username = ?",
    [username],
    async (err, userRow) => {
      if (err) {
        return res.status(500).json({ message: "데이터베이스 오류가 발생했습니다." });
      }

      if (!userRow) {
        reportToIDS(req.headers["x-forwarded-for"] || req.socket.remoteAddress, "AUTH", `로그인 실패 (아이디 없음): ${username}`, false);
        return res.status(401).json({ message: "아이디 또는 비밀번호가 올바르지 않습니다." });
      }

      const isPasswordValid = await bcrypt.compare(password, userRow.password_hash);
      if (!isPasswordValid) {
        reportToIDS(req.headers["x-forwarded-for"] || req.socket.remoteAddress, "AUTH", `로그인 실패 (비밀번호 불일치): ${username}`, true);
        return res.status(401).json({ message: "아이디 또는 비밀번호가 올바르지 않습니다." });
      }

      req.session.user = { userId: userRow.user_id, username: userRow.username };
      return res.json({ message: "로그인되었습니다.", user: req.session.user });
    }
  );
});

app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: "로그아웃에 실패했습니다." });
    }
    return res.json({ message: "로그아웃되었습니다." });
  });
});

app.get("/api/me", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "인증이 필요합니다." });
  }

  return res.json({ user: req.session.user });
});

app.get("/api/profile", isAuthenticated, (req, res) => {
  db.get(
    "SELECT full_name, phone, bio FROM profiles WHERE user_id = ?",
    [req.session.user.userId],
    (err, row) => {
      if (err) {
        return res.status(500).json({ message: "개인정보 조회에 실패했습니다." });
      }

      return res.json({
        profile: row || { full_name: "", phone: "", bio: "" }
      });
    }
  );
});

app.post("/api/profile", isAuthenticated, (req, res) => {
  const { fullName = "", phone = "", bio = "" } = req.body;

  db.run(
    `
    INSERT INTO profiles (user_id, full_name, phone, bio, updated_at)
    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(user_id)
    DO UPDATE SET full_name=excluded.full_name, phone=excluded.phone, bio=excluded.bio, updated_at=CURRENT_TIMESTAMP
    `,
    [req.session.user.userId, fullName, phone, bio],
    (err) => {
      if (err) {
        return res.status(500).json({ message: "개인정보 저장에 실패했습니다." });
      }
      return res.json({ message: "개인정보가 저장되었습니다." });
    }
  );
});

app.get("/api/preferences", isAuthenticated, (req, res) => {
  db.get(
    "SELECT interests, notifications, theme FROM preferences WHERE user_id = ?",
    [req.session.user.userId],
    (err, row) => {
      if (err) {
        return res.status(500).json({ message: "선호 정보 조회에 실패했습니다." });
      }

      return res.json({
        preferences: row || { interests: "", notifications: 0, theme: "light" }
      });
    }
  );
});

app.post("/api/preferences", isAuthenticated, (req, res) => {
  const { interests = "", notifications = false, theme = "light" } = req.body;
  const notificationsInt = notifications ? 1 : 0;

  db.run(
    `
    INSERT INTO preferences (user_id, interests, notifications, theme, updated_at)
    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(user_id)
    DO UPDATE SET interests=excluded.interests, notifications=excluded.notifications, theme=excluded.theme, updated_at=CURRENT_TIMESTAMP
    `,
    [req.session.user.userId, interests, notificationsInt, theme],
    (err) => {
      if (err) {
        return res.status(500).json({ message: "선호 정보 저장에 실패했습니다." });
      }
      return res.json({ message: "선호 정보가 저장되었습니다." });
    }
  );
});

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Hexa app is running on http://localhost:${PORT}`);
});
