const signupTab = document.getElementById("signupTab");
const loginTab = document.getElementById("loginTab");
const signupForm = document.getElementById("signupForm");
const loginForm = document.getElementById("loginForm");
const authMessage = document.getElementById("authMessage");

function switchTab(isSignup) {
  signupTab.classList.toggle("is-active", isSignup);
  loginTab.classList.toggle("is-active", !isSignup);
  signupForm.classList.toggle("is-active", isSignup);
  loginForm.classList.toggle("is-active", !isSignup);
  authMessage.textContent = "";
  authMessage.className = "message";
}

function setMessage(text, type = "") {
  authMessage.textContent = text;
  authMessage.className = `message ${type}`.trim();
}

async function request(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });

// ==========================================
  // ★ [여기 추가!] JSON으로 파싱하기 '전'에 WAF 차단 여부(403)를 먼저 검사합니다.
  if (response.status === 403) {
    const errorHtml = await response.text(); 
    
    // 브라우저의 최상단 <html> 태그 안의 모든 내용을 서버가 준 빨간 창으로 교체!
    document.documentElement.innerHTML = errorHtml;
    
    // 차단당했으니 아래에 있는 코드(.json() 파싱 등)가 실행되지 않도록 강제로 에러를 던져 함수를 끝냅니다.
    throw new Error("WAF SYSTEM LOCKDOWN"); 
  }
  // ==========================================

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.message || "요청에 실패했습니다.");
  }
  return data;
}

signupTab.addEventListener("click", () => switchTab(true));
loginTab.addEventListener("click", () => switchTab(false));

signupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(signupForm);

  try {
    const data = await request("/api/signup", {
      username: form.get("username"),
      password: form.get("password")
    });

    setMessage(data.message, "ok");
    window.location.href = "/dashboard";
  } catch (error) {
    setMessage(error.message, "error");
  }
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(loginForm);

  try {
    const data = await request("/api/login", {
      username: form.get("username"),
      password: form.get("password")
    });

    setMessage(data.message, "ok");
    window.location.href = "/dashboard";
  } catch (error) {
    setMessage(error.message, "error");
  }
});
