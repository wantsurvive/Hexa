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
