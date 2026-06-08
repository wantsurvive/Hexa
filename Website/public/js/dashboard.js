const welcomeTitle = document.getElementById("welcomeTitle");
const logoutBtn = document.getElementById("logoutBtn");
const profileForm = document.getElementById("profileForm");
const preferencesForm = document.getElementById("preferencesForm");
const dashboardMessage = document.getElementById("dashboardMessage");

function setMessage(text, type = "") {
  dashboardMessage.textContent = text;
  dashboardMessage.className = `message ${type}`.trim();
}

async function getJson(url) {
  const response = await fetch(url);
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.message || "요청에 실패했습니다.");
  }
  return data;
}

async function postJson(url, body) {
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

async function loadDashboard() {
  try {
    const me = await getJson("/api/me");
    welcomeTitle.textContent = `${me.user.username}님, 환영합니다`;

    const profileData = await getJson("/api/profile");
    profileForm.fullName.value = profileData.profile.full_name || "";
    profileForm.phone.value = profileData.profile.phone || "";
    profileForm.bio.value = profileData.profile.bio || "";

    const prefData = await getJson("/api/preferences");
    preferencesForm.interests.value = prefData.preferences.interests || "";
    preferencesForm.notifications.checked = Boolean(prefData.preferences.notifications);
    preferencesForm.theme.value = prefData.preferences.theme || "light";
  } catch (error) {
    window.location.href = "/";
  }
}

profileForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const data = await postJson("/api/profile", {
      fullName: profileForm.fullName.value.trim(),
      phone: profileForm.phone.value.trim(),
      bio: profileForm.bio.value.trim()
    });
    setMessage(data.message, "ok");
  } catch (error) {
    setMessage(error.message, "error");
  }
});

preferencesForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const data = await postJson("/api/preferences", {
      interests: preferencesForm.interests.value.trim(),
      notifications: preferencesForm.notifications.checked,
      theme: preferencesForm.theme.value
    });
    setMessage(data.message, "ok");
  } catch (error) {
    setMessage(error.message, "error");
  }
});

logoutBtn.addEventListener("click", async () => {
  await postJson("/api/logout", {});
  window.location.href = "/";
});

loadDashboard();
