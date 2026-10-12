const result = document.querySelector("#result");
const state = document.querySelector("#state");
const profile = document.querySelector("#profile");

// Запити лише на свій origin, cookie додає браузер, JavaScript її не читає
function apiFetch(path, options = {}) {
  const url = new URL(path, location.origin);
  if (url.origin !== location.origin) throw new Error("Потрібна адреса цього застосунку.");
  return fetch(url, { ...options, credentials: "same-origin" });
}

function postJson(path, body) {
  return apiFetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

// Стан сеансу - лише з відповіді сервера, у браузерному storage нічого не зберігається
async function refreshState() {
  try {
    const response = await apiFetch("/api/auth/session-check");
    state.textContent = response.status === 204 ? "Сеанс активний"
      : response.status === 401 ? "Не ввійшли" : `Невизначений (${response.status})`;
  } catch {
    state.textContent = "Невизначений (помилка мережі)";
  }
}

function clearProfile() {
  profile.hidden = true;
  for (const id of ["profile-id", "profile-name", "profile-role"]) document.querySelector(`#${id}`).textContent = "";
}

// Профіль - лише дозволені поля DTO через textContent
async function loadProfile() {
  const response = await apiFetch("/api/me");
  const isJson = response.headers.get("Content-Type")?.includes("application/json");
  if (response.ok && isJson) {
    const me = await response.json();
    document.querySelector("#profile-id").textContent = me.userId;
    document.querySelector("#profile-name").textContent = me.userName;
    document.querySelector("#profile-role").textContent = me.role;
    profile.hidden = false;
  } else {
    clearProfile();
  }
  result.textContent = `Профіль: ${response.status}`;
}

document.querySelector("#register").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  form.elements.password.value = "";
  const response = await postJson("/api/auth/register", data);
  delete data.password;
  // Після реєстрації автоматичного входу немає
  result.textContent = response.status === 201
    ? "Реєстрація: 201, тепер увійдіть" : `Реєстрація: ${response.status}`;
});

document.querySelector("#login").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  form.elements.password.value = "";
  const response = await postJson("/api/auth/login", data);
  delete data.password;
  result.textContent = `Login: ${response.status}`;
  await refreshState();
  if (response.ok) await loadProfile();
});

document.querySelector("#me").addEventListener("click", loadProfile);

// DTO створення без owner, role, status та id - власника визначає сервер
document.querySelector("#create").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  const body = {
    title: data.title,
    description: data.description,
    severity: data.severity,
    occurredAtUtc: new Date(data.occurredAt).toISOString()
  };
  const response = await postJson("/api/incidents", body);
  if (response.status === 201) {
    const created = await response.json();
    result.textContent = `Створено: 201, ${created.title}, ${created.severity}, ${created.status}`;
    form.reset();
  } else if (response.status === 400) {
    // Повідомлення валідації по полях - текстом, без HTML
    const problem = await response.json();
    const messages = Object.entries(problem.errors ?? {}).map(([field, list]) => `${field}: ${list.join(" ")}`);
    result.textContent = `Створення: 400\n${messages.join("\n")}`;
  } else {
    result.textContent = `Створення: ${response.status}`;
  }
});

document.querySelector("#logout").addEventListener("click", async () => {
  const response = await apiFetch("/api/auth/logout", { method: "POST" });
  clearProfile();
  await refreshState();
  // Повторна перевірка тим самим браузером - очищення UI не замінює sign-out
  const me = await apiFetch("/api/me");
  result.textContent = `Logout: ${response.status}, повторний /api/me: ${me.status}`;
});

refreshState();
