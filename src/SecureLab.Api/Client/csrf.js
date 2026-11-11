// ЛР 6 - один helper для всіх змінювальних запитів сторінки, token лише в пам'яті цієї сторінки
(() => {
  const tokenRoute = "/api/antiforgery/token";
  const headerName = "X-CSRF-TOKEN";
  let token = null;
  let pending = null;
  let generation = 0;

  // Після login, logout або 400 старий token більше не використовується
  function reset() {
    token = null;
    pending = null;
    generation++;
  }

  // Lazy - token запитується перед першою mutation на цій сторінці
  async function ensureToken() {
    if (token) return token;
    if (pending) return pending;
    const current = generation;
    const operation = (async () => {
      const response = await fetch(tokenRoute, { credentials: "same-origin", cache: "no-store" });
      if (!response.ok) throw new Error(`Token: ${response.status}`);
      const data = await response.json();
      if (current !== generation) throw new Error("Сеанс змінився, потрібен новий token.");
      if (typeof data.token !== "string" || !data.token) throw new Error("Некоректна відповідь token.");
      token = data.token;
      return token;
    })();
    pending = operation;
    try { return await operation; } finally { if (pending === operation) pending = null; }
  }

  // Header додається лише до same-origin POST, PUT, PATCH, DELETE, повторного POST після 4xx немає
  async function mutate(path, options = {}) {
    const method = (options.method || "POST").toUpperCase();
    if (!["POST", "PUT", "PATCH", "DELETE"].includes(method)) throw new Error("Для читання - звичайний fetch.");
    const url = new URL(path, location.origin);
    if (url.origin !== location.origin) throw new Error("Token лише для цього origin.");
    const headers = new Headers(options.headers);
    headers.set(headerName, await ensureToken());
    const response = await fetch(url, { ...options, method, headers, credentials: "same-origin" });
    if (response.status === 400 || response.status === 401) reset();
    return response;
  }

  window.SecureLabCsrf = { reset, mutate };
  window.addEventListener("pageshow", reset);
})();
