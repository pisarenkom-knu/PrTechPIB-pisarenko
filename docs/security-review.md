# Security review SecureLab, ЛР-6

Рівень: відмінний («Відмінно»), рівні накопичувальні. Commit початку огляду (review-start): `220b9b38938db7c232a922be1b574a79f6cb35ee`. Хеші прийнятого merge commit і тегу v1.0.0 додає скрипт експорту в PDF. Дата 2026-11-11, SDK 10.0.302, профіль `http` (Development) і production-like `--no-launch-profile`, клієнт Chrome.

## 1. Executive summary

Один абзац: що перевірено, скільки знахідок зафіксовано й виправлено, результат фактичного фінального прогону, головні залишкові ризики.

## 2. Scope та exclusions

Поточні відстежувані Git файли — обов’язково. Історія Git: лише фактично переглянуті файли, refs або проміжок дат; інакше напишіть «не перевірено».

## 3. System overview і trust boundaries

Для всіх: див. threat-model.md. Добрий/відмінний: кожна межа → конкретний test; відмінний: asset → threat → control → verification.

## 4. Methodology та test environment

Відомий початковий стан, яка саме локальна БД, хеші початку й кінця, профіль запуску, конкретний клієнт і сеанс, команди та їхні коди завершення.

### 4.1. Production-like profile і безпечна помилка (етап 1, п. 4-5)

Запуск `bash ../lr06-resources/commands/production.sh normal` (Production, `--no-launch-profile`, `-c Release`, connection string через `ConnectionStrings__SecureLab` поза Git, `Include Error Detail=false`). Клієнт curl і test host.

| Властивість                              | Команда або перевірка                                                                            | Фактичний результат                                                                                                                                                                                                      | Межа висновку                                                                              |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| profile активний                         | консоль `production.sh normal`                                                                   | `Hosting environment: Production`, `Now listening on: http://localhost:5080`                                                                                                                                             | доводить, що застосунок прочитав environment, а не лише що змінну передано                 |
| OpenAPI лише в Development               | `curl -sS -D - http://localhost:5080/openapi/v1.json`                                            | `404`, `application/problem+json`, `traceId`                                                                                                                                                                             |                                                                                            |
| `/scalar/v1` не є документацією          | `curl -sS -D - http://localhost:5080/scalar/v1`                                                  | `200`, `text/html`, `<!doctype html>` клієнта, тобто `MapFallbackToFile("index.html")`                                                                                                                                   | status 200 сам по собі нічого не доводить                                                  |
| reset заборонено                         | `production.sh` не передає аргументи, тому пряма команда з `-- --reset-database`                 | процес завершився `InvalidOperationException: Reset даних дозволено лише в явно налаштованому Development environment.`, дані не змінено                                                                                 | stack trace у консолі розробника, не у відповіді клієнту                                   |
| `ApplyMigrationsOnStartup`, `AllowReset` | `appsettings.json`                                                                               | обидва `false`, у Production `appsettings.Development.json` не читається                                                                                                                                                 |                                                                                            |
| `AllowedHosts`                           | `appsettings.json`                                                                               | `"*"`, фільтр Host вимкнено                                                                                                                                                                                              | прийнятно лише для локального стенда, для реального deployment потрібне окреме рішення     |
| HTTPS і HSTS                             | `Program.cs`                                                                                     | `UseHttpsRedirection` і `UseHsts` не налаштовано, cookie поза Development має `SecurePolicy.Always`                                                                                                                      | локальний HTTP не є доказом production transport safety, деталі в етапі 2, п. 6            |
| очікувані 4xx у Production               | `dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~Lab06ProductionProfileTests"` | `succeeded: 1, failed: 0`. Test host `UseEnvironment("Production")`, `session-check` 204 тим самим клієнтом, `?status=Unknown` 400 Validation Problem Details, неіснуючий id 404 Problem Details, `/openapi/v1.json` 404 | TestServer з `https://localhost` перевіряє поведінку застосунку й cookie, а не TLS чи HSTS |

**Контрольована неочікувана помилка.** `bash ../lr06-resources/commands/production.sh broken` (БД на недосяжному порту 54399), один `POST /api/auth/login` з вигаданим паролем через curl.

| Канал          | Фактичний вміст                                                                                                                                                    | Чого немає                                                                 |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| HTTP response  | `500`, `application/problem+json`, `title` «An error occurred while processing your request.», `traceId` `00-9474da1818bf5a2a693e324bba458f15-167f12420a61d837-00`     | stack trace, SQL, шлях файлової системи, версії пакетів, connection string |
| внутрішній log | `fail: Microsoft.AspNetCore.Diagnostics.ExceptionHandlerMiddleware[1]` з `TraceId:02a14b2b634391d68ff300577b96ead5`, `RequestPath:/api/auth/login`                 | пароль, cookie, тіло запиту                                                |

Зв’язок двох каналів: середній 32-символьний сегмент `traceId` у відповіді є тим самим `TraceId`, який console logger пише в scope запису `ExceptionHandlerMiddleware`. Обмеження доказу: збережена відповідь (`9474da18…8f15`) і збережений запис журналу (`02a14b2b…ead5`) належать двом послідовним запускам `production.sh broken` з однаковим сценарієм, тому на скріншотах ідентифікатори різні, а пари з одного запиту не збережено. Вивід другого запуску збережено поза репозиторієм у `../lr06-broken.log`, команда `grep -A2 "ExceptionHandlerMiddleware\[1\]" ../lr06-broken.log` показує запис, а `grep -ciE "NotARealPassword|unreachable-study-value|local-study-password" ../lr06-broken.log` дає 0, тобто ні пароль із запиту, ні пароль із connection string у журнал не потрапили.

Пара з одного запиту збережена під час retest F-01 (етап 2, п. 1): в одному вікні запуск `production.sh broken` з журналом у `../lr06-broken-after-fix.log`, запит curl і `grep -A2 "ExceptionHandlerMiddleware\[1\]"`. Відповідь має `traceId` `00-761ad2a540e2e031d46b4b4054e2a0b5-1d6aeabddf27eb59-00`, запис журналу `TraceId:761ad2a540e2e031d46b4b4054e2a0b5`, `SpanId:1d6aeabddf27eb59`, `RequestPath:/api/auth/login`. Пошук паролів у цьому журналі теж дає 0.

Спостереження: відповідь 500 не містить `X-Content-Type-Options`, `Referrer-Policy` і `Content-Security-Policy`, які є у відповіді 404 того самого запуску. Аналіз і виправлення у finding етапу 2, п. 1.

**Відновлення.** Після помилки API зупинено, запущено звичайний Development (`dotnet run --project src/SecureLab.Api`), `/health` 200, вхід як `alice` (Reporter, `GET /api/me` 200), список показує 3 власні інциденти, `GET /api/incidents`, `severity-summary` і details відповідають 200.

## 5. Findings summary

Таблиця: ID / актив / вплив / ймовірність / пріоритет / статус / ID повторної перевірки.

## 6. Detailed findings

Щонайменше одна власна знахідка для достатнього рівня, дві виправлені — для доброго; три виправлені — для відмінного, з них третя поза прямим checklist; кожна в окремому файлі docs/findings/*.md.

## 7. Regression results

Для всіх: мінімальний pack SQLi/authentication/authorization-IDOR/XSS/CSRF. Добрий/відмінний: ще validation/CORS/rate limiting. Відмінний: автоматизований повний REG-CSRF-01 (login/cookie → відмова → незмінний стан → token → успіх → змінений стан), команда й фактичний результат. Початкові ID сценаріїв (T/S/A/E/R/REG), команда або тест, передумова, точний результат, перевірка стану ресурсу, перевірений фінальний commit.

### 7.1. REG-CSRF-01

Автоматизовано в `tests/SecureLab.Api.Tests/Lab06CsrfRegressionTests.cs`, тест `RegCsrf01_UpdateWithoutToken_IsRejected_StateUnchanged_ThenTokenSucceeds`. Команда `dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~Lab06"`. Harness власний: `SecureLabApiFactory`, `CookieClient.LoginAsync` (реальний login і cookie), `UseAntiforgeryTokenAsync` одержує token тим самим клієнтом. Header не додається глобально, негативна частина йде без нього.

| Поле | Без token / невалідний token | Валідна пара токенів |
|---|---|---|
| Передумови | reset, окремий сеанс Alice створює власний інцидент з описом «Опис до REG-CSRF-01», основний клієнт Alice входить без token | той самий клієнт після `UseAntiforgeryTokenAsync` |
| Request | `PUT /api/incidents/{id}` з новим описом без `X-CSRF-TOKEN`, а також з `invalid-test-value` і з token Bob | той самий `PUT` з `X-CSRF-TOKEN` |
| Очікуваний HTTP результат | 400 `application/problem+json`, title «Antiforgery token відсутній або недійсний.», без `errors` | 204 |
| Перевірка після request | `GET /api/incidents/{id}` повертає незмінний опис | `GET` повертає саме «Змінено з токеном» |
| Доказ | `lr06-f02-06` (6 тестів Lab06 Passed), ручний curl `lr06-s2-10` (triage без header 400, стан New) | `lr06-s2-10` (з header 204, стан Triaged) |

Додатково `Perimeter_EveryCookieMutationWithoutToken_IsRejected` перевіряє той самий 400 на SC-01...SC-05 і незмінність ресурсу та сеансу, а `F02_TriageAsSimpleFormPost_WithoutToken_IsRejected_AndStatusStaysNew` відтворює F-02. Старі змінювальні тести ЛР 2-4 (T-02, A-04...A-09, A-06 logout) після login одержують власний token, тому знову перевіряють свою первинну мету: T-02 падав би без валідації DTO, бо перевіряє `errors.title`, а не лише 400. Повний набір після reset: `Passed: 60, Failed: 0` (`lr06-s2-15`).

## 8. Hardening controls

Для всіх: наявні controls; наявний login limiter — повторна перевірка (quota, 429, відновлення), відсутній — gap або виключення з причиною. Добрий/відмінний: наявні headers, CORS, search limiter (два partitions, quota, 429, відновлення). CSP, якої не було, — N/A на достатньому/доброму; для відмінного вона обов’язкова й не має ламати client. Добрий/відмінний: змістові відмінності Development/Production. Відмінний: погодження advanced variant до реалізації й фактична перевірка; Redis — shared state, TTL, partition isolation, failure mode.

Зв’язок «control → ризик → фактична перевірка → межа»; у рядках про headers зазначте профіль, клієнт і status.

### 8.1. Browser headers на п’яти класах відповідей (етап 2, п. 1)

Заголовки виставляє inline middleware у `src/SecureLab.Api/Program.cs` одразу після `UseExceptionHandler()` і `UseStatusCodePages()`, до `UseRouting()`, отже має діяти на всіх відповідях конвеєра. Клієнт curl (`-D -`), сеанс Alice через `-c`/`-b` cookie jar поза репозиторієм, login дав 204. Стан після виправлення F-01, перевірено 2026-11-11.

| Клас | Profile і client | Method + route | Status | Фактичні значення | Ризик | Межа |
|---|---|---|---|---|---|---|
| статична сторінка | Development, curl, anonymous | `GET /` | 200 `text/html` | `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, CSP `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'` | MIME sniffing, витік referrer, сторонні скрипти, clickjacking | не замінює правильний `Content-Type`, safe DOM і заборону секретів в URL |
| успішний API | Development, curl, сеанс Alice | `GET /api/incidents/20000000-0000-0000-0000-000000000005` | 200 `application/json` | ті самі три заголовки | MIME sniffing JSON як HTML | не замінює авторизацію ресурсу (A-02) |
| validation 4xx | Development, curl, сеанс Alice | `GET /api/incidents?status=Unknown` | 400 `application/problem+json`, `errors.status` | ті самі три заголовки | те саме | не замінює server-side validation |
| unknown resource | Development, curl, сеанс Alice | `GET /api/incidents/99999999-9999-9999-9999-999999999999` | 404 `application/problem+json` «Інцидент не знайдено» | ті самі три заголовки | те саме | 404 для чужого й неіснуючого однаковий (`docs/access-matrix.md`) |
| unexpected error | Production, `--no-launch-profile`, curl, anonymous | `POST /api/auth/login` з недосяжною БД | 500 `application/problem+json` | до виправлення заголовків не було (F-01), після виправлення ті самі три заголовки плюс `Cache-Control: no-cache,no-store` | те саме, на шляху помилки | заголовки не захищають від відповідей, які Kestrel формує до конвеєра |

| Control | Що перевірено | Який ризик зменшує | Чого не замінює |
|---|---|---|---|
| Content-Security-Policy (з ЛР 5, enforcement, не Report-Only) | усі ресурси клієнта з власного origin, inline-коду немає, `connect-src 'self'`, клієнт працює (список, details, severity-summary 200 у Chrome на етапі 1) | частину наслідків injection і небажані джерела ресурсів | safe DOM, validation, authorization |
| `X-Content-Type-Options: nosniff` | присутній на всіх п’яти класах | MIME sniffing у браузері | правильний `Content-Type` на сервері |
| `Referrer-Policy: no-referrer` | присутній на всіх п’яти класах, клієнту referrer не потрібний | надмірний витік referrer | заборону секретів в URL |
| `frame-ancestors 'none'` у CSP | присутній на всіх п’яти класах, вбудовування клієнта не потрібне | embedding і clickjacking | authorization |
| виняток `/scalar` | лише в Development, у Production шлях віддає fallback клієнта з CSP | Scalar потребує власних inline-ресурсів | не діє поза Development |

### 8.2. CORS і профіль cookie, REG-CORS-01 (етап 2, п. 2)

Profile Development (`dotnet run --project src/SecureLab.Api`), бо policy `Lab05BrowserProbe` реєструється лише в Development. Probes ЛР 5 `python3 -m http.server 4173|4174 --bind localhost --directory demonstrations/cors-probe`. Клієнт Google Chrome, окреме вікно, сеанс Alice (login через `auth-lab.html`), DevTools Network і Console. Probe робить `fetch("http://localhost:5080/api/incidents", { credentials: "include" })`. Policy в `Program.cs`: `WithOrigins("http://localhost:4173")`, `WithMethods("GET")`, `WithHeaders("X-Lab-Cors-Probe")`, `AllowCredentials()`, `UseCors` після `UseRouting` і до `UseAuthentication`.

| Сценарій | Method + URL | Origin | Відповідь сервера | Що бачить JS сторінки | Висновок |
|---|---|---|---|---|---|
| дозволений origin, браузер | `GET http://localhost:5080/api/incidents` | `http://localhost:4173` | 200, `Access-Control-Allow-Origin: http://localhost:4173`, `Access-Control-Allow-Credentials: true`, ті самі security headers | `200: [{"id":"20000000-...0005", ...}]`, список Alice | allowlist і credentials працюють лише разом для точного origin |
| недозволений origin, браузер | те саме | `http://localhost:4174` | 200 без жодного `Access-Control-*` | `fetch` кидає `TypeError`, сторінка показує «Браузер не надав response JavaScript». Network `CORS error`, Console `has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header`, `net::ERR_FAILED 200 (OK)` | браузер не віддає відповідь коду сторінки, але запит із cookie дійшов до API і виконався |
| прямий HTTP, дозволений origin | `curl -H 'Origin: http://localhost:4173'` без cookie | 4173 | 401 з `Access-Control-Allow-Origin: http://localhost:4173` і `Allow-Credentials: true` | не застосовується | CORS стоїть до authentication, тож дозволений origin бачить навіть відмову 401 |
| прямий HTTP, недозволений origin | `curl -H 'Origin: http://localhost:4174'` | 4174 | 401 без `Access-Control-*` | не застосовується | curl не застосовує CORS, сервер нічого не блокує, рішення лише в заголовках |
| preflight змінювального методу | `OPTIONS`, `Access-Control-Request-Method: POST` | 4173 | 204, `Access-Control-Allow-Methods: GET` | браузер не надішле POST | cross-origin POST з JSON із 4173 браузер не дозволяє |
| preflight дозволеного заголовка | `OPTIONS`, `Access-Control-Request-Method: GET`, `Access-Control-Request-Headers: X-Lab-Cors-Probe` | 4173 | 204, `Allow-Headers: X-Lab-Cors-Probe`, `Allow-Methods: GET` | GET з цим заголовком дозволено | policy відповідає реальному probe |

**Межа висновку.** CORS вирішує лише, чи віддасть браузер cross-origin відповідь коду сторінки. Він не автентифікує, не авторизує і не зупиняє запит: з 4174 запит із cookie Alice дійшов до API (Network 200). Порти 4173, 4174 і 5080 на `localhost` є різними origins, але одним site, тому `SameSite=Lax` cookie надсилається з усіх трьох, і це не доказ поведінки SameSite між різними сайтами. Тому для змінювальних маршрутів потрібна окрема antiforgery-перевірка (п. 3-5). У Production policy не реєструється, cross-origin читання не дозволено жодному origin.

**Профіль cookie.** `.AspNetCore.Identity.Application`: `HttpOnly`, `SameSite=Lax`, `Secure` поза Development (`CookieSecurePolicy.Always`), у Development `SameAsRequest`, бо стенд працює по HTTP (`Scaffolding/Lab03Identity.cs`). `HttpOnly` не дає скриптам сторінки читати cookie, але браузер сам додає її до запитів, тож захисту від CSRF вона не дає.

### 8.3. Периметр змінювальних маршрутів і antiforgery (етап 2, п. 3-5)

Джерела зіставлено трьома способами на одному стані: `git grep -n -E "\.Map(Post|Put|Patch|Delete)\(" -- src` (7 маршрутів сервера), `git grep -n -E "method: *.(POST|PUT|PATCH|DELETE)" -- src/SecureLab.Api/Client` (3 виклики клієнта: `postJson` для register, login, create у `auth-lab.js`, logout у `auth-lab.js`, create у `browser-lab.js`) і `GET /openapi/v1.json` у Development (ті самі 7 змінювальних шляхів). `MapMethods` і контролерів у проєкті немає. Жоден GET, HEAD чи OPTIONS не змінює стан.

**Контракт.** Сервіс `AddAntiforgery` у `Program.cs` до `builder.Build()`, header `X-CSRF-TOKEN`, cookie `securelab-af` (`HttpOnly`, `SameSite=Strict`). Видача `GET /api/antiforgery/token` (лише автентифікованому principal) викликає `GetAndStoreTokens` і повертає `{ "token": ... }`. Єдине місце перевірки `AntiforgeryValidationFilter` у `Presentation/Endpoints/AntiforgeryEndpoints.cs`: `ValidateRequestAsync`, а `AntiforgeryValidationException` перетворюється на 400 Problem Details з title «Antiforgery token відсутній або недійсний.» без `errors`. Фільтр підключено методом `RequireAntiforgeryToken()` до кожного рядка окремо, не до групи з GET. `UseAntiforgery()` не потрібний, бо жоден маршрут не приймає form data, тому колонка всюди explicit. Клієнт `Client/csrf.js` (`SecureLabCsrf.mutate`) одержує token lazy перед першою mutation сторінки, тримає його лише в пам’яті, додає header лише до same-origin POST, PUT, PATCH, DELETE, скидає token після login, logout, 400 чи 401 і на `pageshow`. Підключено перед page script на `auth-lab.html` і `browser-lab.html`. На `index.html` (`app.js`) змінювальних викликів немає, тому helper там не потрібний.

| ID | Method + route | Джерело / розбіжність | Яка зміна стану | Cookie authentication | Browser-accessible | Antiforgery validation | Regression ID |
|---|---|---|---|---|---|---|---|
| SC-01 | `POST /api/incidents` | ЛР 2 (`Scaffolding/Lab02Endpoints.cs`), OpenAPI, client `auth-lab.js` і `browser-lab.js` | створює Incident, власник з principal | так | так | explicit, `RequireAntiforgeryToken()` | Perimeter test, T-02 з токеном, UI create |
| SC-02 | `PUT /api/incidents/{id}` | ЛР 4 (`IncidentEndpoints.UpdateAsync`), OpenAPI. DISCREPANCY: клієнтського виклику немає | змінює title і description власного інциденту | так | так (cookie додається до будь-якого запиту браузера) | explicit | REG-CSRF-01, invalid і чужий token |
| SC-03 | `DELETE /api/incidents/{id}` | ЛР 4 (`IncidentEndpoints.DeleteAsync`), OpenAPI. DISCREPANCY: клієнтського виклику немає | видаляє власний інцидент зі статусом New | так | так | explicit | Perimeter test (ресурс лишився) |
| SC-04 | `POST /api/incidents/{id}/triage` | ЛР 4 (`IncidentEndpoints.TriageAsync`), OpenAPI. DISCREPANCY: клієнтського виклику немає | привілейований перехід New -> Triaged | так | так, простою HTML-формою без тіла (F-02) | explicit | F-02 test, ручний retest з 4175 |
| SC-05 | `POST /api/auth/logout` | ЛР 3 (`Scaffolding/Lab03Identity.cs`), OpenAPI, client `auth-lab.js` | завершує сеанс (`SignOutAsync`) | так | так, простою формою | explicit, фільтр виконується до `SignOutAsync` | Perimeter test (`/api/me` 200 після відмови), A-06 з токеном |
| SC-06 | `POST /api/auth/login` | ЛР 3, OpenAPI, client `auth-lab.js` | створює cookie-сеанс | ні | так | absent, рішення нижче | `lr06-s2-16`, A-07, rate limit тести |
| SC-07 | `POST /api/auth/register` | ЛР 3, OpenAPI, client `auth-lab.js` | створює обліковий запис | ні | так | absent, рішення нижче | `lr06-s2-16`, тести реєстрації ЛР 3 |

**DISCREPANCY SC-02, SC-03, SC-04.** Маршрути є на сервері й в OpenAPI, але клієнт їх не викликає. Це не баг документації: їх додано в ЛР 4 як HTTP-контракт, перевірений тестами й `.http`. Для CSRF важливий саме HTTP endpoint, а не наявність кнопки, тому всі три захищено так само. Коли з’явиться UI, він має йти через `SecureLabCsrf.mutate`.

**Рішення для login і register.** Вони не довіряють наявній authentication cookie, а login сам її створює. Ризики login-CSRF (зловмисник входить жертвою у свій акаунт) і небажаної реєстрації залишено в межах огляду, але токен не додано. Причина: обидва маршрути приймають лише JSON. Проста форма з іншого origin (`application/x-www-form-urlencoded` або `text/plain`) до handler не доходить (фактично 404, див. кандидат F-03), а JSON з іншого origin вимагає preflight, на який API для 4175 не повертає `Access-Control-Allow-Origin` (`lr06-s2-16`). Токен для анонімного login потребував би окремого bootstrap до входу, що методика радить проєктувати окремо. Залишковий ризик: якщо CORS колись дозволить чужий origin з credentials для POST, login-CSRF стане можливим.

**Ручна перевірка всіх змінювальних дій UI (Chrome, Development, після впровадження).**

| Дія | Сторінка, користувач | Результат | Доказ |
|---|---|---|---|
| створення | `auth-lab.html`, Alice | `Створено: 201`, перед ним `token 200` з `csrf.js:22`, POST з `csrf.js:42` | `lr06-s2-11`, `lr06-s2-12` (фільтр `has-request-header:x-csrf-token` показує лише mutation, значення не видно) |
| створення після F5 | `auth-lab.html`, Alice | `201`, token одержано знову | `lr06-s2-13` |
| logout | `auth-lab.html`, Alice | `Logout: 204, повторний /api/me: 401`, header є | `lr06-s2-13` |
| створення після нового login | `auth-lab.html`, Bob | `201` з новим token | `lr06-s2-13` |
| створення й читання | `browser-lab.html`, Bob | `POST incidents 201`, далі `GET: 200` | `lr06-s2-14` |
| атака з іншого origin | `http://localhost:4175`, Morgan | `triage 400`, статус 0005 лишився `New` | `lr06-f02-05`, `lr06-f02-06` |

## 9. Dependency and secret audit

Для всіх рівнів: огляд поточної відстежуваної конфігурації й класифікація кожного збігу пошуку. Для доброго рівня додатково: таблиця рішень щодо залежностей, систематичний пошук у поточних відстежуваних файлах, повний огляд журналів і аудиту. Перевіряти всю історію не обов’язково — зазначте фактичні межі. Перевірки доброго рівня, які ви не виконували на достатньому, позначте «Не входить до обраного рівня», а не PASS.

### 9.1. Секрети й конфігурація (етап 1, п. 3)

Перевірено на review-start `220b9b3`, лише tracked files. Команди read-only, нічого не надсилалося стороннім сервісам.

```bash
git ls-files '*appsettings*.json' '*.env*' '*compose*.yml' '*compose*.yaml' '*.config'
git check-ignore -v infra/.env src/SecureLab.Api/appsettings.Local.json
git log --all --follow --oneline -- src/SecureLab.Api/appsettings.Development.json
git log --all -p -- src/SecureLab.Api/appsettings.Development.json infra/compose.yaml src/SecureLab.Api/appsettings.json
git grep -n -I -i -E 'password|passwd|secret|api.?key' -- .
```

**Tracked configuration.** `git ls-files` повертає 4 файли: `infra/.env.example`, `infra/compose.yaml`, `src/SecureLab.Api/appsettings.json`, `src/SecureLab.Api/appsettings.Development.json`. Додатково переглянуто `src/SecureLab.Api/Properties/launchSettings.json` (лише `ASPNETCORE_ENVIRONMENT` і порт) і `scripts/test.sh` (лише `docker compose` і `dotnet test`, без значень). CI-файлів у репозиторії немає.

**.gitignore.** `git check-ignore -v` знаходить правила `.gitignore:15:.env` для `infra/.env` і `.gitignore:18:appsettings.Local.json` для локального файла, код завершення 0. Правило `!.env.example` залишає безпечний шаблон у Git. Також ігноруються `*.pfx`, `*.pem`, `*.key`, `*.log`, `*.dump`.

**.env.example.** Містить лише `POSTGRES_PORT=54329` і коментар, що це не секрет. Пароля чи ключа немає.

**README.** Рядки 63-66 описують `securelab / local-study-password` як відкриті навчальні credentials для БД на `127.0.0.1`, забороняють повторне використання й радять передавати реальний connection string через `ConnectionStrings__SecureLab`. Скопіювати реальний пароль README не просить.

**Історія конфігурації.** `appsettings.Development.json`, `compose.yaml` і `.env.example` мають один commit `d6639b5 Initial commit`, `appsettings.json` ще `cf10f83` (без секретів). Patch history містить лише ті самі study-only значення, інших паролів не додавалося й не видалялося.

**Результат пошуку.** Шаблон `password|passwd|secret|api.?key` дав 146 збігів у 26 файлах. Збіги згруповано за файлом і контекстом, бо в межах одного файла контекст однаковий.

| Path (кількість збігів)                                                | Безпечний контекст                                                                                                                               | Рішення                         | Причина й межа                                                                                                                |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `infra/compose.yaml:9` (1)                                             | пароль локального контейнера PostgreSQL, порт прив’язано до `127.0.0.1`                                                                          | accepted, study-only            | відкрите навчальне значення, README:63 забороняє повторне використання, не поширюється на інші БД і середовища                |
| `src/SecureLab.Api/appsettings.Development.json:3` (1)                 | connection string Development до тієї самої локальної БД                                                                                         | accepted, study-only            | діє лише в Development, у Production цей файл не читається, реальне значення передається через `ConnectionStrings__SecureLab` |
| `src/SecureLab.Api/Data/SecureLabDesignTimeDbContextFactory.cs:10` (1) | fallback для `dotnet ef` на локальну БД, рядок 14 спершу читає `ConnectionStrings__SecureLab`                                                    | accepted, study-only            | те саме навчальне значення, використовується лише інструментами міграцій                                                      |
| `src/SecureLab.Api/Data/DbSeeder.cs` (12)                              | код читає ключ `SeedUsers:Password` і передає змінну в `UserManager`                                                                             | не секрет, джерело конфігурації | значення задається поза Git, без нього seed зупиняється з повідомленням                                                       |
| `src/SecureLab.Api/Scaffolding/Lab03Identity.cs` (12)                  | поле `Password` у DTO, валідація довжини, `PasswordSignInAsync`, політика `RequiredLength`                                                       | не секрет, назва поля           | значень немає                                                                                                                 |
| `src/SecureLab.Api/Data/Migrations/*.cs` (4)                           | колонка `PasswordHash` і коментар про seed                                                                                                       | не секрет, схема БД             | схема без даних                                                                                                               |
| `src/SecureLab.Api/Client/auth-lab.html`, `auth-lab.js` (6)            | поле форми `type="password"`, очищення поля після відправки                                                                                      | не секрет, назва поля           | значень немає                                                                                                                 |
| `tests/SecureLab.Api.Tests/*.cs` (85)                                  | `Environment.GetEnvironmentVariable("SeedUsers__Password")`, випадкові `"Wrong-" + Guid` і `"Aa1-" + Guid`, перевірки відсутності пароля в логах | не секрет, тестові дані         | постійних паролів у коді немає, навчальний пароль лише зі змінної середовища                                                  |
| `tests/SecureLab.Api.Tests/packages.lock.json` (2)                     | ідентифікатор пакета `Microsoft.Extensions.Configuration.UserSecrets`                                                                            | не секрет, назва залежності     | збіг за назвою пакета                                                                                                         |
| `tests/http/lab-04-access.http` (3)                                    | `{{$processEnv SeedUsers__Password}}`                                                                                                            | не секрет, посилання на змінну  | значення підставляє REST Client із середовища                                                                                 |
| `README.md`, `.gitignore`, `docs/*.md` (19)                            | опис політики секретів і звіти ЛР 3-4 про те, що пароль не логується                                                                             | не секрет, документація         | значень немає                                                                                                                 |

Висновок: у поточних tracked files немає реального credential, а три study-only входи (`compose.yaml`, `appsettings.Development.json`, `SecureLabDesignTimeDbContextFactory.cs`) залишено без змін, бо їх видалення зламає локальний стенд.

**Чому видалення недостатньо при реальному витоку.** Якби у tracked file потрапив реальний пароль або ключ, видалення з поточного файла прибрало б його лише з нового commit. Значення лишилося б в історії Git, у клонах і форках, у кеші CI, у журналах і, можливо, у пошуковому індексі хостингу. Тому реальний credential треба вважати скомпрометованим: відкликати або змінити (rotate) у системі, яка його видала, перевірити журнали доступу за період витоку, а в репозиторії замінити на назву змінної або placeholder. Переписування історії без окремої інструкції не виконується.

| Перевірка              | Очікуваний результат                                        | Доказ                                                     | Межа висновку                                                                           |
| ---------------------- | ----------------------------------------------------------- | --------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `.env.example`         | лише safe placeholders                                      | `infra/.env.example` містить тільки `POSTGRES_PORT=54329` | не доводить відсутність секрету в untracked `infra/.env`                                |
| tracked configuration  | немає реального credential, study-only values класифіковано | команди вище, 146 збігів у таблиці                        | не доводить відсутність в усій історії чи зовнішньому CI                                |
| history у межах огляду | немає непогодженого secret-like value                       | `git log --all -p` для трьох файлів конфігурації          | охоплює лише ці файли, не охоплює форки, видалені refs, старі записи stash і чужі клони |

## 10. Residual risks

Неперевірені й тимчасово прийняті ризики, відповідальний і наступна дія.

## 11. Conclusion

Лише фактичні результати.

## 12. Evidence appendix

Для відмінного: доказ відсутності чутливих даних у логах шести сценаріїв етапу 3, п. 4; обґрунтування пріоритетів findings; відтворювані передумови й retest для іншої людини.
Шляхи, точні команди, ID сценаріїв, безпечний зв’язок відповіді з записом журналу через traceId; без паролів, cookie, токенів і connection strings.

## Декларація й журнал ШІ

Використовував/ла / не використовував/ла. Назва сервісу, для чого, що перевірено й змінено автором, власна інтерпретація.

| Дата                               | Сервіс | Завдання/фрагмент | Авторська адаптація | Перевірка й результат |
| ---------------------------------- | ------ | ----------------- | ------------------- | --------------------- |
| заповнити або не використовував/ла |        |                   |                     |                       |
