# Security review SecureLab, ЛР-6

Рівень: відмінний («Відмінно»), рівні накопичувальні. Commit початку огляду (review-start): `220b9b38938db7c232a922be1b574a79f6cb35ee`. Хеші прийнятого merge commit і тегу v1.0.0 додає скрипт експорту в PDF. Дата 2026-11-11, SDK 10.0.302, профіль `http` (Development) і production-like `--no-launch-profile`, клієнт Chrome.

## 1. Executive summary

Один абзац: що перевірено, скільки знахідок зафіксовано й виправлено, результат фактичного фінального прогону, головні залишкові ризики.

## 2. Scope та exclusions

**У межах огляду.** Baseline 2-A, ресурс Incident. ASP.NET Core API `src/SecureLab.Api` (маршрути, middleware, Identity cookie, antiforgery, rate limiting, error handling, журнали консолі), браузерний клієнт `src/SecureLab.Api/Client` (`index.html`, `auth-lab.html`, `browser-lab.html`), PostgreSQL у `infra/compose.yaml`, конфігурація `appsettings*.json`, `launchSettings.json`, `.gitignore`, `infra/.env.example`, NuGet-залежності за `packages.lock.json`, тести `tests/SecureLab.Api.Tests`, `tests/browser`, `tests/http`. Профілі Development (`http`) і production-like (`--no-launch-profile`, Production). Клієнти curl, Google Chrome (окреме вікно), xUnit test host.

**Git.** Усі 434 поточні tracked files на `1ba23a3` для пошуку секретів (п. 9.3). Історія переглянута лише для `appsettings.Development.json`, `appsettings.json`, `infra/compose.yaml`, `infra/.env.example` (п. 9.1) і нових тестових файлів ЛР 6. Решта історії, stash, інші клони й зовнішні CI не перевірено.

**Виключення.** Немає production host, TLS termination і HSTS response, тому транспорт перевірено лише як конфігурацію (п. 8.4). Зовнішній penetration test, автоматичний secret scanner і DAST не виконувались. Мініпроєкти `lr06-resources/examples`, Docker Desktop і ОС розробника поза межами. Redis не використовується, бо погоджений advanced variant інший.

## 3. System overview і trust boundaries

Компоненти, суб’єкти, entry points і схему меж довіри наведено в `docs/threat-model.md`. Кожна межа там пов’язана з конкретним тестом або перевіркою (таблиця «Очікувані властивості на межах»).

**Зв’язок asset → threat → control → verification.** Retest повторює інша людина з reset (`dotnet run --project src/SecureLab.Api -- --reset-database`, пароль seed у `SeedUsers__Password`) і вказаних даних.

| Актив | Загроза | Control | Перевірка й retest |
|---|---|---|---|
| Привілейований перехід New -> Triaged, право змінювати лише власні інциденти | стороння сторінка в тому самому браузері надсилає змінювальний запит з автоматичною cookie (CSRF, F-02) | antiforgery `X-CSRF-TOKEN` + `securelab-af`, `AntiforgeryValidationFilter` на SC-01...SC-05 до будь-якої зміни | REG-CSRF-01: Alice, власний інцидент, PUT без token 400 і незмінний опис, з token 204 і новий опис. `dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~Lab06Csrf"`. Ручно: Morgan, інцидент `20000000-...-0005`, сторінка `http://localhost:4175`, triage 400 і статус New (розділ 8.3) |
| Чужі інциденти й коментарі (конфіденційність) | Reporter читає або змінює чужий ресурс за id (IDOR) | resource-based authorization `IncidentAuthorizationHandler`, 404 для чужого й неіснуючого, 403 для дозволеного читання без права дії | ЛР 4 A-03, A-04, A-06, A-10, A-11, A-12: `dotnet test ... --filter "FullyQualifiedName~Lab04"`, Alice проти `20000000-...-0002` Bob |
| Сеанс користувача й облікові дані | перебір паролів, фіксація чи викрадення cookie, розкриття існування акаунта | Identity PBKDF2, cookie `HttpOnly`, `SameSite=Lax`, `Secure` у Production, login limiter 5 за 60 с за IP, однаковий 401 і 429 | ЛР 3 A-06, A-07, Rate limit: `Lab03SecurityTests`, `Lab03RateLimitTests`, ручно `lr06-s2-18`, прапорці cookie `lr06-s4-01` |
| Цілісність відображення й дані сеансу в браузері | збережений XSS через опис чи коментар | `textContent` у `renderText`, CSP `script-src 'self'` без inline, `nosniff` | REG-XSS-01: Alice у Chrome на `/browser-lab.html`, запис з marker `lab05-marker.txt`, `tests/browser/description-dom.js` у Console, PASS 11 з 11 (`lr06-s3-05`) |
| Дані інцидентів у відповіді іншому origin | сторінка іншого origin читає відповідь API з cookie | CORS лише Development, точний origin 4173, `AllowCredentials` без wildcard, у Production policy немає | REG-CORS-01: probes 4173 і 4174 у Chrome, curl з `Origin` (розділ 8.2) |
| Структура SQL-запиту пошуку | SQLi через `q` або `sortBy` | EF Core параметри, `EscapeLike`, allowlist `sortBy` | ЛР 2 S-02, T-04, T-05: `SearchMechanicsTests` |
| Доступність пошуку | автоматичний перебір `q` одним користувачем | search limiter 20 за 60 с на user id (REG-RL-01) | `Lab06SearchRateLimitTests`, ручно `lr06-s2-17` |
| Внутрішня діагностика (stack trace, SQL, connection string) | розкриття деталей у відповіді на помилку | `AddProblemDetails` + `UseExceptionHandler`, `Include Error Detail=false`, browser headers через `OnStarting` (F-01) | Production з БД 54399: 500 без деталей, той самий TraceId у журналі, headers присутні (`lr06-s2-02`, `F01_UnexpectedError_KeepsSecurityHeaders`) |
| Паролі, cookie й токени в журналах | витік credentials через log sink | structured logging без імені з форми, без тіла, `EnableSensitiveDataLogging` вимкнено | шість сценаріїв п. 9.4, `grep -c` по `../lr06-logs/api.log` усюди 0 |
| Секрети конфігурації | реальний credential у tracked files | `.gitignore` для `.env` і `appsettings.Local.json`, `ConnectionStrings__SecureLab` поза Git | `git grep` п. 9.1 і 9.3, 0 реальних credential |
| Правдивість error contract | 404 маскує наявний маршрут і хибно описує стан ресурсу (F-03) | `ApiFallback.Handle`: 405 з `Allow`, 415, 404 лише для невідомого шляху | `Lab06ApiFallbackTests` 11 з 11, ручно `lr06-f03-02` |

## 4. Methodology та test environment

Локальна БД PostgreSQL 18 у контейнері `secure-lab-postgres-1` (`127.0.0.1:54329`, БД `securelab`), відомий стан відновлюється `dotnet run --project src/SecureLab.Api -- --reset-database` у Development з `SeedUsers__Password` поза Git (пароль зберігався у `~/.securelab-seed` з правами 600 і читався `source`, у команди й докази не потрапляв). Hash початку `220b9b3`, гілка `lab/6-hardening-review`, hash кінця й тег додаються після фінального прогону на merge commit. Профілі: Development (`http`, `http://localhost:5080`) і Production (`production.sh normal` або `broken`, `--no-launch-profile`, `-c Release`). Клієнти: curl 8 з cookie jar поза репозиторієм, Google Chrome в окремому вікні з DevTools, xUnit test host (`SecureLabApiFactory`, Production-варіант через `WithWebHostBuilder`). Ручні сценарії в Terminal виконувались скриптом з виводом `$ команда` перед результатом, тому кожен знімок містить точну команду. Коди завершення наведено біля команд, де вони важливі (restore і audit 0, `grep -c` з 0 збігів).

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

| ID | Актив | Вплив | Ймовірність і передумови | Пріоритет | Статус | ID повторної перевірки |
|---|---|---|---|---|---|---|
| F-02 | привілейований перехід статусу, власні інциденти, сеанс | несанкціонована зміна стану від імені Analyst чи власника, примусовий logout, середній для цілісності | висока: досить відкрити сторінку того самого site у браузері з активним сеансом, автентифікація зловмисника не потрібна, для triage потрібна жертва з роллю Analyst | P1 | Fixed | REG-CSRF-01, `F02_TriageAsSimpleFormPost_...`, `Perimeter_...`, ручний retest з 4175 |
| F-01 | browser controls на відповідях помилки | низький: відповідь 500 без `nosniff`, `Referrer-Policy`, CSP і `frame-ancestors`, даних у ній немає | середня: потрібна необроблена помилка (недоступна БД або дефект коду), запит може надіслати будь-хто | P3 | Fixed | `F01_UnexpectedError_KeepsSecurityHeaders`, ручно `lr06-s2-02` |
| F-03 | правдивість error contract | низький: наявний маршрут і ресурс видаються відсутніми, хибні висновки клієнта, моніторингу й огляду, без розкриття даних | висока: будь-який запит з іншим методом чи Content-Type, автентифікація не потрібна | P3 | Fixed | `Lab06ApiFallbackTests`, ручно `lr06-f03-02` |

**Порядок дій і чому саме такий.** Першою виправлено F-02, бо лише вона дає зловмиснику змінити дані іншої людини. Передумова мінімальна (жертва відкриває сторінку), а захисту не було на жодному з п’яти змінювальних маршрутів, тож це єдина знахідка з реальним впливом на цілісність. F-01 і F-03 мають низький вплив без витоку даних, тому їх виправлено після F-02. Між ними F-01 пріоритетніша за класом control: вона вимикає вже налаштовані браузерні захисти саме на відповіді, яку зловмисник може спровокувати, тоді як F-03 стосується правдивості коду помилки. Обидві отримали P3, але F-01 виправлено раніше, бо вона виявилась ще на етапі 2 і її виправлення не залежало від периметра CSRF. Тимчасово прийнятих ризиків серед findings немає, усі три закрито зі retest. Відкриті ризики поза findings перелічено в розділі 10.

## 6. Detailed findings

| ID | Картка | Джерело | Fixed у commit |
|---|---|---|---|
| F-01 | `docs/findings/F-01-error-path-security-headers.md` | етап 2, п. 1 (підказано методикою) | `fde58a5` |
| F-02 | `docs/findings/F-02-csrf-cookie-mutations.md` | етап 2, п. 3-5, власне відтворення атаки triage простою формою | `27b5674` |
| F-03 | `docs/findings/F-03-api-fallback-masks-405-415.md` | власний аналіз поза прямим checklist під час рішення щодо login і register | `c75995d` |

Кожна картка містить передумови, відтворення, вплив і ймовірність, першопричину, виправлення, retest, positive regression, залишковий ризик і доказ без секретів.

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

### 7.2. Regression pack (етап 3, п. 5)

Передумова для всіх рядків: API зупинено, `dotnet run --project src/SecureLab.Api -- --reset-database` з `SeedUsers__Password` поза Git, потім `dotnet test SecureLab.sln -c Release`. ID лабораторних збережено, бо ЛР 3 і ЛР 4 обидві мають A-*, вони позначені номером ЛР. Нові ID ЛР 6 мають лише нові сценарії: REG-CSRF-01 і REG-RL-01 (search). Попередній прогін етапу 3 на commit `995cd60` плюс правка `tests/browser/description-dom.js`: `Passed: 62, Failed: 0`. Фінальний прогін на перевіреному merge commit записується в етапі 4.

| Рівень | ID сценарію у проєкті | Property | Передумови | Негативний сценарій | Позитивна перевірка | Evidence / command | Result |
|---|---|---|---|---|---|---|---|
| добрий | ЛР 2 T-02 (і T-01, T-03) | server validation | reset, login Alice, token через `UseAntiforgeryTokenAsync` | `title` з пробілів, `severity` 7, без дати -> 400 з `errors.title`, `errors.severity`, `errors.occurredAtUtc` | коректне створення 201, повтор активного title 409 | `Lab02ContractTests.Post_WithInvalidFields_Returns400WithFieldKeys`, `Post_DuplicateActiveTitle_Returns409`, `Post_WithServerManagedFields_IgnoresThem` | pass |
| достатній | ЛР 2 S-02 і T-04 | query не змінює структуру SQL | seed | контрольний read-only ввід S-02 C -> 200 `[]` | `q=USB` рівно один запис `...0005`, легітимний апостроф | `SearchMechanicsTests.Search_WithControlInput_ReturnsEmptySet`, `Search_ForUsb_ReturnsExactlyOneSeedIncident`, `Search_WithApostrophe_ReturnsOnlyMatchingIncident`, `Search_WithUnknownSortBy_Returns400` (T-05) | pass |
| достатній | ЛР 3 A-01, A-06, A-07 | identity lifecycle | test accounts | анонім 401 без redirect, невідоме ім’я й хибний пароль однаковий 401, після logout `/api/me` 401 | login -> `/api/me` 200 (A-02), logout з token 204 | `Lab03SecurityTests.A01_AnonymousCreate_Returns401_NotRedirect`, `A07_UnknownUserAndWrongPassword_LookTheSame`, `A06_Logout_ThenMe_Returns401`, `A02_LoginThenMe_ReturnsVerifiedUser` | pass |
| достатній | ЛР 4 A-03, A-04, A-06, A-10, A-11, A-12 | server-side ownership і role check | seed Alice, Bob, Morgan | Alice читає й змінює чужий -> 404 без зміни, Reporter triage -> 403 без зміни, чужий і неіснуючий id однаковий 404, пошук і коментарі не показують чужого | власник читає свій (A-02), Analyst triage New -> Triaged (A-07), update лише content (A-08a) | `Lab04AuthorizationTests` (усі 14 тестових методів A-01...A-12) | pass |
| достатній | REG-XSS-01 (ЛР 5) | text не виконується як code | Chrome, Alice, запис `REG-XSS-01 ЛР6` з marker `lab05-marker.txt` (`253f00f6-...`), сторінку оновлено | marker в описі й коментарі `30...0005` не виконується, атрибут `data-lab05-marker` лишається `null` | позитивний складний текст `O'Brien "терміново", 5 < 7, <b>` зберігається й показується як текст | `tests/browser/description-dom.js` у DevTools Console (`lr06-s3-05`), плюс `IncidentEndpointTests.ClientScript_DoesNotUseDangerousInnerHtmlSink` | pass, 11 з 11 |
| добрий | REG-CORS-01 (ЛР 5) | exact browser origin scope | Development, probes 4173 і 4174, Chrome, сеанс Alice | 4174: `CORS error`, JS не одержав відповіді, preflight POST з 4173 дає лише `Allow-Methods: GET` | 4173 читає список з `Allow-Origin: http://localhost:4173` і `Allow-Credentials: true` | розділ 8.2, `lr06-s2-05`...`lr06-s2-09` | pass |
| достатній | REG-CSRF-01 (ЛР 6) | token pair required | reset, cookie-сеанс Alice, власний інцидент | PUT без token, з невалідним і чужим token -> 400, стан не змінився, той самий 400 на SC-01...SC-05, F-02 форма з 4175 -> 400 | з валідним token 204 і саме очікувана зміна, UI-дії працюють | `Lab06CsrfRegressionTests` (4 тести), розділи 7.1 і 8.3, `lr06-s2-10`...`lr06-s2-16`, `lr06-f02-05`, `lr06-f02-06` | pass |
| добрий | ЛР 3 Rate limit і REG-RL-01 (ЛР 6) | abuse flow limited | окремий host або тимчасові змінні процесу з малою quota | login понад quota -> 429 однаковий для існуючого й неіснуючого акаунта, search понад quota -> 429 Problem Details без даних | у межах quota 401/200, інший користувач має свій лічильник, після вікна знову доступно | `Lab03RateLimitTests.Login_TooManyAttempts_Returns429_ThenRecovers`, `Lab06SearchRateLimitTests` (2 тести), розділ 8.5, `lr06-s2-17`, `lr06-s2-18` | pass |
| добрий | ЛР 1 і ЛР 2 contract, F-01 | error contract і browser headers | Production test host | невалідний status 400, неіснуючий 404, 500 з security headers і `traceId` | Production 4xx лишаються Problem Details | `IncidentEndpointTests.InvalidStatus_ReturnsValidationProblem400`, `GetDetails_ForUnknownId_ReturnsProblemDetails404`, `Lab06ProductionProfileTests` (2 тести) | pass |

**Правка під час збирання pack.** DOM-тест ЛР 5 створював позитивний запис через `fetch` без token, тож після ЛР 6 він одержав би 400 і впав на кроці створення. Створення переведено на `SecureLabCsrf.mutate`, як і в клієнті. Перевірки тесту й marker не змінювались.

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

**Рішення для login і register.** Вони не довіряють наявній authentication cookie, а login сам її створює. Ризики login-CSRF (зловмисник входить жертвою у свій акаунт) і небажаної реєстрації залишено в межах огляду, але токен не додано. Причина: обидва маршрути приймають лише JSON. Проста форма з іншого origin (`application/x-www-form-urlencoded` або `text/plain`) до handler не доходить: routing відкидає її за Content-Type (до F-03 це маскувалося як 404, після виправлення 415), а JSON з іншого origin вимагає preflight, на який API для 4175 не повертає `Access-Control-Allow-Origin` (`lr06-s2-16`). Токен для анонімного login потребував би окремого bootstrap до входу, що методика радить проєктувати окремо. Залишковий ризик: якщо CORS колись дозволить чужий origin з credentials для POST, login-CSRF стане можливим.

**Ручна перевірка всіх змінювальних дій UI (Chrome, Development, після впровадження).**

| Дія | Сторінка, користувач | Результат | Доказ |
|---|---|---|---|
| створення | `auth-lab.html`, Alice | `Створено: 201`, перед ним `token 200` з `csrf.js:22`, POST з `csrf.js:42` | `lr06-s2-11`, `lr06-s2-12` (фільтр `has-request-header:x-csrf-token` показує лише mutation, значення не видно) |
| створення після F5 | `auth-lab.html`, Alice | `201`, token одержано знову | `lr06-s2-13` |
| logout | `auth-lab.html`, Alice | `Logout: 204, повторний /api/me: 401`, header є | `lr06-s2-13` |
| створення після нового login | `auth-lab.html`, Bob | `201` з новим token | `lr06-s2-13` |
| створення й читання | `browser-lab.html`, Bob | `POST incidents 201`, далі `GET: 200` | `lr06-s2-14` |
| атака з іншого origin | `http://localhost:4175`, Morgan | `triage 400`, статус 0005 лишився `New` | `lr06-f02-05`, `lr06-f02-06` |

### 8.4. HTTPS і HSTS як конфігурація (етап 2, п. 6)

| Що перевірено | Фактичний стан | Висновок і межа |
|---|---|---|
| `Properties/launchSettings.json` | один profile `http`, `applicationUrl` `http://localhost:5080`, `ASPNETCORE_ENVIRONMENT=Development`. HTTPS profile немає | локальний стенд працює лише по HTTP |
| `Program.cs` | `UseHttpsRedirection()` і `UseHsts()` відсутні. Reverse proxy чи іншої TLS-межі в репозиторії немає (`infra/compose.yaml` містить лише PostgreSQL) | baseline не дає фактичного доказу HTTPS, redirect чи HSTS |
| Production-like запуск етапу 1 | `ASPNETCORE_URLS=http://localhost:5080`, cookie поза Development має `SecurePolicy.Always` | cookie позначається `Secure`, але сам транспорт лишається HTTP |

HTTPS шифрує канал і автентифікує сервер, redirect лише переводить клієнта з HTTP на HTTPS (першу відповідь ще можна перехопити), HSTS наказує браузеру надалі звертатися до host тільки по HTTPS. `UseHsts()` за замовчуванням має `ExcludedHosts` `localhost`, `127.0.0.1`, `[::1]`, тому відсутність `Strict-Transport-Security` на loopback не є дефектом і не змінювалася. Локальну HSTS policy заради видимого header не додано. Реальний deployment, TLS termination і HSTS response на production host не тестувалися, це записано в залишкових ризиках.

### 8.5. Rate limiting (етап 2, п. 7)

`UseRateLimiter()` стоїть після `UseAuthentication()` і `UseAuthorization()`, тому limiter бачить verified principal, а анонім на захищеному маршруті одержує 401 раніше й не витрачає quota. Відмова 429 має Problem Details від `UseStatusCodePages()`. Обидва limiter in-memory, тобто лічильник окремий для кожного екземпляра API і скидається після перезапуску.

| Policy | Маршрут | Partition key | Quota і window | Відмова й подія |
|---|---|---|---|---|
| `login` (з ЛР 3, збережено) | `POST /api/auth/login` | IP клієнта (`RemoteIpAddress`) | `LoginRateLimit:PermitLimit` 5 за `LoginRateLimit:WindowSeconds` 60 с, без черги | 429, `Auth event login: result rate-limited`, без імені й пароля |
| `search` (нова, ЛР 6) | `GET /api/incidents/search` з параметром `q` | id автентифікованого користувача `user:{NameIdentifier}` з verified principal, не IP і не header від клієнта | `SearchRateLimit:PermitLimit` 20 за `SearchRateLimit:WindowSeconds` 60 с, без черги | 429, `Rate limit event search: result rate-limited` (до ЛР 6 будь-яка відмова записувалась як login) |

Ключ search обрано за користувачем, бо маршрут доступний лише після входу, а IP може бути спільним для кількох людей (NAT, аудиторія). Значення 20 за хвилину покриває звичайний інтерактивний пошук і обмежує автоматичний перебір `q`.

| Перевірка | Як | Фактичний результат |
|---|---|---|
| search, quota і 429 | Development із тимчасовим `SearchRateLimit__PermitLimit=3`, `SearchRateLimit__WindowSeconds=10` у змінних процесу, curl із сеансом Alice, `q=Перевірка USB` | `200, 200, 200, 429`, відповідь `application/problem+json` без даних (`lr06-s2-17`) |
| search, другий partition | той самий запит від Bob одразу після 429 Alice | 200, 0 записів: власний лічильник і та сама авторизація, quota не відкриває чужий запис |
| search, маршрут без policy | Alice `GET /api/incidents` під час 429 | 200 |
| search, відновлення | `sleep 11`, повтор Alice | 200, 1 запис |
| search, автоматично | `Lab06SearchRateLimitTests` (quota 3 за 2 с): quota, 429 Problem Details, Bob 0 записів, маршрут без policy, відновлення, подія search, анонім 5 разів 401 | Passed |
| login, у межах limit | `LoginRateLimit__WindowSeconds=10`, 5 хибних спроб Alice | `401` x5 (`lr06-s2-18`) |
| login, вичерпання | 6-та спроба, далі неіснуючий `nobody-x1` і знову Alice | 429 з однаковим тілом для існуючого й неіснуючого акаунта, існування не розкривається |
| login, відновлення | `sleep 11`, коректний login Alice | 204 |
| login, авторизація окремо | Alice після відновлення `GET /api/incidents/20000000-...-0002` (Bob) | 404, ліміт не замінює і не послаблює авторизацію |
| login, автоматично | `Lab03RateLimitTests` (quota 3 за 2 с) | Passed |

Тимчасові значення задавалися лише змінними процесу, tracked `appsettings*.json` не змінено. Для інших тестів `SecureLabApiFactory` піднімає обидві quota до 1000, бо всі клієнти test host мають спільний `RemoteIpAddress=null`.

### 8.6. Змістові відмінності Development і Production (етап 4, п. 4)

Однакові запити на двох запусках одного commit (`lr06-s4-01-dev-vs-production.png`), значення cookie приховано.

| Властивість | Development (`dotnet run --project src/SecureLab.Api`) | Production (`production.sh normal`) | Причина в коді чи конфігурації |
|---|---|---|---|
| `GET /openapi/v1.json` | 200 `application/json` | 404 `application/problem+json` | `MapOpenApi()` і `MapScalarApiReference()` лише в `IsDevelopment()` |
| CORS для `Origin: http://localhost:4173` | є `Access-Control-Allow-Origin: http://localhost:4173` | заголовка немає | `AddCors` і `UseCors("Lab05BrowserProbe")` лише в Development |
| `Set-Cookie` після login | `path=/; samesite=lax; httponly` | `path=/; secure; samesite=lax; httponly` | `CookieSecurePolicy.SameAsRequest` у Development, `Always` поза ним |
| `--reset-database` | очищує й заповнює seed | процес завершується «Reset даних дозволено лише в явно налаштованому Development environment» | `Database:AllowReset` true лише в `appsettings.Development.json`, перевірка `IsDevelopment()` |
| міграції під час старту | `ApplyMigrationsOnStartup=true` | `false` | `appsettings.json` проти `appsettings.Development.json` |
| connection string | з `appsettings.Development.json` | лише з `ConnectionStrings__SecureLab` поза Git | у Production файл Development не читається |
| CSP на `/scalar` | не додається (довідник має inline-ресурси) | шлях віддає fallback клієнта з повною CSP | виняток `isDevelopmentApiReference` у middleware |

Спільними лишаються безпечна 500 (`AddProblemDetails` + `UseExceptionHandler`), antiforgery, rate limiting, авторизація й browser headers, тож різниця профілів не послаблює ці controls.

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

### 9.2. Аудит залежностей (етап 3, п. 1-2)

SDK 10.0.302 (`global.json` 10.0.100, `latestFeature`, `allowPrerelease: false`), 2026-11-11 22:55 EET, commit `1ba23a3`, `RestorePackagesWithLockFile=true` і `TreatWarningsAsErrors=true` у `Directory.Build.props`. Знімок `lr06-s3-01-dependency-audit.png`.

```bash
dotnet --version
dotnet restore
dotnet package list --vulnerable --include-transitive
dotnet package list --outdated
```

`dotnet restore` завершився з кодом 0 без NU1901-NU1904. `dotnet package list --vulnerable --include-transitive` завершився з кодом 0: джерело `https://api.nuget.org/v3/index.json`, «The given project `SecureLab.Api` has no vulnerable packages given the current sources», те саме для `SecureLab.Api.Tests`. Межа висновку: лише відомі на цю дату advisories цього джерела для версій із `packages.lock.json`. Досяжність коду й невідомі вразливості не оцінювалися.

| Package | Version | Direct / transitive | Advisory / severity | Чи використовується relevant functionality | Доступне оновлення | Рішення і причина |
|---|---|---|---|---|---|---|
| Microsoft.AspNetCore.Identity.EntityFrameworkCore, Microsoft.EntityFrameworkCore (+Design, Relational), Microsoft.AspNetCore.OpenApi | 10.0.10 | direct | немає | так, Identity, EF Core, OpenApi | 11.0.0 (major, .NET 11) | без оновлення: advisory немає, major змінює target framework, а політика курсу `net10.0` |
| Npgsql.EntityFrameworkCore.PostgreSQL | 10.0.3 | direct | немає | так, доступ до PostgreSQL | у `--outdated` не показано | без змін |
| Microsoft.OpenApi | 2.7.5 | direct | немає | так, документ OpenAPI лише в Development | 3.11.0 (major) | без оновлення: major змінює API, ризику немає |
| Scalar.AspNetCore | 2.16.16 | direct | немає | так, довідник `/scalar` лише в Development | 2.20.0 (minor) | відкладено до окремого оновлення з повною регресією, бо компонент лише Development і advisory немає |
| Тестові пакети (xunit 2.9.3, xunit.runner.visualstudio 3.1.4, Microsoft.NET.Test.Sdk 17.14.1, Microsoft.AspNetCore.Mvc.Testing 10.0.10, coverlet.collector 6.0.4) | див. ліворуч | direct, лише тести | немає | лише test host, у застосунок не потрапляють | major-версії | без оновлення, ризику для застосунку немає |
| Транзитивні (Npgsql 10.0.3, Microsoft.CodeAnalysis.* 5.0.0, Newtonsoft.Json 13.0.3, Humanizer.Core 2.14.1 та інші) | з lockfile | transitive | немає | Npgsql у runtime, решта через `Microsoft.EntityFrameworkCore.Design` лише на етапі міграцій | не оцінювалось окремо | без змін, `dotnet nuget why` не знадобився, бо advisories немає |

`NuGetAuditSuppress` і `WarningsNotAsErrors` не додавалися, бо придушувати нічого. Lockfile не змінювався.

### 9.3. Систематичний пошук у tracked files (етап 3, п. 3)

Межі: усі 434 поточні tracked files на commit `1ba23a3` при чистому робочому дереві (`git status --short` порожній). History, stash, інші клони й зовнішні CI систематично не перевірено, окрім історії конфігурації з п. 9.1. Знімок `lr06-s3-02-tracked-files-search.png`.

| Пошук | Збігів | Review і рішення |
|---|---|---|
| `git grep -n -I -i -E 'password\|passwd\|secret\|api.?key' -- .` | 185 | ті самі категорії, що в п. 9.1 (146 збігів на review-start), плюс нові тести й docs ЛР 6: назви полів, `SeedUsers__Password` зі змінної середовища, випадкові `"Wrong-" + Guid`, документація. Не секрет |
| `git grep -n -I -i -E 'token\|connection.?string\|private.?key\|BEGIN [A-Z ]*KEY\|bearer\|client.?secret\|access.?key\|signing.?key' -- .` | 184 | `CancellationToken` і `IsConcurrencyToken` у коді й міграціях, таблиця `identity_user_tokens`, `AddDefaultTokenProviders`, antiforgery-код (`X-CSRF-TOKEN`, `RequestToken`, `csrf.js`), `GetConnectionString` і `ConnectionStrings__SecureLab` як назви ключів, документація. Значень ключів, сертифікатів чи bearer-токенів немає |
| `git grep -n -I -E '[A-Za-z0-9+/]{32,}={0,2}' -- . ':!*packages.lock.json'`, без URL | 59 | commit-хеші в `.scaffolds/*.json` і звітах, traceId у docs, шляхи файлів і довгі C#-ідентифікатори (`OperationAuthorizationRequirement`, `WebApplicationFactoryClientOptions`), рядки довжини в `tests/http/lab-02-checks.http`. Високоентропійних секретів немає |
| `git grep -l -I -i 'local-study-password\|unreachable-study-value' -- .` | 6 файлів | три study-only входи з п. 9.1, README і review як документація, а також новий `tests/.../Lab06ProductionProfileTests.cs` (commits `a55bc15`, `fde58a5`): та сама відкрита навчальна БД на 127.0.0.1 і свідомо недосяжний порт 54399 з методики. Рішення accepted, study-only, межа та сама, що в п. 9.1 |

Висновок: у поточних tracked files реального credential не знайдено. Шаблони є широким базовим пошуком засобами Git, а не повноцінним secret scanner, тому секрет іншого формату цей пошук міг пропустити.

### 9.4. Діагностичні журнали й журнал аудиту (етап 3, п. 4)

Діагностичний журнал потрібен розробнику, щоб знайти причину збою (рівень, категорія, trace, технічні деталі на сервері). Подія аудиту фіксує, хто що зробив з яким ресурсом і з яким результатом, і має бути зрозумілою без stack trace. У проєкті обидва канали пишуть у console logger зі scopes (`Logging:Console:IncludeScopes=true`), аудиторські категорії `SecureLab.AuthEvents` і `SecureLab.AuthorizationAudit`, а історія статусів зберігається в таблиці `incident_status_history`.

Запуск, sink поза Git `../lr06-logs/api.log`: reset у Development, `dotnet run --project src/SecureLab.Api 2>&1 | tee ../lr06-logs/api.log`, сценарії curl із cookie jar поза репозиторієм, потім `bash ../lr06-resources/commands/production.sh broken 2>&1 | tee -a ../lr06-logs/api.log` і один login. Паролі в командах брались зі змінної середовища через `jq --arg`, токени лише у тимчасових файлах `../lr06-logs/*.tmp`, видалених після перевірки.

| № | Сценарій | Request і результат | Запис у журналі або аудиті | Перевірені поля й чого немає |
|---|---|---|---|---|
| 1 | successful login | `POST /api/auth/login` alice, 204 | `SecureLab.AuthEvents`: `Auth event login: result success, user 10000000-...0001, trace 0HNQ06PG3UVS3:00000001` | є result, subject id, trace і час запису. Немає пароля, cookie, імені з форми |
| 2 | failed login | alice з `NotARealPassword1!`, 401 | `warn: SecureLab.AuthEvents`: `Auth event login: result failure, trace 0HNQ06PG3UVS4:00000001` | немає пароля, імені з форми і ознаки, чи існує акаунт |
| 3 | denied protected action | Alice (Reporter) з валідним `X-CSRF-TOKEN` `POST /api/incidents/...0003/triage`, 403 | `warn: SecureLab.AuthorizationAudit`: `authorization.denied subject=...0001 action=incident.triage resource=...0003 result=denied occurredAtUtc=... traceId=00-aeb30be5...` | subject, action, resource, result, time, trace. Немає токена, cookie, тіла, персональних даних чужого |
| 4 | validation error | Alice `POST /api/incidents` з `title` з пробілів і `severity` 7, 400 Validation Problem Details | окремого запису немає (`Microsoft.AspNetCore` на рівні Warning), відповідь має `traceId` | у журналі немає тіла запиту. Межа: мінімальний діагностичний контекст лише в відповіді |
| 5 | unexpected server error | Production, БД 54399, login, 500 з `traceId` `00-f222a01eec14b206ac2612ae3b82ea0a-...` | `fail: ExceptionHandlerMiddleware[1]` з `TraceId:f222a01eec14b206ac2612ae3b82ea0a`, `RequestPath:/api/auth/login`, stack trace лише в журналі | збіг TraceId. Немає пароля з запиту і пароля з connection string |
| 6 | privileged transition | Morgan (Analyst) з валідним токеном triage `...0003`, 204 | рядок `incident_status_history`: `changed_by_user_id=...0003`, `old_status=New`, `new_status=Triaged`, `note=Triage`, `created_at_utc=2026-11-11 20:57:20` (запит `psql`). У журналі лише EF `INSERT INTO incident_status_history` з параметрами `@p0...`, значення замасковані | subject, action, resource, result (успішний перехід), time. Відмову Reporter для того самого переходу показує сценарій 3 |

**Доказ відсутності чутливих даних (відмінний рівень).** Знімки `lr06-s3-03-log-sensitive-check.png`, `lr06-s3-04-log-cookie-pattern.png`, файл журналу 376 рядків, обидва запуски.

| Команда | Збігів |
|---|---|
| `grep -c -F "$SeedUsers__Password" ../lr06-logs/api.log` (змінну перевірено як задану) | 0 |
| `grep -c -F 'NotARealPassword1!' ../lr06-logs/api.log` | 0 |
| `grep -c -i -E 'cookie:\|set-cookie' ../lr06-logs/api.log` | 0 |
| `grep -c -i -E 'securelab-af\|\.AspNetCore\.Identity\.Application' ../lr06-logs/api.log` (назви cookie) | 0 |
| `grep -c -i 'X-CSRF-TOKEN' ../lr06-logs/api.log` (назва antiforgery header) | 0 |
| `grep -c -F -f ../lr06-logs/token-alice.tmp` і `token-morgan.tmp` (фактичні request token) | 0 і 0 |
| `grep -c -E 'local-study-password\|unreachable-study-value\|Host=127' ../lr06-logs/api.log` (connection string) | 0 |

Ширший власний шаблон з `\.AspNetCore\.Identity` спершу дав 2 збіги, але це рядки stack trace `Microsoft.AspNetCore.Identity.UserManager` і `SignInManager` сценарію 5, назва простору імен, а не значення cookie. Перевірка робилась на початковому файлі журналу, а не на очищеній копії. Межа висновку: лише ці шість сценаріїв і цей console sink. Після перевірки тимчасові токени видалено, журнал лежить лише поза репозиторієм.

**Log injection.** Повідомлення будуються message template з параметрами (`{EventType}`, `{UserId}`), а не конкатенацією. Невдалий login не пише введене ім’я взагалі, audit відмови пише лише Guid з principal і маршруту, тому довільний текст користувача в ці записи не потрапляє. Пароль у SQL-журналі EF не видно, бо `EnableSensitiveDataLogging` вимкнено і параметри показано як `'?'`.

**Gap для аудиту.** Успішний перехід статусу має audit trail лише в БД (`incident_status_history`), окремої аудиторської події в журналі немає, і ні журнал, ні таблиця не захищені від зміни тим, хто має доступ на запис. Це закриває погоджений advanced variant (tamper-evident журнал security-подій).

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
