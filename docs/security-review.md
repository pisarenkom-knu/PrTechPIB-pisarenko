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

Спостереження: відповідь 500 не містить `X-Content-Type-Options`, `Referrer-Policy` і `Content-Security-Policy`, які є у відповіді 404 того самого запуску. Аналіз і виправлення у finding етапу 2, п. 1.

**Відновлення.** Після помилки API зупинено, запущено звичайний Development (`dotnet run --project src/SecureLab.Api`), `/health` 200, вхід як `alice` (Reporter, `GET /api/me` 200), список показує 3 власні інциденти, `GET /api/incidents`, `severity-summary` і details відповідають 200.

## 5. Findings summary

Таблиця: ID / актив / вплив / ймовірність / пріоритет / статус / ID повторної перевірки.

## 6. Detailed findings

Щонайменше одна власна знахідка для достатнього рівня, дві виправлені — для доброго; три виправлені — для відмінного, з них третя поза прямим checklist; кожна в окремому файлі docs/findings/*.md.

## 7. Regression results

Для всіх: мінімальний pack SQLi/authentication/authorization-IDOR/XSS/CSRF. Добрий/відмінний: ще validation/CORS/rate limiting. Відмінний: автоматизований повний REG-CSRF-01 (login/cookie → відмова → незмінний стан → token → успіх → змінений стан), команда й фактичний результат. Початкові ID сценаріїв (T/S/A/E/R/REG), команда або тест, передумова, точний результат, перевірка стану ресурсу, перевірений фінальний commit.

## 8. Hardening controls

Для всіх: наявні controls; наявний login limiter — повторна перевірка (quota, 429, відновлення), відсутній — gap або виключення з причиною. Добрий/відмінний: наявні headers, CORS, search limiter (два partitions, quota, 429, відновлення). CSP, якої не було, — N/A на достатньому/доброму; для відмінного вона обов’язкова й не має ламати client. Добрий/відмінний: змістові відмінності Development/Production. Відмінний: погодження advanced variant до реалізації й фактична перевірка; Redis — shared state, TTL, partition isolation, failure mode.

Зв’язок «control → ризик → фактична перевірка → межа»; у рядках про headers зазначте профіль, клієнт і status.

| ID    | Method + route | Джерело / розбіжність                        | Яка зміна стану | Cookie authentication | Browser-accessible | Antiforgery validation        | Regression ID |
| ----- | -------------- | -------------------------------------------- | --------------- | --------------------- | ------------------ | ----------------------------- | ------------- |
| SC-01 | заповнити      | ЛР 2–5 / OpenAPI / client call / DISCREPANCY | заповнити       | так/ні                | так/ні             | explicit / automatic / absent | фактичний ID  |

Login і register внесіть до таблиці з позначкою Cookie authentication = ні та окремим рішенням щодо ризику й меж огляду. Logout входить до cookie-периметра; перевірка токена — до SignOutAsync.

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
