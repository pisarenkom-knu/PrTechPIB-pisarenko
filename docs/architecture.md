# Карта архітектури

Карта описує стан після ЛР 1: додано `GET /api/incidents/severity-summary`.

## Компоненти

| Компонент      | Розташування                | Відповідальність                                                  |
| -------------- | --------------------------- | ----------------------------------------------------------------- |
| Browser client | [`src/SecureLab.Api/Client/`](../src/SecureLab.Api/Client/) | Надсилає HTTP-запити, безпечно показує відповідь через DOM API    |
| Presentation   | [`Presentation/`](../src/SecureLab.Api/Presentation/)             | Описує endpoints, читає зовнішні параметри, формує HTTP-відповідь |
| Application    | [`Application/`](../src/SecureLab.Api/Application/)              | Виконує сценарій отримання списку або деталей інциденту           |
| Data           | [`Data/`](../src/SecureLab.Api/Data/)                     | Відображає C#-сутності на PostgreSQL через EF Core/Npgsql         |
| PostgreSQL     | [`infra/compose.yaml`](../infra/compose.yaml)        | Зберігає навчальні дані у локальному контейнері                   |

## Підготовлений наскрізний маршрут

```text
submit/click у Client/app.js
  → GET /api/incidents або GET /api/incidents/{id}
  → Presentation/Endpoints/IncidentEndpoints.cs
  → Application/Incidents/IncidentQueries.cs
  → Data/SecureLabDbContext.cs
  → PostgreSQL
  → response DTO у Presentation/Contracts/
  → JSON
  → textContent/createTextNode у Client/app.js
```

## Змінений маршрут (severity-summary)

```text
  кнопка #severity-summary-button у Client/index.html
  → loadSeveritySummary у Client/app.js (apiFetch)
  → GET /api/incidents/severity-summary[?status=<IncidentStatus>]
  → IncidentEndpoints.GetSeveritySummaryAsync (allowlist status → 400)
  → IncidentQueries.GetSeveritySummaryAsync (AsNoTracking, Where, GroupBy, Count, ToListAsync)
  → SecureLabDbContext.Incidents → таблиця incidents
  → IncidentSeveritySummaryResponse(Severity, Count) → JSON
  → renderSeveritySummary: textContent у списку підсумку
```

Endpoint `GET /api/incidents/severity-summary` повертає `200` і масив пар `severity` та `count`.
Рівні завжди йдуть в одному порядку: `Low`, `Medium`, `High`, `Critical`. Так вони оголошені в enum,
а сортувати в SQL не можна, бо `severity` зберігається текстом і порядок вийшов би алфавітним.
Якщо інцидентів певного рівня немає, він усе одно є у відповіді з `count: 0`.

Можна додавати `?status=`, щоб порахувати лише інциденти з потрібним статусом.
Сервер приймає тільки назви зі списку `IncidentStatus` незалежно від регістру.
Числа `1`, переліки `New,Triaged` і інші невідомі значення відхиляються з `400`.

Якщо запитати неіснуючий шлях під `/api/`, API відповість `404` у форматі `application/problem+json`,
і не надасть `index.html` (дану функцію виконує fallback у [`Program.cs`](../src/SecureLab.Api/Program.cs)).

## Межі довіри

Доповніть таблицю щонайменше трьома конкретними спостереженнями.

| Межа                        | Чому даним ще не можна довіряти                                             | Де перевіряємо або обмежуємо                                                                              |
| --------------------------- | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Користувач → Browser client | Користувач контролює введення                                               | `<select>` лише допомагає, жодних рішень безпеки на боці клієнта немає                                    |
| Browser client → API        | Клієнт і HTTP-запит можна змінити поза UI (`?status=1`, довільний URL)      | Route constraint `{id:guid}`, allowlist `status` за іменами enum → `400`, невідомий `/api/*` → `404`      |
| API → PostgreSQL            | Значення з URL не мають потрапляти в SQL як текст                           | EF Core параметризує LINQ, `AsNoTracking`, проєкція в DTO                                                 |
| PostgreSQL → API → DOM      | У БД може зберігатися раніше введений недовірений текст (`<script>` у seed) | Response DTO без `OwnerUserId`/email/internal-коментарів, `textContent`/`createTextNode`, без `innerHTML` |

## Конфігураційні входи

- [`global.json`](../global.json) — версія .NET SDK;
- `src/SecureLab.Api/appsettings*.json` — режим міграцій і локальний connection string;
- [`infra/compose.yaml`](../infra/compose.yaml) — версія PostgreSQL, порт і локальні навчальні облікові дані;
- [`src/SecureLab.Api/appsettings.json`](../src/SecureLab.Api/appsettings.json) - рівні логування та `Console.IncludeScopes` (у журнал потрапляє `TraceId`).
- [`src/SecureLab.Api/Properties/launchSettings.json`](../src/SecureLab.Api/Properties/launchSettings.json) - URL `http://localhost:5080` і Development environment.
- змінна середовища `ConnectionStrings__SecureLab` — безпечний спосіб перевизначити connection string поза репозиторієм.

### Залежності конфігурації

[`infra/compose.yaml`](../infra/compose.yaml) (порт 54329, облікові дані) →
[`appsettings.Development.json`](../src/SecureLab.Api/appsettings.Development.json) (connection string) →
перевизначається `ConnectionStrings__SecureLab` →
[`Program.cs`](../src/SecureLab.Api/Program.cs) читає `GetConnectionString("SecureLab")` →
`SecureLabDbContext`.
[`global.json`](../global.json) визначає SDK для всіх команд у корені.

## Повернення до seed-стану

Зупинити API, потім:

```bash
dotnet run --project src/SecureLab.Api -- --reset-database
```

Команда працює лише в Development, очищує навчальні таблиці й повторно
заповнює seed (Low/New, Medium/Triaged, High/InProgress по одному інциденту).

## Автоматизована перевірка

Однією командою `bash scripts/test.sh` (будується (за потреби) та вмикається контейнер з PostgreSQL і запускаються всі тести).

## Журналювання

Журнал summary містить кількість груп і фільтр статусу та `TraceId` зі scope, без описів інцидентів і секретів.
