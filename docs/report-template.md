# Звіт до лабораторної роботи № 1

## 1. Ідентифікація стану

- Варіант: 2-A «Трекер інцидентів».
- Робоча гілка: `lab/1-system`, основна: `main`.
- Фінальний тег: `TODO`.
- Commit hash: `TODO`.

У власних робочих нотатках заповніть щонайменше три рядки таблиці. Для кожної межі назвіть конкретні дані, хибне припущення й контроль, який ви справді знайшли на маршруті.

| Межа або перехід    | Дані, що її перетинають                                                                                                                   | Що не можна припускати                                                                                    | Контроль у дослідженому маршруті                                                                                                                                                                   |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| браузер → API       | `GET /api/incidents?status=New` або `GET /api/incidents/{id}` із GUID                                                                     | Що запит обов'язково надійшов із форми frontend: будь-який HTTP-клієнт може повторити його вручну.        | API самостійно перевіряє `status` через `Enum.TryParse`/`Enum.IsDefined`, а обмеження маршруту `{id:guid}` перевіряє формат ідентифікатора. У frontend додатково використано `encodeURIComponent`. |
| API → PostgreSQL    | Розібраний `IncidentStatus` або `Guid`, передані в LINQ-умови `Where`, а також вибрані поля інциденту, власника й невнутрішніх коментарів | Що значення з URL потрапляють у SQL як конкатенований текст або що клієнтський фільтр захищає базу даних. | EF Core формує параметризований SQL із LINQ, а запити використовують проєкцію DTO, `AsNoTracking()` і фільтрацію `!comment.IsInternal`.                                                            |
| API → браузер       | JSON `200 OK` з даними інциденту, списком або summary. Для помилки JSON Problem Details із `404` чи `400`                                 | Що успішною буде будь-яка відповідь або що помилка повернеться у тому самому форматі, що й успіх.         | `Results.Ok`, `Results.ValidationProblem` і `Results.Problem` задають HTTP-статус та контракт, а `apiFetch` перевіряє `response.ok` і читає `title` з Problem Details.                             |
| дані response → DOM | `title`, `description`, `ownerDisplayName`, `comment.text` із JSON-відповіді                                                              | Що дані response є довіреним HTML і можуть безпечно вставлятися через `innerHTML`.                        | `createTextElement` використовує `textContent`, а текст коментаря вставляється через `createTextNode`, тому рядок на кшталт `<script>` відображається як текст, а не виконується.                  |

## 2. Змінений маршрут

```text
кнопка summary (Client/index.html) → loadSeveritySummary (Client/app.js)
  → GET /api/incidents/severity-summary[?status=...]
  → IncidentEndpoints.GetSeveritySummaryAsync → IncidentQueries.GetSeveritySummaryAsync
  → SecureLabDbContext.Incidents → таблиця incidents
  → IncidentSeveritySummaryResponse → JSON → textContent у списку
```

Ключовий фрагмент (`IncidentQueries.GetSeveritySummaryAsync`, файл [`Application/Incidents/IncidentQueries.cs`](../src/SecureLab.Api/Application/Incidents/IncidentQueries.cs)):

```csharp
var aggregates = await dbContext.Incidents
    .AsNoTracking()
    .Where(incident => incident.Status == status)
    .GroupBy(incident => incident.Severity)
    .Select(group => new IncidentSeveritySummaryResponse(group.Key.ToString(), group.Count()))
    .ToListAsync(cancellationToken);
```

`Where` додається лише тоді, коли передано `status`. Повна карта та межі довіри - у [`docs/architecture.md`](architecture.md).

### Підготовка стенда (CP-01)

Гілка `lab/1-system`, версії інструментів, `.env` в ігнорі:

![cp-01-1.png](evidence/cp-01-1.png)
![cp-01-2.png](evidence/cp-01-2.png)
![cp-01-3.png](evidence/cp-01-3.png)

Контейнер PostgreSQL у стані `healthy` і запуск API (`Now listening on: http://localhost:5080`):

![cp-01-4.png](evidence/cp-01-4.png)
![cp-01-5.png](evidence/cp-01-5.png)

Клієнт, OpenAPI (Scalar) і відновлення seed командою `--reset-database`:

![cp-01-8.png](evidence/cp-01-8.png)
![cp-01-9.png](evidence/cp-01-9.png)
![cp-01-10.png](evidence/cp-01-10.png)

### Дослідження маршруту деталей (CP-02)

Успішний `GET /api/incidents/20000000-0000-0000-0000-000000000003`: метод, URL, `200`, `Content-Type: application/json`, заголовки запиту й відповіді, відсутнє тіло запиту, JSON відповіді та тривалість.

![s22-4-1.png](evidence/s22-4-1.png)
![s22-4-2.png](evidence/s22-4-2.png)
![s22-4-3.png](evidence/s22-4-3.png)
![s22-4-4.png](evidence/s22-4-4.png)

Гілка відсутнього ресурсу (`aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa`): `404`, `application/problem+json` і `traceId` цього запуску.

![s22-5-1.png](evidence/s22-5-1.png)
![s22-5-2.png](evidence/s22-5-2.png)

Зв'язок із кодом. Спочатку endpoint, де `null` з query стає 404:

![s23-1.png](evidence/s23-1.png)

Потім query з `AsNoTracking`, `Where` і `SingleOrDefaultAsync`, а далі `DbSet<Incident> Incidents` та `ToTable("incidents")`:

![s23-2.png](evidence/s23-2.png)
![s23-3.png](evidence/s23-3.png)

Read-only SQL-звірка з JSON-відповіддю:

![s24.png](evidence/s24.png)

Поля `IncidentDetailsResponse` збігаються з проєкцією в query (немає `OwnerUserId`, email і внутрішніх коментарів), а `renderIncidentDetails` записує текст через `textContent` і `createTextNode`, тому `<script>` показується як звичайний текст:

![s25-1.png](evidence/s25-1.png)
![s25-2.png](evidence/s25-2.png)

### Наскрізне розширення summary (CP-03)

Було й стало. До реалізації `GET /api/incidents/severity-summary` повертав `501 Not Implemented`:

![s09-501.png](evidence/s09-501.png)

Після реалізації той самий запит дає `200` і повний перелік рівнів у сталому порядку (`Low 1`, `Medium 1`, `High 1`, `Critical 0`):

![cp-03-1.png](evidence/cp-03-1.png)

Окремий response DTO `IncidentSeveritySummaryResponse` містить лише `Severity` і `Count`, без полів сутності:

![cp-03-2.png](evidence/cp-03-2.png)

Асинхронний query: `AsNoTracking()`, необов'язковий `Where` за `status`, `GroupBy(Severity)`, `Count()` і `ToListAsync(cancellationToken)`. Після цього відсутні рівні доповнюються нулями в порядку enum, а в журнал іде кількість груп і фільтр:

![cp-03-3.png](evidence/cp-03-3.png)

Endpoint отримує `IncidentQueries` і `CancellationToken`, перевіряє `status` за allowlist (`TryParseStatus`) і повертає `Results.Ok(...)`. Замість baseline `501` у metadata тепер `Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>()` і `ProducesValidationProblem()`:

![cp-03-5.png](evidence/cp-03-5.png)

Контракт, політика нульових груп і порядок задокументовані в `tests/http/incidents.http`, поруч із запитами для `status=Triaged`, `Resolved`, `Unknown`, `status=1` і невідомого `/api/...`:

![cp-03-4.png](evidence/cp-03-4.png)

Кнопка в клієнті створює `GET /api/incidents/severity-summary` (запис Network) і показує результат:

![cp-03-6.png](evidence/cp-03-6.png)

`renderSeveritySummary` створює вузли через `createElement` і `textContent`, без `innerHTML`:

![cp-03-7.png](evidence/cp-03-7.png)

`loadSeveritySummary` має окремі стани: «Завантаження…», «Даних немає» для порожнього масиву та фіксоване повідомлення про помилку без деталей:

![cp-03-8.png](evidence/cp-03-8.png)

## 3. Виконані зміни

- `IncidentSeveritySummaryResponse`, `IncidentQueries.GetSeveritySummaryAsync`, endpoint замість baseline `501`.
- Політика: повний перелік рівнів, порядок `Low, Medium, High, Critical`.
- Необов'язковий `status` з allowlist (імена `IncidentStatus`), `400` для некоректного значення.
- Клієнт: кнопка, стани «Завантаження…», «Даних немає», фіксована помилка, `textContent`.
- Структурований log (`{GroupCount}`, `{Status}`) + `Console.IncludeScopes` для `TraceId`.
- Виправлено дві проблеми starter (розділ 5): числовий `status` і HTML `200` для невідомого `/api/*`.
- Тести: 12 (`bash scripts/test.sh`), `.http`-сценарії в [`tests/http/incidents.http`](../tests/http/incidents.http).

## 4. Перевірка

| ID   | Передумови                             | Дія                                                                                 | Очікувано                                                                     | Фактично                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Доказ                                                                                                    |
| ---- | -------------------------------------- | ----------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| T-01 | PostgreSQL healthy, API запущено       | `GET /health`                                                                       | `200 OK`, API з'єднується з БД                                                | Фактично отримано `200 OK`, `Content-Type: application/json`, `{"status":"ready"}`. PostgreSQL має статус `healthy`.                                                                                                                                                                                                                                                                                                                                       | ![cp-01-6.png](evidence/cp-01-6.png) ![cp-01-7.png](evidence/cp-01-7.png)                                        |
| T-02 | Відновлений seed                       | `GET /api/incidents?status=Triaged`                                                 | `200 OK`, список відповідає фільтру                                           | Підтверджено `200`                                                                                                                                                                                                                                                                                                                                                                                                                                         | ![t-02.png](evidence/t-02.png)                                                                           |
| T-03 | Відновлений seed                       | `GET /api/incidents?status=Resolved`                                                | `200 OK` і `[]`                                                               | Фактично отримано `200 OK`, `Content-Type: application/json`, тіло `[]`.                                                                                                                                                                                                                                                                                                                                                                                   | ![t-03.png](evidence/t-03.png) ![t-03-1.png](evidence/t-03-1.png) ![t-03-2.png](evidence/t-03-2.png)     |
| T-04 | Відновлений seed                       | `GET /api/incidents/99999999-9999-9999-9999-999999999999`                           | `404` Problem Details                                                         | Фактично отримано `404 Not Found`, `Content-Type: application/problem+json`, `title: Інцидент не знайдено`.                                                                                                                                                                                                                                                                                                                                                | ![t-04.png](evidence/t-04.png) ![s21-2.png](evidence/s21-2.png)                                          |
| T-05 | Відновлений seed                       | `GET /api/incidents?status=Unknown`                                                 | `400` Validation Problem Details                                              | Фактично отримано `400 Bad Request`, `Content-Type: application/problem+json`, помилка поля `status`.                                                                                                                                                                                                                                                                                                                                                      | ![cp-03-10.png](evidence/cp-03-10.png)                                                                   |
| T-06 | Реалізований summary, відновлений seed | `GET /api/incidents/severity-summary`                                               | `200`, `Low`, `Medium`, `High` по `1` і `Critical` з `0` у сталому порядку    | Фактично отримано `200 OK`, `application/json`: `Low: 1`, `Medium: 1`, `High: 1`, `Critical: 0`. Порядок відповідає політиці повного переліку.                                                                                                                                                                                                                                                                                                             | ![evidence/cp-03-1.png](evidence/cp-03-1.png)                                                            |
| T-07 | API і клієнт запущено                  | Натиснути кнопку підсумку                                                           | Network GET і безпечний UI-вивід. Для доброго рівня також loading/empty/error | У коді є окрема async-функція, loading, `summary.length === 0`, фіксована помилка та DOM-вузли через `textContent`.                                                                                                                                                                                                                                                                                                                                        | ![t-07-1.png](evidence/t-07-1.png) ![t-07-2.png](evidence/t-07-2.png) ![t-07-3.png](evidence/t-07-3.png) |
| T-08 | Після контрольованої зміни даних       | `dotnet run --project src/SecureLab.Api -- --reset-database`, повторити T-02 і T-06 | Seed повертає стенд до відомого стану                                         | Фактично виконано команду `dotnet run --project src/SecureLab.Api -- --reset-database`. У терміналі з’явилося повідомлення: `Локальні навчальні дані очищено та повторно заповнено seed-значеннями.` Після цього повторно перевірено T-02 і T-06: `GET /api/incidents?status=Triaged` і `GET /api/incidents/severity-summary` повернули `200 OK` з відновленим seed-станом, а summary зберіг порядок `Low, Medium, High, Critical` і значення `1, 1, 1, 0` | ![t-08-1.png](evidence/t-08-1.png) ![t-08-2.png](evidence/t-08-2.png)                                    |

### Необов'язковий параметр `status` для summary

`GET /api/incidents/severity-summary?status=Triaged` → `200 OK`, `application/json`:
`Low: 0`, `Medium: 1`, `High: 0`, `Critical: 0` (Triaged має лише інцидент із severity Medium).

![sum-triaged.png](evidence/sum-triaged.png)

`GET /api/incidents/severity-summary?status=Unknown` → `400 Bad Request`,
`application/problem+json`, помилка поля `status`, `traceId` цього запуску.

![sum-unknown.png](evidence/sum-unknown.png)

### Результат автоматизованої перевірки та журнал

Після останньої зміни: `bash scripts/test.sh` - 12 тестів пройдено, 0 провалено.

![final-test-results.png](evidence/final-test-results.png)

Структурований log summary (`{GroupCount}`, `{Status}`) з `TraceId` у scope, без чутливих даних:

![logs.png](evidence/logs.png)

## 5. Security-сценарій

Для робіт із навмисно вразливим станом зафіксуйте: гіпотезу, стан «до»,
мінімальний локальний PoC, спостереження, першопричину, виправлення, повторну
перевірку, позитивну регресію та залишковий ризик.

?status=1 → 200 з Triaged
![bug-01.png](evidence/bug-01.png)
`Enum.TryParse` приймає рядок `1` як число, а `Enum.IsDefined(1)` теж дає `true`, тож `allowlist` не працює.

![bug-resolved-01.png](evidence/bug-resolved-01.png)

/api/incidents/abc → HTML
![bug-02.png](evidence/bug-02.png)
Запит не збігся з жодним маршрутом API, і MapFallbackToFile віддав index.html зі статусом 200.

![bug-resolved-02.png](evidence/bug-resolved-02.png)

### Виправлення та повторна перевірка

Першопричина 1: `Enum.TryParse` + `Enum.IsDefined` не є allowlist (приймають `1` і `New,Triaged`).
Виправлення: `TryParseStatus` порівнює рядок лише з `Enum.GetNames<IncidentStatus>()` (спільний для `/api/incidents` і `/severity-summary`).
Після виправлення `?status=1` → `400`.
Позитивна регресія: `?status=Triaged` → `200`.

Першопричина 2: `MapFallbackToFile("index.html")` відповідав на будь-який невідомий шлях.
Виправлення: `app.MapFallback("/api/{**path}", …)` повертає `404 application/problem+json`.
Позитивна регресія: `/api/incidents/{guid}` та решта маршрутів працюють, клієнт `/` відкривається.

Автоматично: `InvalidStatus_ReturnsValidationProblem400`, `UnknownApiRoute_ReturnsProblemDetails404_NotIndexHtml`.
Залишковий ризик: `status` - лише фільтр, а автентифікації й авторизації ще немає (ЛР 3-4).

## 6. Висновок

`severity-summary` реалізовано наскрізно (клієнт → API → PostgreSQL → DOM), знайдено й усунуто дві проблеми валідації й маршрутизації starter.
`bash scripts/test.sh` виконується успішно з результатом:

```sh
Test summary: total: 12, failed: 0, succeeded: 12, skipped: 0, duration: 2,0s
Build succeeded in 5,5s
```
