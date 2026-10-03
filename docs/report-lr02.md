# Звіт до лабораторної роботи № 2

## 1. Ідентифікація

- ПІБ і група: Пісаренко Марія, група КБ-42.
- Спільний baseline 2-A «Трекер інцидентів», індивідуального номера немає.
- Заявлений рівень: відмінний («Відмінно»).
- Гілка: `lab/2-input-sqli`.
- Release, base_commit та entry_parent із квитанції `.scaffolds/lab-02.json`: `lab-02-start-v1`, `742beef606974c6f6beb10ae565cdf12ab40111d`, `742beef606974c6f6beb10ae565cdf12ab40111d`.
- Vulnerable commit: `81fdc80e55339ad201ceb242bf1408ecc4a9c2eb`. Fixed commit коду: `1cb6613d7a7751f33b08baca209ba66f0efc9472`. Фінальний тег `v0.2.0` стоїть на commit із завершеним звітом.
- DEL-01: приватний remote `https://github.com/pisarenkom-knu/PrTechPIB-pisarenko.git`, гілка `lab/2-input-sqli` і тег `v0.2.0`.

Перевірка SDK і встановлення scaffold:

![01-sdk.png](evidence/lab-02/01-sdk.png)
![02-installer.png](evidence/lab-02/02-installer.png)
![03-git-status-scaffold.png](evidence/lab-02/03-git-status-scaffold.png)
![04-receipt.png](evidence/lab-02/04-receipt.png)

Scaffold додав два інциденти Low, тому тест підсумку з ЛР-1 очікувано зламався на лічильниках. Оновлено лише очікувані числа (Low=3, Medium=1, High=1), логіку тесту не послаблено:

![05-tests-summary-counts-fail.png](evidence/lab-02/05-tests-summary-counts-fail.png)
![06-tests-baseline-pass.png](evidence/lab-02/06-tests-baseline-pass.png)

Перевірка встановлення `q=USB` дає 200 і один запис `…0005`:

![07-usb-search.png](evidence/lab-02/07-usb-search.png)

## 2. Контракт і CP-01

Наданий обробник `POST /api/incidents` мовчки підміняв невідомий `severity` на `Low`, відсутню дату на поточний час і повертав анонімний об'єкт. Його доповнено перевірками в `src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs` у такому порядку: базові перевірки полів, нормалізація через `Trim()`, залежні перевірки, одна відповідь `400` до звернення до БД, предметний конфлікт `409`, створення entity, `201` з `CreatedIncidentResponse`.

| Поле або правило           | Перевірка                                                                                                | Відповідь                 | Доказ                                                                                                                                                     |
| -------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `title`                    | не порожній після `Trim()`, довжина до `Trim()` не більше 160                                            | 400, ключ `title`         | ![09-t02a-validation.png](evidence/lab-02/09-t02a-validation.png)                                                                                         |
| `description`              | не порожній після `Trim()`, довжина до `Trim()` не більше 4000                                           | 400, ключ `description`   | ![08-t01-created.png](evidence/lab-02/08-t01-created.png)                                                                                                 |
| `severity`                 | `Enum.TryParse` без урахування регістру, `Enum.IsDefined`, без коми                                      | 400, ключ `severity`      | ![09-t02a-validation.png](evidence/lab-02/09-t02a-validation.png) ![11-t02c-enum-comma.png](evidence/lab-02/11-t02c-enum-comma.png)                       |
| `occurredAtUtc`            | обов'язковий, не пізніше `now + 5 хв`, перед записом `.ToUniversalTime()`                                | 400, ключ `occurredAtUtc` | ![10-t02b-future-date.png](evidence/lab-02/10-t02b-future-date.png) ![08-t01-created.png](evidence/lab-02/08-t01-created.png)                             |
| cross-field (T-09)         | для High і Critical `description` після `Trim()` щонайменше 40 символів                                  | 400, ключ `description`   | ![12-t09-39.png](evidence/lab-02/12-t09-39.png) ![13-t09-40.png](evidence/lab-02/13-t09-40.png)                                                           |
| T-10                       | Critical реєструється не пізніше ніж через 72 години після події                                         | 400, ключ `occurredAtUtc` | ![16-t10-reject.png](evidence/lab-02/16-t10-reject.png) ![17-t10-accept.png](evidence/lab-02/17-t10-accept.png)                                           |
| предметний конфлікт (T-03) | збіг `title` після `Trim()` з урахуванням регістру серед статусів, крім `Closed`                         | 409                       | ![14-t03-conflict.png](evidence/lab-02/14-t03-conflict.png) ![15-t03-case.png](evidence/lab-02/15-t03-case.png)                                           |
| server-managed поля        | `Id`, `OwnerUserId = DbSeeder.AliceId`, `Status = New`, `CreatedAtUtc`, `UpdatedAtUtc` задає лише сервер | зайві поля ігноруються    | ![18-cp01-overposting-post.png](evidence/lab-02/18-cp01-overposting-post.png) ![19-cp01-overposting-get.png](evidence/lab-02/19-cp01-overposting-get.png) |
| ресурс не знайдено (T-06)  | синтаксично коректний id, якого немає в БД                                                               | 404                       | ![20-t06-not-found.png](evidence/lab-02/20-t06-not-found.png)                                                                                             |

Потрібні обидві перевірки enum. `Enum.TryParse` перетворює рядок `"7"` на `(IncidentSeverity)7`, хоча такого значення немає, а `Enum.IsDefined` його відхиляє. Під час перевірки знайдено ще один обхід: рядок `"Medium,High"` `TryParse` розбирає як побітове OR `1 | 2 = 3`, тобто `Critical`, і `IsDefined(3)` дає `true`. До виправлення такий запит створював інцидент Critical. Додано умову `!request.Severity.Contains(',')`, після чого запит отримує 400. Аналогічну властивість enum виявлено ще в ЛР-1 для фільтра `status`.

Атрибут `<select>` чи перевірка JavaScript у браузері не замінюють цієї логіки, бо будь-який HTTP-клієнт надсилає JSON напряму, оминаючи форму. Маршрут перевірки такий: JSON, прив'язка до `CreateIncidentRequest`, серверні перевірки в обробнику, `Results.ValidationProblem(errors)` з `application/problem+json`.

Коректне створення T-01 приймає дату `13:00+03:00` і зберігає її як `10:00+00:00`, у відповіді немає `ownerUserId` і `description`.

Додаткове правило T-10 обрано, бо критичні інциденти потребують швидкої реакції. Правило лише додає обмеження й не послаблює контракт 2-A.

Перевірка CP-01. Запит із зайвими `id`, `ownerUserId` (Bob), `status: "Closed"` і `createdAtUtc` створює запис із новим id, статусом `New` і власником «Аліса Коваль». У `CreateIncidentRequest` таких властивостей немає, тому зайві поля JSON ігноруються.

Відповіді 400, 409 і 404 мають єдиний формат `application/problem+json` з полями `title` і `status`, без stack trace, SQL і назв внутрішніх класів.

## 3. Security-сценарій і CP-02/CP-03

**Контекст і гіпотеза.** Endpoint `GET /api/incidents/search` отримує недовірені `q` і `sortBy` з query string. Ризик полягає в тому, що значення стане частиною структури SQL-команди.

**Стан до.** Vulnerable commit `81fdc80`, файл `src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs`:

- рядки 21-22: `q` двічі приєднується до SQL-тексту через `+` всередині лапок `'%…%'`,
- рядок 19: гілка `_ => sortBy` передає будь-яке значення сортування в `ORDER BY` без лапок,
- рядок 23: `db.Incidents.FromSqlRaw(sql)` надсилає до PostgreSQL готовий суцільний текст.

Тести й commit до виправлення:

![21-tests-vulnerable.png](evidence/lab-02/21-tests-vulnerable.png)
![22-vulnerable-commit.png](evidence/lab-02/22-vulnerable-commit.png)

**Мінімальний доказ дефекту (PoC).** Єдиний дозволений контрольний read-only ввід C з методички, запит у `tests/http/lab-02-checks.http`, рядок 143.

**Спостереження.** Одразу після reset:

| Запит               | Status | Результат                                                                |
| ------------------- | ------ | ------------------------------------------------------------------------ |
| A, `q=USB`          | 200    | один запис `…0005`                                                       |
| B, `q=zz-no-match`  | 200    | `[]`                                                                     |
| C, контрольний ввід | 200    | усі 5 записів seed                                                       |
| D, `q=O'Brien`      | 500    | Problem Details без деталей, у журналі `syntax error at or near "Brien"` |
| `q=комп'ютерного`   | 500    | та синтаксична помилка                                                   |
| `sortBy=price`      | 500    | у журналі `column "price" does not exist`                                |

![23-s01-a-usb.png](evidence/lab-02/23-s01-a-usb.png)
![24-s01-b-no-match.png](evidence/lab-02/24-s01-b-no-match.png)
![25-s01-c-injection-log.png](evidence/lab-02/25-s01-c-injection-log.png)
![25-s01-c-injection-records.png](evidence/lab-02/25-s01-c-injection-records.png)
![26-s01-d-apostrophe.png](evidence/lab-02/26-s01-d-apostrophe.png)
![27-t04-before-komp.png](evidence/lab-02/27-t04-before-komp.png)
![28-t05-before-sortby.png](evidence/lab-02/28-t05-before-sortby.png)

**Першопричина.** У запиті B значення `zz-no-match` лишається всередині лапок і є даними. У запиті C апостроф закриває рядковий літерал, `OR TRUE` стає частиною умови `WHERE` й робить її істинною для кожного рядка, а `--` перетворює решту тексту на коментар разом із другим `ILIKE`, `ORDER BY` і `LIMIT`. У журналі обох запитів `Parameters=[]`, тобто значення не передавалось окремо від тексту. Легітимний апостроф у `O'Brien` і `комп'ютерного` ламав запит із цієї ж причини. Фільтр апострофа не усуває механізм, бо ламає коректні дані, а `sortBy` вставляється без лапок і апостроф для нього не потрібен.

**Виправлення.** `FromSqlRaw` замінено на LINQ з `EF.Functions.ILike(item.Title, pattern, "\\") || EF.Functions.ILike(item.Description, pattern, "\\")`. Значення `pattern` EF Core передає параметром. Власна `EscapeLike` екранує спершу `\`, потім `_` і `%`, тому пошук буквальний. `sortBy` обирає один із трьох виразів `switch`: `createdAtUtc` (за замовчуванням, нові спершу), `severity` з рангами Critical, High, Medium, Low і `status` з рангами New, Triaged, InProgress, Resolved, Closed. Ранги потрібні, бо enum зберігається в БД як рядок і звичайне сортування дало б алфавітний порядок. Скрізь додано `ThenBy(Id)`, після сортування `Take(50)`. Невідоме значення дає `null` і 400 з ключем `sortBy` до звернення до БД.

**Retest і позитивна регресія.** Контрольний ввід C повертає `[]`. У журналі тепер `Parameters=[@pattern='?', @pattern0='?', @p='?']`, а в тексті SQL замість значення стоїть `ILIKE @pattern ESCAPE '\'`. Звичайний пошук і обидва апострофи працюють:

![29-s02-c-retest.png](evidence/lab-02/29-s02-c-retest.png)
![30-t04-a-usb.png](evidence/lab-02/30-t04-a-usb.png)
![31-s02-b-params.png](evidence/lab-02/31-s02-b-params.png)
![32-t04-d-obrien.png](evidence/lab-02/32-t04-d-obrien.png)
![33-t04-komp.png](evidence/lab-02/33-t04-komp.png)
![34-t05-sortby-price.png](evidence/lab-02/34-t05-sortby-price.png)

Буквальний пошук `%`, `_` і `\` на штатному seed дає `[]`:

![35-literal-percent.png](evidence/lab-02/35-literal-percent.png)
![36-literal-underscore.png](evidence/lab-02/36-literal-underscore.png)
![37-literal-backslash.png](evidence/lab-02/37-literal-backslash.png)

Порядок сортування збігається з контрактом, у журналі `ORDER BY CASE WHEN … THEN 0 …`:

![38-sort-default-1.png](evidence/lab-02/38-sort-default-1.png)
![38-sort-default-2.png](evidence/lab-02/38-sort-default-2.png)
![39-sort-severity-1.png](evidence/lab-02/39-sort-severity-1.png)
![39-sort-severity-2.png](evidence/lab-02/39-sort-severity-2.png)
![40-sort-status-1.png](evidence/lab-02/40-sort-status-1.png)
![40-sort-status-2.png](evidence/lab-02/40-sort-status-2.png)

**CP-03.** Раніше СУБД отримувала один текст після конкатенації. Тепер текст SQL сталий, значення `pattern` передається окремо, а SQL-структуру сортування обирає серверний allowlist. Security diff `git diff 81fdc80..1cb6613 -- src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs`:

![48-fixed-commit.png](evidence/lab-02/48-fixed-commit.png)
![49-cp03-security-diff-1.png](evidence/lab-02/49-cp03-security-diff-1.png)

**Залишковий ризик.** Виправлення не замінює автентифікацію й авторизацію, обмеження частоти запитів, пагінацію та перевірку інших endpoint.

## 4. Фактичні перевірки DEL-02

| ID   | Сценарій                   | Передумови                                            | Дія                                                                          | Очікувано                                  | Фактично                                                                                                                                                                                                                      | Доказ                                                                                                                                                                                                                                                                                                                     |
| ---- | -------------------------- | ----------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T-01 | Коректне створення         | reset, унікальний title                               | `POST /api/incidents` з `+03:00`                                             | 201, response DTO без зайвих полів         | 201, `Location`, title обрізано, `occurredAtUtc` у UTC, немає `ownerUserId`                                                                                                                                                   | ![08-t01-created.png](evidence/lab-02/08-t01-created.png)                                                                                                                                                                                                                                                                 |
| T-02 | Некоректний DTO            |                                                       | POST з порожнім title, `severity: "7"`, без дати, дата 2099, `"Medium,High"` | 400, `application/problem+json`            | 400, ключі `title`, `severity`, `occurredAtUtc`, без stack trace і SQL. Автотест `Post_WithInvalidFields_Returns400WithFieldKeys` пройдено                                                                                    | ![09-t02a-validation.png](evidence/lab-02/09-t02a-validation.png) ![10-t02b-future-date.png](evidence/lab-02/10-t02b-future-date.png) ![11-t02c-enum-comma.png](evidence/lab-02/11-t02c-enum-comma.png) ![41-tests-all-pass.png](evidence/lab-02/41-tests-all-pass.png)                                                   |
| T-03 | Предметний конфлікт        | інцидент «Невідома спроба входу» у статусі InProgress | повторний POST із цим title після `Trim()`                                   | 409 у Problem Details                      | 409, `title` і `detail`, без `errors`. Інший регістр дає 201. Автотест `Post_DuplicateActiveTitle_Returns409` пройдено                                                                                                        | ![14-t03-conflict.png](evidence/lab-02/14-t03-conflict.png) ![15-t03-case.png](evidence/lab-02/15-t03-case.png) ![41-tests-all-pass.png](evidence/lab-02/41-tests-all-pass.png)                                                                                                                                           |
| S-01 | SQLi до виправлення        | vulnerable commit `81fdc80`, reset                    | контрольний read-only ввід C                                                 | небажано розширена вибірка                 | 200, усі 5 записів seed, `Parameters=[]`                                                                                                                                                                                      | ![25-s01-c-injection-log.png](evidence/lab-02/25-s01-c-injection-log.png) ![25-s01-c-injection-records.png](evidence/lab-02/25-s01-c-injection-records.png)                                                                                                                                                               |
| S-02 | Retest SQLi                | fixed стан, reset                                     | повтор вводу C, автотест                                                     | порожній результат                         | 200, `[]`, значення передано як `@pattern`. Автотест `Search_WithControlInput_ReturnsEmptySet` перевіряє `Assert.Empty`, позитивний контроль `Search_ForUsb_ReturnsExactlyOneSeedIncident` перевіряє рівно один запис `…0005` | ![29-s02-c-retest.png](evidence/lab-02/29-s02-c-retest.png) ![42-tests-lab02-list.png](evidence/lab-02/42-tests-lab02-list.png)                                                                                                                                                                                           |
| T-04 | Позитивна регресія         | fixed стан                                            | `q=USB`, `q=O'Brien`, `q=комп'ютерного`                                      | коректні записи без 500                    | 200, записи `…0005`, `…0004`, `…0003`. Автотест `Search_WithApostrophe_ReturnsOnlyMatchingIncident` пройдено                                                                                                                  | ![30-t04-a-usb.png](evidence/lab-02/30-t04-a-usb.png) ![32-t04-d-obrien.png](evidence/lab-02/32-t04-d-obrien.png) ![33-t04-komp.png](evidence/lab-02/33-t04-komp.png)                                                                                                                                                     |
| T-05 | Невідоме сортування        | fixed стан                                            | `sortBy=price`                                                               | 400                                        | 400, `errors.sortBy` з переліком `createdAtUtc, severity, status`. Автотест `Search_WithUnknownSortBy_Returns400` пройдено                                                                                                    | ![34-t05-sortby-price.png](evidence/lab-02/34-t05-sortby-price.png)                                                                                                                                                                                                                                                       |
| T-06 | Ресурс не знайдено         | відсутній id                                          | `GET /api/incidents/99999999-…`                                              | 404 у Problem Details                      | 404, `application/problem+json`, «Інцидент не знайдено»                                                                                                                                                                       | ![20-t06-not-found.png](evidence/lab-02/20-t06-not-found.png)                                                                                                                                                                                                                                                             |
| T-09 | Cross-field перевірка      | High, решта полів коректна                            | опис 39 і 40 символів після `Trim()`                                         | 400 `description`, потім 201               | 400 з ключем `description`, потім 201                                                                                                                                                                                         | ![12-t09-39.png](evidence/lab-02/12-t09-39.png) ![13-t09-40.png](evidence/lab-02/13-t09-40.png)                                                                                                                                                                                                                           |
| T-10 | Critical не пізніше 72 год | Critical, решта полів коректна                        | подія 73 і 71 годину тому                                                    | 400 `occurredAtUtc`, потім 201             | 400 з ключем `occurredAtUtc`, потім 201                                                                                                                                                                                       | ![16-t10-reject.png](evidence/lab-02/16-t10-reject.png) ![17-t10-accept.png](evidence/lab-02/17-t10-accept.png)                                                                                                                                                                                                           |
| A-01 | Огляд точок доступу до БД  | fixed стан                                            | пошук методички і перегляд усіх запитів у `src`                              | для кожної точки файл, категорія, висновок | 11 точок, одну виправлено, решта безпечні                                                                                                                                                                                     | [a01-data-access-review.md](evidence/lab-02/a01-data-access-review.md) ![46-a01-grep.png](evidence/lab-02/46-a01-grep.png)                                                                                                                                                                                                |
| A-02 | Ризик overposting          | fixed стан                                            | POST із зайвими `id`, `ownerUserId`, `status`, `createdAtUtc`                | ризик заблоковано контрактом і тестом      | новий id, `New`, «Аліса Коваль». Автотест `Post_WithServerManagedFields_IgnoresThem` пройдено                                                                                                                                 | ![18-cp01-overposting-post.png](evidence/lab-02/18-cp01-overposting-post.png) ![19-cp01-overposting-get.png](evidence/lab-02/19-cp01-overposting-get.png) ![44-a02-sensitivity-fail-2.png](evidence/lab-02/44-a02-sensitivity-fail-2.png) ![45-a02-sensitivity-pass-2.png](evidence/lab-02/45-a02-sensitivity-pass-2.png) |

**A-02.** Відтвореного дефекту в коді не було. Ризик полягає в тому, що клієнт підмінив би `id`, `ownerUserId`, `status` і `createdAtUtc`, якби request DTO повторював entity. Його усунено контрактом `CreateIncidentRequest` (`Lab02Endpoints.cs`, рядок 134), де таких властивостей немає. Чутливість тесту перевірено локально: після тимчасового додавання `string? Status` до DTO тест упав з `Expected: "New"`, `Actual: "Closed"`, а після повернення коду знову пройшов. Тимчасову зміну не закомічено.

![43-a02-temp-dto-change.png](evidence/lab-02/43-a02-temp-dto-change.png)
![43-a02-temp-status-change.png](evidence/lab-02/43-a02-temp-status-change.png)
![44-a02-sensitivity-fail-1.png](evidence/lab-02/44-a02-sensitivity-fail-1.png)
![44-a02-sensitivity-fail-2.png](evidence/lab-02/44-a02-sensitivity-fail-2.png)
![45-a02-sensitivity-pass-1.png](evidence/lab-02/45-a02-sensitivity-pass-1.png)
![45-a02-sensitivity-pass-2.png](evidence/lab-02/45-a02-sensitivity-pass-2.png)

**A-01.** Повний огляд у [evidence/lab-02/a01-data-access-review.md](evidence/lab-02/a01-data-access-review.md).

Автоматичні тести і build після останньої зміни:

![41-tests-all-pass.png](evidence/lab-02/41-tests-all-pass.png)
![42-tests-lab02-list.png](evidence/lab-02/42-tests-lab02-list.png)
![47-tests-before-fixed-commit.png](evidence/lab-02/47-tests-before-fixed-commit.png)

```sh
Test summary: total: 20, failed: 0, succeeded: 20, skipped: 0, duration: 2,5s
Build succeeded in 3,7s
```

## 5. Обмеження і висновок

Перевірено контракт створення інциденту з усіма базовими правилами 2-A, cross-field правилом, предметним конфліктом і додатковим правилом T-10, а також усунуто SQL injection у пошуку разом із небезпечним динамічним сортуванням.

Обмеження:

- перевірка `AnyAsync` перед записом не гарантує інваріант за одночасних запитів, для цього потрібен унікальний індекс або транзакція
- `TryParse` з `IsDefined` пропускає комбінацію через кому, тому для enum потрібна додаткова перевірка
- `GetListAsync` з ЛР-1 сортує лише за `CreatedAtUtc` без другого ключа, а записи 0004 і 0005 мають однаковий час, тож їхній порядок у списку не визначений
- `GetDetailsAsync` відкриває будь-який інцидент за id без перевірки власника, що потребує verified principal

## 6. Декларація використання ШІ

| Сервіс                  | Задачі                                                                                                     | Авторська адаптація/інтерпретація                                                                                                                                                               | Фактична перевірка                                                                                                                                                                                                                                                                             |
| ----------------------- | ---------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Claude Code (Anthropic) | покроковий план за методичкою, підказки для коду валідації, безпечного пошуку й автотестів, чернетка звіту | код створено за підказками ШІ й перевірено власноруч, коментарі, сценарії `.http` і формулювання звіту адаптовано самостійно, обхід enum через кому підтверджено власним запитом до виправлення | кожен сценарій виконано вручну через `.http` з фотофіксацією відповіді, 20 автотестів пройдено після останньої зміни, тест A-02 перевірено на здатність виявити дефект: після тимчасового додавання поля `Status` до `CreateIncidentRequest` він зламався, після повернення коду знову пройшов |
