# SecureLab starter: трекер інцидентів

Це baseline starter для дисципліни «Прикладні технології програмування в
інформаційній безпеці», варіант **2-A**. Він містить один простий
трирівневий моноліт, локальний PostgreSQL, мінімальний Vanilla JavaScript
клієнт, відтворювані seed/reset і готовий `WebApplicationFactory` test harness.

Це стан системи **до ЛР 1**. Далі студент послідовно розвиває власний проєкт:
результат завершеної ЛР стає основою наступної. Якщо попередню роботу технічно
не завершено, її потрібно завершити або виправити перед переходом далі.

Starter навмисно не містить завершених рішень ЛР 1–6, автентифікації,
авторизації або навмисних уразливостей. Потрібні для конкретної роботи зміни
студент виконує у власному проєкті за методичними вказівками й лише у
дозволеному локальному середовищі.

## 1. Передумови

- .NET SDK `10.0.302` (зафіксовано у `global.json`);
- Docker із підтримкою `docker compose`;
- Git;
- вільні локальні порти `5080` і `54329`.

Перевірте:

```bash
dotnet --version
docker --version
docker compose version
```

## 2. Перший запуск

У корені starter виконайте:

```bash
docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait
dotnet tool restore
dotnet restore SecureLab.sln
dotnet run --project src/SecureLab.Api
```

Під час першого Development-запуску API застосує готову EF Core migration і
додасть фіксовані навчальні дані. Відкрийте:

- browser client: <http://localhost:5080/>;
- health/readiness: <http://localhost:5080/health>;
- інтерактивний OpenAPI: <http://localhost:5080/scalar/v1>;
- OpenAPI JSON: <http://localhost:5080/openapi/v1.json>.

Зупиніть API через `Ctrl+C`. Контейнер БД зупиняється командою:

```bash
docker compose --env-file infra/.env.example -f infra/compose.yaml down
```

## 3. Відомий початковий стан

Seed містить Alice, Bob, Morgan (Analyst) та Admin, три інциденти, два
публічні коментарі й одну зміну статусу. UUID не випадкові: їх можна
використовувати у `.http`-сценаріях і тестах.

Локальні значення `securelab / local-study-password` є лише відкритими
навчальними credentials для БД, прив'язаної до `127.0.0.1`. Це не секрет і
його заборонено повторно використовувати для іншої БД чи середовища. Реальний
connection string передавайте поза Git через `ConnectionStrings__SecureLab`.

Щоб застосувати наявні migrations, **очистити лише відомі навчальні таблиці**
локальної БД і повернути seed до відомого стану:

```bash
dotnet run --project src/SecureLab.Api -- --reset-database
```

Команда навмисно відмовляється працювати поза явно налаштованим Development
environment. Вона знищує поточні локальні навчальні дані у відомих таблицях
БД `securelab`, але не видаляє саму БД або її схему. З ЛР 6 reset також очищує
журнал аудиту `security_audit_events` і видаляє його файл-якір.

### Налаштування поза Git з ЛР 6

Login, logout і triage записують подію в журнал аудиту й без ключа повертають
503 (fail-closed). Ключі генеруються локально й зберігаються лише поза
репозиторієм, наприклад у файлі з правами 600:

```bash
read -rs 'P?Seed password: '; printf 'export SeedUsers__Password=%q\n' "$P" > ~/.securelab-seed; unset P; echo
```

```bash
printf 'export AuditLog__KeyId=k1\nexport AuditLog__Keys__k1=%s\nexport AuditLog__LoginHashKey=%s\n' "$(openssl rand -base64 32)" "$(openssl rand -base64 32)" >> ~/.securelab-seed; chmod 600 ~/.securelab-seed
```

```bash
source ~/.securelab-seed
```

Файл-якір за замовчуванням лежить у `~/Library/Application Support/SecureLab/audit-anchor.json`
(macOS), інший шлях задає `AuditLog__AnchorPath`. Перевірка й експорт журналу
лише з командного рядка, шлях до файлу абсолютний, бо `dotnet run` працює з теки проєкту:

```bash
dotnet run --project src/SecureLab.Api -- --verify-audit
```

```bash
dotnet run --project src/SecureLab.Api -- --export-audit "$(cd .. && pwd)/lr06-audit/clean.jsonl"
```

Код завершення 0 означає цілий ланцюжок, 2 означає попередження (якір відстає на
один запис), 1 означає порушення. Тести пишуть у ту саму локальну БД власним
ключем `test`, тому перед ручною перевіркою CLI виконайте reset.

## 4. Перевірка

Коли PostgreSQL уже працює:

```bash
dotnet build src/SecureLab.Api/SecureLab.Api.csproj --configuration Release
dotnet test tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj --configuration Release
```

З ЛР 3 тестам потрібна `SeedUsers__Password` у тому самому терміналі. Регресія ЛР 6
виконується на відомому стані після reset, API при цьому зупинено:

```bash
source ~/.securelab-seed
dotnet run --project src/SecureLab.Api -- --reset-database
dotnet test SecureLab.sln -c Release
```

Окремі набори ЛР 6: `--filter "FullyQualifiedName~Lab06Csrf"` (REG-CSRF-01 і
периметр), `~Lab06AuditLog` (журнал аудиту), `~Lab06ApiFallback` (F-03),
`~Lab06SearchRateLimit`, `~Lab06ProductionProfile`. Браузерна регресія
REG-XSS-01 - `tests/browser/description-dom.js` у DevTools Console на
`/browser-lab.html` після входу.

На macOS/Linux або у Git Bash увесь сценарій підняття PostgreSQL і тестів
виконує одна команда:

```bash
bash scripts/test.sh
```

HTTP-сценарії для ручної перевірки розташовані у `tests/http/incidents.http`.
Вони охоплюють `200`, `400`, `404` та початковий `501` для точки розширення.

## 5. Завдання ЛР 1 у starter

Працюючий близький приклад — фільтр інцидентів за `status` через browser → API
→ EF Core → PostgreSQL → JSON → безпечні DOM sinks. Обмежена точка зміни —
`GET /api/incidents/severity-summary`, який у baseline повертає `501`.

Під час ЛР 1 студент реалізує підсумок кількості інцидентів за severity,
викликає endpoint із клієнта, безпечно відображає результат, додає
відтворюваний HTTP-сценарій або адаптує інтеграційний тест і доповнює
`docs/architecture.md`. Зміна схеми БД для мінімального маршруту не потрібна.

## 6. Структура

```text
src/SecureLab.Api/
  Presentation/   endpoints і зовнішні response contracts
  Application/    сценарії застосунку
  Data/           DbContext, entities, migration, seed/reset
  Client/         HTML/CSS/Vanilla JavaScript
tests/
  SecureLab.Api.Tests/   інтеграційні й security regression приклади
  http/                  ручні HTTP-сценарії
infra/                   локальний PostgreSQL
docs/                    карта архітектури, варіант, матриця доступу, звіт
```

Це не Clean/Onion Architecture, DDD, мікросервіси або вимога TDD. Каталоги
позначають відповідальність коду в одному server project.

## 7. Типові проблеми запуску

| Ознака | Перевірка |
|---|---|
| `connection refused` до PostgreSQL | `docker compose ... ps`, порт `54329`, стан healthcheck |
| SDK не знайдено | `dotnet --version` має повернути `10.0.302` у цій директорії |
| порт API зайнятий | зупиніть інший процес на `5080` або задайте `ASPNETCORE_URLS` |
| migration не застосовується | перевірте `ASPNETCORE_ENVIRONMENT=Development` і connection string |
| змінили credentials у compose | узгоджено перевизначте `ConnectionStrings__SecureLab`; не записуйте реальне значення до Git |

Перед commit перегляньте `git status`, `git diff --staged` і переконайтеся, що
до Git не потрапили `.env`, cookies, tokens, реальні passwords, dumps або logs.
