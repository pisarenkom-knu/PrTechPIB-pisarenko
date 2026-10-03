# A-01. Огляд точок доступу до БД

Пошук за командами методички на vulnerable commit 81fdc80 знаходить три збіги: `DatabaseBootstrap.cs:29`, `Lab02Endpoints.cs:22` і `Lab02Endpoints.cs:23`. На fixed стані лишається один збіг `DatabaseBootstrap.cs:29`. Пошук `$"SELECT` і `+ query` в обох станах дає порожній результат.

![46-a01-grep.png](46-a01-grep.png)

Пошук за шаблонами охоплює лише raw SQL, тому додатково переглянуто всі місця в `src`, де формується або виконується запит до PostgreSQL.
| Файл:рядок / метод | Категорія | Висновок |
|---|---|---|
| `Lab02Endpoints.cs:15-47`, пошук GET `/api/incidents/search` | до виправлення raw SQL зі склеюванням, після виправлення LINQ з `ILIKE @pattern ESCAPE '\'` і allowlist | виправлено. Значення `q` передається параметром, `sortBy` обирає один із трьох виразів сервера, невідоме значення дає 400 |
| `Lab02Endpoints.cs:102`, перевірка дубліката в POST `/api/incidents` | LINQ `AnyAsync`, параметр `@title` | безпечно. Значення вже перевірене й нормалізоване |
| `Lab02Endpoints.cs:121-122`, запис у POST `/api/incidents` | EF `Add` і `SaveChangesAsync`, `INSERT` з параметрами | безпечно. Усі значення передаються параметрами, службові поля задає сервер |
| `IncidentQueries.cs:16-31`, `GetListAsync` | LINQ, фільтр `status` параметром | безпечно. `status` проходить `TryParseStatus` і стає enum |
| `IncidentQueries.cs:38-59`, `GetDetailsAsync` | LINQ, `WHERE i.id = @id` | безпечно. `id` обмежено маршрутом `{id:guid}` |
| `IncidentQueries.cs:66-77`, `GetSeveritySummaryAsync` | LINQ `GROUP BY`, фільтр `status` параметром | безпечно. Той самий `TryParseStatus` |
| `Program.cs:53-54`, GET `/health` | службовий виклик `CanConnectAsync` | безпечно. Дані користувача в запит не входять |
| `DatabaseBootstrap.cs:29`, reset | trusted static SQL, `ExecuteSqlRawAsync` з літералом `TRUNCATE` | безпечно. Рядок сталий і без вводу, виконується лише в Development за `Database:AllowReset` |
| `DatabaseBootstrap.cs:26, 42`, міграції | EF `MigrateAsync` | безпечно. SQL міграцій згенеровано з моделі |
| `DbSeeder.cs:18, 93-126`, `SeedAsync` | LINQ `AnyAsync`, EF `AddRange` і `SaveChangesAsync` | безпечно. Значення сталі й передаються параметрами |
| `Lab02Seed.cs:16-27`, `EnsureAsync` | LINQ `AnyAsync`, EF `Add` і `SaveChangesAsync` | безпечно. Значення сталі |
