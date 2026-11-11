# F-03. API fallback маскує 405 і 415 під 404

**Статус:** Fixed
**Актив:** узгоджений error contract API, на який спираються клієнт, моніторинг і висновки security review
**Компонент:** `app.MapFallback("/api/{**path}", ...)` у `src/SecureLab.Api/Program.cs`
**Пріоритет:** P3

## Передумови і межі огляду

Commit до виправлення `ae19cb2`, Development (`dotnet run --project src/SecureLab.Api`), curl без cookie і test host. Знайдено власним аналізом під час рішення щодо login і register (етап 2, п. 5): перевіряючи, чи може проста форма з іншого origin дійти до JSON-маршруту, я очікувала 415, а одержала 404 «Ресурс API не знайдено». Методика цієї перевірки не називає, тому це знахідка поза прямим checklist.

## Відтворення

1. `curl -s -i -H 'Content-Type: text/plain' -d '{"userName":"alice","password":"x"}' http://localhost:5080/api/auth/login`
   Очікувано: 415 Unsupported Media Type, бо маршрут існує й приймає лише JSON.
   Фактично: 404 `application/problem+json`, title «Ресурс API не знайдено».
2. `curl -s -i -X PUT -H 'Content-Type: text/plain' -d x http://localhost:5080/api/incidents/20000000-0000-0000-0000-000000000005` без cookie.
   Очікувано: 415 (або 401, якби routing дійшов до авторизації).
   Фактично: 404, ніби інциденту немає.
3. `curl -s -i -X PATCH .../api/incidents/20000000-...-0005`, `curl -s -i http://localhost:5080/api/auth/login` (GET), `curl -s -i -X DELETE http://localhost:5080/api/incidents`.
   Очікувано: 405 з заголовком `Allow`.
   Фактично: 404 без `Allow`.
4. Автоматично `dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~Lab06ApiFallbackTests"` на `ae19cb2` в окремому worktree: `Failed: 6, Passed: 5` (`lr06-f03-01`).

Для шляху поза `/api` (`POST /foo`) фреймворк коректно повертав 405, тобто дефект обмежений API-fallback.

## Вплив і ймовірність

**Статус перевірки:** спостережено локально.

Даних і прав відповідь не розкриває, тому прямий вплив на конфіденційність немає. Але API повідомляє неправду про стан ресурсу: наявний інцидент і наявний маршрут видаються відсутніми. Через це клієнт не може відрізнити помилку свого запиту від видаленого ресурсу, моніторинг рахує 405 і 415 як 404, а security review міг би хибно вважати, що login із простої форми «не існує», хоча насправді його відкидає лише перевірка Content-Type. Ймовірність висока (будь-який запит з іншим методом або типом тіла), вплив низький, тому P3.

## Першопричина

Endpoint routing ASP.NET Core відкидає кандидата через `HttpMethodMatcherPolicy` або `ContentTypeMatcherPolicy` і лише тоді, коли інших кандидатів не лишилось, повертає 405 або 415. Fallback `/api/{**path}` не має обмежень ні на метод, ні на Content-Type, тому завжди лишався валідним кандидатом для будь-якого шляху під `/api` і перехоплював ці випадки, повертаючи жорстко заданий 404.

## Виправлення

Новий обробник `ApiFallback.Handle` у `src/SecureLab.Api/Presentation/Endpoints/ApiFallback.cs` і рядок `app.MapFallback("/api/{**path}", ApiFallback.Handle)` у `Program.cs`. Обробник перебирає зареєстровані `RouteEndpoint` (без catch-all), зіставляє шаблон через `TemplateMatcher` і перевіряє обмеження параметрів (`{id:guid}`) через `IInlineConstraintResolver`, тобто так само, як routing. Якщо маршрут не знайдено, як і раніше 404 «Ресурс API не знайдено». Якщо знайдено, але метод не підходить, 405 Problem Details з `Allow`. Якщо метод підходить, 415 Problem Details. Порядок middleware, авторизацію й інші маршрути не змінено.

## Retest

`dotnet test ... --filter "FullyQualifiedName~Lab06ApiFallbackTests"` після виправлення: `Passed: 11, Failed: 0` (`lr06-f03-01`). Ручно на Development (`lr06-f03-02`): PATCH інциденту 405 `Allow: DELETE, GET, PUT`, GET login 405 `Allow: POST`, login і PUT з `text/plain` 415, усі `application/problem+json` з `traceId`.

## Positive regression

`POST /api/nope` і `GET /api/nope`, `PUT /api/incidents/not-a-guid`, `GET /api/incidents/abc` лишаються 404 «Ресурс API не знайдено» (тести `F03_UnknownApiRoute_StillReturnsProblemDetails404`, `UnknownApiRoute_ReturnsProblemDetails404_NotIndexHtml`). JSON-login з хибним паролем 401. Повний набір після reset `Passed: 73, Failed: 0`.

## Залишковий ризик

405 і 415 для аноніма підтверджують, що маршрут існує. Це стандартна поведінка ASP.NET Core без fallback, а перелік маршрутів і так видно в OpenAPI Development, тому ризик прийнято. Обробник повторює логіку routing для шаблонів і обмежень, тож маршрути з власними `MatcherPolicy`, яких у проєкті немає, він не врахує.

## Доказ

`lr06-f03-01-tests-before-after.png` (worktree `ae19cb2` з новим тестом: 6 failed, потім проєкт з виправленням: 11 passed), `lr06-f03-02-manual-after.png`, `lr06-s2-16-login-register-simple-form.png` (стан до виправлення: login і register з простою формою 404).
