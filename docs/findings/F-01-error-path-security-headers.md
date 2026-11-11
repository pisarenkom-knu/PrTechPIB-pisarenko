# F-01. Відповідь 500 втрачає security headers

**Статус:** Fixed
**Актив:** браузерні controls клієнта (захист від MIME sniffing, витоку referrer, вбудовування у frame і небажаних джерел ресурсів)
**Компонент:** inline middleware security headers у `src/SecureLab.Api/Program.cs`
**Пріоритет:** P3

## Передумови і межі огляду

Review-start `220b9b3`, гілка `lab/6-hardening-review`, commit до виправлення `a55bc15`. Production-like запуск `bash ../lr06-resources/commands/production.sh broken` (PostgreSQL на недосяжному порту 54399), анонімний клієнт curl, маршрут `POST /api/auth/login`. Той самий сценарій автоматизовано в test host з `UseEnvironment("Production")`. Reset не потрібний. Знахідку підказує методика (етап 2, п. 1), тому вона не є знахідкою «поза checklist».

## Відтворення

1. Запустити API командою `bash ../lr06-resources/commands/production.sh normal` і виконати `curl -sS -D - http://localhost:5080/openapi/v1.json`.
   Результат: `404`, є `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'self'; ... frame-ancestors 'none'`.
2. Зупинити API, запустити `bash ../lr06-resources/commands/production.sh broken`.
3. Надіслати `POST /api/auth/login` з вигаданим паролем (`curl -sS -i ... -d '{"userName":"alice","password":"NotARealPassword1!"}'`).
   Очікувано: `500` Problem Details з тими самими трьома заголовками.
   Фактично: `500`, `application/problem+json`, `traceId`, є лише `Cache-Control`, `Expires`, `Pragma`, а `X-Content-Type-Options`, `Referrer-Policy` і `Content-Security-Policy` відсутні.
4. Автоматично: `dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~F01_UnexpectedError"` на `a55bc15` дає `Failed: 1`, `InvalidOperationException: The given header was not found.` для `X-Content-Type-Options`.

## Вплив і ймовірність

**Статус перевірки:** спостережено локально.

Відповідь 500 має тип `application/problem+json` і не містить даних користувача, тому прямий вплив малий. Проте browser controls мають діяти однаково на всіх відповідях: без `nosniff` браузер може інтерпретувати тіло помилки за вмістом, без CSP і `frame-ancestors 'none'` сторінку помилки можна вбудувати у frame, без `Referrer-Policy` браузер застосовує власну політику за замовчуванням. Сценарій доступний будь-кому, хто може спричинити необроблену помилку (недоступність БД, майбутня помилка в коді). Ймовірність середня, вплив низький, тому P3.

## Першопричина

Middleware записував заголовки в `context.Response.Headers` до виклику `next`. Він стоїть після `app.UseExceptionHandler()`, тому виняток із endpoint проходить назад через нього до `ExceptionHandlerMiddleware`. Перед формуванням Problem Details exception handler очищає відповідь (статус, тіло й уже встановлені заголовки, крім cache-заголовків, які додає сам), тож заголовки, встановлені раніше, зникають. На звичайних 200, 400 і 404 відповідь не очищується, тому розбіжність видно лише на шляху помилки.

## Виправлення

У тому самому middleware заголовки тепер встановлюються в callback `context.Response.OnStarting(...)`. Callback виконується безпосередньо перед надсиланням заголовків, тобто після того, як exception handler очистив і заново сформував відповідь. Порядок конвеєра й значення заголовків не змінено, другого catch-all middleware не додано. `Referrer-Policy` записується присвоєнням замість `Append`, щоб повторний виклик не дублював значення. Diff: `src/SecureLab.Api/Program.cs`, блок `app.Use` після `const string csp`.

## Retest

`dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~F01_UnexpectedError"` після виправлення: `Passed: 1, Failed: 0`. Тест `F01_UnexpectedError_KeepsSecurityHeaders` створює Production host з недосяжною БД, надсилає той самий login і перевіряє `500`, `application/problem+json`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` і `frame-ancestors 'none'` у CSP. Ручний retest у Production (`production.sh broken`, curl): `500`, `application/problem+json`, є `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` і CSP з `frame-ancestors 'none'`, `traceId` `00-761ad2a540e2e031d46b4b4054e2a0b5-1d6aeabddf27eb59-00` збігається з `TraceId` запису `ExceptionHandlerMiddleware` того самого запиту. Повний набір `dotnet test SecureLab.sln -c Release`: `Passed: 56, Failed: 0`.

## Positive regression

Звичайні відповіді зберігають ті самі заголовки й працюють як раніше: статична сторінка `GET /` 200, details Alice 200, `?status=Unknown` 400, неіснуючий id 404 (таблиця етапу 2, п. 1 у `docs/security-review.md`), увесь набір `dotnet test SecureLab.sln -c Release`. Сторінка `/scalar` у Development лишається без CSP, як і до змін.

## Залишковий ризик

Заголовки не додаються до відповідей, які Kestrel формує до входу в конвеєр (наприклад, 400 на некоректний HTTP-запит). Заголовки не замінюють правильний `Content-Type`, безпечну роботу з DOM і авторизацію. HTTPS і HSTS не перевірялися, бо локальний стенд працює по HTTP.

## Доказ

Скріни відповіді 500 без заголовків (Production, curl), 404 з заголовками того самого запуску, тест до (`Failed: 1`) і після (`Passed: 1`) виправлення. Без пароля, cookie чи connection string.
