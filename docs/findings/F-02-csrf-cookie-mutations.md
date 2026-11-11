# F-02. CSRF на змінювальних маршрутах cookie-сеансу

**Статус:** Fixed
**Актив:** привілейований перехід New -> Triaged, власні інциденти, сеанс користувача
**Компонент:** `POST /api/incidents/{id}/triage` та весь периметр SC-01...SC-05 (`docs/security-review.md`, розділ 8.3)
**Пріоритет:** P1

## Передумови і межі огляду

Commit до виправлення `fc4c7d6`, Development (`dotnet run --project src/SecureLab.Api`), Google Chrome, навчальний акаунт Morgan (Analyst), seed-інцидент `20000000-0000-0000-0000-000000000005` («Перевірка USB навчальної мережі», статус New). Сторінка іншого origin `demonstrations/csrf-probe/index.html` на `http://localhost:4175` (`python3 -m http.server 4175 --bind localhost --directory demonstrations/csrf-probe`). Лише localhost і seed-дані, після досліду виконано reset.

## Відтворення

1. Увійти як Morgan на `http://localhost:5080/auth-lab.html`.
   Перевірити стан: `GET /api/incidents/20000000-0000-0000-0000-000000000005` дає `"status":"New"`.
2. У тому самому браузері відкрити `http://localhost:4175` і натиснути «Надіслати triage для 0005». Сторінка надсилає звичайну HTML-форму `method="post"` без полів на `http://localhost:5080/api/incidents/20000000-0000-0000-0000-000000000005/triage`.
   Очікувано: відмова, бо дію ініціював не клієнт SecureLab.
   Фактично: Network `triage 204 No Content`, браузер сам додав cookie сеансу Morgan.
3. Повторний `GET` того самого інциденту дає `"status":"Triaged"`.

Під час першої спроби DevTools було на вкладці Sources, тому запит на seed-інцидент `0003` не записався в Network, але статус `0003` так само змінився на Triaged. Для доказу дослід повторено на `0005` з відкритим Network, після чого виконано reset.

## Вплив і ймовірність

**Статус перевірки:** спостережено локально.

Будь-яка сторінка, яку відкриє залогінений Analyst, може без його відома перевести чужі інциденти New у Triaged, змінивши робочий процес і історію статусів. Так само можна завершити сеанс будь-якого користувача (`POST /api/auth/logout` теж простий POST без тіла). CORS цьому не заважає, бо форма не читає відповідь. Cookie `SameSite=Lax` браузер надсилає з будь-якого origin того самого site (інші порти localhost, у реальному розгортанні інші піддомени того самого домену), а з іншого site на POST не надсилає. Отже SameSite звужує коло атакувальних сторінок, але не усуває ризик. Ймовірність висока (потрібен лише візит на сторінку), вплив на цілісність середній, тому P1.

## Першопричина

API довіряв authentication cookie як доказу наміру користувача. Для маршрутів без тіла (triage, logout) не було жодної ознаки, яку стороння сторінка не може підробити: ні request token, ні вимоги JSON. Маршрути з JSON-тілом (create, update) від простої форми рятувала лише прив’язка тіла до JSON, а DELETE лише preflight, тобто захист був випадковим, а не задуманим.

## Виправлення

Стандартний ASP.NET Core antiforgery (commit з цією карткою): `AddAntiforgery` з header `X-CSRF-TOKEN` і cookie `securelab-af` у `Program.cs`, маршрут видачі `GET /api/antiforgery/token` (`GetAndStoreTokens`), єдиний `AntiforgeryValidationFilter` (`ValidateRequestAsync`, 400 Problem Details) у `Presentation/Endpoints/AntiforgeryEndpoints.cs`, підключений до SC-01...SC-05. Клієнт `Client/csrf.js` додає header до кожної mutation на `auth-lab.html` і `browser-lab.html`. Сторінка іншого origin не може прочитати token (CORS не дозволяє 4175 читати відповідь), тому не може його підставити.

## Retest

Той самий сценарій у Chrome після виправлення: Network `triage 400`, статус `0005` лишився `New` (`lr06-f02-05`, `lr06-f02-06`). Автоматично `F02_TriageAsSimpleFormPost_WithoutToken_IsRejected_AndStatusStaysNew` (form-urlencoded POST з `Origin: http://localhost:4175`, cookie Morgan) і `Perimeter_EveryCookieMutationWithoutToken_IsRejected` (SC-01...SC-05) проходять.

## Positive regression

Легітимний triage з валідною парою токенів дає 204 і статус Triaged (`lr06-s2-10`, тест A-07). UI: створення на обох сторінках, після F5, logout і новий login працюють (`docs/security-review.md`, розділ 8.3). Повний набір `Passed: 60, Failed: 0`.

## Залишковий ризик

Захист не діє, якщо на самому origin `localhost:5080` виконається чужий скрипт (XSS може запросити token), тому safe DOM і CSP з ЛР 5 лишаються обов’язковими. Login і register свідомо без token (рішення в розділі 8.3). `SameSite=Strict` для antiforgery cookie не замінює перевірку, бо origins на різних портах localhost є одним site.

## Доказ

`lr06-f02-01-before-status-new.png`, `lr06-f02-02-attack-network-204.png`, `lr06-f02-03-attack-headers.png`, `lr06-f02-04-after-status-triaged.png`, `lr06-f02-05-retest-attack-400.png`, `lr06-f02-06-retest-state-and-tests.png`. Без cookie і token: блок Request headers не потрапив у кадр.
