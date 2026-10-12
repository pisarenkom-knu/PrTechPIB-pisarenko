using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        app.MapPost("/api/auth/register", async (RegistrationInput input, UserManager<ApplicationUser> users) =>
        {
            // ЛР 03: завершіть DTO validation та перевірки довірчої межі.
            var errors = new Dictionary<string, string[]>();

            // Перевірка довжини до Trim - межі з моделі БД (UserName, Email 256, DisplayName 120)
            if (string.IsNullOrWhiteSpace(input.UserName))
                errors["userName"] = ["Ім'я користувача обов'язкове."];
            else if (input.UserName.Length > 256)
                errors["userName"] = ["Ім'я користувача не довше за 256 символів."];

            if (string.IsNullOrWhiteSpace(input.Email))
                errors["email"] = ["Email обов'язковий."];
            else if (input.Email.Length > 256)
                errors["email"] = ["Email не довший за 256 символів."];

            if (string.IsNullOrWhiteSpace(input.DisplayName))
                errors["displayName"] = ["Відображуване ім'я обов'язкове."];
            else if (input.DisplayName.Length > 120)
                errors["displayName"] = ["Відображуване ім'я не довше за 120 символів."];

            // Пароль не нормалізуємо, верхня межа обмежує вартість хешування
            if (string.IsNullOrEmpty(input.Password))
                errors["password"] = ["Пароль обов'язковий."];
            else if (input.Password.Length > 128)
                errors["password"] = ["Пароль не довший за 128 символів."];

            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            // Нормалізація - лише Trim, пароль без змін
            var userName = input.UserName?.Trim() ?? "";
            var email = input.Email?.Trim() ?? "";
            var displayName = input.DisplayName?.Trim() ?? "";

            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(), UserName = userName, Email = email,
                DisplayName = displayName
            };
            var result = await users.CreateAsync(user, input.Password!);
            if (!result.Succeeded)
            {
                var codes = result.Errors.Select(error => error.Code).ToArray();

                // Дублікат імені або email - 409 без уточнення, яке саме поле зайняте
                if (codes.Any(code => code is "DuplicateUserName" or "DuplicateEmail"))
                    return Results.Problem(
                        statusCode: StatusCodes.Status409Conflict,
                        title: "Реєстрація неможлива",
                        detail: "Обліковий запис із такими даними вже існує.");

                // Решта відмов Identity - 400 з ключем поля, без значень із запиту
                var identityErrors = new Dictionary<string, string[]>();
                if (codes.Any(code => code.StartsWith("Password", StringComparison.Ordinal)))
                    identityErrors["password"] = ["Пароль має містити щонайменше 10 символів, велику й малу латинські літери, цифру та спецсимвол."];
                if (codes.Contains("InvalidUserName"))
                    identityErrors["userName"] = ["Допустимі символи: латинські літери, цифри та -._@+"];
                if (codes.Contains("InvalidEmail"))
                    identityErrors["email"] = ["Некоректний формат email."];
                if (identityErrors.Count == 0)
                    identityErrors["registration"] = ["Реєстрацію відхилено."];
                return Results.ValidationProblem(identityErrors);
            }
            var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
            if (!role.Succeeded) throw new InvalidOperationException("Default role assignment failed.");
            // Відповідь лише з дозволених полів - без пароля, hash, stamp і ролі
            return Results.Created("/api/me", new RegistrationResponse(user.Id, userName, user.DisplayName));
        });
        app.MapPost("/api/auth/login", async (LoginInput input, SignInManager<ApplicationUser> signIn) =>
        {
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password))
                return Results.Unauthorized();
            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, false, false);
            return result.Succeeded ? Results.NoContent() : Results.Unauthorized();
        });
        // Стандартний sign-out Identity - сервер наказує браузеру видалити cookie
        app.MapPost("/api/auth/logout", async (SignInManager<ApplicationUser> signIn) =>
        {
            await signIn.SignOutAsync();
            return Results.NoContent();
        });
        // Профіль лише з verified principal, X-Demo-UserId більше не читається
        app.MapGet("/api/me", GetCurrentUser).RequireAuthorization();
        // Приклад лише mechanics: не повертає identity і не реалізує оцінювану operation.
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }

    private static IResult GetCurrentUser(HttpContext httpContext)
    {
        // Id з claim NameIdentifier, який сервер сам поклав у зашифровану cookie
        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userId, out var verifiedUserId))
            return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);

        var userName = httpContext.User.FindFirst(ClaimTypes.Name)?.Value ?? "";
        var role = httpContext.User.FindFirst(ClaimTypes.Role)?.Value ?? "";

        return Results.Ok(new CurrentUserResponse(verifiedUserId, userName, role));
    }
}

public sealed record RegistrationInput(string? UserName, string? Email, string? DisplayName, string? Password);
public sealed record RegistrationResponse(Guid Id, string UserName, string DisplayName);
public sealed record LoginInput(string? UserName, string? Password);
public sealed record CurrentUserResponse(Guid UserId, string UserName, string Role);
