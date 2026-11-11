using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authorization;
using SecureLab.Api.Scaffolding;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Endpoints;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    WebRootPath = "Client"
});
builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();

var connectionString = builder.Configuration.GetConnectionString("SecureLab")
    ?? throw new InvalidOperationException(
        "Connection string 'SecureLab' не налаштовано.");

builder.Services.AddDbContext<SecureLabDbContext>(options =>
    options.UseNpgsql(connectionString));
builder.Services.AddScoped<IncidentQueries>();
// ЛР 4 - без реєстрації AuthorizeAsync відмовлятиме всім
builder.Services.AddScoped<IAuthorizationHandler, IncidentAuthorizationHandler>();

builder.AddLab03Identity();

// ЛР 6 - antiforgery для cookie-сеансу, клієнт повертає request token у цьому header
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = AntiforgeryEndpoints.HeaderName;
    options.Cookie.Name = "securelab-af";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

// Обмеження спроб входу - ключ за IP, за замовчуванням 5 запитів за 60 секунд
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = (context, _) =>
    {
        // Подія без імені користувача, пароля й тіла запиту
        // ЛР 6 - тип події за маршрутом, щоб відмова search не записувалась як login
        var isSearch = context.HttpContext.Request.Path.StartsWithSegments("/api/incidents/search");
        context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger(isSearch ? "SecureLab.RateLimit" : "SecureLab.AuthEvents")
            .LogWarning(isSearch ? "Rate limit event {EventType}: result {Result}, trace {TraceId}"
                    : "Auth event {EventType}: result {Result}, trace {TraceId}",
                isSearch ? "search" : "login", "rate-limited", context.HttpContext.TraceIdentifier);
        return ValueTask.CompletedTask;
    };
    // ЛР 6 - search, ключ лише з verified principal, анонім сюди не доходить (UseAuthorization раніше)
    options.AddPolicy("search", httpContext =>
    {
        var config = httpContext.RequestServices.GetRequiredService<IConfiguration>();
        var userId = httpContext.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: userId is null ? "anonymous" : $"user:{userId}",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = config.GetValue("SearchRateLimit:PermitLimit", 20),
                Window = TimeSpan.FromSeconds(config.GetValue("SearchRateLimit:WindowSeconds", 60)),
                QueueLimit = 0
            });
    });
    options.AddPolicy("login", httpContext =>
    {
        var config = httpContext.RequestServices.GetRequiredService<IConfiguration>();
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = config.GetValue("LoginRateLimit:PermitLimit", 5),
                Window = TimeSpan.FromSeconds(config.GetValue("LoginRateLimit:WindowSeconds", 60)),
                QueueLimit = 0
            });
    });
});

// ЛР 5 - навчальна CORS policy лише в Development, точний origin probe 4173, 4174 - контроль
if (builder.Environment.IsDevelopment())
{
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("Lab05BrowserProbe", policy =>
        {
            policy.WithOrigins("http://localhost:4173")
                .WithMethods("GET")
                .WithHeaders("X-Lab-Cors-Probe")
                // Cookie-дослід - лише разом із точним origin, без wildcard
                .AllowCredentials();
        });
    });
}

var app = builder.Build();

var resetRequested = args.Contains("--reset-database", StringComparer.Ordinal);
await DatabaseBootstrap.InitializeAsync(app.Services, app.Configuration, app.Environment, resetRequested);

if (resetRequested)
{
    return;
}

app.UseExceptionHandler();
app.UseStatusCodePages();

// ЛР 5 - CSP за фактичними ресурсами клієнта, усе з власного origin, inline-коду немає
const string csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    + "connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

app.Use(async (context, next) =>
{
    // ЛР 6, F-01 - headers додаються перед надсиланням, бо exception handler очищає вже встановлені
    context.Response.OnStarting(() =>
    {
        context.Response.Headers.XContentTypeOptions = "nosniff";
        context.Response.Headers["Referrer-Policy"] = "no-referrer";
        // Development-довідник Scalar має власні inline-ресурси, виняток лише для нього
        var isDevelopmentApiReference = app.Environment.IsDevelopment()
            && context.Request.Path.StartsWithSegments("/scalar");
        if (!isDevelopmentApiReference)
        {
            context.Response.Headers["Content-Security-Policy"] = csp;
        }
        return Task.CompletedTask;
    });
    await next(context);
});

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

// ЛР 5 - CORS після routing і до authentication, щоб дозвіл був і на 401/403
app.UseRouting();
if (app.Environment.IsDevelopment())
{
    app.UseCors("Lab05BrowserProbe");
}

app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/health", async (SecureLabDbContext dbContext, CancellationToken cancellationToken) =>
    await dbContext.Database.CanConnectAsync(cancellationToken)
        ? Results.Ok(new { status = "ready" })
        : Results.Problem(
            title: "База даних недоступна",
            statusCode: StatusCodes.Status503ServiceUnavailable))
    .WithName("GetHealth")
    .Produces(StatusCodes.Status200OK)
    .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

app.MapAntiforgeryEndpoints();
app.MapIncidentEndpoints();
app.MapLab03Identity();
app.MapLab02Endpoints();
// ЛР 6, F-03 - 404 лише для невідомого шляху, для наявного маршруту 405 або 415
app.MapFallback("/api/{**path}", ApiFallback.Handle);
app.MapFallbackToFile("index.html");

app.Run();

public partial class Program;
