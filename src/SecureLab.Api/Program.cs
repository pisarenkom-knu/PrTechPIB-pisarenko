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

// Обмеження спроб входу - ключ за IP, за замовчуванням 5 запитів за 60 секунд
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = (context, _) =>
    {
        // Подія без імені користувача, пароля й тіла запиту
        context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("SecureLab.AuthEvents")
            .LogWarning("Auth event {EventType}: result {Result}, trace {TraceId}",
                "login", "rate-limited", context.HttpContext.TraceIdentifier);
        return ValueTask.CompletedTask;
    };
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
    context.Response.Headers.XContentTypeOptions = "nosniff";
    context.Response.Headers.Append("Referrer-Policy", "no-referrer");
    // Development-довідник Scalar має власні inline-ресурси, виняток лише для нього
    var isDevelopmentApiReference = app.Environment.IsDevelopment()
        && context.Request.Path.StartsWithSegments("/scalar");
    if (!isDevelopmentApiReference)
    {
        context.Response.Headers["Content-Security-Policy"] = csp;
    }
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

app.MapIncidentEndpoints();
app.MapLab03Identity();
app.MapLab02Endpoints();
app.MapFallback("/api/{**path}", () => Results.Problem(
    title: "Ресурс API не знайдено",
    statusCode: StatusCodes.Status404NotFound));
app.MapFallbackToFile("index.html");

app.Run();

public partial class Program;
