using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace SecureLab.Api.Tests;

// ЛР 6, етап 1, п. 4 - очікувані 4xx у Production test host, БД готується reset у Development
public sealed class Lab06ProductionProfileTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task Production_ExpectedErrors_StayProblemDetails4xx()
    {
        // Похідний host, звичайний factory лишається Development
        using var production = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("ConnectionStrings:SecureLab",
                "Host=127.0.0.1;Port=54329;Database=securelab;Username=securelab;"
                + "Password=local-study-password;Include Error Detail=false");
        });
        Assert.Equal("Production",
            production.Services.GetRequiredService<IHostEnvironment>().EnvironmentName);

        // OpenAPI реєструється лише в Development
        using var anonymous = production.CreateClient();
        using var openApi = await anonymous.GetAsync("/openapi/v1.json");
        Assert.Equal(HttpStatusCode.NotFound, openApi.StatusCode);
        Assert.Equal("application/problem+json", openApi.Content.Headers.ContentType?.MediaType);

        // Спершу дозволений GET тим самим клієнтом, інакше 401 нічого не доводить
        using var alice = await production.LoginAsync("alice", StudyPassword);
        using var session = await alice.GetAsync("/api/auth/session-check");
        Assert.Equal(HttpStatusCode.NoContent, session.StatusCode);

        using var badStatus = await alice.GetAsync("/api/incidents?status=Unknown");
        Assert.Equal(HttpStatusCode.BadRequest, badStatus.StatusCode);
        Assert.Equal("application/problem+json", badStatus.Content.Headers.ContentType?.MediaType);
        var badStatusJson = await badStatus.Content.ReadAsStringAsync();
        using (var document = JsonDocument.Parse(badStatusJson))
            Assert.True(document.RootElement.TryGetProperty("errors", out _));

        using var missing = await alice.GetAsync("/api/incidents/99999999-9999-9999-9999-999999999999");
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        Assert.Equal("application/problem+json", missing.Content.Headers.ContentType?.MediaType);
        var missingJson = await missing.Content.ReadAsStringAsync();

        // Жодна відповідь не розкриває внутрішніх деталей
        foreach (var json in new[] { badStatusJson, missingJson })
        {
            Assert.DoesNotContain("Exception", json, StringComparison.Ordinal);
            Assert.DoesNotContain("SELECT", json, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Host=", json, StringComparison.Ordinal);
        }
    }

    // F-01 - контрольована 500 має ті самі security headers, що й звичайні відповіді
    [Fact]
    public async Task F01_UnexpectedError_KeepsSecurityHeaders()
    {
        // Недосяжна БД на 54399, як у production.sh broken
        using var broken = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("ConnectionStrings:SecureLab",
                "Host=127.0.0.1;Port=54399;Database=securelab;Username=securelab;"
                + "Password=unreachable-study-value;Include Error Detail=false;Timeout=2");
        });
        using var client = broken.CreateClient();

        using var response = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = "NotARealPassword1!" });

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.Contains("frame-ancestors 'none'",
            response.Headers.GetValues("Content-Security-Policy").Single(), StringComparison.Ordinal);
    }
}
