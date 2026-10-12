using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class Lab03SecurityTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    // Пароль лише зі змінної середовища, у коді й у failure його немає
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // A-01 - анонімне створення дає 401, а не redirect, HTML чи Bearer
    [Fact]
    public async Task A01_AnonymousCreate_Returns401_NotRedirect()
    {
        using var anonymous = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        using var response = await anonymous.PostAsJsonAsync("/api/incidents", NewIncident("A01"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Empty(response.Headers.WwwAuthenticate);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    // A-02 - після login профіль сформовано з principal, без чутливих полів
    [Fact]
    public async Task A02_LoginThenMe_ReturnsVerifiedUser()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var response = await alice.GetAsync("/api/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = document.RootElement;
        Assert.Equal(DbSeeder.AliceId, root.GetProperty("userId").GetGuid());
        Assert.Equal("alice", root.GetProperty("userName").GetString());
        foreach (var forbidden in new[] { "password", "passwordHash", "securityStamp", "cookie", "token" })
            Assert.False(root.TryGetProperty(forbidden, out _), $"Поле {forbidden} не має бути у відповіді");
    }

    // A-03 - чужий X-Demo-UserId не змінює поточного користувача
    [Fact]
    public async Task A03_MeWithForeignHeader_StaysCurrentUser()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("X-Demo-UserId", DbSeeder.BobId.ToString());

        using var response = await alice.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(DbSeeder.AliceId, document.RootElement.GetProperty("userId").GetGuid());
    }

    // A-04 - Bob створює запис без owner, власник береться з principal
    [Fact]
    public async Task A04_CreateWithoutOwner_OwnerIsPrincipal()
    {
        var body = NewIncident("A04");
        using var bob = await factory.LoginAsync("bob", StudyPassword);

        try
        {
            using var response = await bob.PostAsJsonAsync("/api/incidents", body);

            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            Assert.Equal(DbSeeder.BobId, await OwnerOfCreatedAsync(response));
        }
        finally
        {
            await DeleteByTitleAsync(body.Title);
        }
    }

    // A-05 - Bob додає ownerUserId Alice, власником однаково лишається Bob
    [Fact]
    public async Task A05_CreateWithForgedOwner_OwnerStaysPrincipal()
    {
        var title = $"A05-{Guid.NewGuid():N}";
        var body = new
        {
            title,
            description = "Bob намагається створити запис від імені Alice.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
            ownerUserId = DbSeeder.AliceId
        };
        using var bob = await factory.LoginAsync("bob", StudyPassword);

        try
        {
            using var response = await bob.PostAsJsonAsync("/api/incidents", body);

            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            Assert.Equal(DbSeeder.BobId, await OwnerOfCreatedAsync(response));
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    // A-06 - після logout той самий клієнт знову отримує 401
    [Fact]
    public async Task A06_Logout_ThenMe_Returns401()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var before = await alice.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);

        using var logout = await alice.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        using var after = await alice.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    // A-07 - невідомий користувач і хибний пароль мають однаковий зовнішній результат
    [Fact]
    public async Task A07_UnknownUserAndWrongPassword_LookTheSame()
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        // Хибний пароль формується локально
        var wrongPassword = "Wrong-" + Guid.NewGuid().ToString("N");
        var unknownUser = "nobody" + Guid.NewGuid().ToString("N")[..8];

        using var unknown = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = unknownUser, password = wrongPassword });
        using var wrong = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = wrongPassword });

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(unknown.StatusCode, wrong.StatusCode);
        Assert.Equal(unknown.Content.Headers.ContentType?.MediaType, wrong.Content.Headers.ContentType?.MediaType);
        Assert.Equal(await StableShapeAsync(unknown), await StableShapeAsync(wrong));
    }

    private static NewIncidentBody NewIncident(string prefix) => new(
        $"{prefix}-{Guid.NewGuid():N}", "Штучний запис для перевірки власника.", "Low",
        DateTimeOffset.UtcNow.AddMinutes(-10));

    private sealed record NewIncidentBody(
        string Title, string Description, string Severity, DateTimeOffset OccurredAtUtc);

    // Фактичний власник читається з БД за id із відповіді, API це поле не віддає
    private async Task<Guid> OwnerOfCreatedAsync(HttpResponseMessage response)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var id = document.RootElement.GetProperty("id").GetGuid();
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var incident = await db.Incidents.AsNoTracking().SingleAsync(item => item.Id == id);
        return incident.OwnerUserId;
    }

    // Стабільні поля Problem Details - traceId навмисно не порівнюється
    private static async Task<string> StableShapeAsync(HttpResponseMessage response)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = document.RootElement;
        string Field(string name) => root.TryGetProperty(name, out var value) ? value.ToString() : "<none>";
        return string.Join("|", Field("type"), Field("title"), Field("status"), Field("detail"));
    }

    private async Task DeleteByTitleAsync(string title)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(item => item.Title == title).ExecuteDeleteAsync();
    }
}
