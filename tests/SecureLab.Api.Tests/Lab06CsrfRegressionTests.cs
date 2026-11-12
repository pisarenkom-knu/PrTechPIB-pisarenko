using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

// ЛР 6 - REG-CSRF-01 і периметр cookie-authenticated mutations, header навмисно не глобальний
public sealed class Lab06CsrfRegressionTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private const string HeaderName = "X-CSRF-TOKEN";

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // REG-CSRF-01 - вхід і cookie-сеанс, відмова без токена, незмінний стан, токен, зміна, змінений стан
    [Fact]
    public async Task RegCsrf01_UpdateWithoutToken_IsRejected_StateUnchanged_ThenTokenSucceeds()
    {
        var id = await CreateOwnIncidentAsync("REG-CSRF-01");
        try
        {
            // Той самий клієнт грає роль одного браузера Alice
            using var alice = await factory.LoginAsync("alice", StudyPassword);
            var before = await alice.GetFromJsonAsync<IncidentDetailsResponse>($"/api/incidents/{id}");
            Assert.Equal("Опис до REG-CSRF-01", before!.Description);

            using var rejected = await alice.PutAsJsonAsync($"/api/incidents/{id}",
                new { title = before.Title, description = "Змінено без токена" });
            await AssertAntiforgeryRejectionAsync(rejected);
            var afterRejected = await alice.GetFromJsonAsync<IncidentDetailsResponse>($"/api/incidents/{id}");
            Assert.Equal(before.Description, afterRejected!.Description);

            await alice.UseAntiforgeryTokenAsync();
            using var accepted = await alice.PutAsJsonAsync($"/api/incidents/{id}",
                new { title = before.Title, description = "Змінено з токеном" });
            Assert.Equal(HttpStatusCode.NoContent, accepted.StatusCode);
            var afterAccepted = await alice.GetFromJsonAsync<IncidentDetailsResponse>($"/api/incidents/{id}");
            Assert.Equal("Змінено з токеном", afterAccepted!.Description);
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // Невалідне значення і токен іншого користувача дають той самий 400 без зміни стану
    [Fact]
    public async Task Update_WithInvalidOrForeignToken_IsRejected_AndStateUnchanged()
    {
        var id = await CreateOwnIncidentAsync("invalid-token");
        try
        {
            using var alice = await factory.LoginAsync("alice", StudyPassword);
            using var bob = await factory.LoginAsync("bob", StudyPassword);
            await bob.UseAntiforgeryTokenAsync();
            var bobToken = bob.DefaultRequestHeaders.GetValues(HeaderName).Single();
            // Alice одержує власну antiforgery cookie, але надсилає чужий або вигаданий request token
            await alice.UseAntiforgeryTokenAsync();

            foreach (var value in new[] { "invalid-test-value", bobToken })
            {
                alice.DefaultRequestHeaders.Remove(HeaderName);
                alice.DefaultRequestHeaders.Add(HeaderName, value);
                using var response = await alice.PutAsJsonAsync($"/api/incidents/{id}",
                    new { title = "REG invalid-token", description = "Не має змінитися" });
                await AssertAntiforgeryRejectionAsync(response);
            }

            var after = await alice.GetFromJsonAsync<IncidentDetailsResponse>($"/api/incidents/{id}");
            Assert.Equal("Опис до invalid-token", after!.Description);
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // Увесь периметр - кожна mutation без токена дає той самий 400, ресурс і сеанс лишаються
    [Fact]
    public async Task Perimeter_EveryCookieMutationWithoutToken_IsRejected()
    {
        var id = await CreateOwnIncidentAsync("perimeter");
        try
        {
            using var alice = await factory.LoginAsync("alice", StudyPassword);
            using var morgan = await factory.LoginAsync("morgan", StudyPassword);
            var titlesBefore = await CountTitleAsync("REG perimeter create");

            await AssertAntiforgeryRejectionAsync(await alice.PostAsJsonAsync("/api/incidents", new
            {
                title = "REG perimeter create", description = "Не має створитися.",
                severity = "Low", occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5)
            }));
            await AssertAntiforgeryRejectionAsync(await alice.PutAsJsonAsync($"/api/incidents/{id}",
                new { title = "REG perimeter", description = "Не має змінитися" }));
            await AssertAntiforgeryRejectionAsync(await alice.DeleteAsync($"/api/incidents/{id}"));
            await AssertAntiforgeryRejectionAsync(await morgan.PostAsync($"/api/incidents/{id}/triage", null));
            await AssertAntiforgeryRejectionAsync(await alice.PostAsync("/api/auth/logout", null));

            Assert.Equal(titlesBefore, await CountTitleAsync("REG perimeter create"));
            var after = await alice.GetFromJsonAsync<IncidentDetailsResponse>($"/api/incidents/{id}");
            Assert.Equal("Опис до perimeter", after!.Description);
            Assert.Equal("New", after.Status);
            // Logout без токена не завершив сеанс
            using var me = await alice.GetAsync("/api/me");
            Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // F-02 - triage звичайною HTML-формою з іншого origin, лише cookie без request token
    [Fact]
    public async Task F02_TriageAsSimpleFormPost_WithoutToken_IsRejected_AndStatusStaysNew()
    {
        var id = await CreateOwnIncidentAsync("F-02");
        try
        {
            using var morgan = await factory.LoginAsync("morgan", StudyPassword);
            using var request = new HttpRequestMessage(HttpMethod.Post, $"/api/incidents/{id}/triage")
            {
                Content = new FormUrlEncodedContent([])
            };
            request.Headers.Add("Origin", "http://localhost:4175");

            using var response = await morgan.SendAsync(request);

            await AssertAntiforgeryRejectionAsync(response);
            var after = await morgan.GetFromJsonAsync<IncidentDetailsResponse>($"/api/incidents/{id}");
            Assert.Equal("New", after!.Status);
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // Один точний contract відмови - 400 Problem Details без errors валідації DTO
    private static async Task AssertAntiforgeryRejectionAsync(HttpResponseMessage response)
    {
        using (response)
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.Equal("Antiforgery token відсутній або недійсний.",
                document.RootElement.GetProperty("title").GetString());
            Assert.False(document.RootElement.TryGetProperty("errors", out _));
        }
    }

    // Підготовка окремим сеансом Alice з токеном, щоб основний клієнт тесту лишався без header
    private async Task<Guid> CreateOwnIncidentAsync(string marker)
    {
        using var setup = await factory.LoginAsync("alice", StudyPassword);
        await setup.UseAntiforgeryTokenAsync();
        using var response = await setup.PostAsJsonAsync("/api/incidents", new
        {
            title = $"REG {marker} {Guid.NewGuid():N}"[..40],
            description = $"Опис до {marker}",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<CreatedIncidentResponse>())!.Id;
    }

    private async Task<int> CountTitleAsync(string title)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return await db.Incidents.CountAsync(item => item.Title == title);
    }

    private async Task DeleteIncidentAsync(Guid id)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.IncidentStatusHistory.Where(item => item.IncidentId == id).ExecuteDeleteAsync();
        await db.Incidents.Where(item => item.Id == id).ExecuteDeleteAsync();
    }
}
