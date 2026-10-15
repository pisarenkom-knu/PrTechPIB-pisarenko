using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

// ЛР 4 - матриця доступу Incident через HTTP boundary, політика 404 для чужого ресурсу
public sealed class Lab04AuthorizationTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static readonly Guid AliceNewIncidentId = Guid.Parse("20000000-0000-0000-0000-000000000003");
    private static readonly Guid BobSearchIncidentId = Guid.Parse("20000000-0000-0000-0000-000000000004");
    private static readonly Guid BobCommentId = Guid.Parse("30000000-0000-0000-0000-000000000002");
    private static readonly Guid InternalCommentId = Guid.Parse("30000000-0000-0000-0000-000000000003");

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // A-01 - анонім одержує 401 Problem Details, а не HTML redirect
    [Theory]
    [InlineData("GET", "/api/incidents/20000000-0000-0000-0000-000000000001")]
    [InlineData("GET", "/api/incidents")]
    [InlineData("GET", "/api/incidents/search?q=O'Brien")]
    [InlineData("GET", "/api/incidents/severity-summary")]
    [InlineData("GET", "/api/incident-comments/30000000-0000-0000-0000-000000000001")]
    [InlineData("POST", "/api/incidents/20000000-0000-0000-0000-000000000003/triage")]
    public async Task A01_Anonymous_Returns401_NotRedirect(string method, string url)
    {
        using var anonymous = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        using var response = await anonymous.SendAsync(new HttpRequestMessage(new HttpMethod(method), url));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.NotEqual("text/html", response.Content.Headers.ContentType?.MediaType);
    }

    // A-02 - власник читає власний інцидент
    [Fact]
    public async Task A02_Details_AsOwner_ReturnsOwnIncident()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        var details = await alice.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.NotNull(details);
        Assert.Equal(DbSeeder.AliceIncidentId, details.Id);
        Assert.Equal("Аліса Коваль", details.OwnerDisplayName);
    }

    // A-03 - інший Reporter одержує 404 без даних Bob
    [Fact]
    public async Task A03_Details_AsNonOwner_ReturnsNotFound_WithoutForeignData()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var response = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain("Боб Мельник", body, StringComparison.Ordinal);
        Assert.DoesNotContain(DbSeeder.BobIncidentId.ToString(), body, StringComparison.Ordinal);
    }

    // A-03R - Analyst читає чужий інцидент для аналізу разом з internal comment
    [Fact]
    public async Task A03R_Details_AsAnalyst_ReturnsIncidentWithInternalComment()
    {
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);

        var details = await morgan.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.NotNull(details);
        Assert.Equal("Аліса Коваль", details.OwnerDisplayName);
        Assert.Contains(details.Comments, comment => comment.Id == InternalCommentId);
    }

    // A-04 - update і delete чужого ресурсу дають 404 і не змінюють стан Bob
    [Fact]
    public async Task A04_UpdateAndDelete_AsNonOwner_ReturnNotFound_AndDoNotChangeResource()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var bob = await factory.LoginAsync("bob", StudyPassword);
        var before = await bob.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.BobIncidentId}");

        using var update = await alice.PutAsJsonAsync($"/api/incidents/{DbSeeder.BobIncidentId}",
            new { title = "Змінено Alice", description = "Опис інциденту Bob замінено чужим користувачем." });
        using var delete = await alice.DeleteAsync($"/api/incidents/{BobSearchIncidentId}");

        Assert.Equal(HttpStatusCode.NotFound, update.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, delete.StatusCode);
        // Стан читає власник, бо Alice цього ресурсу не бачить
        var after = await bob.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.BobIncidentId}");
        Assert.Equal(before!.Title, after!.Title);
        Assert.Equal(before.Description, after.Description);
        using var stillExists = await bob.GetAsync($"/api/incidents/{BobSearchIncidentId}");
        Assert.Equal(HttpStatusCode.OK, stillExists.StatusCode);
    }

    // A-04 - Analyst бачить інцидент, але content update йому не дозволено, тому 403
    [Fact]
    public async Task A04_Update_AsAnalyst_ReturnsForbidden_AndDoesNotChangeResource()
    {
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);
        var before = await morgan.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");

        using var update = await morgan.PutAsJsonAsync($"/api/incidents/{DbSeeder.AliceIncidentId}",
            new { title = "Змінено Morgan", description = "Аналітик не редагує чужий content." });

        Assert.Equal(HttpStatusCode.Forbidden, update.StatusCode);
        var after = await morgan.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.Equal(before!.Title, after!.Title);
    }

    // A-05 - список Alice не містить жодного запису Bob
    [Fact]
    public async Task A05_List_AsReporter_ReturnsOnlyOwnIncidents()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        var items = await alice.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");

        Assert.NotNull(items);
        Assert.Contains(items, item => item.Id == DbSeeder.AliceIncidentId);
        Assert.DoesNotContain(items, item => item.Id == DbSeeder.BobIncidentId || item.Id == BobSearchIncidentId);
    }

    // A-06 - Reporter не виконує privileged transition навіть для власного New
    [Fact]
    public async Task A06_Triage_AsReporter_ReturnsForbidden_AndStatusUnchanged()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        var before = await alice.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{AliceNewIncidentId}");

        using var response = await alice.PostAsync($"/api/incidents/{AliceNewIncidentId}/triage", content: null);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var after = await alice.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{AliceNewIncidentId}");
        Assert.Equal(before!.Status, after!.Status);
    }

    // A-07 - Analyst переводить New -> Triaged, наступний статус визначає сервер, повтор дає 409
    [Fact]
    public async Task A07_Triage_AsAnalyst_MovesNewToTriaged_ThenConflict()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);
        var id = await CreateIncidentAsync(alice, $"Triage-{Guid.NewGuid():N}");

        try
        {
            using var triage = await morgan.PostAsync($"/api/incidents/{id}/triage", content: null);
            Assert.Equal(HttpStatusCode.NoContent, triage.StatusCode);

            var after = await morgan.GetFromJsonAsync<IncidentDetailsResponse>($"/api/incidents/{id}");
            Assert.Equal("Triaged", after!.Status);

            using var repeat = await morgan.PostAsync($"/api/incidents/{id}/triage", content: null);
            Assert.Equal(HttpStatusCode.Conflict, repeat.StatusCode);
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // A-08a - DTO update ігнорує status, ownerUserId і role, змінюється лише content
    [Fact]
    public async Task A08a_Update_WithForgedServerFields_ChangesOnlyContent()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        var id = await CreateIncidentAsync(alice, $"Overposting-{Guid.NewGuid():N}");

        try
        {
            using var update = await alice.PutAsJsonAsync($"/api/incidents/{id}", new
            {
                title = "Власний запис Alice",
                description = "Звичайне редагування власного інциденту.",
                status = "Closed",
                ownerUserId = DbSeeder.BobId,
                role = "Analyst"
            });
            Assert.Equal(HttpStatusCode.NoContent, update.StatusCode);

            var after = await alice.GetFromJsonAsync<IncidentDetailsResponse>($"/api/incidents/{id}");
            Assert.Equal("Власний запис Alice", after!.Title);
            Assert.Equal("New", after.Status);
            Assert.Equal("Аліса Коваль", after.OwnerDisplayName);

            // Позитивна регресія delete - власник видаляє власний New
            using var delete = await alice.DeleteAsync($"/api/incidents/{id}");
            Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);
            using var gone = await alice.GetAsync($"/api/incidents/{id}");
            Assert.Equal(HttpStatusCode.NotFound, gone.StatusCode);
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // A-09 - відмова triage дає audit-подію без секретів і з тим самим traceId, що у відповіді
    [Fact]
    public async Task A09_DeniedTriage_WritesSafeAuditEvent_WithResponseTraceId()
    {
        var logs = new CapturingLoggerProvider();
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureLogging(logging => logging.AddProvider(logs)));
        using var alice = await LoginAsync(host, "alice");

        using var response = await alice.PostAsync($"/api/incidents/{AliceNewIncidentId}/triage", content: null);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        var traceId = body!["traceId"]!.GetValue<string>();

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var audit = Assert.Single(logs.Messages, message =>
            message.StartsWith("authorization.denied", StringComparison.Ordinal));
        Assert.Contains($"subject={DbSeeder.AliceId}", audit, StringComparison.Ordinal);
        Assert.Contains("action=incident.triage", audit, StringComparison.Ordinal);
        Assert.Contains($"resource={AliceNewIncidentId}", audit, StringComparison.Ordinal);
        Assert.Contains("result=denied", audit, StringComparison.Ordinal);
        Assert.Contains($"traceId={traceId}", audit, StringComparison.Ordinal);
        Assert.False(audit.Contains(StudyPassword, StringComparison.Ordinal), "Пароль потрапив в audit");
        Assert.DoesNotContain("AspNetCore.Identity", audit, StringComparison.Ordinal);
    }

    // A-10 - відповідь для чужого й неіснуючого id однакова, крім traceId
    [Fact]
    public async Task A10_ForeignAndUnknownId_ReturnSame404()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var foreign = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        using var unknown = await alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        Assert.Equal(unknown.StatusCode, foreign.StatusCode);
        Assert.Equal(
            unknown.Content.Headers.ContentType?.ToString(),
            foreign.Content.Headers.ContentType?.ToString());
        var foreignBody = await foreign.Content.ReadFromJsonAsync<JsonObject>();
        var unknownBody = await unknown.Content.ReadFromJsonAsync<JsonObject>();
        foreignBody!.Remove("traceId");
        unknownBody!.Remove("traceId");
        Assert.True(JsonNode.DeepEquals(unknownBody, foreignBody));
    }

    // A-11 - search і severity-summary з ЛР 1-2 обмежені множиною Alice
    [Fact]
    public async Task A11_SearchAndSummary_AsReporter_ExcludeForeignIncidents()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);

        var aliceSearch = await alice.GetFromJsonAsync<List<IncidentSearchItemResponse>>(
            "/api/incidents/search?q=" + Uri.EscapeDataString("O'Brien"));
        var morganSearch = await morgan.GetFromJsonAsync<List<IncidentSearchItemResponse>>(
            "/api/incidents/search?q=" + Uri.EscapeDataString("O'Brien"));
        var aliceSummary = await alice.GetFromJsonAsync<List<IncidentSeveritySummaryResponse>>(
            "/api/incidents/severity-summary");

        Assert.Empty(aliceSearch!);
        Assert.Contains(morganSearch!, item => item.Id == BobSearchIncidentId);
        // Єдиний High у seed належить Bob
        Assert.Equal(0, aliceSummary!.Single(item => item.Severity == "High").Count);
        Assert.Equal(1, aliceSummary!.Single(item => item.Severity == "Medium").Count);
    }

    // A-12 - коментар через parent і internal comment закриті для Reporter
    [Fact]
    public async Task A12_ChildComments_AsReporter_FollowParentAndInternalRules()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);

        using var foreignComment = await alice.GetAsync($"/api/incident-comments/{BobCommentId}");
        using var internalComment = await alice.GetAsync($"/api/incident-comments/{InternalCommentId}");
        var ownDetails = await alice.GetFromJsonAsync<IncidentDetailsResponse>(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");
        using var analystInternal = await morgan.GetAsync($"/api/incident-comments/{InternalCommentId}");

        Assert.Equal(HttpStatusCode.NotFound, foreignComment.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, internalComment.StatusCode);
        Assert.DoesNotContain(ownDetails!.Comments, comment => comment.Id == InternalCommentId);
        Assert.Equal(HttpStatusCode.OK, analystInternal.StatusCode);
    }

    private static async Task<Guid> CreateIncidentAsync(HttpClient client, string title)
    {
        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title,
            description = "Штучний запис тесту ЛР 4.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await response.Content.ReadFromJsonAsync<CreatedIncidentResponse>();
        return created!.Id;
    }

    // Прибирання власного запису разом з історією статусів
    private async Task DeleteIncidentAsync(Guid id)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.IncidentStatusHistory.Where(item => item.IncidentId == id).ExecuteDeleteAsync();
        await db.Incidents.Where(item => item.Id == id).ExecuteDeleteAsync();
    }

    private static async Task<HttpClient> LoginAsync(WebApplicationFactory<Program> host, string userName)
    {
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true
        });
        using var response = await client.PostAsJsonAsync("/api/auth/login",
            new { userName, password = StudyPassword });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        return client;
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<string> Messages { get; } = new();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(Messages);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
                Exception? exception, Func<TState, Exception?, string> formatter) =>
                messages.Enqueue(formatter(state, exception));
        }
    }
}
