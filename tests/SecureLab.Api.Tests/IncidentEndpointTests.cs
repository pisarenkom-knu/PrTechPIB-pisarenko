using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Tests;

public sealed class IncidentEndpointTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    // ЛР 4 - група /api/incidents вимагає login, тому тести читають від імені seed-користувачів
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // ЛР 4 A-05 - замість «усі інциденти» список Alice містить лише власні записи
    [Fact]
    public async Task GetList_AsAlice_ReturnsOnlyOwnIncidents()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        var incidents = await alice.GetFromJsonAsync<List<IncidentListItemResponse>>(
            "/api/incidents");

        Assert.NotNull(incidents);
        Assert.Contains(incidents, incident => incident.Id == DbSeeder.AliceIncidentId);
        Assert.DoesNotContain(incidents, incident => incident.Id == DbSeeder.BobIncidentId);
    }

    [Fact]
    public async Task GetDetails_ForUnknownId_ReturnsProblemDetails404()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var response = await alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task GetDetails_DoesNotExposeInternalOwnerFields()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var response = await alice.GetAsync(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(document.RootElement.TryGetProperty("ownerUserId", out _));
        Assert.False(document.RootElement.TryGetProperty("email", out _));
        Assert.Equal("Аліса Коваль", document.RootElement.GetProperty("ownerDisplayName").GetString());
    }

    [Fact]
    public async Task GetSeveritySummary_ReturnsAllLevelsInStableOrder()
    {
        // Analyst бачить усі інциденти, тому лічильники seed не змінюються
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);
        using var response = await morgan.GetAsync("/api/incidents/severity-summary");
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        Assert.All(
            document.RootElement.EnumerateArray(),
            item => Assert.Equal(["severity", "count"], item.EnumerateObject().Select(property => property.Name)));

        var summary = JsonSerializer.Deserialize<List<IncidentSeveritySummaryResponse>>(
            json,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.NotNull(summary);
        Assert.Equal(
            ["Low", "Medium", "High", "Critical"],
            summary.Select(item => item.Severity));
        Assert.Equal([3, 1, 1, 0], summary.Select(item => item.Count));
    }

    [Fact]
    public async Task GetSeveritySummary_WithStatusFilter_CountsOnlyMatchingIncidents()
    {
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);
        var summary = await morgan.GetFromJsonAsync<List<IncidentSeveritySummaryResponse>>(
            "/api/incidents/severity-summary?status=Triaged");

        Assert.NotNull(summary);
        Assert.Equal([0, 1, 0, 0], summary.Select(item => item.Count));
    }

    [Fact]
    public async Task GetSeveritySummary_WithNoMatchingStatus_ReturnsZeroGroups()
    {
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);
        var summary = await morgan.GetFromJsonAsync<List<IncidentSeveritySummaryResponse>>(
            "/api/incidents/severity-summary?status=Resolved");

        Assert.NotNull(summary);
        Assert.All(summary, item => Assert.Equal(0, item.Count));
    }

    [Theory]
    [InlineData("/api/incidents/severity-summary?status=Unknown")]
    [InlineData("/api/incidents/severity-summary?status=1")]
    [InlineData("/api/incidents?status=1")]
    [InlineData("/api/incidents?status=New,Triaged")]
    public async Task InvalidStatus_ReturnsValidationProblem400(string url)
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var response = await alice.GetAsync(url);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task UnknownApiRoute_ReturnsProblemDetails404_NotIndexHtml()
    {
        using var response = await _client.GetAsync("/api/incidents/abc");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task ClientScript_DoesNotUseDangerousInnerHtmlSink()
    {
        var script = await _client.GetStringAsync("/app.js");

        Assert.DoesNotContain("innerHTML", script, StringComparison.Ordinal);
        Assert.Contains("textContent", script, StringComparison.Ordinal);
    }
}
