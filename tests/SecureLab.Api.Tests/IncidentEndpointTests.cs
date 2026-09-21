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

    [Fact]
    public async Task GetList_ReturnsSeededIncidents()
    {
        var incidents = await _client.GetFromJsonAsync<List<IncidentListItemResponse>>(
            "/api/incidents");

        Assert.NotNull(incidents);
        Assert.Contains(incidents, incident => incident.Id == DbSeeder.AliceIncidentId);
        Assert.Contains(incidents, incident => incident.Id == DbSeeder.BobIncidentId);
    }

    [Fact]
    public async Task GetDetails_ForUnknownId_ReturnsProblemDetails404()
    {
        using var response = await _client.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task GetDetails_DoesNotExposeInternalOwnerFields()
    {
        using var response = await _client.GetAsync(
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
        using var response = await _client.GetAsync("/api/incidents/severity-summary");
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
        Assert.Equal([1, 1, 1, 0], summary.Select(item => item.Count));
    }

    [Fact]
    public async Task GetSeveritySummary_WithStatusFilter_CountsOnlyMatchingIncidents()
    {
        var summary = await _client.GetFromJsonAsync<List<IncidentSeveritySummaryResponse>>(
            "/api/incidents/severity-summary?status=Triaged");

        Assert.NotNull(summary);
        Assert.Equal([0, 1, 0, 0], summary.Select(item => item.Count));
    }

    [Fact]
    public async Task GetSeveritySummary_WithNoMatchingStatus_ReturnsZeroGroups()
    {
        var summary = await _client.GetFromJsonAsync<List<IncidentSeveritySummaryResponse>>(
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
        using var response = await _client.GetAsync(url);

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
