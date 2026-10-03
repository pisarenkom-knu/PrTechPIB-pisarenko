using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

public sealed class Lab02ContractTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static readonly Guid UsbIncidentId = Guid.Parse("20000000-0000-0000-0000-000000000005");

    private readonly HttpClient _client = factory.CreateClient();

    // T-02 - некоректний DTO дає 400 з ключами полів і без внутрішніх деталей
    [Fact]
    public async Task Post_WithInvalidFields_Returns400WithFieldKeys()
    {
        var body = new { title = "   ", description = "Опис є.", severity = "7" };

        using var response = await _client.PostAsJsonAsync("/api/incidents", body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        var errors = document.RootElement.GetProperty("errors");
        Assert.True(errors.TryGetProperty("title", out _));
        Assert.True(errors.TryGetProperty("severity", out _));
        Assert.True(errors.TryGetProperty("occurredAtUtc", out _));
        Assert.DoesNotContain("Exception", json, StringComparison.Ordinal);
        Assert.DoesNotContain("SELECT", json, StringComparison.OrdinalIgnoreCase);
    }

    // T-03 - другий активний інцидент з тим самим title дає 409
    [Fact]
    public async Task Post_DuplicateActiveTitle_Returns409()
    {
        var title = $"Regression-{Guid.NewGuid():N}";
        var body = new
        {
            title,
            description = "Штучний запис для перевірки конфлікту.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };

        try
        {
            using var first = await _client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);

            using var second = await _client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
            Assert.Equal("application/problem+json", second.Content.Headers.ContentType?.MediaType);
            var json = await second.Content.ReadAsStringAsync();
            Assert.DoesNotContain("Exception", json, StringComparison.Ordinal);
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    // S-02 - контрольний ввід після виправлення не повертає жодного запису
    [Fact]
    public async Task Search_WithControlInput_ReturnsEmptySet()
    {
        var items = await SearchAsync("zz-no-match' OR TRUE -- ");

        Assert.Empty(items);
    }

    // S-02 позитивний контроль - пошук не став надто суворим
    [Fact]
    public async Task Search_ForUsb_ReturnsExactlyOneSeedIncident()
    {
        var items = await SearchAsync("USB");

        var item = Assert.Single(items);
        Assert.Equal(UsbIncidentId, item.Id);
    }

    // T-04 - легітимний апостроф шукається як звичайний текст
    [Fact]
    public async Task Search_WithApostrophe_ReturnsOnlyMatchingIncident()
    {
        var items = await SearchAsync("O'Brien");

        var item = Assert.Single(items);
        Assert.Equal("O'Brien classroom report", item.Title);
    }

    // T-05 - sortBy поза allowlist дає 400 з ключем sortBy
    [Fact]
    public async Task Search_WithUnknownSortBy_Returns400()
    {
        using var response = await _client.GetAsync("/api/incidents/search?sortBy=price");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        Assert.True(document.RootElement.GetProperty("errors").TryGetProperty("sortBy", out _));
    }

    // A-02 - зайві server-managed поля в JSON ігноруються
    [Fact]
    public async Task Post_WithServerManagedFields_IgnoresThem()
    {
        var title = $"Overposting-{Guid.NewGuid():N}";
        var forgedId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var body = new
        {
            title,
            description = "Клієнт намагається задати службові поля.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
            id = forgedId,
            ownerUserId = DbSeeder.BobId,
            status = "Closed",
            createdAtUtc = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero)
        };

        try
        {
            using var response = await _client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            Assert.NotNull(response.Headers.Location);

            var details = await _client.GetFromJsonAsync<IncidentDetailsResponse>(
                response.Headers.Location);
            Assert.NotNull(details);
            Assert.NotEqual(forgedId, details.Id);
            Assert.Equal("New", details.Status);
            Assert.Equal("Аліса Коваль", details.OwnerDisplayName);
            Assert.True(details.CreatedAtUtc > DateTimeOffset.UtcNow.AddMinutes(-5));
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    private async Task<List<IncidentSearchItemResponse>> SearchAsync(string q)
    {
        var items = await _client.GetFromJsonAsync<List<IncidentSearchItemResponse>>(
            "/api/incidents/search?q=" + Uri.EscapeDataString(q));
        Assert.NotNull(items);
        return items;
    }

    private async Task DeleteByTitleAsync(string title)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(item => item.Title == title).ExecuteDeleteAsync();
    }
}
