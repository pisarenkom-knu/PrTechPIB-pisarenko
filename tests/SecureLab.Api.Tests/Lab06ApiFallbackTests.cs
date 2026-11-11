using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

// ЛР 6, F-03 - API fallback не має маскувати наявний маршрут під 404
public sealed class Lab06ApiFallbackTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private const string Incident = "/api/incidents/20000000-0000-0000-0000-000000000005";

    private HttpClient Anonymous() => factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false
    });

    // Наявний шлях з непідтримуваним методом - 405 з Allow, а не 404
    [Theory]
    [InlineData("PATCH", Incident, "DELETE, GET, PUT")]
    [InlineData("GET", "/api/auth/login", "POST")]
    [InlineData("DELETE", "/api/incidents", "GET, POST")]
    public async Task F03_KnownRouteWithWrongMethod_Returns405WithAllow(string method, string url, string allow)
    {
        using var client = Anonymous();

        using var response = await client.SendAsync(new HttpRequestMessage(new HttpMethod(method), url));

        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(allow, string.Join(", ", response.Content.Headers.Allow.Order(StringComparer.Ordinal)));
    }

    // JSON-маршрут з іншим Content-Type - 415, навіть для аноніма, а не 404 «ресурс не знайдено»
    [Theory]
    [InlineData("POST", "/api/auth/login")]
    [InlineData("POST", "/api/auth/register")]
    [InlineData("PUT", Incident)]
    public async Task F03_KnownJsonRouteWithWrongContentType_Returns415(string method, string url)
    {
        using var client = Anonymous();
        using var request = new HttpRequestMessage(new HttpMethod(method), url)
        {
            Content = new StringContent("{\"userName\":\"alice\"}", Encoding.UTF8, "text/plain")
        };

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    // Позитивна регресія - справді невідомі шляхи й невалідний guid лишаються 404, JSON-запит працює
    [Theory]
    [InlineData("GET", "/api/nope")]
    [InlineData("POST", "/api/nope")]
    [InlineData("PUT", "/api/incidents/not-a-guid")]
    [InlineData("GET", "/api/incidents/abc")]
    public async Task F03_UnknownApiRoute_StillReturnsProblemDetails404(string method, string url)
    {
        using var client = Anonymous();

        using var response = await client.SendAsync(new HttpRequestMessage(new HttpMethod(method), url));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("Ресурс API не знайдено", document.RootElement.GetProperty("title").GetString());
    }

    [Fact]
    public async Task F03_JsonLoginWithWrongPassword_StillReturns401()
    {
        using var client = Anonymous();

        using var response = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = "Wrong-" + Guid.NewGuid().ToString("N") });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
