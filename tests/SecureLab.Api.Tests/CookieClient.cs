using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public static class CookieClient
{
    // ЛР 6 - базовий тип, щоб входити і через похідний Production host
    public static async Task<HttpClient> LoginAsync(this WebApplicationFactory<Program> factory, string userName, string password)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true
        });
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { userName, password });
        if (!response.IsSuccessStatusCode)
        {
            client.Dispose();
            throw new InvalidOperationException("Study login failed (credentials omitted).");
        }
        return client;
    }

    // ЛР 6 - токен цим самим cookie-клієнтом, header лише для same-origin test host
    public static async Task UseAntiforgeryTokenAsync(this HttpClient client,
        string tokenRoute = "/api/antiforgery/token", string headerName = "X-CSRF-TOKEN")
    {
        client.DefaultRequestHeaders.Remove(headerName);
        using var response = await client.GetAsync(tokenRoute);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<TokenResponse>();
        if (string.IsNullOrWhiteSpace(body?.Token))
            throw new InvalidOperationException("Missing request token.");
        client.DefaultRequestHeaders.Add(headerName, body.Token);
    }

    private sealed record TokenResponse(string Token);
}
