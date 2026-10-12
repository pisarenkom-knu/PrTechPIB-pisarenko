using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

// Поглиблення - втрата чинності старого сеансу після серверної події.
// Подія - UpdateSecurityStampAsync (наприклад, після зміни пароля чи примусового виходу).
// Момент перевірки - SecurityStampValidator, за замовчуванням не частіше ніж раз на 30 хвилин
public sealed class Lab03SessionRevocationTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    // Окремий host, у якому stamp перевіряється на кожному запиті
    private WebApplicationFactory<Program> HostWithInterval(TimeSpan interval) =>
        factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.Configure<SecurityStampValidatorOptions>(options => options.ValidationInterval = interval)));

    // Інтервал 0 - стара cookie того самого клієнта після зміни stamp дає 401
    [Fact]
    public async Task StampChanged_WithZeroInterval_OldCookieReturns401()
    {
        using var host = HostWithInterval(TimeSpan.Zero);
        var userName = "rev" + Guid.NewGuid().ToString("N")[..8];
        using var client = await RegisterAndLoginAsync(host, userName);

        try
        {
            using var before = await client.GetAsync("/api/me");
            Assert.Equal(HttpStatusCode.OK, before.StatusCode);

            await UpdateStampAsync(host, userName);

            using var after = await client.GetAsync("/api/me");
            Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
        }
        finally
        {
            await DeleteUserAsync(host, userName);
        }
    }

    // Межа стандартного профілю - з інтервалом 30 хвилин та сама cookie ще діє одразу після зміни stamp
    [Fact]
    public async Task StampChanged_WithDefaultInterval_OldCookieStillValidUntilNextCheck()
    {
        using var host = HostWithInterval(TimeSpan.FromMinutes(30));
        var userName = "rev" + Guid.NewGuid().ToString("N")[..8];
        using var client = await RegisterAndLoginAsync(host, userName);

        try
        {
            await UpdateStampAsync(host, userName);

            using var after = await client.GetAsync("/api/me");
            Assert.Equal(HttpStatusCode.OK, after.StatusCode);
        }
        finally
        {
            await DeleteUserAsync(host, userName);
        }
    }

    // Окремий штучний акаунт з одноразовим паролем, seed-акаунти не змінюються
    private static async Task<HttpClient> RegisterAndLoginAsync(WebApplicationFactory<Program> host, string userName)
    {
        var password = "Aa1-" + Guid.NewGuid().ToString("N");
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true
        });
        using var register = await client.PostAsJsonAsync("/api/auth/register",
            new { userName, email = $"{userName}@example.test", displayName = "Перевірка сеансу", password });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);
        using var login = await client.PostAsJsonAsync("/api/auth/login", new { userName, password });
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        return client;
    }

    private static async Task UpdateStampAsync(WebApplicationFactory<Program> host, string userName)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByNameAsync(userName)
            ?? throw new InvalidOperationException("Штучний акаунт не знайдено.");
        var result = await users.UpdateSecurityStampAsync(user);
        Assert.True(result.Succeeded);
    }

    private static async Task DeleteUserAsync(WebApplicationFactory<Program> host, string userName)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByNameAsync(userName);
        if (user is not null)
            await users.DeleteAsync(user);
    }
}
