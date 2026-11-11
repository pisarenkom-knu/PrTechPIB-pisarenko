using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace SecureLab.Api.Tests;

// ЛР 6 - search limiter, partition за id автентифікованого користувача
public sealed class Lab06SearchRateLimitTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static readonly TimeSpan Window = TimeSpan.FromSeconds(2);
    private const string AliceOnlyQuery = "/api/incidents/search?q=" + "Перевірка USB";

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // Окремий host зі своїм лічильником - 3 пошуки за 2 секунди замість 20 за 60
    private WebApplicationFactory<Program> FreshHost(CapturingLoggerProvider logs) =>
        factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration(config => config.AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["SearchRateLimit:PermitLimit"] = "3",
                    ["SearchRateLimit:WindowSeconds"] = Window.TotalSeconds.ToString()
                }));
            builder.ConfigureLogging(logging => logging.AddProvider(logs));
        });

    // Quota, 429, інший partition, маршрут без policy, відновлення після вікна, окрема авторизація
    [Fact]
    public async Task Search_QuotaPerUser_Returns429_OtherUserUnaffected_ThenRecovers()
    {
        var logs = new CapturingLoggerProvider();
        using var host = FreshHost(logs);
        using var alice = await host.LoginAsync("alice", StudyPassword);
        using var bob = await host.LoginAsync("bob", StudyPassword);

        for (var i = 0; i < 3; i++)
        {
            using var allowed = await alice.GetAsync(AliceOnlyQuery);
            Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
            var rows = await allowed.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal(1, rows.GetArrayLength());
        }

        using var limited = await alice.GetAsync(AliceOnlyQuery);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.Equal("application/problem+json", limited.Content.Headers.ContentType?.MediaType);
        Assert.DoesNotContain("Перевірка USB", await limited.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        // Інший partition має власний лічильник, а quota не розширює права - Bob не бачить запис Alice
        using var bobSearch = await bob.GetAsync(AliceOnlyQuery);
        Assert.Equal(HttpStatusCode.OK, bobSearch.StatusCode);
        Assert.Equal(0, (await bobSearch.Content.ReadFromJsonAsync<JsonElement>()).GetArrayLength());

        // Маршрут без policy для того самого користувача не обмежено
        using var list = await alice.GetAsync("/api/incidents");
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);

        await Task.Delay(Window + TimeSpan.FromMilliseconds(700));
        using var recovered = await alice.GetAsync(AliceOnlyQuery);
        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);

        Assert.Contains(logs.Messages, message =>
            message.StartsWith("Rate limit event search: result rate-limited", StringComparison.Ordinal));
        Assert.DoesNotContain(logs.Messages, message =>
            message.StartsWith("Auth event login: result rate-limited", StringComparison.Ordinal));
    }

    // Анонім одержує 401 від авторизації раніше за limiter і не витрачає чужу quota
    [Fact]
    public async Task Search_Anonymous_Returns401_NotRateLimited()
    {
        using var host = FreshHost(new CapturingLoggerProvider());
        using var anonymous = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false
        });

        for (var i = 0; i < 5; i++)
        {
            using var response = await anonymous.GetAsync(AliceOnlyQuery);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
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

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter) => messages.Enqueue(formatter(state, exception));
        }
    }
}
