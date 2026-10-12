using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace SecureLab.Api.Tests;

public sealed class Lab03RateLimitTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static readonly TimeSpan Window = TimeSpan.FromSeconds(2);

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // Окремий host зі своїм лічильником - 3 спроби за 2 секунди замість 5 за 60
    private WebApplicationFactory<Program> FreshHost(CapturingLoggerProvider? logs = null) =>
        factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration(config => config.AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["LoginRateLimit:PermitLimit"] = "3",
                    ["LoginRateLimit:WindowSeconds"] = Window.TotalSeconds.ToString()
                }));
            if (logs is not null)
                builder.ConfigureLogging(logging => logging.AddProvider(logs));
        });

    private static HttpClient HttpsClient(WebApplicationFactory<Program> host) =>
        host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false
        });

    // Rate limit - після ліміту 429 і для чужого, і для неіснуючого імені, після вікна знову 401
    [Fact]
    public async Task Login_TooManyAttempts_Returns429_ThenRecovers()
    {
        using var host = FreshHost();
        using var client = HttpsClient(host);
        var wrong = new { userName = "alice", password = "Wrong-" + Guid.NewGuid().ToString("N") };

        for (var i = 0; i < 3; i++)
        {
            using var attempt = await client.PostAsJsonAsync("/api/auth/login", wrong);
            Assert.Equal(HttpStatusCode.Unauthorized, attempt.StatusCode);
        }

        using var limited = await client.PostAsJsonAsync("/api/auth/login", wrong);
        using var limitedUnknown = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "nobody" + Guid.NewGuid().ToString("N")[..8], password = wrong.password });
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, limitedUnknown.StatusCode);

        await Task.Delay(Window + TimeSpan.FromMilliseconds(500));
        using var recovered = await client.PostAsJsonAsync("/api/auth/login", wrong);
        Assert.Equal(HttpStatusCode.Unauthorized, recovered.StatusCode);
    }

    // Події - є записи success, failure і rate-limited, але без пароля та імені з форми
    [Fact]
    public async Task AuthEvents_AreLogged_WithoutCredentials()
    {
        var logs = new CapturingLoggerProvider();
        using var host = FreshHost(logs);
        using var client = HttpsClient(host);
        var wrongPassword = "Wrong-" + Guid.NewGuid().ToString("N");
        var unknownUser = "nobody" + Guid.NewGuid().ToString("N")[..8];

        using var success = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = StudyPassword });
        using var failure = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = unknownUser, password = wrongPassword });
        using var third = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = unknownUser, password = wrongPassword });
        using var limited = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = unknownUser, password = wrongPassword });
        Assert.Equal(HttpStatusCode.NoContent, success.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);

        var events = logs.Messages.Where(message => message.StartsWith("Auth event", StringComparison.Ordinal)).ToArray();
        Assert.Contains(events, message => message.Contains("result success", StringComparison.Ordinal));
        Assert.Contains(events, message => message.Contains("result failure", StringComparison.Ordinal));
        Assert.Contains(events, message => message.Contains("result rate-limited", StringComparison.Ordinal));
        // Перевірка без друку значень - у failure потрапить лише текст пояснення
        Assert.False(logs.Messages.Any(message => message.Contains(StudyPassword, StringComparison.Ordinal)),
            "Навчальний пароль потрапив у журнал");
        Assert.False(logs.Messages.Any(message => message.Contains(wrongPassword, StringComparison.Ordinal)),
            "Хибний пароль потрапив у журнал");
        Assert.False(events.Any(message => message.Contains(unknownUser, StringComparison.Ordinal)),
            "Введене ім'я потрапило в подію невдалого входу");
    }

    // Простий провайдер, що збирає відформатовані повідомлення журналу в пам'ять
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
