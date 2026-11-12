using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace SecureLab.Api.Tests;

public sealed class SecureLabApiFactory : WebApplicationFactory<Program>
{
    public const string TestAuditKeyId = "test";
    // Не секрет - відомі тестові значення лише для test host, справжні ключі задаються поза Git
    public static readonly string TestAuditKey = Convert.ToBase64String("SecureLab-LR6-test-audit-hmac-key-32B"u8.ToArray());
    public static readonly string TestLoginHashKey = Convert.ToBase64String("SecureLab-LR6-test-login-hash-key-32"u8.ToArray());
    public static readonly string TestAnchorPath = Path.Combine(Path.GetTempPath(), "securelab-tests", "audit-anchor.json");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        // У test host усі клієнти мають RemoteIpAddress=null і спільний ключ ліміту.
        // Функціональні тести не мають ловити 429, ліміт перевіряє окремий host у Lab03RateLimitTests
        builder.ConfigureAppConfiguration(config => config.AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["LoginRateLimit:PermitLimit"] = "1000",
                // ЛР 6 - search limiter перевіряє окремий host у Lab06SearchRateLimitTests
                ["SearchRateLimit:PermitLimit"] = "1000",
                // ЛР 6 - лише тестові ключі аудиту (key id test), окремий якір у тимчасовій теці
                ["AuditLog:KeyId"] = TestAuditKeyId,
                [$"AuditLog:Keys:{TestAuditKeyId}"] = TestAuditKey,
                ["AuditLog:LoginHashKey"] = TestLoginHashKey,
                ["AuditLog:AnchorPath"] = TestAnchorPath
            }));
    }
}
