using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace SecureLab.Api.Tests;

public sealed class SecureLabApiFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        // У test host усі клієнти мають RemoteIpAddress=null і спільний ключ ліміту.
        // Функціональні тести не мають ловити 429, ліміт перевіряє окремий host у Lab03RateLimitTests
        builder.ConfigureAppConfiguration(config => config.AddInMemoryCollection(
            new Dictionary<string, string?> { ["LoginRateLimit:PermitLimit"] = "1000" }));
    }
}
