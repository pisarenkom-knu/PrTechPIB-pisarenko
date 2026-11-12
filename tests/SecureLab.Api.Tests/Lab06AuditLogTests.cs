using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Application.Audit;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

// ЛР 6, advanced variant - tamper-evident журнал security-подій
public sealed class Lab06AuditLogTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static readonly byte[] Key = Convert.FromBase64String(SecureLabApiFactory.TestAuditKey);
    private static readonly IReadOnlyDictionary<string, byte[]> Keys =
        new Dictionary<string, byte[]> { [SecureLabApiFactory.TestAuditKeyId] = Key };

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // Ланцюжок із n записів, підписаний так само, як SecurityAuditLog
    private static List<SecurityAuditEvent> Chain(int count)
    {
        var records = new List<SecurityAuditEvent>();
        var previous = AuditChain.Genesis;
        for (var sequence = 1; sequence <= count; sequence++)
        {
            var record = new SecurityAuditEvent
            {
                Sequence = sequence,
                OccurredAtUtc = AuditChain.TruncateToMicroseconds(DateTimeOffset.UtcNow.AddSeconds(sequence)),
                EventType = sequence % 2 == 0 ? "login" : "csrf.rejected",
                Result = sequence % 2 == 0 ? "success" : "denied",
                SubjectId = "10000000-0000-0000-0000-000000000001",
                TraceId = $"00-{sequence:D32}-{sequence:D16}-00",
                KeyId = SecureLabApiFactory.TestAuditKeyId,
                PreviousHmac = previous,
                Hmac = ""
            };
            record.Hmac = AuditChain.ComputeHmac(record, Key);
            previous = record.Hmac;
            records.Add(record);
        }
        return records;
    }

    private static AuditAnchor AnchorOf(SecurityAuditEvent record) => new(record.Sequence, record.Hmac, record.KeyId);

    [Fact]
    public void Verify_CleanChain_WithMatchingAnchor_IsValid()
    {
        var records = Chain(5);

        var result = AuditChain.Verify(records, AnchorOf(records[^1]), Keys);

        Assert.True(result.IsValid);
        Assert.Empty(result.Warnings);
        Assert.Equal(5, result.LastSequence);
    }

    [Fact]
    public void Verify_ModifiedRecord_IsDetected()
    {
        var records = Chain(5);
        records[2].Result = "success";

        var result = AuditChain.Verify(records, AnchorOf(records[^1]), Keys);

        Assert.Contains(result.Errors, error => error.Contains("sequence 3: HMAC", StringComparison.Ordinal));
    }

    [Fact]
    public void Verify_ForgedRecordSignedWithoutKey_IsDetected()
    {
        var records = Chain(5);
        records[2].Result = "success";
        records[2].Hmac = AuditChain.ComputeHmac(records[2], "attacker-key-without-real-secret"u8.ToArray());

        var result = AuditChain.Verify(records, AnchorOf(records[^1]), Keys);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Verify_DeletedMiddleRecord_IsDetected()
    {
        var records = Chain(5);
        records.RemoveAt(2);

        var result = AuditChain.Verify(records, AnchorOf(records[^1]), Keys);

        Assert.Contains(result.Errors, error => error.Contains("очікувався 3", StringComparison.Ordinal));
    }

    [Fact]
    public void Verify_ReorderedRecords_AreDetected()
    {
        var records = Chain(5);
        (records[1], records[2]) = (records[2], records[1]);

        var result = AuditChain.Verify(records, AnchorOf(records.MaxBy(record => record.Sequence)!), Keys);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Verify_FirstRecordRemoved_SequenceMustStartAtOne()
    {
        var records = Chain(5);
        records.RemoveAt(0);

        var result = AuditChain.Verify(records, AnchorOf(records[^1]), Keys);

        Assert.Contains(result.Errors, error => error.Contains("очікувався 1", StringComparison.Ordinal));
    }

    // Якір попереду БД - обрізання з кінця
    [Fact]
    public void Verify_TruncatedTail_AnchorAhead_IsDetected()
    {
        var records = Chain(5);
        var anchor = AnchorOf(records[^1]);
        records.RemoveRange(3, 2);

        var result = AuditChain.Verify(records, anchor, Keys);

        Assert.Contains(result.Errors, error => error.StartsWith("обрізання", StringComparison.Ordinal));
    }

    [Fact]
    public void Verify_WholeJournalDeleted_WithAnchor_IsDetected()
    {
        var anchor = AnchorOf(Chain(5)[^1]);

        var result = AuditChain.Verify([], anchor, Keys);

        Assert.Contains(result.Errors, error => error.StartsWith("обрізання", StringComparison.Ordinal));
    }

    [Fact]
    public void Verify_MissingAnchor_WithRecords_IsDetected()
    {
        var result = AuditChain.Verify(Chain(3), null, Keys);

        Assert.Contains(result.Errors, error => error.StartsWith("якір відсутній", StringComparison.Ordinal));
    }

    // Якір відстає на один - збій між commit і записом якоря, попередження, а не підміна
    [Fact]
    public void Verify_AnchorBehindByOne_IsWarning()
    {
        var records = Chain(5);

        var result = AuditChain.Verify(records, AnchorOf(records[^2]), Keys);

        Assert.True(result.IsValid);
        Assert.Contains(result.Warnings, warning => warning.StartsWith("якір відстає на один", StringComparison.Ordinal));
    }

    [Fact]
    public void Verify_AnchorBehindByTwo_IsError()
    {
        var records = Chain(5);

        var result = AuditChain.Verify(records, AnchorOf(records[^3]), Keys);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void HashLogin_NormalizesCase_AndDoesNotContainLogin()
    {
        var loginKey = Convert.FromBase64String(SecureLabApiFactory.TestLoginHashKey);

        var first = AuditChain.HashLogin(" Alice ", loginKey);
        var second = AuditChain.HashLogin("alice", loginKey);

        Assert.Equal(first, second);
        Assert.Equal(32, first.Length);
        Assert.DoesNotContain("alice", first, StringComparison.OrdinalIgnoreCase);
    }

    // Реальні події через HTTP - перелік подій, відсутність секретів, цілий сегмент і якір
    [Fact]
    public async Task Requests_WriteExpectedEvents_WithoutSecrets_AndChainVerifies()
    {
        var start = await LastSequenceAsync();
        var wrongPassword = "Wrong-" + Guid.NewGuid().ToString("N");
        var incidentId = await CreateOwnIncidentAsync();
        try
        {
            using var anonymous = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false
            });
            using var failed = await anonymous.PostAsJsonAsync("/api/auth/login",
                new { userName = " Alice ", password = wrongPassword });
            Assert.Equal(HttpStatusCode.Unauthorized, failed.StatusCode);

            using var alice = await factory.LoginAsync("alice", StudyPassword);
            using var csrf = await alice.PostAsync($"/api/incidents/{incidentId}/triage", null);
            Assert.Equal(HttpStatusCode.BadRequest, csrf.StatusCode);
            await alice.UseAntiforgeryTokenAsync();
            using var forbidden = await alice.PostAsync($"/api/incidents/{incidentId}/triage", null);
            Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
            using var foreign = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
            Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);

            using var morgan = await factory.LoginAsync("morgan", StudyPassword);
            await morgan.UseAntiforgeryTokenAsync();
            using var triage = await morgan.PostAsync($"/api/incidents/{incidentId}/triage", null);
            Assert.Equal(HttpStatusCode.NoContent, triage.StatusCode);
            using var logout = await alice.PostAsync("/api/auth/logout", null);
            Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

            var (previous, segment) = await SegmentAfterAsync(start);
            string Event(SecurityAuditEvent record) => $"{record.EventType}:{record.Result}";
            var events = segment.Select(Event).ToList();
            foreach (var expected in new[] { "login:failure", "login:success", "csrf.rejected:denied",
                         "incident.triage:forbidden", "incident.read:hidden", "incident.triage:success", "logout:success" })
                Assert.Contains(expected, events);

            var loginKey = Convert.FromBase64String(SecureLabApiFactory.TestLoginHashKey);
            Assert.Contains(segment, record => record.EventType == "login" && record.Result == "failure"
                && record.LoginHash == AuditChain.HashLogin("alice", loginKey));
            Assert.Contains(segment, record => record.EventType == "incident.read"
                && record.ResourceId == DbSeeder.BobIncidentId.ToString() && record.SubjectId == DbSeeder.AliceId.ToString());
            foreach (var record in segment)
            {
                var text = AuditChain.Canonical(record);
                Assert.DoesNotContain(StudyPassword, text, StringComparison.Ordinal);
                Assert.DoesNotContain(wrongPassword, text, StringComparison.Ordinal);
                Assert.DoesNotContain("alice", text, StringComparison.OrdinalIgnoreCase);
            }

            var anchor = new AuditAnchorStore(SecureLabApiFactory.TestAnchorPath).Read();
            var result = AuditChain.Verify(segment, anchor, Keys, start + 1, previous);
            Assert.True(result.IsValid, string.Join("; ", result.Errors));
        }
        finally
        {
            await DeleteIncidentAsync(incidentId);
        }
    }

    // Паралельний запис - один writer через advisory lock, послідовність без пропусків
    [Fact]
    public async Task ParallelAppends_KeepSequenceContiguous_AndChainValid()
    {
        var start = await LastSequenceAsync();
        const int count = 30;

        await Task.WhenAll(Enumerable.Range(0, count).Select(async index =>
        {
            await using var scope = factory.Services.CreateAsyncScope();
            var audit = scope.ServiceProvider.GetRequiredService<SecurityAuditLog>();
            await audit.AppendAsync(new DefaultHttpContext { TraceIdentifier = $"parallel-{index}" },
                new AuditEntry("test.parallel", "success"), CancellationToken.None);
        }));

        var (previous, segment) = await SegmentAfterAsync(start);
        Assert.Equal(count, segment.Count);
        Assert.Equal(Enumerable.Range(1, count).Select(offset => start + offset), segment.Select(record => record.Sequence));
        var anchor = new AuditAnchorStore(SecureLabApiFactory.TestAnchorPath).Read();
        var result = AuditChain.Verify(segment, anchor, Keys, start + 1, previous);
        Assert.True(result.IsValid, string.Join("; ", result.Errors));
        Assert.Empty(result.Warnings);
    }

    // Fail-closed - без ключа аудиту успішний вхід 503 і без cookie, а невдалий лишається 401
    [Fact]
    public async Task AuditUnavailable_LoginSuccessIs503WithoutCookie_FailureStays401()
    {
        using var host = factory.WithWebHostBuilder(builder => builder.ConfigureAppConfiguration(config =>
            config.AddInMemoryCollection(new Dictionary<string, string?> { ["AuditLog:KeyId"] = "absent" })));
        using var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false
        });

        using var success = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = StudyPassword });
        using var failure = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = "Wrong-" + Guid.NewGuid().ToString("N") });

        Assert.Equal(HttpStatusCode.ServiceUnavailable, success.StatusCode);
        Assert.False(success.Headers.Contains("Set-Cookie"));
        Assert.Equal(HttpStatusCode.Unauthorized, failure.StatusCode);
    }

    // Fail-closed для зміни стану - без запису аудиту статус не змінюється
    [Fact]
    public async Task AuditUnavailable_StateChangeIsNotCommitted()
    {
        var incidentId = await CreateOwnIncidentAsync();
        try
        {
            using var host = factory.WithWebHostBuilder(builder => builder.ConfigureAppConfiguration(config =>
                config.AddInMemoryCollection(new Dictionary<string, string?> { ["AuditLog:KeyId"] = "absent" })));
            await using (var scope = host.Services.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
                var audit = scope.ServiceProvider.GetRequiredService<SecurityAuditLog>();
                var incident = await db.Incidents.SingleAsync(item => item.Id == incidentId);
                incident.Status = IncidentStatus.Triaged;

                await Assert.ThrowsAsync<AuditUnavailableException>(() => audit.AppendWithChangesAsync(db,
                    new DefaultHttpContext(), new AuditEntry("incident.triage", "success"), CancellationToken.None));
            }

            await using var check = factory.Services.CreateAsyncScope();
            var status = await check.ServiceProvider.GetRequiredService<SecureLabDbContext>().Incidents
                .Where(item => item.Id == incidentId).Select(item => item.Status).SingleAsync();
            Assert.Equal(IncidentStatus.New, status);
        }
        finally
        {
            await DeleteIncidentAsync(incidentId);
        }
    }

    private async Task<long> LastSequenceAsync()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return await db.SecurityAuditEvents.Select(record => (long?)record.Sequence).MaxAsync() ?? 0;
    }

    // Записи після start і HMAC запису start як початок сегмента
    private async Task<(string Previous, List<SecurityAuditEvent> Segment)> SegmentAfterAsync(long start)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var previous = start == 0
            ? AuditChain.Genesis
            : await db.SecurityAuditEvents.Where(record => record.Sequence == start).Select(record => record.Hmac).SingleAsync();
        var segment = await db.SecurityAuditEvents.AsNoTracking()
            .Where(record => record.Sequence > start).OrderBy(record => record.Sequence).ToListAsync();
        return (previous, segment);
    }

    private async Task<Guid> CreateOwnIncidentAsync()
    {
        using var setup = await factory.LoginAsync("alice", StudyPassword);
        await setup.UseAntiforgeryTokenAsync();
        using var response = await setup.PostAsJsonAsync("/api/incidents", new
        {
            title = $"AUDIT {Guid.NewGuid():N}"[..30],
            description = "Запис для тесту журналу аудиту.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<CreatedIncidentResponse>())!.Id;
    }

    private async Task DeleteIncidentAsync(Guid id)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.IncidentStatusHistory.Where(item => item.IncidentId == id).ExecuteDeleteAsync();
        await db.Incidents.Where(item => item.Id == id).ExecuteDeleteAsync();
    }
}
