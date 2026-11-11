using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Application.Audit;

// Ключі не зберігаються в Git - AuditLog__Keys__<id>, AuditLog__LoginHashKey, base64 щонайменше 32 байти
public sealed class AuditLogOptions
{
    public string KeyId { get; set; } = "k1";
    public Dictionary<string, string> Keys { get; set; } = [];
    public string? LoginHashKey { get; set; }
    public string? AnchorPath { get; set; }

    public string ResolveAnchorPath() => AnchorPath ?? System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecureLab", "audit-anchor.json");

    public IReadOnlyDictionary<string, byte[]> DecodedKeys() =>
        Keys.ToDictionary(pair => pair.Key, pair => Convert.FromBase64String(pair.Value), StringComparer.Ordinal);
}

public sealed record AuditEntry(string EventType, string Result, string? SubjectId = null, string? ResourceId = null,
    string? LoginHash = null);

public sealed class AuditUnavailableException(string message, Exception? inner = null) : Exception(message, inner);

// ЛР 6, advanced variant - один writer для всіх екземплярів через session-level advisory lock
public sealed class SecurityAuditLog(
    DbContextOptions<SecureLabDbContext> dbOptions,
    AuditLogOptions options,
    ILogger<SecurityAuditLog> logger)
{
    // Довільна стала, однакова для всіх процесів, що пишуть у цю БД
    private const long LockKey = 6_006_001;

    public AuditAnchorStore Anchor { get; } = new(options.ResolveAnchorPath());

    // Подія без зміни бізнес-стану - окремий DbContext, щоб не зберегти чужі pending changes
    public async Task AppendAsync(HttpContext httpContext, AuditEntry entry, CancellationToken cancellationToken)
    {
        await using var dbContext = new SecureLabDbContext(dbOptions);
        await AppendCoreAsync(dbContext, httpContext, entry, cancellationToken);
    }

    // Подія разом зі зміною стану - pending changes dbContext і запис аудиту в одній транзакції
    public Task AppendWithChangesAsync(SecureLabDbContext dbContext, HttpContext httpContext, AuditEntry entry,
        CancellationToken cancellationToken) =>
        AppendCoreAsync(dbContext, httpContext, entry, cancellationToken);

    public string? HashLogin(string? userName)
    {
        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrEmpty(options.LoginHashKey))
            return null;
        return AuditChain.HashLogin(userName, Convert.FromBase64String(options.LoginHashKey));
    }

    public static string? SubjectOf(ClaimsPrincipal user) => user.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    private async Task AppendCoreAsync(SecureLabDbContext dbContext, HttpContext httpContext, AuditEntry entry,
        CancellationToken cancellationToken)
    {
        if (!options.Keys.TryGetValue(options.KeyId, out var encodedKey) || string.IsNullOrEmpty(encodedKey))
            throw new AuditUnavailableException("Ключ журналу аудиту не налаштовано.");
        var key = Convert.FromBase64String(encodedKey);

        SecurityAuditEvent record;
        try
        {
            await dbContext.Database.OpenConnectionAsync(cancellationToken);
            await dbContext.Database.ExecuteSqlRawAsync("SELECT pg_advisory_lock({0})", [LockKey], cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            await dbContext.Database.CloseConnectionAsync();
            throw new AuditUnavailableException("Сховище журналу аудиту недоступне.", exception);
        }

        try
        {
            try
            {
                await using var transaction = await dbContext.Database.BeginTransactionAsync(cancellationToken);
                var last = await dbContext.SecurityAuditEvents.AsNoTracking()
                    .OrderByDescending(item => item.Sequence)
                    .Select(item => new { item.Sequence, item.Hmac })
                    .FirstOrDefaultAsync(cancellationToken);

                record = new SecurityAuditEvent
                {
                    Sequence = (last?.Sequence ?? 0) + 1,
                    OccurredAtUtc = AuditChain.TruncateToMicroseconds(DateTimeOffset.UtcNow),
                    EventType = entry.EventType,
                    Result = entry.Result,
                    SubjectId = entry.SubjectId,
                    ResourceId = entry.ResourceId,
                    LoginHash = entry.LoginHash,
                    TraceId = System.Diagnostics.Activity.Current?.Id ?? httpContext.TraceIdentifier,
                    KeyId = options.KeyId,
                    PreviousHmac = last?.Hmac ?? AuditChain.Genesis,
                    Hmac = ""
                };
                record.Hmac = AuditChain.ComputeHmac(record, key);
                dbContext.SecurityAuditEvents.Add(record);

                // Спершу commit у БД разом зі зміною стану, якщо вона є
                await dbContext.SaveChangesAsync(cancellationToken);
                await transaction.CommitAsync(cancellationToken);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                throw new AuditUnavailableException("Запис аудиту не вдався, зміну не застосовано.", exception);
            }

            // Потім якір, ще під тим самим lock. Збій тут лишає якір на один запис позаду,
            // подія вже збережена, тому запит не відхиляється, а верифікатор покаже попередження
            try
            {
                Anchor.Write(new AuditAnchor(record.Sequence, record.Hmac, record.KeyId));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                logger.LogError("Audit anchor write failed for sequence {Sequence}", record.Sequence);
            }
        }
        finally
        {
            // Якщо з'єднання вже втрачено, PostgreSQL сам знімає session lock разом із сесією
            try
            {
                await dbContext.Database.ExecuteSqlRawAsync("SELECT pg_advisory_unlock({0})", [LockKey], CancellationToken.None);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                logger.LogWarning("Audit advisory unlock failed, the lock ends with the session");
            }
            await dbContext.Database.CloseConnectionAsync();
        }
    }
}

public static class AuditProblems
{
    // Fail-closed для дозволених змін - без запису аудиту зміна стану не застосовується
    public static IResult Unavailable() => Results.Problem(
        title: "Журнал аудиту недоступний",
        detail: "Дію не виконано, повторіть пізніше.",
        statusCode: StatusCodes.Status503ServiceUnavailable);
}
