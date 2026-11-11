using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Application.Audit;

// ЛР 6, advanced variant - канонічна серіалізація, HMAC-ланцюжок і перевірка
public static class AuditChain
{
    // Фіксоване початкове значення ланцюжка для запису з sequence 1
    public const string Genesis = "0000000000000000000000000000000000000000000000000000000000000000";

    // PostgreSQL timestamptz зберігає мікросекунди, тому час обрізається до них до підпису
    public static DateTimeOffset TruncateToMicroseconds(DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        return new DateTimeOffset(utc.Ticks - utc.Ticks % 10, TimeSpan.Zero);
    }

    // Фіксований порядок полів, UTF-8, час у UTC з мікросекундами, null як JSON null
    public static string Canonical(SecurityAuditEvent record) =>
        JsonSerializer.Serialize(new object?[]
        {
            "v1",
            record.Sequence,
            record.OccurredAtUtc.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ", CultureInfo.InvariantCulture),
            record.EventType,
            record.Result,
            record.SubjectId,
            record.ResourceId,
            record.LoginHash,
            record.TraceId,
            record.KeyId,
            record.PreviousHmac
        });

    public static string ComputeHmac(SecurityAuditEvent record, byte[] key) =>
        Convert.ToHexStringLower(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(Canonical(record))));

    // Keyed-хеш нормалізованого логіна - події пов'язуються, сам логін не зберігається
    public static string HashLogin(string userName, byte[] loginHashKey) =>
        Convert.ToHexStringLower(HMACSHA256.HashData(loginHashKey,
            Encoding.UTF8.GetBytes(userName.Trim().ToUpperInvariant())))[..32];

    // records у тому порядку, у якому їх прочитано, без пересортування
    public static AuditVerificationResult Verify(
        IReadOnlyList<SecurityAuditEvent> records,
        AuditAnchor? anchor,
        IReadOnlyDictionary<string, byte[]> keys,
        long firstSequence = 1,
        string firstPreviousHmac = Genesis)
    {
        var errors = new List<string>();
        var warnings = new List<string>();
        var expectedSequence = firstSequence;
        var expectedPrevious = firstPreviousHmac;

        foreach (var record in records)
        {
            if (record.Sequence != expectedSequence)
            {
                errors.Add($"sequence {record.Sequence}: очікувався {expectedSequence} (пропуск або перестановка)");
                break;
            }
            if (!string.Equals(record.PreviousHmac, expectedPrevious, StringComparison.Ordinal))
            {
                errors.Add($"sequence {record.Sequence}: PreviousHmac не збігається з попереднім записом");
                break;
            }
            if (!keys.TryGetValue(record.KeyId, out var key))
            {
                errors.Add($"sequence {record.Sequence}: невідомий key id {record.KeyId}");
                break;
            }
            if (!CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(ComputeHmac(record, key)), Encoding.ASCII.GetBytes(record.Hmac)))
            {
                errors.Add($"sequence {record.Sequence}: HMAC не збігається (запис змінено)");
                break;
            }
            expectedPrevious = record.Hmac;
            expectedSequence++;
        }

        var lastSequence = expectedSequence - 1;
        if (errors.Count == 0)
        {
            if (anchor is null)
            {
                if (records.Count > 0)
                    errors.Add("якір відсутній, хоча журнал має записи");
            }
            else if (anchor.Sequence > lastSequence)
            {
                // Якір попереду БД - записи з кінця або весь журнал видалено
                errors.Add($"обрізання: якір має sequence {anchor.Sequence}, останній запис {lastSequence}");
            }
            else if (anchor.Sequence == lastSequence)
            {
                if (lastSequence >= firstSequence && !string.Equals(anchor.Hmac, expectedPrevious, StringComparison.Ordinal))
                    errors.Add($"якір sequence {anchor.Sequence}: HMAC не збігається з останнім записом");
            }
            else if (anchor.Sequence == lastSequence - 1
                     && string.Equals(anchor.Hmac, records[^1].PreviousHmac, StringComparison.Ordinal))
            {
                // Commit пройшов, а запис якоря ні - збій між двома кроками, а не підміна
                warnings.Add($"якір відстає на один запис (sequence {anchor.Sequence} проти {lastSequence}): збій між commit і записом якоря");
            }
            else
            {
                errors.Add($"якір sequence {anchor.Sequence} не відповідає журналу з останнім записом {lastSequence}");
            }
        }

        return new AuditVerificationResult(lastSequence, errors, warnings);
    }
}

public sealed record AuditAnchor(long Sequence, string Hmac, string KeyId);

public sealed record AuditVerificationResult(long LastSequence, IReadOnlyList<string> Errors, IReadOnlyList<string> Warnings)
{
    public bool IsValid => Errors.Count == 0;
}
