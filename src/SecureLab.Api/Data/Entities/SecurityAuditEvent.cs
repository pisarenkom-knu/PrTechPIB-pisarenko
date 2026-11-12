namespace SecureLab.Api.Data.Entities;

// ЛР 6, advanced variant - запис tamper-evident журналу security-подій
// Без паролів, cookie, токенів і тіла запиту, лише ідентифікатори й результат
public sealed class SecurityAuditEvent
{
    public long Sequence { get; set; }
    public DateTimeOffset OccurredAtUtc { get; set; }
    public required string EventType { get; set; }
    public required string Result { get; set; }
    public string? SubjectId { get; set; }
    public string? ResourceId { get; set; }
    public string? LoginHash { get; set; }
    public required string TraceId { get; set; }
    public required string KeyId { get; set; }
    public required string PreviousHmac { get; set; }
    public required string Hmac { get; set; }
}
