namespace SecureLab.Api.Application.Audit;

// ЛР 6, advanced variant - handler позначає відмову, фільтр записує її після рішення endpoint
public sealed class AuditDenialFilter(SecurityAuditLog audit, ILogger<AuditDenialFilter> logger) : IEndpointFilter
{
    private const string ItemKey = "SecureLab.AuditDenial";

    // 404 на чужий ресурс - result hidden, 403 на видимий без права дії - result forbidden
    public static void Mark(HttpContext httpContext, string action, Guid resourceId, string result) =>
        httpContext.Items[ItemKey] = new AuditEntry(action, result,
            SecurityAuditLog.SubjectOf(httpContext.User), resourceId.ToString());

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var result = await next(context);
        if (context.HttpContext.Items[ItemKey] is AuditEntry entry)
        {
            try
            {
                await audit.AppendAsync(context.HttpContext, entry, context.HttpContext.RequestAborted);
            }
            catch (AuditUnavailableException)
            {
                // Відмова лишається відмовою, 503 замість 404 розкрив би існування чужого ресурсу
                logger.LogError("Audit append failed for denied {Action}", entry.EventType);
            }
        }
        return result;
    }
}
