using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        // ЛР 4 - уся група лише для автентифікованого principal, анонім одержує 401
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents")
            .RequireAuthorization();

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .WithName("GetIncidentSeveritySummary")
            .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>()
            .ProducesValidationProblem();

        // ЛР 4 - рішення для ресурсу приймає IncidentAuthorizationHandler усередині endpoint
        group.MapPut("/{id:guid}", UpdateAsync)
            .WithName("UpdateIncident");

        group.MapDelete("/{id:guid}", DeleteAsync)
            .WithName("DeleteIncident");

        group.MapPost("/{id:guid}/triage", TriageAsync)
            .WithName("TriageIncident");

        endpoints.MapGet("/api/incident-comments/{id:guid}", GetCommentAsync)
            .WithTags("Incidents")
            .WithName("GetIncidentComment")
            .RequireAuthorization();

        return endpoints;
    }

    // ЛР 4 - content update лише власником, DTO містить тільки title і description
    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(request.Title))
            errors["title"] = ["Назва обов'язкова."];
        else if (request.Title.Length > 160)
            errors["title"] = ["Назва не довша за 160 символів."];
        if (string.IsNullOrWhiteSpace(request.Description))
            errors["description"] = ["Опис обов'язковий."];
        else if (request.Description.Length > 4000)
            errors["description"] = ["Опис не довший за 4000 символів."];
        if (errors.Count > 0)
            return Results.ValidationProblem(errors);

        // Tracked entity без AsNoTracking, інакше SaveChanges нічого не запише
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        var denied = await AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Update, authorizationService);
        if (denied is not null)
            return denied;

        // Зміна стану лише після дозволу
        incident!.Title = request.Title!.Trim();
        incident.Description = request.Description!.Trim();
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    // ЛР 4 - видалення лише власником і лише поки статус New
    private static async Task<IResult> DeleteAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        var denied = await AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Delete, authorizationService);
        if (denied is not null)
            return denied;

        dbContext.Incidents.Remove(incident!);
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    // ЛР 4 - privileged transition лише для Analyst, відмова записується в audit
    private static async Task<IResult> TriageAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        ILoggerFactory loggerFactory,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        if (!IncidentAccess.TryGetUserId(httpContext.User, out var userId))
            return Results.Challenge();

        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        var denied = await AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Triage, authorizationService);
        if (denied is not null)
        {
            // Рішення ухвалено всередині endpoint, тому подію можна записати
            if (incident is not null)
                LogAuthorizationDenied(loggerFactory, httpContext, userId, "incident.triage", incident.Id);
            return denied;
        }

        // Наступний статус визначає сервер, допустимий лише New -> Triaged
        if (incident!.Status != IncidentStatus.New)
            return Results.Problem(
                title: "Перехід неможливий",
                detail: "Triage дозволено лише для інциденту зі статусом New.",
                statusCode: StatusCodes.Status409Conflict);

        var now = DateTimeOffset.UtcNow;
        incident.Status = IncidentStatus.Triaged;
        incident.UpdatedAtUtc = now;
        dbContext.IncidentStatusHistory.Add(new IncidentStatusHistory
        {
            Id = Guid.NewGuid(),
            IncidentId = incident.Id,
            ChangedByUserId = userId,
            OldStatus = IncidentStatus.New,
            NewStatus = IncidentStatus.Triaged,
            Note = "Triage",
            CreatedAtUtc = now
        });
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    // ЛР 4 - child через parent, те саме рішення Read і правило internal comment
    private static async Task<IResult> GetCommentAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var comment = await dbContext.IncidentComments
            .AsNoTracking()
            .Include(item => item.Incident)
            .Include(item => item.Author)
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (comment is null)
            return IncidentNotFound();

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User, comment.Incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
            return IncidentNotFound();

        // Internal comment для Reporter так само невидимий, як неіснуючий
        if (comment.IsInternal)
        {
            var canReadInternal = await authorizationService.AuthorizeAsync(
                httpContext.User, comment.Incident, IncidentOperations.ReadInternalComments);
            if (!canReadInternal.Succeeded)
                return IncidentNotFound();
        }

        return Results.Ok(new IncidentCommentResponse(
            comment.Id, comment.Author.DisplayName, comment.Text, comment.CreatedAtUtc));
    }

    // Порядок для mutation - невідомий або невидимий ресурс 404, видимий без права на дію 403
    private static async Task<IResult?> AuthorizeAsync(
        ClaimsPrincipal user,
        Incident? incident,
        OperationAuthorizationRequirement operation,
        IAuthorizationService authorizationService)
    {
        if (incident is null)
            return IncidentNotFound();

        var canRead = await authorizationService.AuthorizeAsync(user, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
            return IncidentNotFound();

        var canAct = await authorizationService.AuthorizeAsync(user, incident, operation);
        return canAct.Succeeded ? null : Results.Forbid();
    }

    // Audit без cookie, пароля і body, trace id той самий, що у traceId відповіді
    private static void LogAuthorizationDenied(
        ILoggerFactory loggerFactory, HttpContext httpContext, Guid subjectId, string action, Guid resourceId) =>
        loggerFactory.CreateLogger("SecureLab.AuthorizationAudit").LogWarning(
            "authorization.denied subject={SubjectId} action={Action} resource={ResourceId} "
            + "result={Result} occurredAtUtc={OccurredAtUtc:O} traceId={TraceId}",
            subjectId,
            action,
            resourceId,
            "denied",
            DateTimeOffset.UtcNow,
            Activity.Current?.Id ?? httpContext.TraceIdentifier);

    private static IResult IncidentNotFound() => Results.Problem(
        title: "Інцидент не знайдено",
        statusCode: StatusCodes.Status404NotFound);

    private static async Task<IResult> GetListAsync(
        string? status,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        IncidentStatus? parsedStatus = null;
        if (status is not null)
        {
            if (!TryParseStatus(status, out var candidate))
            {
                return StatusValidationProblem();
            }

            parsedStatus = candidate;
        }

        // Id і роль лише з principal
        if (!IncidentAccess.TryGetUserId(httpContext.User, out var userId))
            return Results.Challenge();
        var isAnalyst = httpContext.User.IsInRole(DbSeeder.AnalystRole);

        return Results.Ok(await queries.GetListAsync(parsedStatus, userId, isAnalyst, cancellationToken));
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        // ЛР 4 - спершу entity для рішення, DTO формується лише після дозволу
        var entity = await queries.FindForAuthorizationAsync(id, cancellationToken);
        if (entity is null)
            return IncidentNotFound();

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User, entity, IncidentOperations.Read);
        if (!canRead.Succeeded)
            return IncidentNotFound();

        // Internal comment бачить лише роль, якій це дозволяє handler
        var canReadInternal = await authorizationService.AuthorizeAsync(
            httpContext.User, entity, IncidentOperations.ReadInternalComments);
        var incident = await queries.GetDetailsAsync(id, canReadInternal.Succeeded, cancellationToken);
        return incident is null ? IncidentNotFound() : Results.Ok(incident);
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
        string? status,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        IncidentStatus? parsedStatus = null;
        if (status is not null)
        {
            if (!TryParseStatus(status, out var candidate))
            {
                return StatusValidationProblem();
            }

            parsedStatus = candidate;
        }

        if (!IncidentAccess.TryGetUserId(httpContext.User, out var userId))
            return Results.Challenge();
        var isAnalyst = httpContext.User.IsInRole(DbSeeder.AnalystRole);

        return Results.Ok(await queries.GetSeveritySummaryAsync(parsedStatus, userId, isAnalyst, cancellationToken));
    }

    private static bool TryParseStatus(string raw, out IncidentStatus status)
    {
        foreach (var name in Enum.GetNames<IncidentStatus>())
        {
            if (string.Equals(name, raw, StringComparison.OrdinalIgnoreCase))
            {
                status = Enum.Parse<IncidentStatus>(name);
                return true;
            }
        }

        status = default;
        return false;
    }

    private static IResult StatusValidationProblem() =>
        Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
        });
}
