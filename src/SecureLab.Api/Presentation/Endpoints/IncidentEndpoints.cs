using System.Security.Claims;
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
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents");

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

        // ЛР 4 vulnerable - лише автентифікація, рішення для ресурсу відсутнє
        group.MapPut("/{id:guid}", UpdateAsync)
            .WithName("UpdateIncident")
            .RequireAuthorization();

        group.MapDelete("/{id:guid}", DeleteAsync)
            .WithName("DeleteIncident")
            .RequireAuthorization();

        group.MapPost("/{id:guid}/triage", TriageAsync)
            .WithName("TriageIncident")
            .RequireAuthorization();

        endpoints.MapGet("/api/incident-comments/{id:guid}", GetCommentAsync)
            .WithTags("Incidents")
            .WithName("GetIncidentComment")
            .RequireAuthorization();

        return endpoints;
    }

    // ЛР 4 vulnerable - пошук лише за id, status із body записується в entity
    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
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

        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
            return IncidentNotFound();

        incident.Title = request.Title!.Trim();
        incident.Description = request.Description!.Trim();
        if (request.Status is not null && TryParseStatus(request.Status, out var status))
            incident.Status = status;
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    // ЛР 4 vulnerable - видалення будь-якого інциденту за id
    private static async Task<IResult> DeleteAsync(
        Guid id,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
            return IncidentNotFound();

        dbContext.Incidents.Remove(incident);
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    // ЛР 4 vulnerable - transition без перевірки ролі Analyst
    private static async Task<IResult> TriageAsync(
        Guid id,
        HttpContext httpContext,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var userIdValue = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdValue, out var userId))
            return Results.Challenge();

        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
            return IncidentNotFound();

        // Наступний статус визначає сервер, допустимий лише New -> Triaged
        if (incident.Status != IncidentStatus.New)
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

    // ЛР 4 vulnerable - коментар за прямим id без перевірки parent і IsInternal
    private static async Task<IResult> GetCommentAsync(
        Guid id,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var comment = await dbContext.IncidentComments
            .AsNoTracking()
            .Where(item => item.Id == id)
            .Select(item => new IncidentCommentResponse(
                item.Id,
                item.Author.DisplayName,
                item.Text,
                item.CreatedAtUtc))
            .SingleOrDefaultAsync(cancellationToken);
        return comment is null ? IncidentNotFound() : Results.Ok(comment);
    }

    private static IResult IncidentNotFound() => Results.Problem(
        title: "Інцидент не знайдено",
        statusCode: StatusCodes.Status404NotFound);

    private static async Task<IResult> GetListAsync(
        string? status,
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

        return Results.Ok(await queries.GetListAsync(parsedStatus, cancellationToken));
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var incident = await queries.GetDetailsAsync(id, cancellationToken);
        return incident is null
            ? Results.Problem(
                title: "Інцидент не знайдено",
                detail: $"Інцидент '{id}' не існує.",
                statusCode: StatusCodes.Status404NotFound)
            : Results.Ok(incident);
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
        string? status,
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

        return Results.Ok(await queries.GetSeveritySummaryAsync(parsedStatus, cancellationToken));
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
