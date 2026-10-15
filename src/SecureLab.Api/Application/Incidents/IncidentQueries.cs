using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Application.Incidents;

public sealed class IncidentQueries(SecureLabDbContext dbContext, ILogger<IncidentQueries> logger)
{
    public async Task<IReadOnlyList<IncidentListItemResponse>> GetListAsync(
        IncidentStatus? status,
        Guid userId,
        bool isAnalyst,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incidents with status filter {Status}", status);

        // ЛР 4 - лише дозволена множина, як у матриці
        var query = dbContext.Incidents.AsNoTracking().VisibleTo(userId, isAnalyst);
        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }

        return await query
            .OrderByDescending(incident => incident.CreatedAtUtc)
            .Select(incident => new IncidentListItemResponse(
                incident.Id,
                incident.Title,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc))
            .ToListAsync(cancellationToken);
    }

    // ЛР 4 - entity з OwnerUserId для handler, клієнту не повертається
    public Task<Incident?> FindForAuthorizationAsync(Guid id, CancellationToken cancellationToken) =>
        dbContext.Incidents
            .AsNoTracking()
            .SingleOrDefaultAsync(incident => incident.Id == id, cancellationToken);

    // Викликається лише після дозволу Read, includeInternal - результат рішення handler
    public Task<IncidentDetailsResponse?> GetDetailsAsync(
        Guid id,
        bool includeInternal,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incident {IncidentId}", id);

        return dbContext.Incidents
            .AsNoTracking()
            .Where(incident => incident.Id == id)
            .Select(incident => new IncidentDetailsResponse(
                incident.Id,
                incident.Title,
                incident.Description,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc,
                incident.Owner.DisplayName,
                incident.Comments
                    .Where(comment => includeInternal || !comment.IsInternal)
                    .OrderBy(comment => comment.CreatedAtUtc)
                    .Select(comment => new IncidentCommentResponse(
                        comment.Id,
                        comment.Author.DisplayName,
                        comment.Text,
                        comment.CreatedAtUtc))
                    .ToList()))
            .SingleOrDefaultAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<IncidentSeveritySummaryResponse>> GetSeveritySummaryAsync(
        IncidentStatus? status,
        Guid userId,
        bool isAnalyst,
        CancellationToken cancellationToken)
    {
        // ЛР 4 A-11 - обмеження до групування
        var query = dbContext.Incidents.AsNoTracking().VisibleTo(userId, isAnalyst);
        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }

        var aggregates = await query
            .GroupBy(incident => incident.Severity)
            .Select(group => new IncidentSeveritySummaryResponse(
                group.Key.ToString(),
                group.Count()))
            .ToListAsync(cancellationToken);

        var counts = aggregates.ToDictionary(
            item => Enum.Parse<IncidentSeverity>(item.Severity),
            item => item.Count);

        var summary = Enum.GetValues<IncidentSeverity>()
            .Select(severity => new IncidentSeveritySummaryResponse(
                severity.ToString(),
                counts.GetValueOrDefault(severity)))
            .ToList();

        logger.LogInformation(
            "Built incident severity summary with {GroupCount} groups for status filter {Status}",
            summary.Count,
            status);

        return summary;
    }
}
