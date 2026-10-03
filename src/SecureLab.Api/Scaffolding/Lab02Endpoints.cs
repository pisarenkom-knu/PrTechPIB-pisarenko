using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, SecureLabDbContext db, CancellationToken ct) =>
        {
            // Значення q потрапляє в SQL лише параметром
            var pattern = "%" + EscapeLike(q ?? "") + "%";
            var found = db.Incidents.AsNoTracking()
                .Where(item => EF.Functions.ILike(item.Title, pattern, "\\") || EF.Functions.ILike(item.Description, pattern, "\\"));

            // Allowlist sortBy - клієнт лише обирає один із трьох варіантів switch
            IQueryable<Incident>? ordered = sortBy switch
            {
                null or "" or "createdAtUtc" => found
                    .OrderByDescending(item => item.CreatedAtUtc).ThenBy(item => item.Id),
                "severity" => found
                    .OrderBy(item => item.Severity == IncidentSeverity.Critical ? 0
                        : item.Severity == IncidentSeverity.High ? 1
                        : item.Severity == IncidentSeverity.Medium ? 2 : 3)
                    .ThenBy(item => item.Id),
                "status" => found
                    .OrderBy(item => item.Status == IncidentStatus.New ? 0
                        : item.Status == IncidentStatus.Triaged ? 1
                        : item.Status == IncidentStatus.InProgress ? 2
                        : item.Status == IncidentStatus.Resolved ? 3 : 4)
                    .ThenBy(item => item.Id),
                _ => null
            };
            if (ordered is null)
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["sortBy"] = ["Допустимі значення: createdAtUtc, severity, status."]
                });

            var rows = await ordered.Take(50)
                .Select(row => new IncidentSearchItemResponse(
                    row.Id, row.Title, row.Description,
                    row.Severity.ToString(), row.Status.ToString(), row.CreatedAtUtc))
                .ToListAsync(ct);
            return Results.Ok(rows);
        });
        app.MapPost("/api/incidents", async (CreateIncidentRequest request, SecureLabDbContext db, CancellationToken ct) =>
        {
            // ЛР 02: доповніть server validation, business rules та response contract.
            var now = DateTimeOffset.UtcNow;
            var errors = new Dictionary<string, string[]>();

            // Перевірка заголовку запиту - максимальна довжина до Trim
            if (string.IsNullOrWhiteSpace(request.Title))
                errors["title"] = ["Назва обов'язкова."];
            else if (request.Title.Length > 160)
                errors["title"] = ["Назва не довша за 160 символів."];

            if (string.IsNullOrWhiteSpace(request.Description))
                errors["description"] = ["Опис обов'язковий."];
            else if (request.Description.Length > 4000)
                errors["description"] = ["Опис не довший за 4000 символів."];

            // Перевірка Enum - "7" не пройде, кома відсікає комбінацію "Medium,High"
            var severityIsValid =
                Enum.TryParse<IncidentSeverity>(request.Severity, ignoreCase: true, out var severity)
                && Enum.IsDefined(severity)
                && !request.Severity.Contains(',');
            if (!severityIsValid)
                errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];

            // Перевірка дати - не пізніше now + 5 хвилин
            if (request.OccurredAtUtc is null)
                errors["occurredAtUtc"] = ["Час інциденту обов'язковий."];
            else if (request.OccurredAtUtc > now.AddMinutes(5))
                errors["occurredAtUtc"] = ["Час інциденту не може бути в майбутньому."];

            // Нормалізація
            var title = request.Title?.Trim() ?? "";
            var description = request.Description?.Trim() ?? "";

            // Cross-field 2-A (T-09): для High/Critical опис має бути щонайменше 40 символів
            if (severityIsValid
                && (severity == IncidentSeverity.High || severity == IncidentSeverity.Critical)
                && !errors.ContainsKey("description")
                && description.Length < 40)
                errors["description"] = ["Для High або Critical опис має містити щонайменше 40 символів."];

            // Додаткове правило (T-10): Critical реєструється максимум через 72 години
            if (severityIsValid && severity == IncidentSeverity.Critical
                && !errors.ContainsKey("occurredAtUtc")
                && request.OccurredAtUtc < now.AddHours(-72))
                errors["occurredAtUtc"] = ["Критичний інцидент реєструється не пізніше ніж через 72 години після події."];

            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            // Предметний конфлікт 2-A (T-03): title серед незакритих інцидентів
            if (await db.Incidents.AnyAsync(
                    item => item.Title == title && item.Status != IncidentStatus.Closed, ct))
                return Results.Problem(
                    statusCode: StatusCodes.Status409Conflict,
                    title: "Інцидент уже існує",
                    detail: "Активний інцидент із такою назвою вже зареєстровано.");

            var incident = new Incident
            {
                Id = Guid.NewGuid(),
                OwnerUserId = DbSeeder.AliceId,
                Title = title,
                Description = description,
                Severity = severity,
                Status = IncidentStatus.New,
                OccurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime(),
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            };
            db.Incidents.Add(incident);
            await db.SaveChangesAsync(ct);
            return Results.Created($"/api/incidents/{incident.Id}", new CreatedIncidentResponse(
                incident.Id, incident.Title, incident.Severity.ToString(), incident.Status.ToString(),
                incident.OccurredAtUtc, incident.CreatedAtUtc));
        });
    }

    // Для буквального пошуку екрануємо: \, потім _ і %
    private static string EscapeLike(string value) =>
        value.Replace("\\", "\\\\").Replace("_", "\\_").Replace("%", "\\%");
}

public sealed record CreateIncidentRequest(
    string? Title, string? Description, string? Severity, DateTimeOffset? OccurredAtUtc);

public sealed record CreatedIncidentResponse(
    Guid Id, string Title, string Severity, string Status,
    DateTimeOffset OccurredAtUtc, DateTimeOffset CreatedAtUtc);

public sealed record IncidentSearchItemResponse(
    Guid Id, string Title, string Description, string Severity, string Status,
    DateTimeOffset CreatedAtUtc);
