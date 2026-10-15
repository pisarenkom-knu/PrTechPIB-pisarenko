using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Application.Incidents;

// ЛР 4 - операції над Incident, правила для кожної описано в docs/access-matrix.md
public static class IncidentOperations
{
    public static readonly OperationAuthorizationRequirement Read = new() { Name = nameof(Read) };
    public static readonly OperationAuthorizationRequirement Update = new() { Name = nameof(Update) };
    public static readonly OperationAuthorizationRequirement Delete = new() { Name = nameof(Delete) };
    public static readonly OperationAuthorizationRequirement Triage = new() { Name = nameof(Triage) };
    public static readonly OperationAuthorizationRequirement ReadInternalComments =
        new() { Name = nameof(ReadInternalComments) };
}

// Єдине місце рішення для завантаженого Incident - principal + операція + ресурс + статус
public sealed class IncidentAuthorizationHandler
    : AuthorizationHandler<OperationAuthorizationRequirement, Incident>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OperationAuthorizationRequirement requirement,
        Incident incident)
    {
        // Id і роль лише з verified principal, owner і status лише зі збереженого ресурсу
        var isOwner = IncidentAccess.TryGetUserId(context.User, out var userId)
            && incident.OwnerUserId == userId;
        var isAnalyst = context.User.IsInRole(DbSeeder.AnalystRole);

        var allowed = requirement.Name switch
        {
            nameof(IncidentOperations.Read) => isOwner || isAnalyst,
            nameof(IncidentOperations.Update) => isOwner,
            nameof(IncidentOperations.Delete) => isOwner && incident.Status == IncidentStatus.New,
            nameof(IncidentOperations.Triage) => isAnalyst,
            nameof(IncidentOperations.ReadInternalComments) => isAnalyst,
            _ => false
        };

        if (allowed)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

// Те саме правило видимості для запитів над множиною - list, search, severity-summary
public static class IncidentAccess
{
    public static bool TryGetUserId(ClaimsPrincipal user, out Guid userId) =>
        Guid.TryParse(user.FindFirstValue(ClaimTypes.NameIdentifier), out userId);

    // Умова стоїть у самому SQL-запиті, чужі рядки не завантажуються
    public static IQueryable<Incident> VisibleTo(
        this IQueryable<Incident> query, Guid userId, bool isAnalyst) =>
        query.Where(incident => isAnalyst || incident.OwnerUserId == userId);
}
