using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Routing.Template;

namespace SecureLab.Api.Presentation.Endpoints;

// ЛР 6, F-03 - fallback /api/{**path} спрацьовує й тоді, коли маршрут існує, але
// routing відкинув його через метод або Content-Type, тому тут відновлюється 405 або 415
public static class ApiFallback
{
    public static IResult Handle(HttpContext context, EndpointDataSource dataSource,
        IInlineConstraintResolver constraintResolver)
    {
        var known = dataSource.Endpoints
            .OfType<RouteEndpoint>()
            .Where(endpoint => !endpoint.RoutePattern.Parameters.Any(parameter => parameter.IsCatchAll))
            .Where(endpoint => Matches(endpoint, context, constraintResolver))
            .ToList();
        if (known.Count == 0)
            return Results.Problem(title: "Ресурс API не знайдено", statusCode: StatusCodes.Status404NotFound);

        var allowed = known
            .SelectMany(endpoint => endpoint.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods ?? [])
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (!allowed.Contains(context.Request.Method, StringComparer.OrdinalIgnoreCase))
        {
            context.Response.Headers.Allow = string.Join(", ", allowed);
            return Results.Problem(title: "Метод не підтримується", statusCode: StatusCodes.Status405MethodNotAllowed);
        }

        // Метод підходить, отже маршрут відкинуто через тип тіла запиту
        return Results.Problem(title: "Непідтримуваний Content-Type", statusCode: StatusCodes.Status415UnsupportedMediaType);
    }

    // Шаблон і обмеження параметрів ({id:guid}) перевіряються так само, як у routing
    private static bool Matches(RouteEndpoint endpoint, HttpContext context, IInlineConstraintResolver constraintResolver)
    {
        var pattern = endpoint.RoutePattern;
        if (pattern.RawText is null)
            return false;
        var values = new RouteValueDictionary();
        var matcher = new TemplateMatcher(TemplateParser.Parse(pattern.RawText), new RouteValueDictionary(pattern.Defaults));
        if (!matcher.TryMatch(context.Request.Path, values))
            return false;

        foreach (var (name, policies) in pattern.ParameterPolicies)
        {
            foreach (var policy in policies)
            {
                var constraint = policy.Content is null ? null : constraintResolver.ResolveConstraint(policy.Content);
                if (constraint is not null && !constraint.Match(context, null, name, values, RouteDirection.IncomingRequest))
                    return false;
            }
        }
        return true;
    }
}
