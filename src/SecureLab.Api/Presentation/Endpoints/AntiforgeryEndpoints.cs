using Microsoft.AspNetCore.Antiforgery;

namespace SecureLab.Api.Presentation.Endpoints;

// ЛР 6 - видача пари antiforgery-токенів і єдине місце їх перевірки
public static class AntiforgeryEndpoints
{
    // Контракт між сервером і Client/csrf.js
    public const string HeaderName = "X-CSRF-TOKEN";
    public const string TokenRoute = "/api/antiforgery/token";

    public static IEndpointRouteBuilder MapAntiforgeryEndpoints(this IEndpointRouteBuilder endpoints)
    {
        // Cookie-частина йде в Set-Cookie, request token - у JSON, лише для автентифікованого principal
        endpoints.MapGet(TokenRoute, (IAntiforgery antiforgery, HttpContext httpContext) =>
            {
                var tokens = antiforgery.GetAndStoreTokens(httpContext);
                return Results.Ok(new AntiforgeryTokenResponse(tokens.RequestToken!));
            })
            .WithTags("Antiforgery")
            .WithName("GetAntiforgeryToken")
            .RequireAuthorization();

        return endpoints;
    }

    // Підключається до кожного cookie-authenticated mutation окремо, не до групи з GET
    public static TBuilder RequireAntiforgeryToken<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder =>
        builder.AddEndpointFilter<TBuilder, AntiforgeryValidationFilter>();
}

public sealed record AntiforgeryTokenResponse(string Token);

public sealed class AntiforgeryValidationFilter(IAntiforgery antiforgery) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        try
        {
            await antiforgery.ValidateRequestAsync(context.HttpContext);
        }
        catch (AntiforgeryValidationException)
        {
            // Один точний 400 для відсутнього, невалідного або чужого токена, без деталей причини
            return Results.Problem(
                title: "Antiforgery token відсутній або недійсний.",
                statusCode: StatusCodes.Status400BadRequest);
        }
        return await next(context);
    }
}
