using FluentValidation;
using Identity.Application;
using Identity.Application.Audit;
using Identity.Contracts;
using Identity.Gateway.Errors;

namespace Identity.Gateway;

/// <summary>
/// Keycloak's login and admin events of the tenant realm (read-only), the dashboard summary built from them,
/// and the event recording settings.
/// </summary>
public static class AuditEndpoints
{
    public static IEndpointRouteBuilder MapAudit(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/identity/audit").WithTags("Audit");

        g.MapGet("/login-events", async (DateOnly? from, DateOnly? to, string[]? type, string? client, string? user,
                    int? first, int? max, IAuditEventReader reader, IValidator<LoginEventQuery> validator, CancellationToken ct) =>
                await ValidatedAsync(new LoginEventQuery(from, to, type, client, user, first ?? 0, max ?? 50), validator,
                    q => reader.ListLoginEventsAsync(q, ct), ct))
            .RequireAuthorization(IamPermissions.AuditRead).WithName("ListLoginEvents")
            .Produces<IReadOnlyList<LoginEventDto>>(200).ProducesValidationProblem();

        g.MapGet("/admin-events", async (DateOnly? from, DateOnly? to, string[]? resourceType, string[]? operation,
                    int? first, int? max, IAuditEventReader reader, IValidator<AdminEventQuery> validator, CancellationToken ct) =>
                await ValidatedAsync(new AdminEventQuery(from, to, resourceType, operation, first ?? 0, max ?? 50), validator,
                    q => reader.ListAdminEventsAsync(q, ct), ct))
            .RequireAuthorization(IamPermissions.AuditRead).WithName("ListAdminEvents")
            .Produces<IReadOnlyList<AdminEventDto>>(200).ProducesValidationProblem();

        g.MapGet("/summary", async (int? days, AuditService audit, CancellationToken ct) =>
                (await audit.SummaryAsync(days ?? 7, ct)).ToHttpResult(s => Results.Ok(s)))
            .RequireAuthorization(IamPermissions.AuditRead).WithName("AuditSummary")
            .Produces<AuditSummaryDto>(200);

        var settings = app.MapGroup("/api/identity/settings/events").WithTags("Settings");
        settings.MapGet("", async (IAuditEventReader reader, CancellationToken ct) =>
                (await reader.GetSettingsAsync(ct)).ToHttpResult(s => Results.Ok(s)))
            .RequireAuthorization(IamPermissions.SettingsRead).WithName("GetEventSettings")
            .Produces<EventSettingsDto>(200);
        settings.MapPut("", async (EventSettingsDto body, IAuditEventReader reader, CancellationToken ct) =>
            {
                var written = await reader.SetSettingsAsync(body, ct);
                if (!written.IsSuccess) return written.Error!.ToProblem();
                return (await reader.GetSettingsAsync(ct)).ToHttpResult(s => Results.Ok(s));
            })
            .WithValidation<EventSettingsDto>()
            .RequireAuthorization(IamPermissions.SettingsManage).WithName("SetEventSettings")
            .Produces<EventSettingsDto>(200);

        return app;
    }

    private static async Task<IResult> ValidatedAsync<TQuery, T>(TQuery query, IValidator<TQuery> validator,
        Func<TQuery, Task<Result<T>>> run, CancellationToken ct)
    {
        var validation = await validator.ValidateAsync(query, ct);
        if (!validation.IsValid)
            return Error.Validation("request.invalid", "One or more fields are invalid.", validation.Errors
                .GroupBy(e => e.PropertyName)
                .ToDictionary(e => e.Key, e => e.Select(x => x.ErrorMessage).Distinct().ToArray())).ToProblem();
        return (await run(query)).ToHttpResult(v => Results.Ok(v));
    }
}
