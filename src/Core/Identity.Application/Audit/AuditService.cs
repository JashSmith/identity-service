using FluentValidation;
using Identity.Contracts;

namespace Identity.Application.Audit;

/// <summary>
/// Keycloak's own login and admin events of the tenant realm (the gateway stores no audit log of its own).
/// Errors: audit.* or a Keycloak availability error.
/// </summary>
public interface IAuditEventReader
{
    Task<Result<IReadOnlyList<LoginEventDto>>> ListLoginEventsAsync(LoginEventQuery query, CancellationToken ct);
    Task<Result<IReadOnlyList<AdminEventDto>>> ListAdminEventsAsync(AdminEventQuery query, CancellationToken ct);
    Task<Result<EventSettingsDto>> GetSettingsAsync(CancellationToken ct);
    Task<Result> SetSettingsAsync(EventSettingsDto settings, CancellationToken ct);
}

/// <summary>Builds the dashboard summary from the raw events.</summary>
public sealed class AuditService(IAuditEventReader reader, TimeProvider clock)
{
    /// <summary>Events read per kind for one summary; beyond it the summary is marked truncated.</summary>
    public const int SummaryEventLimit = 2000;

    /// <summary>The event types counted as sign-ins (interactive and direct-grant logins).</summary>
    public static readonly string[] LoginTypes = ["LOGIN", "LOGIN_ERROR"];

    public async Task<Result<AuditSummaryDto>> SummaryAsync(int days, CancellationToken ct)
    {
        days = Math.Clamp(days, 1, 30);
        var settings = await reader.GetSettingsAsync(ct);
        if (!settings.IsSuccess) return settings.Error!;

        var to = DateOnly.FromDateTime(clock.GetUtcNow().UtcDateTime);
        var from = to.AddDays(1 - days);

        IReadOnlyList<LoginEventDto> logins = [];
        if (settings.Value.LoginEventsEnabled)
        {
            var read = await reader.ListLoginEventsAsync(new LoginEventQuery(from, to, LoginTypes, Max: SummaryEventLimit), ct);
            if (!read.IsSuccess) return read.Error!;
            logins = read.Value;
        }

        IReadOnlyList<AdminEventDto> changes = [];
        if (settings.Value.AdminEventsEnabled)
        {
            var read = await reader.ListAdminEventsAsync(new AdminEventQuery(from, to, Max: SummaryEventLimit), ct);
            if (!read.IsSuccess) return read.Error!;
            changes = read.Value;
        }

        return Summarize(from, to, settings.Value, logins, changes);
    }

    /// <summary>Pure aggregation, separated for tests.</summary>
    public static AuditSummaryDto Summarize(DateOnly from, DateOnly to, EventSettingsDto settings,
        IReadOnlyList<LoginEventDto> logins, IReadOnlyList<AdminEventDto> changes)
    {
        var byDay = logins
            .GroupBy(e => DateOnly.FromDateTime(e.Time.UtcDateTime))
            .ToDictionary(g => g.Key, g => (Ok: g.Count(e => !e.IsError), Failed: g.Count(e => e.IsError)));
        var days = new List<DailyLoginCountDto>();
        for (var day = from; day <= to; day = day.AddDays(1))
            days.Add(byDay.TryGetValue(day, out var c) ? new DailyLoginCountDto(day, c.Ok, c.Failed) : new DailyLoginCountDto(day, 0, 0));

        var top = logins
            .Where(e => !e.IsError && !string.IsNullOrEmpty(e.ClientId))
            .GroupBy(e => e.ClientId!, StringComparer.Ordinal)
            .Select(g => new ApplicationLoginCountDto(g.Key, g.Count()))
            .OrderByDescending(a => a.Logins).ThenBy(a => a.ClientId, StringComparer.Ordinal)
            .Take(5)
            .ToArray();

        return new AuditSummaryDto(from, to, settings.LoginEventsEnabled, settings.AdminEventsEnabled,
            logins.Count(e => !e.IsError), logins.Count(e => e.IsError), changes.Count, days, top,
            changes.OrderByDescending(e => e.Time).Take(8).ToArray(),
            logins.Count >= SummaryEventLimit || changes.Count >= SummaryEventLimit);
    }
}

public sealed class EventSettingsValidator : AbstractValidator<EventSettingsDto>
{
    public EventSettingsValidator() => RuleFor(s => s.RetentionDays).InclusiveBetween(1, 365)
        .WithMessage("Retention is between 1 and 365 days.");
}

public sealed class LoginEventQueryValidator : AbstractValidator<LoginEventQuery>
{
    public LoginEventQueryValidator()
    {
        RuleFor(q => q.First).GreaterThanOrEqualTo(0);
        RuleFor(q => q.Max).InclusiveBetween(1, 200);
        RuleFor(q => q).Must(q => q.From is null || q.To is null || q.From <= q.To).WithMessage("'From' is after 'To'.");
        RuleForEach(q => q.Types).Matches("^[A-Z_]{2,60}$").WithMessage("Event types are Keycloak names, e.g. LOGIN_ERROR.");
    }
}

public sealed class AdminEventQueryValidator : AbstractValidator<AdminEventQuery>
{
    public static readonly string[] Operations = ["CREATE", "UPDATE", "DELETE", "ACTION"];

    public AdminEventQueryValidator()
    {
        RuleFor(q => q.First).GreaterThanOrEqualTo(0);
        RuleFor(q => q.Max).InclusiveBetween(1, 200);
        RuleFor(q => q).Must(q => q.From is null || q.To is null || q.From <= q.To).WithMessage("'From' is after 'To'.");
        RuleForEach(q => q.Operations).Must(o => Operations.Contains(o)).WithMessage("Operation is CREATE, UPDATE, DELETE or ACTION.");
        RuleForEach(q => q.ResourceTypes).Matches("^[A-Z_]{2,60}$").WithMessage("Resource types are Keycloak names, e.g. USER.");
    }
}
