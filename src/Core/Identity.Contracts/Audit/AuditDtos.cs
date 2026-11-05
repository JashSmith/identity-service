namespace Identity.Contracts;

/// <summary>Whether Keycloak records login and admin events for the tenant realm, and for how long.</summary>
/// <param name="LoginEventsEnabled">User events (logins, failures, logouts, token exchanges).</param>
/// <param name="AdminEventsEnabled">Changes made through the Admin API (by the gateway or Keycloak's console).</param>
/// <param name="AdminEventDetails">Also store the changed representation of each admin event (may contain personal data).</param>
/// <param name="RetentionDays">Days Keycloak keeps user events before deleting them.</param>
public sealed record EventSettingsDto(bool LoginEventsEnabled, bool AdminEventsEnabled, bool AdminEventDetails, int RetentionDays);

/// <summary>A Keycloak user event, e.g. LOGIN or LOGIN_ERROR.</summary>
public sealed record LoginEventDto(
    DateTimeOffset Time,
    string Type,
    bool IsError,
    string? Error,
    string? ClientId,
    string? UserId,
    string? Username,
    string? IpAddress);

/// <summary>A change made through Keycloak's Admin API.</summary>
/// <param name="Operation">CREATE, UPDATE, DELETE or ACTION.</param>
/// <param name="ResourceType">e.g. USER, GROUP, CLIENT_ROLE, REALM.</param>
public sealed record AdminEventDto(
    DateTimeOffset Time,
    string Operation,
    string ResourceType,
    string? ResourcePath,
    string? ActorUserId,
    string? ActorClientId,
    string? IpAddress,
    string? Error);

/// <summary>Filter of login events. Dates are inclusive calendar days (UTC, as Keycloak stores them).</summary>
public sealed record LoginEventQuery(
    DateOnly? From = null,
    DateOnly? To = null,
    IReadOnlyCollection<string>? Types = null,
    string? ClientId = null,
    string? UserId = null,
    int First = 0,
    int Max = 50);

/// <summary>Filter of admin events. Dates are inclusive calendar days (UTC).</summary>
public sealed record AdminEventQuery(
    DateOnly? From = null,
    DateOnly? To = null,
    IReadOnlyCollection<string>? ResourceTypes = null,
    IReadOnlyCollection<string>? Operations = null,
    int First = 0,
    int Max = 50);

public sealed record DailyLoginCountDto(DateOnly Date, int Succeeded, int Failed);

public sealed record ApplicationLoginCountDto(string ClientId, int Logins);

/// <summary>Dashboard figures for the last days.</summary>
/// <param name="Truncated">More events existed than the gateway reads for a summary; the counts are lower bounds.</param>
public sealed record AuditSummaryDto(
    DateOnly From,
    DateOnly To,
    bool LoginEventsEnabled,
    bool AdminEventsEnabled,
    int Logins,
    int FailedLogins,
    int AdminChanges,
    IReadOnlyList<DailyLoginCountDto> Days,
    IReadOnlyList<ApplicationLoginCountDto> TopApplications,
    IReadOnlyList<AdminEventDto> RecentChanges,
    bool Truncated);
