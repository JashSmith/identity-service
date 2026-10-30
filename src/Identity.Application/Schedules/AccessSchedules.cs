using System.Collections.Concurrent;
using Identity.Contracts;

namespace Identity.Application.Schedules;

/// <summary>Entities that can carry an <c>access.schedule</c> attribute.</summary>
public enum ScheduleTarget { Realm, Role, Permission, User }

/// <summary>Everything that decides a user's schedules, read from Keycloak.</summary>
/// <param name="Permissions">Schedules of the permissions the user's roles grant (only those that have one).</param>
public sealed record UserScheduleSources(
    WeeklySchedule? Realm,
    WeeklySchedule? User,
    IReadOnlyCollection<RoleScheduleSource> Roles,
    IReadOnlyDictionary<string, WeeklySchedule> Permissions);

public sealed record RoleScheduleSource(string Role, WeeklySchedule? Schedule, IReadOnlyCollection<string> Permissions);

/// <summary>
/// Reads and writes <c>access.schedule</c> attributes. <c>id</c> is the role name, the full permission name or the
/// user id (ignored for the realm). A null schedule removes the attribute (the entity inherits again).
/// Errors: role.not_found, permission.not_found, user.not_found, or a Keycloak availability error.
/// </summary>
public interface IAccessScheduleStore
{
    Task<Result<WeeklySchedule?>> GetAsync(ScheduleTarget target, string? id, CancellationToken ct);
    Task<Result> SetAsync(ScheduleTarget target, string? id, WeeklySchedule? schedule, CancellationToken ct);
    Task<Result<UserScheduleSources>> GetSourcesAsync(string userId, CancellationToken ct);
}

public sealed class AccessScheduleOptions
{
    /// <summary>IANA or Windows id of the time zone schedules are written in.</summary>
    public string TimeZone { get; set; } = "Asia/Tehran";

    /// <summary>How long a user's resolved schedules are reused before Keycloak is read again.</summary>
    public TimeSpan CacheDuration { get; set; } = TimeSpan.FromSeconds(30);
}

/// <summary>
/// Precedence: user &gt; permission &gt; role &gt; realm. A role without a schedule follows the realm; a user with
/// several roles may work whenever any of them allows it. No schedule anywhere means unrestricted.
/// </summary>
public static class AccessScheduleResolver
{
    public static (WeeklySchedule Login, IReadOnlyDictionary<string, WeeklySchedule> Permissions) Resolve(UserScheduleSources s)
    {
        var fallback = s.Realm ?? WeeklySchedule.Unrestricted;
        var granted = s.Roles.SelectMany(r => r.Permissions).Distinct(StringComparer.Ordinal).ToArray();
        if (s.User is not null)
            return (s.User, granted.ToDictionary(p => p, _ => s.User, StringComparer.Ordinal));

        WeeklySchedule RoleSchedule(RoleScheduleSource r) => r.Schedule ?? fallback;
        var login = s.Roles.Count == 0 ? fallback : s.Roles.Select(RoleSchedule).Aggregate((a, b) => a.Union(b));

        var permissions = new Dictionary<string, WeeklySchedule>(StringComparer.Ordinal);
        foreach (var permission in granted)
        {
            permissions[permission] = s.Permissions.TryGetValue(permission, out var own)
                ? own
                : s.Roles.Where(r => r.Permissions.Contains(permission, StringComparer.Ordinal)).Select(RoleSchedule)
                    .Aggregate((a, b) => a.Union(b));
        }
        return (login, permissions);
    }
}

/// <summary>Resolves, caches and enforces users' schedules; administers schedule attributes.</summary>
public sealed class AccessScheduleService(IAccessScheduleStore store, AccessScheduleOptions options, TimeProvider clock)
{
    private readonly ConcurrentDictionary<string, (DateTimeOffset Expires, AccessScheduleSnapshot Snapshot)> _cache = new(StringComparer.Ordinal);
    private readonly TimeZoneInfo _timeZone = TimeZoneInfo.FindSystemTimeZoneById(options.TimeZone);

    public static Error OutsideSchedule => Error.Forbidden("access.outside_schedule", "Access is not allowed at this time.");

    public async Task<Result<AccessScheduleSnapshot>> GetSnapshotAsync(string userId, CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        if (_cache.TryGetValue(userId, out var cached) && cached.Expires > now) return cached.Snapshot;

        var sources = await store.GetSourcesAsync(userId, ct);
        if (!sources.IsSuccess) return sources.Error!;
        var (login, permissions) = AccessScheduleResolver.Resolve(sources.Value);
        var loginText = login.ToString();
        var snapshot = new AccessScheduleSnapshot(options.TimeZone, loginText,
            permissions.Where(p => p.Value.ToString() != loginText)
                .ToDictionary(p => p.Key, p => p.Value.ToString(), StringComparer.Ordinal));
        _cache[userId] = (now + options.CacheDuration, snapshot);
        return snapshot;
    }

    /// <summary>Fails with access.outside_schedule when the user may not sign in now.</summary>
    public async Task<Result> EnsureCanSignInAsync(string userId, CancellationToken ct)
    {
        var snapshot = await GetSnapshotAsync(userId, ct);
        if (!snapshot.IsSuccess) return snapshot.Error!;
        return snapshot.Value.Allows(null, clock.GetUtcNow()) ? Result.Success() : OutsideSchedule;
    }

    public Task<Result<WeeklySchedule?>> GetAsync(ScheduleTarget target, string? id, CancellationToken ct) =>
        store.GetAsync(target, id, ct);

    public async Task<Result> SetAsync(ScheduleTarget target, string? id, WeeklySchedule? schedule, CancellationToken ct)
    {
        var written = await store.SetAsync(target, id, schedule, ct);
        // Any change can affect many users; cached snapshots are short-lived, so they are simply dropped.
        _cache.Clear();
        return written;
    }

    public TimeZoneInfo TimeZone => _timeZone;
}
