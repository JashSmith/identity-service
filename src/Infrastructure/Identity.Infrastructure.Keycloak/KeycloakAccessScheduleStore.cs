using System.Text.Json;
using Identity.Application;
using Identity.Application.Permissions;
using Identity.Application.Schedules;
using Identity.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// <c>access.schedule</c> attributes on the realm (string attribute), business-role groups, permission client
/// roles and users (list attributes). Writes read the current representation and send it back with only the
/// schedule changed, because Keycloak's PUT replaces representations.
/// </summary>
public sealed class KeycloakAccessScheduleStore(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    IBusinessRoleStore roles,
    ILogger<KeycloakAccessScheduleStore>? logger = null) : IAccessScheduleStore
{
    private const string Resource = "schedule";
    private readonly ILogger _logger = (ILogger?)logger ?? NullLogger.Instance;
    private readonly KeycloakAdminApi _api = new(http, opts.Value, tokenProvider, (ILogger?)logger ?? NullLogger.Instance);

    private static string UserPath(string id) => $"users/{Uri.EscapeDataString(id)}";

    public async Task<Result<WeeklySchedule?>> GetAsync(ScheduleTarget target, string? id, CancellationToken ct)
    {
        var representation = await ReadAsync(target, id, ct);
        if (!representation.IsSuccess) return representation.Error!;
        return Parse(AttributeOf(representation.Value.Json), target, id);
    }

    public async Task<Result> SetAsync(ScheduleTarget target, string? id, WeeklySchedule? schedule, CancellationToken ct)
    {
        var representation = await ReadAsync(target, id, ct);
        if (!representation.IsSuccess) return representation.Error!;
        var text = schedule?.ToString();

        if (target == ScheduleTarget.Realm)
        {
            // Realm attributes are a string map and only the sent keys are updated; "" means "inherit".
            return await _api.SendWithoutResultAsync(HttpMethod.Put, "",
                new { attributes = new Dictionary<string, string> { [WeeklySchedule.AttributeName] = text ?? "" } }, Resource, ct,
                includeKeycloakMessage: true);
        }

        var body = JsonSerializer.Deserialize<Dictionary<string, object?>>(representation.Value.Json.GetRawText())!;
        var attributes = representation.Value.Json.TryGetProperty("attributes", out var a) && a.ValueKind == JsonValueKind.Object
            ? JsonSerializer.Deserialize<Dictionary<string, object?>>(a.GetRawText())!
            : new Dictionary<string, object?>();
        if (text is null) attributes.Remove(WeeklySchedule.AttributeName);
        else attributes[WeeklySchedule.AttributeName] = new[] { text };
        body["attributes"] = attributes;

        return await _api.SendWithoutResultAsync(HttpMethod.Put, representation.Value.Path, body, Resource, ct, includeKeycloakMessage: true);
    }

    public async Task<Result<UserScheduleSources>> GetSourcesAsync(string userId, CancellationToken ct)
    {
        var realm = await GetAsync(ScheduleTarget.Realm, null, ct);
        if (!realm.IsSuccess) return realm.Error!;
        var user = await GetAsync(ScheduleTarget.User, userId, ct);
        if (!user.IsSuccess) return user.Error!;

        var groups = await _api.GetAllAsync($"{UserPath(userId)}/groups?briefRepresentation=false", Resource, ct);
        if (!groups.IsSuccess) return groups.Error!;

        var roleSources = new List<RoleScheduleSource>();
        foreach (var group in groups.Value)
        {
            var name = KeycloakAdminApi.GetString(group, "name");
            if (name is null || ReservedGroups.IsReserved(name)) continue;
            var schedule = Parse(AttributeOf(group), ScheduleTarget.Role, name);
            if (!schedule.IsSuccess) return schedule.Error!;
            var role = await roles.GetAsync(name, ct);
            if (!role.IsSuccess) return role.Error!;
            roleSources.Add(new RoleScheduleSource(name, schedule.Value, role.Value.Permissions));
        }

        var permissions = await PermissionSchedulesAsync(roleSources.SelectMany(r => r.Permissions).ToHashSet(StringComparer.Ordinal), ct);
        if (!permissions.IsSuccess) return permissions.Error!;
        return new UserScheduleSources(realm.Value, user.Value, roleSources, permissions.Value);
    }

    /// <summary>Schedules of the given permissions, reading each application's roles once.</summary>
    private async Task<Result<IReadOnlyDictionary<string, WeeklySchedule>>> PermissionSchedulesAsync(
        HashSet<string> granted, CancellationToken ct)
    {
        var schedules = new Dictionary<string, WeeklySchedule>(StringComparer.Ordinal);
        var applications = granted
            .Select(p => PermissionName.TryParseFull(p, out var name) ? name : null)
            .OfType<PermissionName>().Select(n => n.Application).Distinct(StringComparer.Ordinal);

        foreach (var application in applications)
        {
            var client = await FindClientUuidAsync(application, ct);
            if (!client.IsSuccess) return client.Error!;
            var clientRoles = await _api.GetAllAsync($"clients/{Uri.EscapeDataString(client.Value)}/roles?briefRepresentation=false", Resource, ct);
            if (!clientRoles.IsSuccess) return clientRoles.Error!;
            foreach (var role in clientRoles.Value)
            {
                var full = $"{application}:{KeycloakAdminApi.GetString(role, "name")}";
                if (!granted.Contains(full)) continue;
                var schedule = Parse(AttributeOf(role), ScheduleTarget.Permission, full);
                if (!schedule.IsSuccess) return schedule.Error!;
                if (schedule.Value is not null) schedules[full] = schedule.Value;
            }
        }
        return schedules;
    }

    private sealed record Representation(string Path, JsonElement Json);

    private async Task<Result<Representation>> ReadAsync(ScheduleTarget target, string? id, CancellationToken ct)
    {
        switch (target)
        {
            case ScheduleTarget.Realm:
                var realm = await _api.GetAsync("", Resource, ct);
                return realm.IsSuccess ? new Representation("", realm.Value) : realm.Error!;

            case ScheduleTarget.User:
                if (string.IsNullOrWhiteSpace(id)) return UserNotFound(id);
                var user = await _api.GetAsync(UserPath(id), Resource, ct);
                if (user.IsSuccess) return new Representation(UserPath(id), user.Value);
                return user.Error!.Kind == ErrorKind.NotFound ? UserNotFound(id) : user.Error;

            case ScheduleTarget.Role:
                if (string.IsNullOrWhiteSpace(id) || ReservedGroups.IsReserved(id)) return RoleNotFound(id);
                // briefRepresentation=false is required: the brief form omits attributes.
                var groups = await _api.GetAsync($"groups?search={Uri.EscapeDataString(id)}&exact=true&briefRepresentation=false", Resource, ct);
                if (!groups.IsSuccess) return groups.Error!;
                foreach (var group in groups.Value.EnumerateArray())
                    if (KeycloakAdminApi.GetString(group, "name") == id)
                        return new Representation($"groups/{Uri.EscapeDataString(KeycloakAdminApi.GetString(group, "id")!)}", group);
                return RoleNotFound(id);

            case ScheduleTarget.Permission:
                if (!PermissionName.TryParseFull(id, out var permission)) return PermissionNotFound(id);
                var client = await FindClientUuidAsync(permission.Application, ct);
                if (!client.IsSuccess) return client.Error!.Kind == ErrorKind.NotFound ? PermissionNotFound(id) : client.Error;
                var path = $"clients/{Uri.EscapeDataString(client.Value)}/roles/{Uri.EscapeDataString(permission.Local)}";
                var role = await _api.GetAsync(path, Resource, ct);
                if (role.IsSuccess) return new Representation(path, role.Value);
                return role.Error!.Kind == ErrorKind.NotFound ? PermissionNotFound(id) : role.Error;

            default:
                throw new ArgumentOutOfRangeException(nameof(target), target, null);
        }
    }

    private async Task<Result<string>> FindClientUuidAsync(string clientId, CancellationToken ct)
    {
        var found = await _api.GetAsync($"clients?clientId={Uri.EscapeDataString(clientId)}", Resource, ct);
        if (!found.IsSuccess) return found.Error!;
        var uuid = found.Value.EnumerateArray()
            .Where(c => KeycloakAdminApi.GetString(c, "clientId") == clientId)
            .Select(c => KeycloakAdminApi.GetString(c, "id"))
            .FirstOrDefault();
        return uuid is null ? Error.NotFound("application.not_found", $"Application '{clientId}' was not found.") : uuid;
    }

    /// <summary>The attribute from a realm (string map) or a group/role/user (list map) representation.</summary>
    private static string? AttributeOf(JsonElement representation)
    {
        if (!representation.TryGetProperty("attributes", out var attributes) || attributes.ValueKind != JsonValueKind.Object ||
            !attributes.TryGetProperty(WeeklySchedule.AttributeName, out var value))
            return null;
        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Array => value.EnumerateArray().Select(v => v.GetString()).FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)),
            _ => null,
        };
    }

    /// <summary>Empty means "inherit". An unreadable value fails closed instead of granting unrestricted access.</summary>
    private Result<WeeklySchedule?> Parse(string? text, ScheduleTarget target, string? id)
    {
        if (string.IsNullOrWhiteSpace(text)) return Result<WeeklySchedule?>.Success(null);
        if (WeeklySchedule.TryParse(text, out var schedule, out var error)) return schedule;
        _logger.LogError("Invalid {Attribute} on {Target} {Id}: {Error}", WeeklySchedule.AttributeName, target, id, error);
        return Error.Unexpected("schedule.invalid", $"The schedule stored on {target.ToString().ToLowerInvariant()} '{id}' is invalid; set it again.");
    }

    private static Error UserNotFound(string? id) => Error.NotFound("user.not_found", $"User '{id}' was not found.");
    private static Error RoleNotFound(string? id) => Error.NotFound("role.not_found", $"Business role '{id}' was not found.");
    private static Error PermissionNotFound(string? id) => Error.NotFound("permission.not_found", $"Permission '{id}' was not found.");
}
