using System.Text.Json;
using Identity.Application;
using Identity.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Reads users, roles and sessions of one Keycloak realm (<see cref="IUserDirectory"/>,
/// <see cref="IRoleDirectory"/>, <see cref="IUserSessionService"/>). Every Keycloak failure is
/// reported as an error instead of an empty list or a missing user.
/// </summary>
public sealed class KeycloakDirectoryAdapter(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ICacheInvalidationService? cacheInvalidator = null,
    ILogger<KeycloakDirectoryAdapter>? logger = null)
    : IUserDirectory, IRoleDirectory, IUserSessionService
{
    private const string UserResource = "user";
    private const string RoleResource = "role";

    /// <summary>Upper bound for parallel per-user session lookups when a page is enriched.</summary>
    private const int SessionLookupConcurrency = 8;

    private readonly ILogger _logger = (ILogger?)logger ?? NullLogger.Instance;
    private readonly KeycloakAdminApi _api = new(http, opts.Value, tokenProvider, (ILogger?)logger ?? NullLogger.Instance);

    private static Error UserNotFound(string id) => Error.NotFound("user.not_found", $"User '{id}' was not found.");

    private static string UserPath(string id) => $"users/{Uri.EscapeDataString(id)}";

    public async Task<Result<PagedResponse<UserDto>>> GetUsersAsync(
        string? search, int page, int pageSize, bool includeSessions, CancellationToken ct)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, KeycloakAdminApi.PageSize);
        var filter = string.IsNullOrWhiteSpace(search) ? "" : $"search={Uri.EscapeDataString(search.Trim())}";

        var users = await _api.GetAsync($"users?first={(page - 1) * pageSize}&max={pageSize}&{filter}", UserResource, ct);
        if (!users.IsSuccess) return users.Error!;
        var total = await _api.GetAsync($"users/count?{filter}", UserResource, ct);
        if (!total.IsSuccess) return total.Error!;

        var items = users.Value.EnumerateArray().Select(MapUser).ToArray();
        if (includeSessions)
        {
            var enriched = await WithSessionsAsync(items, ct);
            if (!enriched.IsSuccess) return enriched.Error!;
            items = enriched.Value;
        }

        int? count = total.Value.ValueKind == JsonValueKind.Number ? total.Value.GetInt32() : null;
        return new PagedResponse<UserDto>(items, page, pageSize, count);
    }

    public async Task<Result<UserDto>> GetUserAsync(string id, CancellationToken ct)
    {
        var user = await _api.GetAsync(UserPath(id), UserResource, ct);
        if (!user.IsSuccess) return NamedNotFound(user.Error!, id);

        var sessions = await GetUserSessionsAsync(id, ct);
        if (!sessions.IsSuccess) return sessions.Error!;
        return MapUser(user.Value) with { IsOnline = sessions.Value.Count > 0, ActiveSessionsCount = sessions.Value.Count };
    }

    public async Task<Result<IReadOnlyCollection<RoleDto>>> GetUserRolesAsync(string id, CancellationToken ct)
    {
        var mappings = await _api.GetAsync($"{UserPath(id)}/role-mappings", UserResource, ct);
        if (!mappings.IsSuccess) return NamedNotFound(mappings.Error!, id);

        var roles = new List<RoleDto>();
        if (mappings.Value.TryGetProperty("realmMappings", out var realm) && realm.ValueKind == JsonValueKind.Array)
            roles.AddRange(realm.EnumerateArray().Select(MapRole));
        if (mappings.Value.TryGetProperty("clientMappings", out var clients) && clients.ValueKind == JsonValueKind.Object)
            foreach (var client in clients.EnumerateObject())
                if (client.Value.TryGetProperty("mappings", out var mapped) && mapped.ValueKind == JsonValueKind.Array)
                    roles.AddRange(mapped.EnumerateArray().Select(MapRole));
        return roles;
    }

    public async Task<Result<bool>> IsSuperAdminAsync(string id, CancellationToken ct)
    {
        var groups = await _api.GetAsync(
            $"{UserPath(id)}/groups?search={Uri.EscapeDataString(ReservedGroups.SuperAdmins)}&briefRepresentation=true", UserResource, ct);
        if (!groups.IsSuccess) return NamedNotFound(groups.Error!, id);
        return groups.Value.EnumerateArray().Any(g => KeycloakAdminApi.GetString(g, "name") == ReservedGroups.SuperAdmins);
    }

    public async Task<Result<IReadOnlyCollection<PermissionDto>>> GetUserPermissionsAsync(string id, CancellationToken ct)
    {
        var permissions = new Dictionary<string, PermissionDto>(StringComparer.OrdinalIgnoreCase);

        // Effective realm roles already include roles inherited through groups and composites.
        var realm = await _api.GetAsync($"{UserPath(id)}/role-mappings/realm/composite", UserResource, ct);
        if (!realm.IsSuccess) return NamedNotFound(realm.Error!, id);
        foreach (var role in realm.Value.EnumerateArray()) AddPermission(permissions, role, "realm", "");

        // Only clients the user or one of its groups holds roles of can contribute client permissions,
        // so the composite lookup runs for those clients instead of every client of the realm.
        var clients = await ClientsWithMappingsAsync(id, ct);
        if (!clients.IsSuccess) return clients.Error!;
        foreach (var (clientUuid, clientId) in clients.Value)
        {
            var effective = await _api.GetAsync(
                $"{UserPath(id)}/role-mappings/clients/{Uri.EscapeDataString(clientUuid)}/composite", UserResource, ct);
            if (!effective.IsSuccess) return effective.Error!;
            // Client roles carry the application prefix, exactly as they appear in tokens.
            foreach (var role in effective.Value.EnumerateArray()) AddPermission(permissions, role, clientId, $"{clientId}:");
        }

        return permissions.Values.OrderBy(p => p.Name, StringComparer.Ordinal).ToArray();
    }

    public async Task<Result<IReadOnlyCollection<UserSessionDto>>> GetUserSessionsAsync(string userId, CancellationToken ct)
    {
        var sessions = await _api.GetAsync($"{UserPath(userId)}/sessions", UserResource, ct);
        if (!sessions.IsSuccess) return NamedNotFound(sessions.Error!, userId);
        return sessions.Value.EnumerateArray().Select(s => MapSession(s, userId)).ToArray();
    }

    public async Task<Result<RevokeUserTokensResponse>> RevokeUserTokensAsync(string userId, string? reason, CancellationToken ct)
    {
        var loggedOut = await _api.SendWithoutResultAsync(HttpMethod.Post, $"{UserPath(userId)}/logout", null, UserResource, ct);
        if (!loggedOut.IsSuccess) return NamedNotFound(loggedOut.Error!, userId);
        _logger.LogInformation("Revoked all sessions of user {UserId}. Reason: {Reason}", userId, reason ?? "(none)");

        var message = "All sessions of the user were ended in Keycloak.";
        if (cacheInvalidator is not null)
        {
            try
            {
                await cacheInvalidator.InvalidateUserAsync(userId, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // The sessions are already gone; report the stale cache instead of failing the revocation.
                _logger.LogWarning(ex, "Sessions of user {UserId} were revoked but cached authorization data could not be cleared", userId);
                message += " Cached authorization data could not be cleared and expires on its own.";
            }
        }
        return new RevokeUserTokensResponse(userId, true, message, DateTimeOffset.UtcNow);
    }

    public async Task<Result<PagedResponse<RoleDto>>> GetRolesAsync(string? clientId, int page, int pageSize, CancellationToken ct)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, KeycloakAdminApi.PageSize);
        var path = string.IsNullOrWhiteSpace(clientId) ? "roles" : $"clients/{Uri.EscapeDataString(clientId)}/roles";

        var roles = await _api.GetAsync($"{path}?first={(page - 1) * pageSize}&max={pageSize}", RoleResource, ct);
        if (!roles.IsSuccess) return roles.Error!;
        return new PagedResponse<RoleDto>(roles.Value.EnumerateArray().Select(MapRole).ToArray(), page, pageSize, null);
    }

    public async Task<Result<RoleDto>> GetRoleAsync(string id, CancellationToken ct)
    {
        var role = await _api.GetAsync($"roles-by-id/{Uri.EscapeDataString(id)}", RoleResource, ct);
        return role.IsSuccess ? MapRole(role.Value) : role.Error!;
    }

    private async Task<Result<UserDto[]>> WithSessionsAsync(UserDto[] users, CancellationToken ct)
    {
        using var gate = new SemaphoreSlim(SessionLookupConcurrency);
        var lookups = users.Select(async user =>
        {
            await gate.WaitAsync(ct);
            try
            {
                var sessions = await GetUserSessionsAsync(user.Id, ct);
                return sessions.IsSuccess
                    ? Result<UserDto>.Success(user with { IsOnline = sessions.Value.Count > 0, ActiveSessionsCount = sessions.Value.Count })
                    : Result<UserDto>.Failure(sessions.Error!);
            }
            finally
            {
                gate.Release();
            }
        });

        var results = await Task.WhenAll(lookups);
        var failed = results.FirstOrDefault(r => !r.IsSuccess);
        return failed is not null ? failed.Error! : results.Select(r => r.Value).ToArray();
    }

    /// <summary>(client UUID, client id) of every client the user or one of its groups holds roles of.</summary>
    private async Task<Result<IReadOnlyDictionary<string, string>>> ClientsWithMappingsAsync(string userId, CancellationToken ct)
    {
        var clients = new Dictionary<string, string>(StringComparer.Ordinal);

        var direct = await _api.GetAsync($"{UserPath(userId)}/role-mappings", UserResource, ct);
        if (!direct.IsSuccess) return NamedNotFound(direct.Error!, userId);
        foreach (var (uuid, clientId) in ClientMappings(direct.Value)) clients[uuid] = clientId;

        var groups = await _api.GetAllAsync($"{UserPath(userId)}/groups?briefRepresentation=true", UserResource, ct);
        if (!groups.IsSuccess) return groups.Error!;
        foreach (var groupId in groups.Value.Select(g => KeycloakAdminApi.GetString(g, "id")).OfType<string>())
        {
            var mappings = await _api.GetAsync($"groups/{Uri.EscapeDataString(groupId)}/role-mappings", RoleResource, ct);
            if (!mappings.IsSuccess) return mappings.Error!;
            foreach (var (uuid, clientId) in ClientMappings(mappings.Value)) clients[uuid] = clientId;
        }
        return clients;
    }

    /// <summary>The (client UUID, client id) pairs of a Keycloak MappingsRepresentation.</summary>
    private static IEnumerable<(string Uuid, string ClientId)> ClientMappings(JsonElement mappings)
    {
        if (!mappings.TryGetProperty("clientMappings", out var clients) || clients.ValueKind != JsonValueKind.Object)
            yield break;
        foreach (var client in clients.EnumerateObject())
            if (KeycloakAdminApi.GetString(client.Value, "id") is { Length: > 0 } uuid)
                yield return (uuid, client.Name);
    }

    private static Error NamedNotFound(Error error, string userId) =>
        error.Kind == ErrorKind.NotFound ? UserNotFound(userId) : error;

    private static void AddPermission(Dictionary<string, PermissionDto> permissions, JsonElement role, string source, string prefix)
    {
        if (KeycloakAdminApi.GetString(role, "name") is not { Length: > 0 } local) return;
        var name = prefix + local;
        permissions[name] = new PermissionDto(name, KeycloakAdminApi.GetString(role, "description") ?? "", source, "1.0", false,
            KeycloakAdminApi.GetString(role, "id"));
    }

    private static UserSessionDto MapSession(JsonElement s, string userId)
    {
        var clients = new Dictionary<string, string>();
        if (s.TryGetProperty("clients", out var cl) && cl.ValueKind == JsonValueKind.Object)
            foreach (var c in cl.EnumerateObject())
                clients[c.Name] = c.Value.GetString() ?? string.Empty;

        return new UserSessionDto(
            KeycloakAdminApi.GetString(s, "id") ?? "",
            KeycloakAdminApi.GetString(s, "username") ?? "",
            KeycloakAdminApi.GetString(s, "userId") ?? userId,
            KeycloakAdminApi.GetString(s, "ipAddress"),
            DateTimeOffset.FromUnixTimeMilliseconds(s.TryGetProperty("start", out var st) && st.TryGetInt64(out var start) ? start : 0),
            DateTimeOffset.FromUnixTimeMilliseconds(s.TryGetProperty("lastAccess", out var la) && la.TryGetInt64(out var last) ? last : 0),
            clients);
    }

    private static UserDto MapUser(JsonElement e)
    {
        var id = KeycloakAdminApi.GetString(e, "id") ?? string.Empty;
        var firstName = KeycloakAdminApi.GetString(e, "firstName");
        var lastName = KeycloakAdminApi.GetString(e, "lastName");
        var displayName = string.Join(" ", new[] { firstName, lastName }.Where(s => !string.IsNullOrEmpty(s))).Trim();

        var attrs = new Dictionary<string, string[]>(StringComparer.Ordinal);
        if (e.TryGetProperty("attributes", out var at) && at.ValueKind == JsonValueKind.Object)
            foreach (var prop in at.EnumerateObject())
                attrs[prop.Name] = prop.Value.ValueKind == JsonValueKind.Array
                    ? prop.Value.EnumerateArray().Select(v => v.GetString() ?? string.Empty).ToArray()
                    : [prop.Value.GetString() ?? string.Empty];
        if (KeycloakAdminApi.GetString(e, "email") is { } email) attrs["email"] = [email];
        if (e.TryGetProperty("emailVerified", out var ev) && ev.ValueKind is JsonValueKind.True or JsonValueKind.False)
            attrs["emailVerified"] = [ev.GetBoolean() ? "true" : "false"];
        if (firstName is not null) attrs["firstName"] = [firstName];
        if (lastName is not null) attrs["lastName"] = [lastName];

        return new UserDto(id, KeycloakAdminApi.GetString(e, "username") ?? id, displayName.Length == 0 ? null : displayName,
            e.TryGetProperty("enabled", out var en) && en.ValueKind == JsonValueKind.True, attrs);
    }

    private static RoleDto MapRole(JsonElement e) => new(
        KeycloakAdminApi.GetString(e, "id") ?? string.Empty,
        KeycloakAdminApi.GetString(e, "name") ?? string.Empty,
        KeycloakAdminApi.GetString(e, "description"),
        KeycloakAdminApi.GetString(e, "containerId"),
        e.TryGetProperty("composite", out var composite) && composite.ValueKind == JsonValueKind.True);
}
