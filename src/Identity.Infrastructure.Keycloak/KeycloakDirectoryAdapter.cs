using System.Net.Http.Json;
using System.Text.Json;
using Identity.Application;
using Identity.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Keycloak Admin REST adapter that implements <see cref="IUserDirectory"/>,
/// <see cref="IRoleDirectory"/>, and <see cref="IUserSessionService"/> against a single realm.
/// Provides user listing, online status detection, and token/session revocation.
/// </summary>
public sealed class KeycloakDirectoryAdapter(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ICacheInvalidationService? cacheInvalidator = null,
    ILogger<KeycloakDirectoryAdapter>? logger = null)
    : IUserDirectory, IRoleDirectory, IUserSessionService
{
    private readonly KeycloakOptions _o = opts.Value;
    private string AdminBase => $"{_o.BaseUrl.TrimEnd('/')}/admin/realms";

    private async Task<string> GetAdminTokenAsync(CancellationToken ct) =>
        await tokenProvider.GetTokenAsync(ct) ?? string.Empty;

    private void AttachAuth(HttpRequestMessage req, string token)
    {
        if (!string.IsNullOrEmpty(token)) req.Headers.Add("Authorization", $"Bearer {token}");
    }

    private static UserDto MapUser(JsonElement e)
    {
        var id = e.TryGetProperty("id", out var pid) ? pid.GetString() ?? string.Empty : string.Empty;
        var username = e.TryGetProperty("username", out var p) ? p.GetString() ?? id : id;
        var enabled = e.TryGetProperty("enabled", out var en) && en.GetBoolean();
        string? displayName = null;
        string? fn2 = e.TryGetProperty("firstName", out var fnTmp) ? fnTmp.GetString() : null;
        string? ln2 = e.TryGetProperty("lastName", out var lnTmp) ? lnTmp.GetString() : null;
        if (!string.IsNullOrEmpty(fn2) || !string.IsNullOrEmpty(ln2))
            displayName = string.Join(" ", new[] { fn2, ln2 }.Where(s => !string.IsNullOrEmpty(s))).Trim();
        if (string.IsNullOrEmpty(displayName)) displayName = null;
        var attrs = new Dictionary<string, string[]>(StringComparer.Ordinal);
        if (e.TryGetProperty("attributes", out var at) && at.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in at.EnumerateObject())
                attrs[prop.Name] = prop.Value.ValueKind == JsonValueKind.Array
                    ? prop.Value.EnumerateArray().Select(v => v.GetString() ?? string.Empty).ToArray()
                    : [prop.Value.GetString() ?? string.Empty];
        }
        if (e.TryGetProperty("email", out var em) && em.ValueKind == JsonValueKind.String)
            attrs["email"] = [em.GetString() ?? string.Empty];
        if (e.TryGetProperty("emailVerified", out var ev))
            attrs["emailVerified"] = [ev.GetBoolean().ToString().ToLowerInvariant()];
        if (e.TryGetProperty("firstName", out var fnp) && fnp.ValueKind == JsonValueKind.String)
            attrs["firstName"] = [fnp.GetString() ?? string.Empty];
        if (e.TryGetProperty("lastName", out var lnp) && lnp.ValueKind == JsonValueKind.String)
            attrs["lastName"] = [lnp.GetString() ?? string.Empty];

        return new UserDto(id, username, displayName, enabled, attrs);
    }

    private static RoleDto MapRole(JsonElement e)
    {
        var id = e.TryGetProperty("id", out var pid) ? pid.GetString() ?? string.Empty : string.Empty;
        var name = e.TryGetProperty("name", out var n) ? n.GetString() ?? string.Empty : string.Empty;
        var desc = e.TryGetProperty("description", out var d) ? d.GetString() : null;
        var clientId = e.TryGetProperty("containerId", out var c) ? c.GetString() : null;
        var composite = e.TryGetProperty("composite", out var comp) && comp.GetBoolean();
        return new RoleDto(id, name, desc, clientId, composite);
    }

    /// <summary>
    /// Retrieves a paginated list of users from Keycloak, enriched with real-time online status and active session count.
    /// </summary>
    /// <param name="search">Optional username, email, or name filter.</param>
    /// <param name="page">1-based page index.</param>
    /// <param name="pageSize">Maximum users per page.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A paged response with enriched user DTOs.</returns>
    public async Task<PagedResponse<UserDto>> GetUsersAsync(string? search, int page, int pageSize,
        CancellationToken ct)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 100);
        var token = await GetAdminTokenAsync(ct);
        var first = (page - 1) * pageSize;
        var url = $"{AdminBase}/{_o.Realm}/users?first={first}&max={pageSize}";
        if (!string.IsNullOrWhiteSpace(search)) url += $"&search={Uri.EscapeDataString(search)}";
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        AttachAuth(req, token);
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return new PagedResponse<UserDto>([], page, pageSize, 0);
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            var rawUsers = doc.RootElement.ValueKind == JsonValueKind.Array
                ? doc.RootElement.EnumerateArray().Select(MapUser).ToList()
                : new List<UserDto>();

            // Enrich users with active session information to report online / offline status
            var enrichedTasks = rawUsers.Select(async u =>
            {
                try
                {
                    var sessions = await GetUserSessionsAsync(u.Id, ct);
                    return u with { IsOnline = sessions.Count > 0, ActiveSessionsCount = sessions.Count };
                }
                catch
                {
                    return u with { IsOnline = false, ActiveSessionsCount = 0 };
                }
            });

            var items = await Task.WhenAll(enrichedTasks);
            return new PagedResponse<UserDto>(items, page, pageSize, null);
        }
        catch (Exception ex)
        {
            logger?.LogWarning(ex, "Failed to get users from Keycloak.");
            return new PagedResponse<UserDto>([], page, pageSize, 0);
        }
    }

    /// <summary>
    /// Retrieves a single user by Keycloak ID and attaches real-time online status.
    /// </summary>
    /// <param name="id">Keycloak user ID.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The UserDto or null if not found.</returns>
    public async Task<UserDto?> GetUserAsync(string id, CancellationToken ct)
    {
        var token = await GetAdminTokenAsync(ct);
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(id)}");
        AttachAuth(req, token);
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return null;
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            var u = MapUser(doc.RootElement);
            var sessions = await GetUserSessionsAsync(u.Id, ct);
            return u with { IsOnline = sessions.Count > 0, ActiveSessionsCount = sessions.Count };
        }
        catch (Exception ex)
        {
            logger?.LogWarning(ex, "Failed to get user '{Id}' from Keycloak.", id);
            return null;
        }
    }

    /// <summary>
    /// Retrieves all realm and client roles mapped to a user in Keycloak.
    /// </summary>
    /// <param name="id">Keycloak user ID.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Collection of RoleDto records.</returns>
    public async Task<IReadOnlyCollection<RoleDto>> GetUserRolesAsync(string id, CancellationToken ct)
    {
        var token = await GetAdminTokenAsync(ct);
        var req = new HttpRequestMessage(HttpMethod.Get,
            $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(id)}/role-mappings");
        AttachAuth(req, token);
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return [];
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            var result = new List<RoleDto>();
            if (doc.RootElement.TryGetProperty("realmMappings", out var rm) && rm.ValueKind == JsonValueKind.Array)
                result.AddRange(rm.EnumerateArray().Select(MapRole));
            if (doc.RootElement.TryGetProperty("clientMappings", out var cm) && cm.ValueKind == JsonValueKind.Object)
                foreach (var prop in cm.EnumerateObject())
                    if (prop.Value.TryGetProperty("mappings", out var m) && m.ValueKind == JsonValueKind.Array)
                        result.AddRange(m.EnumerateArray().Select(MapRole));
            return result;
        }
        catch { return []; }
    }

    /// <summary>
    /// Resolves all effective permissions for a user from composite realm and client roles.
    /// </summary>
    /// <param name="id">Keycloak user ID.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Collection of effective permission DTOs.</returns>
    public async Task<IReadOnlyCollection<PermissionDto>> GetUserPermissionsAsync(string id, CancellationToken ct)
    {
        var token = await GetAdminTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return [];
        var result = new Dictionary<string, PermissionDto>(StringComparer.OrdinalIgnoreCase);

        var realmReq = new HttpRequestMessage(HttpMethod.Get,
            $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(id)}/role-mappings/realm/composite");
        AttachAuth(realmReq, token);
        try
        {
            var res = await http.SendAsync(realmReq, ct);
            if (res.IsSuccessStatusCode)
            {
                var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
                if (doc.RootElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var e in doc.RootElement.EnumerateArray())
                    {
                        var name = e.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                        var desc = e.TryGetProperty("description", out var d) ? d.GetString() ?? "" : "";
                        var roleId = e.TryGetProperty("id", out var rid) ? rid.GetString() : null;
                        if (!string.IsNullOrEmpty(name))
                            result[name] = new PermissionDto(name, desc, "realm", "1.0", false, roleId);
                    }
                }
            }
        }
        catch { /* best-effort */ }

        var clients = await ListClientUuidsAsync(token, ct);
        foreach (var clientUuid in clients)
        {
            var clientReq = new HttpRequestMessage(HttpMethod.Get,
                $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(id)}/role-mappings/clients/{clientUuid}/composite");
            AttachAuth(clientReq, token);
            try
            {
                var res = await http.SendAsync(clientReq, ct);
                if (!res.IsSuccessStatusCode) continue;
                var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
                if (doc.RootElement.ValueKind != JsonValueKind.Array) continue;
                foreach (var e in doc.RootElement.EnumerateArray())
                {
                    var name = e.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                    var desc = e.TryGetProperty("description", out var d) ? d.GetString() ?? "" : "";
                    var roleId = e.TryGetProperty("id", out var rid) ? rid.GetString() : null;
                    if (!string.IsNullOrEmpty(name))
                        result[name] = new PermissionDto(name, desc, clientUuid, "1.0", false, roleId);
                }
            }
            catch { /* best-effort */ }
        }

        return result.Values.ToList();
    }

    private async Task<IReadOnlyCollection<string>> ListClientUuidsAsync(string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/clients?first=0&max=200");
        AttachAuth(req, token);
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return [];
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            return doc.RootElement.ValueKind == JsonValueKind.Array
                ? doc.RootElement.EnumerateArray()
                    .Select(e => e.TryGetProperty("id", out var i) ? i.GetString() ?? "" : "")
                    .Where(x => !string.IsNullOrEmpty(x)).ToArray()
                : [];
        }
        catch { return []; }
    }

    /// <summary>
    /// Checks whether the user currently has at least one active Keycloak session.
    /// </summary>
    /// <param name="userId">Keycloak user ID.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True if online; false if offline.</returns>
    public async Task<bool> IsUserOnlineAsync(string userId, CancellationToken ct)
    {
        var sessions = await GetUserSessionsAsync(userId, ct);
        return sessions.Count > 0;
    }

    /// <summary>
    /// Retrieves all active Keycloak sessions for the user.
    /// </summary>
    /// <param name="userId">Keycloak user ID.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A collection of active session DTOs.</returns>
    public async Task<IReadOnlyCollection<UserSessionDto>> GetUserSessionsAsync(string userId, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        var token = await GetAdminTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return [];

        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(userId)}/sessions");
        AttachAuth(req, token);
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return [];
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return [];
            var list = new List<UserSessionDto>();
            foreach (var s in doc.RootElement.EnumerateArray())
            {
                var id = s.TryGetProperty("id", out var sid) ? sid.GetString() ?? string.Empty : string.Empty;
                var uname = s.TryGetProperty("username", out var su) ? su.GetString() ?? string.Empty : string.Empty;
                var uid = s.TryGetProperty("userId", out var suid) ? suid.GetString() ?? userId : userId;
                var ip = s.TryGetProperty("ipAddress", out var sip) ? sip.GetString() : null;
                var startMs = s.TryGetProperty("start", out var st) ? st.GetInt64() : 0;
                var lastMs = s.TryGetProperty("lastAccess", out var la) ? la.GetInt64() : 0;
                var clients = new Dictionary<string, string>();
                if (s.TryGetProperty("clients", out var cl) && cl.ValueKind == JsonValueKind.Object)
                {
                    foreach (var c in cl.EnumerateObject())
                    {
                        clients[c.Name] = c.Value.GetString() ?? string.Empty;
                    }
                }
                list.Add(new UserSessionDto(
                    id, uname, uid, ip,
                    DateTimeOffset.FromUnixTimeMilliseconds(startMs),
                    DateTimeOffset.FromUnixTimeMilliseconds(lastMs),
                    clients));
            }
            return list;
        }
        catch (Exception ex)
        {
            logger?.LogWarning(ex, "Failed to query sessions for user '{UserId}'.", userId);
            return [];
        }
    }

    /// <summary>
    /// Revokes all active sessions for the user in Keycloak and clears user cache in Redis.
    /// </summary>
    /// <param name="userId">Keycloak user ID.</param>
    /// <param name="reason">Administrative reason for revocation.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A RevokeUserTokensResponse.</returns>
    public async Task<RevokeUserTokensResponse> RevokeUserTokensAsync(string userId, string? reason, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        var token = await GetAdminTokenAsync(ct);
        bool success = false;
        string message;

        if (string.IsNullOrEmpty(token))
        {
            return new RevokeUserTokensResponse(userId, false, "Keycloak admin token unavailable.", DateTimeOffset.UtcNow);
        }

        try
        {
            // 1. Terminate all active sessions in Keycloak
            var logoutReq = new HttpRequestMessage(HttpMethod.Post, $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(userId)}/logout");
            AttachAuth(logoutReq, token);
            var logoutRes = await http.SendAsync(logoutReq, ct);
            success = logoutRes.IsSuccessStatusCode;
            message = success ? "User sessions logged out successfully in Keycloak." : $"Keycloak logout returned {(int)logoutRes.StatusCode}";

            // 2. Clear authorization cache in Redis/distributed cache
            if (cacheInvalidator is not null)
            {
                await cacheInvalidator.InvalidateUserAsync(userId, ct);
            }
        }
        catch (Exception ex)
        {
            message = $"Revocation encountered error: {ex.Message}";
            logger?.LogError(ex, "Error revoking user tokens for '{UserId}'.", userId);
        }

        return new RevokeUserTokensResponse(userId, success, message, DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Retrieves roles from Keycloak, optionally filtered by client.
    /// </summary>
    /// <param name="clientId">Client ID or null for realm roles.</param>
    /// <param name="page">1-based page index.</param>
    /// <param name="pageSize">Page size limit.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Paged response containing RoleDto records.</returns>
    public async Task<PagedResponse<RoleDto>> GetRolesAsync(string? clientId, int page, int pageSize,
        CancellationToken ct)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 100);
        var token = await GetAdminTokenAsync(ct);
        var first = (page - 1) * pageSize;
        string url = string.IsNullOrWhiteSpace(clientId)
            ? $"{AdminBase}/{_o.Realm}/roles?first={first}&max={pageSize}"
            : $"{AdminBase}/{_o.Realm}/clients/{Uri.EscapeDataString(clientId)}/roles?first={first}&max={pageSize}";
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        AttachAuth(req, token);
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return new PagedResponse<RoleDto>([], page, pageSize, 0);
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            var items = doc.RootElement.ValueKind == JsonValueKind.Array
                ? doc.RootElement.EnumerateArray().Select(MapRole).ToList()
                : new List<RoleDto>();
            return new PagedResponse<RoleDto>(items, page, pageSize, null);
        }
        catch
        {
            return new PagedResponse<RoleDto>([], page, pageSize, 0);
        }
    }

    /// <summary>
    /// Retrieves a realm role by ID.
    /// </summary>
    /// <param name="id">The role ID.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The RoleDto or null.</returns>
    public async Task<RoleDto?> GetRoleAsync(string id, CancellationToken ct)
    {
        var token = await GetAdminTokenAsync(ct);
        var req = new HttpRequestMessage(HttpMethod.Get,
            $"{AdminBase}/{_o.Realm}/roles-by-id/{Uri.EscapeDataString(id)}");
        AttachAuth(req, token);
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return null;
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            return MapRole(doc.RootElement);
        }
        catch
        {
            return null;
        }
    }
}