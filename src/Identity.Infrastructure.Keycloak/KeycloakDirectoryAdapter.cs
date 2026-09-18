using System.Net.Http.Json;
using System.Text.Json;
using Identity.Application;
using Identity.Contracts;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Keycloak Admin REST adapter that implements <see cref="IUserDirectory"/> and
/// <see cref="IRoleDirectory"/> against a single realm. The facade never invents
/// users locally — Keycloak is the only user store.
/// </summary>
public sealed class KeycloakDirectoryAdapter(HttpClient http, IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider)
    : IUserDirectory, IRoleDirectory
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
            var items = doc.RootElement.ValueKind == JsonValueKind.Array
                ? doc.RootElement.EnumerateArray().Select(MapUser).ToList()
                : new List<UserDto>();
            return new PagedResponse<UserDto>(items, page, pageSize, null);
        }
        catch
        {
            return new PagedResponse<UserDto>([], page, pageSize, 0);
        }
    }

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
            return MapUser(doc.RootElement);
        }
        catch
        {
            return null;
        }
    }

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
        catch
        {
            return [];
        }
    }

    public async Task<IReadOnlyCollection<PermissionDto>> GetUserPermissionsAsync(string id, CancellationToken ct)
    {
        // Permissions are modelled as roles in Keycloak for this facade; map them to PermissionDto by convention.
        // A user normally gets them through business-role GROUP membership rather than direct
        // mappings, so group-inherited realm and client roles must be unioned in — Keycloak's
        // /users/{id}/role-mappings only reports direct assignments and returns [] otherwise.
        var token = await GetAdminTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return [];
        var names = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var r in await GetUserRolesAsync(id, ct)) names[r.Name] = r.Description;

        foreach (var groupId in await GetUserGroupIdsAsync(id, token, ct))
        {
            foreach (var r in await GetGroupRealmRolesAsync(groupId, token, ct)) names[r.Name] = r.Description;
            foreach (var clientUuid in await ListClientUuidsAsync(token, ct))
                foreach (var r in await GetGroupClientRolesAsync(groupId, clientUuid, token, ct))
                    names[r.Name] = r.Description;
        }

        return names
            .Select(kv => new PermissionDto(kv.Key, kv.Value ?? kv.Key, _o.Realm, string.Empty, false, null))
            .ToList();
    }

    private async Task<IReadOnlyCollection<string>> GetUserGroupIdsAsync(string userId, string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(userId)}/groups");
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

    private async Task<IReadOnlyCollection<RoleDto>> GetGroupRealmRolesAsync(string groupId, string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/groups/{Uri.EscapeDataString(groupId)}/role-mappings/realm");
        AttachAuth(req, token);
        return await ReadRoleArrayAsync(req, ct);
    }

    private async Task<IReadOnlyCollection<RoleDto>> GetGroupClientRolesAsync(string groupId, string clientUuid, string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get,
            $"{AdminBase}/{_o.Realm}/groups/{Uri.EscapeDataString(groupId)}/role-mappings/clients/{Uri.EscapeDataString(clientUuid)}");
        AttachAuth(req, token);
        return await ReadRoleArrayAsync(req, ct);
    }

    private async Task<IReadOnlyCollection<RoleDto>> ReadRoleArrayAsync(HttpRequestMessage req, CancellationToken ct)
    {
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return [];
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            return doc.RootElement.ValueKind == JsonValueKind.Array
                ? doc.RootElement.EnumerateArray().Select(MapRole).ToArray()
                : [];
        }
        catch { return []; }
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

    public async Task<RoleDto?> GetRoleAsync(string id, CancellationToken ct)
    {
        // Keycloak has no direct GetRole by id without knowing client; search realm roles only.
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