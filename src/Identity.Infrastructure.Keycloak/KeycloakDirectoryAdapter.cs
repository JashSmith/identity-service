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
public sealed class KeycloakDirectoryAdapter(HttpClient http, IOptions<KeycloakOptions> opts)
    : IUserDirectory, IRoleDirectory
{
    private readonly KeycloakOptions _o = opts.Value;
    private string AdminBase => $"{_o.BaseUrl.TrimEnd('/')}/admin/realms";

    private async Task<string> GetAdminTokenAsync(CancellationToken ct)
    {
        if (!string.IsNullOrEmpty(_o.AdminClientSecret))
        {
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = _o.AdminClientId,
                ["client_secret"] = _o.AdminClientSecret,
            });
            try
            {
                var res = await http.PostAsync(
                    $"{_o.BaseUrl.TrimEnd('/')}/realms/master/protocol/openid-connect/token", form, ct);
                if (!res.IsSuccessStatusCode) return string.Empty;
                var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
                return doc.RootElement.TryGetProperty("access_token", out var t) ? t.GetString() ?? string.Empty : string.Empty;
            }
            catch { return string.Empty; }
        }
        if (!string.IsNullOrEmpty(_o.AdminUsername) && !string.IsNullOrEmpty(_o.AdminPassword))
        {
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["client_id"] = _o.AdminClientId,
                ["username"] = _o.AdminUsername,
                ["password"] = _o.AdminPassword,
            });
            try
            {
                var res = await http.PostAsync(
                    $"{_o.BaseUrl.TrimEnd('/')}/realms/master/protocol/openid-connect/token", form, ct);
                if (!res.IsSuccessStatusCode) return string.Empty;
                var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
                return doc.RootElement.TryGetProperty("access_token", out var t) ? t.GetString() ?? string.Empty : string.Empty;
            }
            catch { return string.Empty; }
        }
        return string.Empty;
    }

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

    public async Task<PagedResponse<UserDto>> GetUsersAsync(string? search, int page, int pageSize, CancellationToken ct)
    {
        page = Math.Max(1, page); pageSize = Math.Clamp(pageSize, 1, 100);
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
        catch { return new PagedResponse<UserDto>([], page, pageSize, 0); }
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
        catch { return null; }
    }

    public async Task<IReadOnlyCollection<RoleDto>> GetUserRolesAsync(string id, CancellationToken ct)
    {
        var token = await GetAdminTokenAsync(ct);
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(id)}/role-mappings");
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

    public async Task<IReadOnlyCollection<PermissionDto>> GetUserPermissionsAsync(string id, CancellationToken ct)
    {
        // Permissions are modelled as roles in Keycloak for this facade; map them to PermissionDto by convention.
        var roles = await GetUserRolesAsync(id, ct);
        return roles.Select(r => new PermissionDto(r.Name, r.Description ?? r.Name, _o.Realm, string.Empty, false, r.Id)).ToList();
    }

    public async Task<PagedResponse<RoleDto>> GetRolesAsync(string? clientId, int page, int pageSize, CancellationToken ct)
    {
        page = Math.Max(1, page); pageSize = Math.Clamp(pageSize, 1, 100);
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
        catch { return new PagedResponse<RoleDto>([], page, pageSize, 0); }
    }

    public async Task<RoleDto?> GetRoleAsync(string id, CancellationToken ct)
    {
        // Keycloak has no direct GetRole by id without knowing client; search realm roles only.
        var token = await GetAdminTokenAsync(ct);
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/roles-by-id/{Uri.EscapeDataString(id)}");
        AttachAuth(req, token);
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return null;
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            return MapRole(doc.RootElement);
        }
        catch { return null; }
    }
}
