using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Identity.Application;
using Identity.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// <see cref="IBusinessRoleStore"/> backed by Keycloak Groups.
/// Each business role is a top-level Keycloak group. The group name is the role name
/// (Keycloak path is "/{name}"). Group attributes hold scope policy:
///   authz.allowed-scopes = ["region","store", ...]
/// Group role mappings (realm + client) are not used for business-role permissions
/// in the per-service client-role model — permissions are resolved via group role mappings.
/// For the transition, permissions are stored as group realm/client role mappings.
/// </summary>
public sealed class KeycloakGroupBusinessRoleStore(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakGroupBusinessRoleStore> logger) : IBusinessRoleStore
{
    private readonly KeycloakOptions _o = opts.Value;
    private string AdminBase => $"{_o.BaseUrl.TrimEnd('/')}/admin/realms";
    private const string AllowedScopesAttr = "authz.allowed-scopes";

    private sealed record GroupRef(string Id, string Name, string Path, Dictionary<string, string[]> Attributes);

    private static GroupRef MapGroup(JsonElement e)
    {
        var id = e.TryGetProperty("id", out var pid) ? pid.GetString() ?? "" : "";
        var name = e.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
        var path = e.TryGetProperty("path", out var p) ? p.GetString() ?? $"/{name}" : $"/{name}";
        var attrs = new Dictionary<string, string[]>(StringComparer.Ordinal);
        if (e.TryGetProperty("attributes", out var a) && a.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in a.EnumerateObject())
            {
                if (prop.Value.ValueKind == JsonValueKind.Array)
                    attrs[prop.Name] = prop.Value.EnumerateArray().Select(x => x.GetString() ?? "").ToArray();
                else if (prop.Value.ValueKind == JsonValueKind.String)
                    attrs[prop.Name] = new[] { prop.Value.GetString() ?? "" };
            }
        }
        return new GroupRef(id, name, path, attrs);
    }

    private async Task<GroupRef?> GetGroupByNameAsync(string name, string token, CancellationToken ct)
    {
        // Keycloak groups search: GET /groups?search=name is substring; we filter exact.
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/groups?search={Uri.EscapeDataString(name)}&exact=true");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return null;
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return null;
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                var g = MapGroup(el);
                if (string.Equals(g.Name, name, StringComparison.Ordinal)) return g;
                // Also check subGroups if any
                if (el.TryGetProperty("subGroups", out var subs) && subs.ValueKind == JsonValueKind.Array)
                    foreach (var s in subs.EnumerateArray())
                    {
                        var sg = MapGroup(s);
                        if (string.Equals(sg.Name, name, StringComparison.Ordinal)) return sg;
                    }
            }
            return null;
        }
        catch { return null; }
    }

    private async Task<GroupRef?> GetGroupByIdAsync(string id, string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/groups/{Uri.EscapeDataString(id)}");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return null;
            return MapGroup(JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct)).RootElement);
        }
        catch { return null; }
    }

    private async Task<IReadOnlyCollection<string>> GetGroupRealmRolesAsync(string groupId, string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/groups/{Uri.EscapeDataString(groupId)}/role-mappings/realm");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return Array.Empty<string>();
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return Array.Empty<string>();
            return doc.RootElement.EnumerateArray()
                .Select(e => e.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "")
                .Where(x => !string.IsNullOrEmpty(x)).ToArray();
        }
        catch { return Array.Empty<string>(); }
    }

    private async Task<IReadOnlyCollection<string>> GetGroupClientRolesAsync(string groupId, string clientId, string token, CancellationToken ct)
    {
        // Need internal client UUID, not clientId string
        var clientUuid = await ResolveClientUuidAsync(clientId, token, ct);
        if (string.IsNullOrEmpty(clientUuid)) return Array.Empty<string>();
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/groups/{Uri.EscapeDataString(groupId)}/role-mappings/clients/{Uri.EscapeDataString(clientUuid)}");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return Array.Empty<string>();
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return Array.Empty<string>();
            return doc.RootElement.EnumerateArray()
                .Select(e => e.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "")
                .Where(x => !string.IsNullOrEmpty(x)).ToArray();
        }
        catch { return Array.Empty<string>(); }
    }

    private async Task<string> ResolveClientUuidAsync(string clientId, string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/clients?clientId={Uri.EscapeDataString(clientId)}");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return "";
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind == JsonValueKind.Array && doc.RootElement.GetArrayLength() > 0)
                return doc.RootElement[0].TryGetProperty("id", out var id) ? id.GetString() ?? "" : "";
            return "";
        }
        catch { return ""; }
    }

    public async Task<BusinessRoleDto?> GetAsync(string name, CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return null;
        var group = await GetGroupByNameAsync(name, token, ct);
        if (group is null) return null;
        var perms = await GetEffectivePermissionsAsync(name, ct);
        var desc = group.Attributes.TryGetValue("description", out var d) ? d.FirstOrDefault() : null;
        return new BusinessRoleDto(group.Name, desc, true, perms);
    }

    public async Task<IReadOnlyCollection<BusinessRoleDto>> ListAsync(CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return Array.Empty<BusinessRoleDto>();
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/groups?briefRepresentation=false");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return Array.Empty<BusinessRoleDto>();
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return Array.Empty<BusinessRoleDto>();
            var result = new List<BusinessRoleDto>();
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                var g = MapGroup(el);
                // Skip internal registry group
                if (string.Equals(g.Name, "iam-scope-registry", StringComparison.OrdinalIgnoreCase)) continue;
                if (string.Equals(g.Name, "key-admins", StringComparison.OrdinalIgnoreCase)) continue;
                var perms = await GetGroupRealmRolesAsync(g.Id, token, ct);
                var desc = g.Attributes.TryGetValue("description", out var d) ? d.FirstOrDefault() : null;
                result.Add(new BusinessRoleDto(g.Name, desc, true, perms));
            }
            return result.OrderBy(x => x.Name, StringComparer.Ordinal).ToArray();
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Failed to list business role groups");
            return Array.Empty<BusinessRoleDto>();
        }
    }

    public async Task<BusinessRoleDto> CreateAsync(string name, string? description, IReadOnlyCollection<string> permissions, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        name = name.Trim();
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) throw new InvalidOperationException("Keycloak admin token unavailable.");

        var body = new Dictionary<string, object>
        {
            ["name"] = name,
        };
        if (!string.IsNullOrWhiteSpace(description))
            body["attributes"] = new Dictionary<string, string[]> { ["description"] = new[] { description! } };

        var req = new HttpRequestMessage(HttpMethod.Post, $"{AdminBase}/{_o.Realm}/groups")
        {
            Content = JsonContent.Create(body)
        };
        req.Headers.Add("Authorization", $"Bearer {token}");
        var res = await http.SendAsync(req, ct);
        if (!res.IsSuccessStatusCode && res.StatusCode != HttpStatusCode.Conflict)
        {
            var err = await res.Content.ReadAsStringAsync(ct);
            throw new InvalidOperationException($"Failed to create business role group '{name}': {(int)res.StatusCode} {err}");
        }

        if (permissions.Count > 0)
            await AddPermissionsInternalAsync(name, permissions, token, ct);

        var created = await GetAsync(name, ct);
        return created ?? new BusinessRoleDto(name, description, true, permissions);
    }

    public async Task<BusinessRoleDto?> UpdateAsync(string name, string? description, CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return null;
        var group = await GetGroupByNameAsync(name, token, ct);
        if (group is null) return null;

        var body = new Dictionary<string, object>
        {
            ["name"] = group.Name,
            ["attributes"] = new Dictionary<string, string[]>
            {
                ["description"] = new[] { description ?? (group.Attributes.TryGetValue("description", out var d2) ? d2.FirstOrDefault() ?? "" : "") }
            }
        };
        // Preserve allowed-scopes if present
        if (group.Attributes.TryGetValue(AllowedScopesAttr, out var allowed))
            ((Dictionary<string, string[]>)body["attributes"])[AllowedScopesAttr] = allowed;

        var req = new HttpRequestMessage(HttpMethod.Put, $"{AdminBase}/{_o.Realm}/groups/{Uri.EscapeDataString(group.Id)}")
        {
            Content = JsonContent.Create(body)
        };
        req.Headers.Add("Authorization", $"Bearer {token}");
        var res = await http.SendAsync(req, ct);
        if (!res.IsSuccessStatusCode) return null;
        return await GetAsync(name, ct);
    }

    public async Task<bool> DeleteAsync(string name, CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return false;
        var group = await GetGroupByNameAsync(name, token, ct);
        if (group is null) return true;
        var req = new HttpRequestMessage(HttpMethod.Delete, $"{AdminBase}/{_o.Realm}/groups/{Uri.EscapeDataString(group.Id)}");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            return res.IsSuccessStatusCode || res.StatusCode == HttpStatusCode.NotFound;
        }
        catch { return false; }
    }

    public async Task<IReadOnlyCollection<string>> GetEffectivePermissionsAsync(string name, CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return Array.Empty<string>();
        var group = await GetGroupByNameAsync(name, token, ct);
        if (group is null) return Array.Empty<string>();
        // Effective = realm roles + all client roles mapped to the group
        var realmRoles = await GetGroupRealmRolesAsync(group.Id, token, ct);
        // Also fetch composite expansion: realm role composites
        var expanded = new HashSet<string>(realmRoles, StringComparer.Ordinal);
        foreach (var r in realmRoles)
        {
            var comps = await GetRealmRoleCompositesAsync(r, token, ct);
            foreach (var c in comps) expanded.Add(c);
        }
        return expanded.OrderBy(x => x, StringComparer.Ordinal).ToArray();
    }

    private async Task<IReadOnlyCollection<string>> GetRealmRoleCompositesAsync(string roleName, string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/roles/{Uri.EscapeDataString(roleName)}/composites");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return Array.Empty<string>();
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return Array.Empty<string>();
            return doc.RootElement.EnumerateArray()
                .Select(e => e.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "")
                .Where(x => !string.IsNullOrEmpty(x)).ToArray();
        }
        catch { return Array.Empty<string>(); }
    }

    public async Task AddPermissionsAsync(string name, IReadOnlyCollection<string> permissions, CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) throw new InvalidOperationException("Keycloak admin token unavailable.");
        await AddPermissionsInternalAsync(name, permissions, token, ct);
    }

    private async Task AddPermissionsInternalAsync(string roleName, IReadOnlyCollection<string> permissions, string token, CancellationToken ct)
    {
        var group = await GetGroupByNameAsync(roleName, token, ct);
        if (group is null) throw new InvalidOperationException($"Business role group '{roleName}' does not exist.");

        // Resolve each permission as realm role or client role.
        // For now, permissions are realm roles (transition). Client-role path added when per-service clients exist.
        var roleReprs = new List<object>();
        foreach (var perm in permissions)
        {
            var role = await LookupRealmRoleAsync(perm, token, ct);
            if (role is null) throw new InvalidOperationException($"Permission role '{perm}' does not exist.");
            roleReprs.Add(new { id = role.Value.Id, name = role.Value.Name });
        }
        if (roleReprs.Count == 0) return;
        var req = new HttpRequestMessage(HttpMethod.Post, $"{AdminBase}/{_o.Realm}/groups/{Uri.EscapeDataString(group.Id)}/role-mappings/realm")
        {
            Content = JsonContent.Create(roleReprs)
        };
        req.Headers.Add("Authorization", $"Bearer {token}");
        var res = await http.SendAsync(req, ct);
        if (!res.IsSuccessStatusCode)
        {
            var err = await res.Content.ReadAsStringAsync(ct);
            throw new InvalidOperationException($"Failed to add permissions to group '{roleName}': {(int)res.StatusCode} {err}");
        }
    }

    private async Task<(string Id, string Name)?> LookupRealmRoleAsync(string roleName, string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/roles/{Uri.EscapeDataString(roleName)}");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return null;
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            var id = doc.RootElement.TryGetProperty("id", out var pid) ? pid.GetString() ?? "" : "";
            var n = doc.RootElement.TryGetProperty("name", out var nn) ? nn.GetString() ?? roleName : roleName;
            return (id, n);
        }
        catch { return null; }
    }

    public async Task RemovePermissionAsync(string name, string permission, CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) throw new InvalidOperationException("Keycloak admin token unavailable.");
        var group = await GetGroupByNameAsync(name, token, ct);
        if (group is null) throw new InvalidOperationException($"Business role group '{name}' does not exist.");
        var role = await LookupRealmRoleAsync(permission, token, ct);
        if (role is null) throw new InvalidOperationException($"Permission role '{permission}' does not exist.");
        var req = new HttpRequestMessage(HttpMethod.Delete, $"{AdminBase}/{_o.Realm}/groups/{Uri.EscapeDataString(group.Id)}/role-mappings/realm")
        {
            Content = JsonContent.Create(new[] { new { id = role.Value.Id, name = role.Value.Name } })
        };
        req.Headers.Add("Authorization", $"Bearer {token}");
        var res = await http.SendAsync(req, ct);
        if (!res.IsSuccessStatusCode && res.StatusCode != HttpStatusCode.NotFound)
        {
            var err = await res.Content.ReadAsStringAsync(ct);
            throw new InvalidOperationException($"Failed to remove permission '{permission}' from '{name}': {(int)res.StatusCode} {err}");
        }
    }
}
