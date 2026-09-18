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
/// Permissions are per-service <b>client roles</b> mapped onto the group
/// (role-mappings/clients/{uuid}); legacy realm-role mappings are still read and
/// removable but new assignments go through the client-role path.
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

    /// <summary>Infrastructure groups that never surface as business roles.</summary>
    private static readonly string[] InternalGroupNames = ["iam-scope-registry", "key-admins", "super-admins"];

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

    /// <summary>Client-role names mapped to the group across all clients (the permission model).</summary>
    private async Task<IReadOnlyCollection<string>> GetGroupClientRoleNamesAsync(string groupId, string token, CancellationToken ct)
    {
        var names = new List<string>();
        foreach (var clientUuid in await ListClientUuidsAsync(token, ct))
            names.AddRange(await GetGroupClientRolesAsync(groupId, clientUuid, token, ct));
        return names;
    }

    private async Task<IReadOnlyCollection<string>> ListClientUuidsAsync(string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/clients?first=0&max=200");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return Array.Empty<string>();
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return Array.Empty<string>();
            return doc.RootElement.EnumerateArray()
                .Select(e => e.TryGetProperty("id", out var id) ? id.GetString() ?? "" : "")
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
                // Skip internal infrastructure groups — they are not business roles
                if (InternalGroupNames.Contains(g.Name, StringComparer.OrdinalIgnoreCase)) continue;
                var perms = await GetEffectivePermissionsAsync(g.Name, ct);
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

        if (await GetGroupByNameAsync(name, token, ct) is not null)
            throw new InvalidOperationException($"Business role '{name}' already exists.");

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

        // Preserve ALL existing group attributes (authz.allowed-scopes, authz.scope.*, …)
        // and only touch description — a partial attribute map in PUT replaces everything.
        var attributes = new Dictionary<string, string[]>(group.Attributes, StringComparer.Ordinal);
        attributes["description"] = new[]
        {
            description ?? (group.Attributes.TryGetValue("description", out var d2) ? d2.FirstOrDefault() ?? "" : "")
        };

        var body = new Dictionary<string, object>
        {
            ["name"] = group.Name,
            ["path"] = group.Path,
            ["attributes"] = attributes,
        };

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
        // Effective = client roles (the permission model) + realm roles (legacy) + composites
        var expanded = new HashSet<string>(StringComparer.Ordinal);
        foreach (var r in await GetGroupClientRoleNamesAsync(group.Id, token, ct)) expanded.Add(r);
        var realmRoles = await GetGroupRealmRolesAsync(group.Id, token, ct);
        foreach (var r in realmRoles)
        {
            expanded.Add(r);
            foreach (var c in await GetRealmRoleCompositesAsync(r, token, ct)) expanded.Add(c);
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

        // Permission model: client roles on the owning service client, mapped to the group.
        // Legacy realm roles remain supported as a fallback for not-yet-migrated permissions.
        var clientUuids = await ListClientUuidsAsync(token, ct);
        var realmReprs = new List<object>();
        var clientReprs = new Dictionary<string, List<object>>(StringComparer.Ordinal);
        foreach (var perm in permissions)
        {
            var found = false;
            foreach (var clientUuid in clientUuids)
            {
                var role = await LookupClientRoleAsync(clientUuid, perm, token, ct);
                if (role is null) continue;
                if (!clientReprs.TryGetValue(clientUuid, out var list)) clientReprs[clientUuid] = list = [];
                list.Add(new { id = role.Value.Id, name = role.Value.Name });
                found = true;
                break;
            }
            if (found) continue;
            var realmRole = await LookupRealmRoleAsync(perm, token, ct);
            if (realmRole is null) throw new InvalidOperationException($"Permission role '{perm}' does not exist.");
            realmReprs.Add(new { id = realmRole.Value.Id, name = realmRole.Value.Name });
        }

        foreach (var (clientUuid, reprs) in clientReprs)
            await PostRoleMappingsAsync($"groups/{Uri.EscapeDataString(group.Id)}/role-mappings/clients/{Uri.EscapeDataString(clientUuid)}", reprs, roleName, token, ct);
        if (realmReprs.Count > 0)
            await PostRoleMappingsAsync($"groups/{Uri.EscapeDataString(group.Id)}/role-mappings/realm", realmReprs, roleName, token, ct);
    }

    private async Task PostRoleMappingsAsync(string path, List<object> reprs, string roleName, string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, $"{AdminBase}/{_o.Realm}/{path}")
        {
            Content = JsonContent.Create(reprs)
        };
        req.Headers.Add("Authorization", $"Bearer {token}");
        var res = await http.SendAsync(req, ct);
        if (!res.IsSuccessStatusCode)
        {
            var err = await res.Content.ReadAsStringAsync(ct);
            throw new InvalidOperationException($"Failed to add permissions to group '{roleName}': {(int)res.StatusCode} {err}");
        }
    }

    private async Task<(string Id, string Name)?> LookupClientRoleAsync(string clientUuid, string roleName, string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/clients/{Uri.EscapeDataString(clientUuid)}/roles/{Uri.EscapeDataString(roleName)}");
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

        // Try the client-role path first (the permission model), then legacy realm roles.
        foreach (var clientUuid in await ListClientUuidsAsync(token, ct))
        {
            var clientRole = await LookupClientRoleAsync(clientUuid, permission, token, ct);
            if (clientRole is null) continue;
            var mapped = await GetGroupClientRolesAsync(group.Id, clientUuid, token, ct);
            if (!mapped.Contains(permission, StringComparer.Ordinal)) continue;
            var delReq = new HttpRequestMessage(HttpMethod.Delete,
                $"{AdminBase}/{_o.Realm}/groups/{Uri.EscapeDataString(group.Id)}/role-mappings/clients/{Uri.EscapeDataString(clientUuid)}")
            {
                Content = JsonContent.Create(new[] { new { id = clientRole.Value.Id, name = clientRole.Value.Name } })
            };
            delReq.Headers.Add("Authorization", $"Bearer {token}");
            var delRes = await http.SendAsync(delReq, ct);
            if (!delRes.IsSuccessStatusCode && delRes.StatusCode != HttpStatusCode.NotFound)
            {
                var err = await delRes.Content.ReadAsStringAsync(ct);
                throw new InvalidOperationException($"Failed to remove permission '{permission}' from '{name}': {(int)delRes.StatusCode} {err}");
            }
            return;
        }

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
