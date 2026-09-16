using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Identity.Application;
using Identity.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

public sealed class KeycloakCompositeRoleStore(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakCompositeRoleStore> logger) : IBusinessRoleStore
{
    private readonly KeycloakOptions _o = opts.Value;
    private string AdminBase => $"{_o.BaseUrl.TrimEnd('/')}/admin/realms";

    private static RoleDto MapRole(JsonElement e)
    {
        var id = e.TryGetProperty("id", out var pid) ? pid.GetString() ?? string.Empty : string.Empty;
        var name = e.TryGetProperty("name", out var n) ? n.GetString() ?? string.Empty : string.Empty;
        var desc = e.TryGetProperty("description", out var d) ? d.GetString() : null;
        var containerId = e.TryGetProperty("containerId", out var c) ? c.GetString() : null;
        var composite = e.TryGetProperty("composite", out var comp) && comp.GetBoolean();
        return new RoleDto(id, name, desc, containerId, composite);
    }

    private async Task<RoleDto?> GetRealmRoleAsync(string name, string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/roles/{Uri.EscapeDataString(name)}");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return null;
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            return MapRole(doc.RootElement);
        }
        catch { return null; }
    }

    private async Task<IReadOnlyCollection<RoleDto>> GetCompositesAsync(string roleName, string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get,
            $"{AdminBase}/{_o.Realm}/roles/{Uri.EscapeDataString(roleName)}/composites");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return Array.Empty<RoleDto>();
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return Array.Empty<RoleDto>();
            return doc.RootElement.EnumerateArray().Select(MapRole).ToArray();
        }
        catch { return Array.Empty<RoleDto>(); }
    }

    private async Task<IReadOnlyCollection<RoleDto>> GetRealmCompositesAsync(string roleName, string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get,
            $"{AdminBase}/{_o.Realm}/roles/{Uri.EscapeDataString(roleName)}/composites/realm");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return Array.Empty<RoleDto>();
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return Array.Empty<RoleDto>();
            return doc.RootElement.EnumerateArray().Select(MapRole).ToArray();
        }
        catch { return Array.Empty<RoleDto>(); }
    }

    public async Task<BusinessRoleDto?> GetAsync(string name, CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return null;
        var role = await GetRealmRoleAsync(name, token, ct);
        if (role is null) return null;
        if (!role.Composite) return new BusinessRoleDto(role.Name, role.Description, false, Array.Empty<string>());
        var realmComps = await GetRealmCompositesAsync(name, token, ct);
        return new BusinessRoleDto(role.Name, role.Description, true, realmComps.Select(r => r.Name).OrderBy(x => x, StringComparer.Ordinal).ToArray());
    }

    public async Task<IReadOnlyCollection<BusinessRoleDto>> ListAsync(CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return Array.Empty<BusinessRoleDto>();
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/roles");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return Array.Empty<BusinessRoleDto>();
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return Array.Empty<BusinessRoleDto>();
            var roles = doc.RootElement.EnumerateArray().Select(MapRole).Where(r => r.Composite).ToArray();
            var result = new List<BusinessRoleDto>();
            foreach (var r in roles)
            {
                var comps = await GetRealmCompositesAsync(r.Name, token, ct);
                result.Add(new BusinessRoleDto(r.Name, r.Description, true, comps.Select(c => c.Name).OrderBy(x => x, StringComparer.Ordinal).ToArray()));
            }
            return result.OrderBy(x => x.Name, StringComparer.Ordinal).ToArray();
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Failed to list business roles");
            return Array.Empty<BusinessRoleDto>();
        }
    }

    public async Task<BusinessRoleDto> CreateAsync(string name, string? description, IReadOnlyCollection<string> permissions, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) throw new InvalidOperationException("Keycloak admin token unavailable.");
        name = name.Trim();

        // Create realm role with composite=true
        var body = new { name, description = description ?? $"Business role: {name}", composite = true };
        var req = new HttpRequestMessage(HttpMethod.Post, $"{AdminBase}/{_o.Realm}/roles")
        {
            Content = JsonContent.Create(body)
        };
        req.Headers.Add("Authorization", $"Bearer {token}");
        var res = await http.SendAsync(req, ct);
        if (!res.IsSuccessStatusCode && res.StatusCode != HttpStatusCode.Conflict)
        {
            var err = await res.Content.ReadAsStringAsync(ct);
            throw new InvalidOperationException($"Failed to create business role '{name}': {(int)res.StatusCode} {err}");
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
        var role = await GetRealmRoleAsync(name, token, ct);
        if (role is null) return null;
        var body = new { name = role.Name, description = description ?? role.Description, composite = true };
        var req = new HttpRequestMessage(HttpMethod.Put, $"{AdminBase}/{_o.Realm}/roles/{Uri.EscapeDataString(name)}")
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
        var req = new HttpRequestMessage(HttpMethod.Delete, $"{AdminBase}/{_o.Realm}/roles/{Uri.EscapeDataString(name)}");
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
        var comps = await GetRealmCompositesAsync(name, token, ct);
        return comps.Select(c => c.Name).OrderBy(x => x, StringComparer.Ordinal).ToArray();
    }

    public async Task AddPermissionsAsync(string name, IReadOnlyCollection<string> permissions, CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) throw new InvalidOperationException("Keycloak admin token unavailable.");
        await AddPermissionsInternalAsync(name, permissions, token, ct);
    }

    private async Task AddPermissionsInternalAsync(string roleName, IReadOnlyCollection<string> permissions, string token, CancellationToken ct)
    {
        var roleReprs = new List<object>();
        foreach (var perm in permissions)
        {
            var permRole = await GetRealmRoleAsync(perm, token, ct);
            if (permRole is null)
                throw new InvalidOperationException($"Permission role '{perm}' does not exist.");
            roleReprs.Add(new { id = permRole.Id, name = permRole.Name });
        }
        if (roleReprs.Count == 0) return;
        var req = new HttpRequestMessage(HttpMethod.Post, $"{AdminBase}/{_o.Realm}/roles/{Uri.EscapeDataString(roleName)}/composites")
        {
            Content = JsonContent.Create(roleReprs)
        };
        req.Headers.Add("Authorization", $"Bearer {token}");
        var res = await http.SendAsync(req, ct);
        if (!res.IsSuccessStatusCode)
        {
            var err = await res.Content.ReadAsStringAsync(ct);
            throw new InvalidOperationException($"Failed to add composites to '{roleName}': {(int)res.StatusCode} {err}");
        }
    }

    public async Task RemovePermissionAsync(string name, string permission, CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) throw new InvalidOperationException("Keycloak admin token unavailable.");
        var permRole = await GetRealmRoleAsync(permission, token, ct);
        if (permRole is null) throw new InvalidOperationException($"Permission role '{permission}' does not exist.");
        var req = new HttpRequestMessage(HttpMethod.Delete, $"{AdminBase}/{_o.Realm}/roles/{Uri.EscapeDataString(name)}/composites")
        {
            Content = JsonContent.Create(new[] { new { id = permRole.Id, name = permRole.Name } })
        };
        req.Headers.Add("Authorization", $"Bearer {token}");
        var res = await http.SendAsync(req, ct);
        if (!res.IsSuccessStatusCode && res.StatusCode != HttpStatusCode.NotFound)
        {
            var err = await res.Content.ReadAsStringAsync(ct);
            throw new InvalidOperationException($"Failed to remove composite '{permission}' from '{name}': {(int)res.StatusCode} {err}");
        }
    }
}
