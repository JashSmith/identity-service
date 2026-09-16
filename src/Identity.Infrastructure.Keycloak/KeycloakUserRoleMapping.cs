using System.Net.Http.Json;
using System.Text.Json;
using Identity.Application;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

public sealed class KeycloakUserRoleMapping(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider) : IUserRoleMapping
{
    private readonly KeycloakOptions _o = opts.Value;
    private string AdminBase => $"{_o.BaseUrl.TrimEnd('/')}/admin/realms";

    private async Task<RoleRef?> LookupRealmRoleAsync(string roleName, string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/roles/{Uri.EscapeDataString(roleName)}");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return null;
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            var id = doc.RootElement.TryGetProperty("id", out var pid) ? pid.GetString() ?? "" : "";
            var name = doc.RootElement.TryGetProperty("name", out var n) ? n.GetString() ?? roleName : roleName;
            return new RoleRef(id, name);
        }
        catch { return null; }
    }

    private sealed record RoleRef(string Id, string Name);

    public async Task<IReadOnlyCollection<string>> GetRealmRolesAsync(string userId, CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return Array.Empty<string>();
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(userId)}/role-mappings");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return Array.Empty<string>();
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (!doc.RootElement.TryGetProperty("realmMappings", out var rm) || rm.ValueKind != JsonValueKind.Array)
                return Array.Empty<string>();
            return rm.EnumerateArray().Select(e => e.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "")
                .Where(x => !string.IsNullOrEmpty(x)).ToArray();
        }
        catch { return Array.Empty<string>(); }
    }

    public async Task<bool> HasRealmRoleAsync(string userId, string roleName, CancellationToken ct)
    {
        var roles = await GetRealmRolesAsync(userId, ct);
        return roles.Contains(roleName, StringComparer.Ordinal);
    }

    public async Task MapRealmRoleAsync(string userId, string roleName, CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) throw new InvalidOperationException("Keycloak admin token unavailable.");
        var role = await LookupRealmRoleAsync(roleName, token, ct);
        if (role is null) throw new InvalidOperationException($"Role '{roleName}' does not exist.");
        var req = new HttpRequestMessage(HttpMethod.Post, $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(userId)}/role-mappings/realm")
        {
            Content = JsonContent.Create(new[] { new { id = role.Id, name = role.Name } })
        };
        req.Headers.Add("Authorization", $"Bearer {token}");
        var res = await http.SendAsync(req, ct);
        if (!res.IsSuccessStatusCode)
            throw new InvalidOperationException($"Failed to map role '{roleName}' to user '{userId}': {(int)res.StatusCode} {await res.Content.ReadAsStringAsync(ct)}");
    }

    public async Task UnmapRealmRoleAsync(string userId, string roleName, CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) throw new InvalidOperationException("Keycloak admin token unavailable.");
        var role = await LookupRealmRoleAsync(roleName, token, ct);
        if (role is null) return; // role gone — mapping already irrelevant
        var req = new HttpRequestMessage(HttpMethod.Delete, $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(userId)}/role-mappings/realm")
        {
            Content = JsonContent.Create(new[] { new { id = role.Id, name = role.Name } })
        };
        req.Headers.Add("Authorization", $"Bearer {token}");
        try { await http.SendAsync(req, ct); } catch { /* best-effort */ }
    }

    public async Task<IReadOnlyCollection<string>> GetUsersWithRealmRoleAsync(string roleName, CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return Array.Empty<string>();
        // POST /roles/{name}/users gives members for that realm role
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/roles/{Uri.EscapeDataString(roleName)}/users?first=0&max=500");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return Array.Empty<string>();
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return Array.Empty<string>();
            return doc.RootElement.EnumerateArray().Select(e => e.TryGetProperty("id", out var id) ? id.GetString() ?? "" : "")
                .Where(x => !string.IsNullOrEmpty(x)).ToArray();
        }
        catch { return Array.Empty<string>(); }
    }
}
