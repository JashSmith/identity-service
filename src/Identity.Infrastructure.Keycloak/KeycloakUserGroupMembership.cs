using System.Net.Http.Json;
using System.Text.Json;
using Identity.Application;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// <see cref="IUserRoleMapping"/> backed by Keycloak Group membership.
/// Business roles are Groups: MapRealmRole = join group, UnmapRealmRole = leave group.
/// The interface keeps its realm-role vocabulary, but the mapping is group membership —
/// a business role's effective permissions reach the token through its group role-mappings.
/// </summary>
public sealed class KeycloakUserGroupMembership(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider) : IUserRoleMapping
{
    private readonly KeycloakOptions _o = opts.Value;
    private string AdminBase => $"{_o.BaseUrl.TrimEnd('/')}/admin/realms";

    private async Task<string> GetTokenAsync(CancellationToken ct) => await tokenProvider.GetTokenAsync(ct) ?? string.Empty;

    private async Task<string?> ResolveGroupIdAsync(string groupName, string token, CancellationToken ct)
    {
        // GET /groups?search=name — filter exact
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/groups?search={Uri.EscapeDataString(groupName)}");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return null;
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return null;
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                var name = el.TryGetProperty("name", out var n) ? n.GetString() : null;
                if (string.Equals(name, groupName, StringComparison.Ordinal))
                    return el.TryGetProperty("id", out var id) ? id.GetString() : null;
                if (el.TryGetProperty("subGroups", out var subs) && subs.ValueKind == JsonValueKind.Array)
                    foreach (var s in subs.EnumerateArray())
                    {
                        var sn = s.TryGetProperty("name", out var snp) ? snp.GetString() : null;
                        if (string.Equals(sn, groupName, StringComparison.Ordinal))
                            return s.TryGetProperty("id", out var sid) ? sid.GetString() : null;
                    }
            }
            return null;
        }
        catch { return null; }
    }

    public async Task<IReadOnlyCollection<string>> GetRealmRolesAsync(string userId, CancellationToken ct)
    {
        // Interpreted as: get group membership names for this user
        var token = await GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return Array.Empty<string>();
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(userId)}/groups");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return Array.Empty<string>();
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return Array.Empty<string>();
            return doc.RootElement.EnumerateArray()
                .Select(e => e.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "")
                .Where(x => !string.IsNullOrEmpty(x))
                .ToArray();
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
        var token = await GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) throw new InvalidOperationException("Keycloak admin token unavailable.");
        var gid = await ResolveGroupIdAsync(roleName, token, ct);
        if (gid is null) throw new InvalidOperationException($"Business role group '{roleName}' does not exist.");
        var req = new HttpRequestMessage(HttpMethod.Put, $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(userId)}/groups/{Uri.EscapeDataString(gid)}");
        req.Headers.Add("Authorization", $"Bearer {token}");
        var res = await http.SendAsync(req, ct);
        if (!res.IsSuccessStatusCode)
            throw new InvalidOperationException($"Failed to add user '{userId}' to group '{roleName}': {(int)res.StatusCode} {await res.Content.ReadAsStringAsync(ct)}");
    }

    public async Task UnmapRealmRoleAsync(string userId, string roleName, CancellationToken ct)
    {
        var token = await GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return;
        var gid = await ResolveGroupIdAsync(roleName, token, ct);
        if (gid is null) return;
        var req = new HttpRequestMessage(HttpMethod.Delete, $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(userId)}/groups/{Uri.EscapeDataString(gid)}");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try { await http.SendAsync(req, ct); } catch { }
    }

    public async Task<IReadOnlyCollection<string>> GetUsersWithRealmRoleAsync(string roleName, CancellationToken ct)
    {
        // GET /groups/{id}/members — need group id first
        var token = await GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return Array.Empty<string>();
        var gid = await ResolveGroupIdAsync(roleName, token, ct);
        if (gid is null) return Array.Empty<string>();
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/groups/{Uri.EscapeDataString(gid)}/members?first=0&max=500");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return Array.Empty<string>();
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return Array.Empty<string>();
            return doc.RootElement.EnumerateArray()
                .Select(e => e.TryGetProperty("id", out var id) ? id.GetString() ?? "" : "")
                .Where(x => !string.IsNullOrEmpty(x))
                .ToArray();
        }
        catch { return Array.Empty<string>(); }
    }
}
