using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Identity.Application;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Client-role provisioner: owns the per-service client, its client roles,
/// the per-client oidc-usermodel-client-role-mapper → permissions claim,
/// and the Admin-group auto-mapping (so Admin never needs manual role grant
/// nor re-login — refresh picks up new resource_access then normalized claim).
/// All operations idempotent; best-effort, never throws.
/// </summary>
public sealed class KeycloakClientRoleProvisioner(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakClientRoleProvisioner> logger) : IKeycloakClientRoleProvisioner
{
    private readonly KeycloakOptions _o = opts.Value;
    private string AdminBase => $"{_o.BaseUrl.TrimEnd('/')}/admin/realms";
    private const string AdminGroupName = "key-admins";
    private const string MapperName = "permission-client-role-mapper";

    private async Task<string> TokenAsync(CancellationToken ct) => await tokenProvider.GetTokenAsync(ct) ?? string.Empty;

    public async Task<string> EnsureClientAsync(string serviceClientId, CancellationToken ct)
    {
        var token = await TokenAsync(ct);
        if (string.IsNullOrEmpty(token) || string.IsNullOrWhiteSpace(serviceClientId)) return string.Empty;

        var uuid = await ResolveClientUuidAsync(serviceClientId, token, ct);
        if (!string.IsNullOrEmpty(uuid)) return uuid;

        // Create bare client idempotently
        try
        {
            var body = new
            {
                clientId = serviceClientId,
                name = serviceClientId,
                enabled = true,
                protocol = "openid-connect",
                publicClient = false,
                serviceAccountsEnabled = false,
                standardFlowEnabled = false,
                directAccessGrantsEnabled = false,
            };
            var req = new HttpRequestMessage(HttpMethod.Post, $"{AdminBase}/{_o.Realm}/clients")
            {
                Content = JsonContent.Create(body)
            };
            req.Headers.Add("Authorization", $"Bearer {token}");
            var res = await http.SendAsync(req, ct);
            if (res.IsSuccessStatusCode || res.StatusCode == HttpStatusCode.Conflict)
            {
                // 201 gives Location; Conflict means race — re-resolve
                if (res.Headers.Location is not null)
                {
                    var last = res.Headers.Location.ToString().Split('/').LastOrDefault()?.Trim();
                    if (!string.IsNullOrEmpty(last)) return last;
                }
                return await ResolveClientUuidAsync(serviceClientId, token, ct) ?? string.Empty;
            }
            logger.LogWarning("EnsureClient {ClientId} failed: {Status}", serviceClientId, res.StatusCode);
        }
        catch (Exception ex) { logger.LogDebug(ex, "EnsureClient {ClientId} error", serviceClientId); }
        return string.Empty;
    }

    public async Task<bool> EnsureClientRoleAsync(string serviceClientId, string roleName, string? description, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(roleName)) return false;
        var token = await TokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return false;
        var uuid = await EnsureClientAsync(serviceClientId, ct);
        if (string.IsNullOrEmpty(uuid)) return false;

        // Fast-path: GET role
        try
        {
            var get = new HttpRequestMessage(HttpMethod.Get,
                $"{AdminBase}/{_o.Realm}/clients/{Uri.EscapeDataString(uuid)}/roles/{Uri.EscapeDataString(roleName)}");
            get.Headers.Add("Authorization", $"Bearer {token}");
            var got = await http.SendAsync(get, ct);
            if (got.IsSuccessStatusCode) return true;
        }
        catch (Exception ex) { logger.LogDebug(ex, "Check client role {Role}", roleName); }

        try
        {
            var body = new { name = roleName, description = description ?? $"Permission: {roleName}" };
            var post = new HttpRequestMessage(HttpMethod.Post,
                $"{AdminBase}/{_o.Realm}/clients/{Uri.EscapeDataString(uuid)}/roles")
            { Content = JsonContent.Create(body) };
            post.Headers.Add("Authorization", $"Bearer {token}");
            var res = await http.SendAsync(post, ct);
            if (res.IsSuccessStatusCode || res.StatusCode == HttpStatusCode.Conflict) return true;
            logger.LogWarning("EnsureClientRole {Role} on {Client} failed: {Status}", roleName, serviceClientId, res.StatusCode);
            return false;
        }
        catch (Exception ex) { logger.LogDebug(ex, "Create client role {Role}", roleName); return false; }
    }

    public async Task EnsureClientRoleMapperAsync(string serviceClientId, CancellationToken ct)
    {
        var token = await TokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return;
        var uuid = await EnsureClientAsync(serviceClientId, ct);
        if (string.IsNullOrEmpty(uuid)) return;
        try
        {
            var list = new HttpRequestMessage(HttpMethod.Get,
                $"{AdminBase}/{_o.Realm}/clients/{Uri.EscapeDataString(uuid)}/protocol-mappers/models");
            list.Headers.Add("Authorization", $"Bearer {token}");
            var res = await http.SendAsync(list, ct);
            if (res.IsSuccessStatusCode)
            {
                var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
                if (doc.RootElement.ValueKind == JsonValueKind.Array)
                    foreach (var el in doc.RootElement.EnumerateArray())
                        if (el.TryGetProperty("name", out var n) && n.GetString() == MapperName)
                            return;
            }
            var body = new
            {
                name = MapperName,
                protocol = "openid-connect",
                protocolMapper = "oidc-usermodel-client-role-mapper",
                config = new Dictionary<string, string>
                {
                    ["claim.name"] = "permissions",
                    ["jsonType.label"] = "String",
                    ["multivalued"] = "true",
                    ["userinfo.token.claim"] = "true",
                    ["access.token.claim"] = "true",
                    ["id.token.claim"] = "false",
                    // emit clientId claim so consumers can tell owner if needed
                    ["usermodel.clientRoleMapping.clientId"] = serviceClientId,
                }
            };
            var post = new HttpRequestMessage(HttpMethod.Post,
                $"{AdminBase}/{_o.Realm}/clients/{Uri.EscapeDataString(uuid)}/protocol-mappers/models")
            { Content = JsonContent.Create(body) };
            post.Headers.Add("Authorization", $"Bearer {token}");
            var created = await http.SendAsync(post, ct);
            if (!created.IsSuccessStatusCode)
                logger.LogDebug("Ensure mapper for {Client} failed: {Status} {Body}", serviceClientId, created.StatusCode, await created.Content.ReadAsStringAsync(ct));
            else
                logger.LogInformation("Provisioned client-role mapper for {Client}", serviceClientId);
        }
        catch (Exception ex) { logger.LogDebug(ex, "Ensure mapper for {Client}", serviceClientId); }
    }

    public async Task<bool> EnsureAdminGroupMappingAsync(string serviceClientId, string roleName, CancellationToken ct)
    {
        var token = await TokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return false;
        var clientUuid = await EnsureClientAsync(serviceClientId, ct);
        if (string.IsNullOrEmpty(clientUuid)) return false;
        var groupId = await ResolveGroupIdAsync(AdminGroupName, token, ct);
        if (string.IsNullOrEmpty(groupId)) { logger.LogDebug("Admin group {Name} not found", AdminGroupName); return false; }
        var role = await GetClientRoleAsync(clientUuid, roleName, token, ct);
        if (role is null) return false;
        try
        {
            var body = new[] { new { id = role.Value.Id, name = role.Value.Name } };
            var req = new HttpRequestMessage(HttpMethod.Post,
                $"{AdminBase}/{_o.Realm}/groups/{Uri.EscapeDataString(groupId)}/role-mappings/clients/{Uri.EscapeDataString(clientUuid)}")
            { Content = JsonContent.Create(body) };
            req.Headers.Add("Authorization", $"Bearer {token}");
            var res = await http.SendAsync(req, ct);
            return res.IsSuccessStatusCode;
        }
        catch (Exception ex) { logger.LogDebug(ex, "Map role {Role} to admin group", roleName); return false; }
    }

    public async Task<int> ReconcileAdminAsync(CancellationToken ct)
    {
        var token = await TokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return 0;
        var groupId = await ResolveGroupIdAsync(AdminGroupName, token, ct);
        if (string.IsNullOrEmpty(groupId)) return 0;
        int added = 0;
        try
        {
            // Enumerate all clients (paged)
            var listReq = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/clients?first=0&max=200");
            listReq.Headers.Add("Authorization", $"Bearer {token}");
            var listRes = await http.SendAsync(listReq, ct);
            if (!listRes.IsSuccessStatusCode) return 0;
            var doc = JsonDocument.Parse(await listRes.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return 0;
            foreach (var c in doc.RootElement.EnumerateArray())
            {
                var clientUuid = c.TryGetProperty("id", out var id) ? id.GetString() : null;
                var clientId = c.TryGetProperty("clientId", out var cid) ? cid.GetString() : null;
                if (string.IsNullOrEmpty(clientUuid) || string.IsNullOrEmpty(clientId)) continue;
                // List roles for this client
                var rolesReq = new HttpRequestMessage(HttpMethod.Get,
                    $"{AdminBase}/{_o.Realm}/clients/{Uri.EscapeDataString(clientUuid)}/roles");
                rolesReq.Headers.Add("Authorization", $"Bearer {token}");
                var rolesRes = await http.SendAsync(rolesReq, ct);
                if (!rolesRes.IsSuccessStatusCode) continue;
                var rdoc = JsonDocument.Parse(await rolesRes.Content.ReadAsStringAsync(ct));
                if (rdoc.RootElement.ValueKind != JsonValueKind.Array) continue;
                // Fetch current admin client mappings to diff
                var mapped = await GetGroupClientRolesAsync(groupId, clientUuid, token, ct);
                var mappedSet = new HashSet<string>(mapped, StringComparer.Ordinal);
                foreach (var r in rdoc.RootElement.EnumerateArray())
                {
                    var rid = r.TryGetProperty("id", out var pid) ? pid.GetString() ?? "" : "";
                    var rname = r.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                    if (string.IsNullOrEmpty(rname) || mappedSet.Contains(rname)) continue;
                    var body = new[] { new { id = rid, name = rname } };
                    var mapReq = new HttpRequestMessage(HttpMethod.Post,
                        $"{AdminBase}/{_o.Realm}/groups/{Uri.EscapeDataString(groupId)}/role-mappings/clients/{Uri.EscapeDataString(clientUuid)}")
                    { Content = JsonContent.Create(body) };
                    mapReq.Headers.Add("Authorization", $"Bearer {token}");
                    var mapRes = await http.SendAsync(mapReq, ct);
                    if (mapRes.IsSuccessStatusCode) added++;
                }
            }
        }
        catch (Exception ex) { logger.LogDebug(ex, "ReconcileAdmin failed"); }
        return added;
    }

    private async Task<string?> ResolveClientUuidAsync(string clientId, string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/clients?clientId={Uri.EscapeDataString(clientId)}");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return null;
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind == JsonValueKind.Array && doc.RootElement.GetArrayLength() > 0)
                return doc.RootElement[0].TryGetProperty("id", out var id) ? id.GetString() : null;
            return null;
        }
        catch { return null; }
    }

    private async Task<string?> ResolveGroupIdAsync(string name, string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/groups?search={Uri.EscapeDataString(name)}");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return null;
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return null;
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                var gname = el.TryGetProperty("name", out var n) ? n.GetString() : null;
                if (string.Equals(gname, name, StringComparison.Ordinal))
                    return el.TryGetProperty("id", out var gid) ? gid.GetString() : null;
            }
            return null;
        }
        catch { return null; }
    }

    private async Task<(string Id, string Name)?> GetClientRoleAsync(string clientUuid, string roleName, string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get,
            $"{AdminBase}/{_o.Realm}/clients/{Uri.EscapeDataString(clientUuid)}/roles/{Uri.EscapeDataString(roleName)}");
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

    private async Task<IReadOnlyCollection<string>> GetGroupClientRolesAsync(string groupId, string clientUuid, string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get,
            $"{AdminBase}/{_o.Realm}/groups/{Uri.EscapeDataString(groupId)}/role-mappings/clients/{Uri.EscapeDataString(clientUuid)}");
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
}
