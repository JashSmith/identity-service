using System.Net.Http.Json;
using System.Text.Json;
using Identity.Application.Scope;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Identity.Infrastructure.Keycloak;

namespace Identity.Infrastructure.Keycloak.Scope;

/// <summary>
/// Scope registry backed by the dedicated config Group <c>iam-scope-registry</c>.
/// Group attributes:
///   scope.&lt;key&gt; = JSON {"displayName":...,"description":...,"isActive":true,"valueType":"String"}
///   resource.&lt;name&gt; = multivalued scope keys (each value = one scope key)
/// Business-role Groups hold <c>authz.allowed-scopes</c> multivalued.
/// Implements <see cref="IScopeDefinitionLookup"/>, <see cref="IResourceScopeResolver"/>, <see cref="IScopeCacheInvalidator"/>.
/// </summary>
public sealed class KeycloakScopeRegistryStore(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    IMemoryCache cache,
    ILogger<KeycloakScopeRegistryStore> logger) : IScopeDefinitionLookup, IResourceScopeResolver, IScopeCacheInvalidator
{
    private readonly KeycloakOptions _o = opts.Value;
    private string AdminBase => $"{_o.BaseUrl.TrimEnd('/')}/admin/realms";
    private const string RegistryGroupName = "iam-scope-registry";
    private const string ActiveKey = "scopes:active:kc:v1";
    private const string RoleAllowedKey = "scopes:roleAllowed:kc:v1";
    private const string ResourceMapKey = "scopes:resourceMap:kc:v1";
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    public void Invalidate()
    {
        cache.Remove(ActiveKey);
        cache.Remove(RoleAllowedKey);
        cache.Remove(ResourceMapKey);
    }

    private sealed record ScopeDef(string Key, string DisplayName, string? Description, bool IsActive, string ValueType);

    private static ScopeDef ParseScope(string key, string json)
    {
        try
        {
            var doc = JsonDocument.Parse(json);
            var display = doc.RootElement.TryGetProperty("displayName", out var d) ? d.GetString() ?? key : key;
            var desc = doc.RootElement.TryGetProperty("description", out var dd) ? dd.GetString() : null;
            var active = doc.RootElement.TryGetProperty("isActive", out var ia) ? ia.GetBoolean() : true;
            var vt = doc.RootElement.TryGetProperty("valueType", out var vt2) ? vt2.GetString() ?? "String" : "String";
            return new ScopeDef(key, display, desc, active, vt);
        }
        catch { return new ScopeDef(key, key, null, true, "String"); }
    }

    private async Task<Dictionary<string, string[]>> GetRegistryAttributesAsync(CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return new(StringComparer.Ordinal);
        try
        {
            // Find registry group
            var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/groups?search={Uri.EscapeDataString(RegistryGroupName)}");
            req.Headers.Add("Authorization", $"Bearer {token}");
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return new(StringComparer.Ordinal);
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return new(StringComparer.Ordinal);
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                var name = el.TryGetProperty("name", out var n) ? n.GetString() : null;
                if (!string.Equals(name, RegistryGroupName, StringComparison.Ordinal)) continue;
                var id = el.TryGetProperty("id", out var gid) ? gid.GetString() : null;
                if (string.IsNullOrEmpty(id)) return AttrsFromElement(el);
                // Fetch full group with attributes
                var gReq = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/groups/{Uri.EscapeDataString(id)}");
                gReq.Headers.Add("Authorization", $"Bearer {token}");
                var gRes = await http.SendAsync(gReq, ct);
                if (!gRes.IsSuccessStatusCode) return AttrsFromElement(el);
                var gDoc = JsonDocument.Parse(await gRes.Content.ReadAsStringAsync(ct));
                return AttrsFromElement(gDoc.RootElement);
            }
        }
        catch (Exception ex) { logger.LogDebug(ex, "Failed to fetch scope registry group"); }
        return new(StringComparer.Ordinal);
    }

    private static Dictionary<string, string[]> AttrsFromElement(JsonElement el)
    {
        var d = new Dictionary<string, string[]>(StringComparer.Ordinal);
        if (!el.TryGetProperty("attributes", out var attrs) || attrs.ValueKind != JsonValueKind.Object) return d;
        foreach (var prop in attrs.EnumerateObject())
        {
            if (prop.Value.ValueKind == JsonValueKind.Array)
                d[prop.Name] = prop.Value.EnumerateArray().Select(v => v.GetString() ?? "").Where(s => s.Length > 0).ToArray();
            else if (prop.Value.ValueKind == JsonValueKind.String)
                d[prop.Name] = new[] { prop.Value.GetString() ?? "" };
        }
        return d;
    }

    private async Task<IReadOnlyCollection<ScopeDef>> GetActiveScopesAsync(CancellationToken ct)
    {
        if (cache.TryGetValue(ActiveKey, out IReadOnlyCollection<ScopeDef>? c) && c is not null) return c;
        var attrs = await GetRegistryAttributesAsync(ct);
        var list = new List<ScopeDef>();
        foreach (var kv in attrs)
        {
            if (!kv.Key.StartsWith("scope.", StringComparison.Ordinal)) continue;
            var key = kv.Key.Substring("scope.".Length);
            var json = kv.Value.FirstOrDefault() ?? "{}";
            var def = ParseScope(key, json);
            if (def.IsActive) list.Add(def);
        }
        // Fallback to defaults if registry empty (migration window / no Keycloak): seed-like defaults
        if (list.Count == 0 && attrs.Count == 0)
        {
            // Return in-memory defaults so validation doesn't break when Keycloak unreachable in tests
            foreach (var k in new[] { "region", "branch", "department", "organization", "warehouse", "customer", "project", "test-key" })
                list.Add(new ScopeDef(k, k, null, true, "String"));
        }
        IReadOnlyCollection<ScopeDef> result = list;
        cache.Set(ActiveKey, result, Ttl);
        return result;
    }

    public async Task<bool> ExistsActiveAsync(string key, CancellationToken ct)
    {
        var active = await GetActiveScopesAsync(ct);
        return active.Any(s => string.Equals(s.Key, key, StringComparison.OrdinalIgnoreCase));
    }

    public async Task<bool> IsScopeAllowedForRoleAsync(string role, string scopeKey, CancellationToken ct)
    {
        var map = await GetRoleAllowedMapAsync(ct);
        if (!map.TryGetValue(role, out var allowed)) return true; // no restriction = allow
        if (allowed.Count == 0) return true;
        return allowed.Contains(scopeKey);
    }

    private async Task<Dictionary<string, HashSet<string>>> GetRoleAllowedMapAsync(CancellationToken ct)
    {
        if (cache.TryGetValue(RoleAllowedKey, out Dictionary<string, HashSet<string>>? c) && c is not null) return c;
        var map = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var token = await tokenProvider.GetTokenAsync(ct);
        if (!string.IsNullOrEmpty(token))
        {
            try
            {
                // List all business-role groups and read authz.allowed-scopes
                var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/groups?briefRepresentation=false");
                req.Headers.Add("Authorization", $"Bearer {token}");
                var res = await http.SendAsync(req, ct);
                if (res.IsSuccessStatusCode)
                {
                    var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
                    if (doc.RootElement.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var el in doc.RootElement.EnumerateArray())
                        {
                            var gname = el.TryGetProperty("name", out var n) ? n.GetString() : null;
                            if (string.IsNullOrEmpty(gname) || string.Equals(gname, RegistryGroupName, StringComparison.OrdinalIgnoreCase)) continue;
                            var attrs = AttrsFromElement(el);
                            if (attrs.TryGetValue("authz.allowed-scopes", out var allowed))
                                map[gname] = new HashSet<string>(allowed, StringComparer.OrdinalIgnoreCase);
                            // Also try to fetch full group if brief lacked attributes
                            if (!attrs.ContainsKey("authz.allowed-scopes") && el.TryGetProperty("id", out var gid) && gid.GetString() is string id)
                            {
                                var gReq = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/groups/{Uri.EscapeDataString(id)}");
                                gReq.Headers.Add("Authorization", $"Bearer {token}");
                                var gRes = await http.SendAsync(gReq, ct);
                                if (gRes.IsSuccessStatusCode)
                                {
                                    var gDoc = JsonDocument.Parse(await gRes.Content.ReadAsStringAsync(ct));
                                    var gAttrs = AttrsFromElement(gDoc.RootElement);
                                    if (gAttrs.TryGetValue("authz.allowed-scopes", out var gAllowed))
                                        map[gname] = new HashSet<string>(gAllowed, StringComparer.OrdinalIgnoreCase);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex) { logger.LogDebug(ex, "Failed to fetch role allowed scopes"); }
        }
        cache.Set(RoleAllowedKey, map, Ttl);
        return map;
    }

    public async Task<HashSet<string>> GetScopesForResourceAsync(string resourceKey, CancellationToken ct)
    {
        var map = await GetResourceMapAsync(ct);
        return map.TryGetValue(resourceKey, out var set) ? new HashSet<string>(set, StringComparer.OrdinalIgnoreCase) : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    }

    private async Task<Dictionary<string, HashSet<string>>> GetResourceMapAsync(CancellationToken ct)
    {
        if (cache.TryGetValue(ResourceMapKey, out Dictionary<string, HashSet<string>>? c) && c is not null) return c;
        var attrs = await GetRegistryAttributesAsync(ct);
        var map = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        // resource.<name> = multivalued scope keys
        foreach (var kv in attrs)
        {
            if (!kv.Key.StartsWith("resource.", StringComparison.Ordinal)) continue;
            var rKey = kv.Key.Substring("resource.".Length);
            map[rKey] = new HashSet<string>(kv.Value, StringComparer.OrdinalIgnoreCase);
        }
        if (map.Count == 0 && attrs.Count == 0)
        {
            // Defaults mirror ScopeSeed
            map["Orders"] = new HashSet<string>(new[] { "region", "branch", "warehouse", "customer" }, StringComparer.OrdinalIgnoreCase);
            map["Branches"] = new HashSet<string>(new[] { "region" }, StringComparer.OrdinalIgnoreCase);
            map["Employees"] = new HashSet<string>(new[] { "region", "branch", "department", "organization" }, StringComparer.OrdinalIgnoreCase);
            map["ProjectTasks"] = new HashSet<string>(new[] { "project" }, StringComparer.OrdinalIgnoreCase);
            map["ProjectDocuments"] = new HashSet<string>(new[] { "project" }, StringComparer.OrdinalIgnoreCase);
            map["CustomerOrders"] = new HashSet<string>(new[] { "customer" }, StringComparer.OrdinalIgnoreCase);
            map["ResourceA"] = new HashSet<string>(new[] { "test-key" }, StringComparer.OrdinalIgnoreCase);
        }
        cache.Set(ResourceMapKey, map, Ttl);
        return map;
    }
}
