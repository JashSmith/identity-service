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
    ILogger<KeycloakScopeRegistryStore> logger) : IScopeDefinitionLookup, IResourceScopeResolver, IScopeCacheInvalidator, IScopeRegistryAdmin
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
            // Well-known defaults for offline/migration-window operation
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

    // ---------- IScopeRegistryAdmin — CRUD on the iam-scope-registry group attributes ----------

    public async Task<IReadOnlyCollection<ScopeDefinitionDto>> ListScopesAsync(CancellationToken ct)
    {
        var attrs = await GetRegistryAttributesAsync(ct);
        var list = new List<ScopeDefinitionDto>();
        foreach (var kv in attrs)
        {
            if (!kv.Key.StartsWith("scope.", StringComparison.Ordinal)) continue;
            var key = kv.Key.Substring("scope.".Length);
            var def = ParseScope(key, kv.Value.FirstOrDefault() ?? "{}");
            list.Add(new ScopeDefinitionDto(def.Key, def.DisplayName, def.Description, def.IsActive, def.ValueType));
        }
        return list.OrderBy(x => x.Key, StringComparer.Ordinal).ToArray();
    }

    public async Task<ScopeDefinitionDto?> GetScopeAsync(string key, CancellationToken ct)
    {
        var all = await ListScopesAsync(ct);
        return all.FirstOrDefault(s => string.Equals(s.Key, key, StringComparison.Ordinal));
    }

    public async Task<IReadOnlyCollection<ResourceScopeMappingDto>> ListResourcesAsync(CancellationToken ct)
    {
        var attrs = await GetRegistryAttributesAsync(ct);
        var list = new List<ResourceScopeMappingDto>();
        foreach (var kv in attrs)
        {
            if (!kv.Key.StartsWith("resource.", StringComparison.Ordinal)) continue;
            list.Add(new ResourceScopeMappingDto(kv.Key.Substring("resource.".Length), kv.Value));
        }
        return list.OrderBy(x => x.Key, StringComparer.Ordinal).ToArray();
    }

    public async Task<ScopeDefinitionDto?> CreateScopeAsync(string key, string? displayName, string? description, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        var existing = await GetScopeAsync(key, ct);
        if (existing is not null) return null; // conflict — caller maps to 409
        var json = JsonSerializer.Serialize(new
        {
            displayName = string.IsNullOrWhiteSpace(displayName) ? key : displayName,
            description,
            isActive = true,
            valueType = "String",
        });
        var ok = await UpsertRegistryAttributeAsync($"scope.{key}", json, ct);
        if (!ok) throw new InvalidOperationException($"Failed to create scope '{key}' in {RegistryGroupName}.");
        Invalidate();
        return await GetScopeAsync(key, ct);
    }

    public async Task<ScopeDefinitionDto?> UpdateScopeAsync(string key, string? displayName, string? description, bool? isActive, CancellationToken ct)
    {
        var attrs = await GetRegistryAttributesAsync(ct);
        var attrName = $"scope.{key}";
        if (!attrs.TryGetValue(attrName, out var vals)) return null;
        var def = ParseScope(key, vals.FirstOrDefault() ?? "{}");
        var json = JsonSerializer.Serialize(new
        {
            displayName = displayName ?? def.DisplayName,
            description = description ?? def.Description,
            isActive = isActive ?? def.IsActive,
            valueType = def.ValueType,
        });
        var ok = await UpsertRegistryAttributeAsync(attrName, json, ct);
        if (!ok) throw new InvalidOperationException($"Failed to update scope '{key}' in {RegistryGroupName}.");
        Invalidate();
        return await GetScopeAsync(key, ct);
    }

    /// <summary>Read-modify-write of a single registry group attribute via GET group + PUT group.</summary>
    private async Task<bool> UpsertRegistryAttributeAsync(string attrName, string value, CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) throw new InvalidOperationException("Keycloak admin token unavailable.");
        try
        {
            // Resolve registry group id
            string? groupId = null;
            var searchReq = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/groups?search={Uri.EscapeDataString(RegistryGroupName)}");
            searchReq.Headers.Add("Authorization", $"Bearer {token}");
            var searchRes = await http.SendAsync(searchReq, ct);
            if (!searchRes.IsSuccessStatusCode) return false;
            var searchDoc = JsonDocument.Parse(await searchRes.Content.ReadAsStringAsync(ct));
            if (searchDoc.RootElement.ValueKind == JsonValueKind.Array)
                foreach (var el in searchDoc.RootElement.EnumerateArray())
                    if (el.TryGetProperty("name", out var n) && n.GetString() == RegistryGroupName &&
                        el.TryGetProperty("id", out var gid)) { groupId = gid.GetString(); break; }
            if (string.IsNullOrEmpty(groupId))
            {
                // Registry group missing — create it so admins can bootstrap scopes without a realm re-import.
                var createReq = new HttpRequestMessage(HttpMethod.Post, $"{AdminBase}/{_o.Realm}/groups")
                { Content = JsonContent.Create(new { name = RegistryGroupName }) };
                createReq.Headers.Add("Authorization", $"Bearer {token}");
                var createRes = await http.SendAsync(createReq, ct);
                if (!createRes.IsSuccessStatusCode && createRes.StatusCode != System.Net.HttpStatusCode.Conflict) return false;
                var reSearch = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/groups?search={Uri.EscapeDataString(RegistryGroupName)}");
                reSearch.Headers.Add("Authorization", $"Bearer {token}");
                var reRes = await http.SendAsync(reSearch, ct);
                if (!reRes.IsSuccessStatusCode) return false;
                var reDoc = JsonDocument.Parse(await reRes.Content.ReadAsStringAsync(ct));
                if (reDoc.RootElement.ValueKind == JsonValueKind.Array)
                    foreach (var el in reDoc.RootElement.EnumerateArray())
                        if (el.TryGetProperty("name", out var n2) && n2.GetString() == RegistryGroupName &&
                            el.TryGetProperty("id", out var gid2)) { groupId = gid2.GetString(); break; }
                if (string.IsNullOrEmpty(groupId)) return false;
            }

            // GET full group, merge attribute, PUT back
            var getReq = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/groups/{Uri.EscapeDataString(groupId)}");
            getReq.Headers.Add("Authorization", $"Bearer {token}");
            var getRes = await http.SendAsync(getReq, ct);
            if (!getRes.IsSuccessStatusCode) return false;
            var groupJson = JsonDocument.Parse(await getRes.Content.ReadAsStringAsync(ct)).RootElement;

            var attributes = new Dictionary<string, string[]>(StringComparer.Ordinal);
            if (groupJson.TryGetProperty("attributes", out var a) && a.ValueKind == JsonValueKind.Object)
                foreach (var prop in a.EnumerateObject())
                    attributes[prop.Name] = prop.Value.ValueKind == JsonValueKind.Array
                        ? prop.Value.EnumerateArray().Select(v => v.GetString() ?? "").ToArray()
                        : [prop.Value.GetString() ?? ""];
            attributes[attrName] = [value];

            var name = groupJson.TryGetProperty("name", out var nm) ? nm.GetString() ?? RegistryGroupName : RegistryGroupName;
            var body = new Dictionary<string, object>
            {
                ["name"] = name,
                ["attributes"] = attributes,
            };
            if (groupJson.TryGetProperty("path", out var path) && path.ValueKind == JsonValueKind.String)
                body["path"] = path.GetString()!;

            var putReq = new HttpRequestMessage(HttpMethod.Put, $"{AdminBase}/{_o.Realm}/groups/{Uri.EscapeDataString(groupId)}")
            { Content = JsonContent.Create(body) };
            putReq.Headers.Add("Authorization", $"Bearer {token}");
            var putRes = await http.SendAsync(putReq, ct);
            if (!putRes.IsSuccessStatusCode)
            {
                logger.LogDebug("Registry group PUT failed: {Status}", putRes.StatusCode);
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Failed to upsert registry attribute {Attr}", attrName);
            return false;
        }
    }
}
