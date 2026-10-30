using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Identity.Application;
using Identity.Application.Scope;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak.Scope;

/// <summary>
/// Scope registry backed by the reserved group <c>iam-scope-registry</c>. Group attributes:
///   scope.&lt;key&gt; = JSON {"displayName","description","isActive","valueType"} (split into 200-byte chunks)
///   resource.&lt;name&gt; = multivalued scope keys
/// Business-role groups restrict usable scopes with <c>authz.allowed-scopes</c>.
/// Reads are cached in memory and, when configured, in Redis; every failure to read Keycloak is an error,
/// so validation fails closed instead of accepting scopes it could not check.
/// </summary>
public sealed class KeycloakScopeRegistryStore(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    IMemoryCache cache,
    ILogger<KeycloakScopeRegistryStore> logger,
    IScopeAttributeProvisioner provisioner,
    IDistributedCache? distributed = null)
    : IScopeDefinitionLookup, IResourceScopeResolver, IScopeCacheInvalidator, IScopeRegistryAdmin
{
    private const string RegistryGroupName = ReservedGroups.ScopeRegistry;
    private const string Resource = "scope";
    private const string ScopePrefix = "scope.";
    private const string ResourcePrefix = "resource.";
    private const string AllowedScopesAttribute = "authz.allowed-scopes";
    private const string RegistryCacheKey = "scopes:registry:kc:v2";
    private const string RoleAllowedKey = "scopes:roleAllowed:kc:v2";
    private const string RedisPrefix = "identity:registry:";
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    private readonly KeycloakAdminApi _api = new(http, opts.Value, tokenProvider, logger);

    /// <summary>
    /// Non-ASCII characters are written raw instead of <c>\uXXXX</c> escapes, which would
    /// inflate Persian/Arabic text sixfold — Keycloak caps GROUP_ATTRIBUTE.VALUE at 255 bytes.
    /// </summary>
    private static readonly JsonSerializerOptions CompactJson = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary>
    /// Keycloak stores each attribute value in a VARCHAR(255) column. Long definitions are
    /// split across the multivalued attribute and rejoined on read.
    /// </summary>
    private const int AttributeChunkBytes = 200;

    private static Error ScopeNotFound(string key) => Error.NotFound("scope.not_found", $"Scope '{key}' was not found.");

    internal static string[] ChunkAttributeValue(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        if (bytes.Length <= AttributeChunkBytes) return [value];
        var chunks = new List<string>();
        var start = 0;
        while (start < bytes.Length)
        {
            var len = Math.Min(AttributeChunkBytes, bytes.Length - start);
            // Never split a multi-byte UTF-8 sequence: back off until not on a continuation byte.
            while (len > 1 && start + len < bytes.Length && (bytes[start + len] & 0xC0) == 0x80) len--;
            chunks.Add(Encoding.UTF8.GetString(bytes, start, len));
            start += len;
        }
        return chunks.ToArray();
    }

    // ---------- cache ----------

    public void Invalidate()
    {
        cache.Remove(RegistryCacheKey);
        cache.Remove(RoleAllowedKey);
        if (distributed is null) return;
        try
        {
            distributed.Remove(RedisPrefix + RegistryCacheKey);
            distributed.Remove(RedisPrefix + RoleAllowedKey);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Other replicas keep their copy until it expires (5 minutes); reported, not fatal.
            logger.LogWarning(ex, "Could not invalidate the shared scope registry cache");
        }
    }

    private async Task<Result<T>> CachedAsync<T>(string key, Func<CancellationToken, Task<Result<T>>> load, CancellationToken ct) where T : class
    {
        if (cache.TryGetValue(key, out T? local) && local is not null) return local;
        if (ReadShared<T>(key) is { } shared)
        {
            cache.Set(key, shared, Ttl);
            return shared;
        }

        var loaded = await load(ct);
        if (!loaded.IsSuccess) return loaded;
        cache.Set(key, loaded.Value, Ttl);
        WriteShared(key, loaded.Value);
        return loaded;
    }

    private T? ReadShared<T>(string key) where T : class
    {
        if (distributed is null) return null;
        try
        {
            var raw = distributed.GetString(RedisPrefix + key);
            return string.IsNullOrEmpty(raw) ? null : JsonSerializer.Deserialize<T>(raw);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Shared scope registry cache unreadable for {Key}; reading Keycloak", key);
            return null;
        }
    }

    private void WriteShared(string key, object value)
    {
        if (distributed is null) return;
        try
        {
            distributed.SetString(RedisPrefix + key, JsonSerializer.Serialize(value),
                new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = Ttl });
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Could not write the shared scope registry cache for {Key}", key);
        }
    }

    // ---------- registry reads ----------

    /// <summary>The registry group's attributes; the group is created when missing.</summary>
    private Task<Result<Dictionary<string, string[]>>> GetRegistryAsync(CancellationToken ct) =>
        CachedAsync(RegistryCacheKey, async token =>
        {
            var group = await GetRegistryGroupAsync(token);
            return group.IsSuccess ? Result<Dictionary<string, string[]>>.Success(Attributes(group.Value)) : group.Error!;
        }, ct);

    private async Task<Result<JsonElement>> GetRegistryGroupAsync(CancellationToken ct)
    {
        var id = await GetRegistryGroupIdAsync(ct);
        if (!id.IsSuccess) return id.Error!;
        return await _api.GetAsync($"groups/{Uri.EscapeDataString(id.Value)}", Resource, ct);
    }

    private async Task<Result<string>> GetRegistryGroupIdAsync(CancellationToken ct)
    {
        var found = await FindRegistryGroupIdAsync(ct);
        if (!found.IsSuccess) return found.Error!;
        if (found.Value is not null) return found.Value;

        // Missing registry: create it so admins can bootstrap scopes without a realm re-import.
        var created = await _api.CreateAsync("groups", new { name = RegistryGroupName }, Resource, ct);
        if (created.IsSuccess) return created.Value;
        if (created.Error!.Kind != ErrorKind.Conflict) return created.Error;
        var again = await FindRegistryGroupIdAsync(ct);
        if (!again.IsSuccess) return again.Error!;
        if (again.Value is not null) return again.Value;
        return created.Error;
    }

    private async Task<Result<string?>> FindRegistryGroupIdAsync(CancellationToken ct)
    {
        var found = await _api.GetAsync($"groups?search={Uri.EscapeDataString(RegistryGroupName)}&exact=true&briefRepresentation=true", Resource, ct);
        if (!found.IsSuccess) return found.Error!;
        return found.Value.EnumerateArray()
            .Where(g => KeycloakAdminApi.GetString(g, "name") == RegistryGroupName)
            .Select(g => KeycloakAdminApi.GetString(g, "id"))
            .FirstOrDefault();
    }

    private IEnumerable<ScopeDefinitionDto> Definitions(Dictionary<string, string[]> registry) =>
        registry.Where(kv => kv.Key.StartsWith(ScopePrefix, StringComparison.Ordinal))
            .Select(kv => ParseScope(kv.Key[ScopePrefix.Length..], string.Concat(kv.Value)))
            .OrderBy(s => s.Key, StringComparer.Ordinal);

    private ScopeDefinitionDto ParseScope(string key, string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            return new ScopeDefinitionDto(key,
                KeycloakAdminApi.GetString(root, "displayName") ?? key,
                KeycloakAdminApi.GetString(root, "description"),
                !root.TryGetProperty("isActive", out var active) || active.ValueKind != JsonValueKind.False,
                KeycloakAdminApi.GetString(root, "valueType") ?? "String");
        }
        catch (JsonException ex)
        {
            // The key exists but its definition is unreadable: keep it usable under its key and report it.
            logger.LogWarning(ex, "Scope '{Key}' has an unreadable definition in {Group}", key, RegistryGroupName);
            return new ScopeDefinitionDto(key, key, null, true, "String");
        }
    }

    private static IEnumerable<ResourceScopeMappingDto> Resources(Dictionary<string, string[]> registry) =>
        registry.Where(kv => kv.Key.StartsWith(ResourcePrefix, StringComparison.Ordinal))
            .Select(kv => new ResourceScopeMappingDto(kv.Key[ResourcePrefix.Length..], kv.Value))
            .OrderBy(r => r.Key, StringComparer.Ordinal);

    // ---------- IScopeDefinitionLookup / IResourceScopeResolver ----------

    public async Task<Result<bool>> ExistsActiveAsync(string key, CancellationToken ct)
    {
        var registry = await GetRegistryAsync(ct);
        if (!registry.IsSuccess) return registry.Error!;
        return Definitions(registry.Value).Any(s => s.IsActive && string.Equals(s.Key, key, StringComparison.OrdinalIgnoreCase));
    }

    public async Task<Result<bool>> IsScopeAllowedForRoleAsync(string role, string scopeKey, CancellationToken ct)
    {
        var map = await CachedAsync(RoleAllowedKey, LoadRoleAllowedAsync, ct);
        if (!map.IsSuccess) return map.Error!;
        // A role without authz.allowed-scopes restricts nothing.
        return !map.Value.TryGetValue(role, out var allowed) || allowed.Length == 0 ||
               allowed.Contains(scopeKey, StringComparer.OrdinalIgnoreCase);
    }

    private async Task<Result<Dictionary<string, string[]>>> LoadRoleAllowedAsync(CancellationToken ct)
    {
        var groups = await _api.GetAllAsync("groups?briefRepresentation=false", Resource, ct);
        if (!groups.IsSuccess) return groups.Error!;
        var map = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in groups.Value)
        {
            var name = KeycloakAdminApi.GetString(group, "name");
            if (string.IsNullOrEmpty(name) || ReservedGroups.IsReserved(name)) continue;
            if (Attributes(group).TryGetValue(AllowedScopesAttribute, out var allowed)) map[name] = allowed;
        }
        return map;
    }

    /// <summary>Scope keys that filter <paramref name="resourceKey"/>; registry outages are raised, never "no scopes".</summary>
    public async Task<HashSet<string>> GetScopesForResourceAsync(string resourceKey, CancellationToken ct)
    {
        var registry = await GetRegistryAsync(ct);
        if (!registry.IsSuccess) throw new ErrorException(registry.Error!);
        var mapping = Resources(registry.Value).FirstOrDefault(r => string.Equals(r.Key, resourceKey, StringComparison.OrdinalIgnoreCase));
        return new HashSet<string>(mapping?.Scopes ?? [], StringComparer.OrdinalIgnoreCase);
    }

    // ---------- IScopeRegistryAdmin ----------

    public async Task<Result<IReadOnlyCollection<ScopeDefinitionDto>>> ListScopesAsync(CancellationToken ct)
    {
        var registry = await GetRegistryAsync(ct);
        return registry.IsSuccess ? Definitions(registry.Value).ToArray() : registry.Error!;
    }

    public async Task<Result<ScopeDefinitionDto>> GetScopeAsync(string key, CancellationToken ct)
    {
        var registry = await GetRegistryAsync(ct);
        if (!registry.IsSuccess) return registry.Error!;
        var scope = Definitions(registry.Value).FirstOrDefault(s => string.Equals(s.Key, key, StringComparison.Ordinal));
        return scope is null ? ScopeNotFound(key) : scope;
    }

    public async Task<Result<IReadOnlyCollection<ResourceScopeMappingDto>>> ListResourcesAsync(CancellationToken ct)
    {
        var registry = await GetRegistryAsync(ct);
        return registry.IsSuccess ? Resources(registry.Value).ToArray() : registry.Error!;
    }

    public async Task<Result<IReadOnlyCollection<string>>> GetResourcesForScopeAsync(string key, CancellationToken ct)
    {
        var scope = await GetScopeAsync(key, ct);
        if (!scope.IsSuccess) return scope.Error!;
        var registry = await GetRegistryAsync(ct);
        if (!registry.IsSuccess) return registry.Error!;
        return Resources(registry.Value).Where(r => r.Scopes.Contains(key, StringComparer.OrdinalIgnoreCase))
            .Select(r => r.Key).ToArray();
    }

    public async Task<Result<ScopeDefinitionDto>> CreateScopeAsync(
        string key, string? displayName, string? description, IReadOnlyCollection<string>? resources, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        var definition = SerializeDefinition(string.IsNullOrWhiteSpace(displayName) ? key : displayName, description, true, "String");

        // Definition and resource mappings are written together in one PUT.
        var written = await ModifyRegistryAsync(attributes =>
        {
            if (attributes.ContainsKey(ScopePrefix + key))
                return Error.Conflict("scope.already_exists", $"Scope '{key}' already exists.");
            attributes[ScopePrefix + key] = ChunkAttributeValue(definition);
            SetResources(attributes, key, resources ?? []);
            return Result.Success();
        }, ct);
        if (!written.IsSuccess) return written.Error!;

        // Without the profile declaration and the claim mapper the scope would be silently unusable,
        // so a failure there removes the scope again.
        var provisioned = await ProvisionAllKeysAsync(ct);
        if (!provisioned.IsSuccess)
        {
            var removed = await ModifyRegistryAsync(attributes => { RemoveScope(attributes, key); return Result.Success(); }, ct);
            if (!removed.IsSuccess)
                logger.LogError("Scope {Key} could not be provisioned and could not be removed again: {Code}", key, removed.Error!.Code);
            return provisioned.Error!;
        }
        return await GetScopeAsync(key, ct);
    }

    public async Task<Result<ScopeDefinitionDto>> UpdateScopeAsync(
        string key, string? displayName, string? description, bool? isActive, IReadOnlyCollection<string>? resources, CancellationToken ct)
    {
        var current = await GetScopeAsync(key, ct);
        if (!current.IsSuccess) return current.Error!;

        var definition = SerializeDefinition(displayName ?? current.Value.DisplayName, description ?? current.Value.Description,
            isActive ?? current.Value.IsActive, current.Value.ValueType);
        var written = await ModifyRegistryAsync(attributes =>
        {
            attributes[ScopePrefix + key] = ChunkAttributeValue(definition);
            if (resources is not null) SetResources(attributes, key, resources);
            return Result.Success();
        }, ct);
        return written.IsSuccess ? await GetScopeAsync(key, ct) : written.Error!;
    }

    public Task<Result> DeleteScopeAsync(string key, CancellationToken ct) =>
        ModifyRegistryAsync(attributes =>
        {
            if (!attributes.ContainsKey(ScopePrefix + key)) return ScopeNotFound(key);
            RemoveScope(attributes, key);
            return Result.Success();
        }, ct);

    public Task<Result> SetScopeResourcesAsync(string key, IReadOnlyCollection<string> resources, CancellationToken ct) =>
        ModifyRegistryAsync(attributes =>
        {
            if (!attributes.ContainsKey(ScopePrefix + key)) return ScopeNotFound(key);
            SetResources(attributes, key, resources);
            return Result.Success();
        }, ct);

    /// <summary>
    /// Ensures the registry group exists and seeds the default <c>region</c> scope when it defines none;
    /// then makes every registry key usable (profile declaration and token mapper).
    /// </summary>
    public async Task<Result> EnsureRegistryAsync(CancellationToken ct)
    {
        Invalidate();
        var registry = await GetRegistryAsync(ct);
        if (!registry.IsSuccess) return registry.Error!;
        if (!registry.Value.Keys.Any(k => k.StartsWith(ScopePrefix, StringComparison.Ordinal)))
        {
            var seeded = await ModifyRegistryAsync(attributes =>
            {
                attributes[ScopePrefix + "region"] = ChunkAttributeValue(SerializeDefinition("Region", "Geographic region", true, "String"));
                return Result.Success();
            }, ct);
            if (!seeded.IsSuccess) return seeded;
            logger.LogInformation("Seeded the default scope 'region' into {Group}", RegistryGroupName);
        }
        return await ProvisionAllKeysAsync(ct);
    }

    // ---------- writes ----------

    /// <summary>Read-modify-write of the registry group's attributes in a single PUT.</summary>
    private async Task<Result> ModifyRegistryAsync(Func<Dictionary<string, string[]>, Result> change, CancellationToken ct)
    {
        var group = await GetRegistryGroupAsync(ct);
        if (!group.IsSuccess) return group.Error!;

        var attributes = Attributes(group.Value);
        var changed = change(attributes);
        if (!changed.IsSuccess) return changed;

        var body = new Dictionary<string, object>
        {
            ["name"] = KeycloakAdminApi.GetString(group.Value, "name") ?? RegistryGroupName,
            ["attributes"] = attributes,
        };
        if (KeycloakAdminApi.GetString(group.Value, "path") is { } path) body["path"] = path;

        var id = KeycloakAdminApi.GetString(group.Value, "id")!;
        var written = await _api.SendWithoutResultAsync(HttpMethod.Put, $"groups/{Uri.EscapeDataString(id)}", body, Resource, ct);
        Invalidate();
        return written;
    }

    private async Task<Result> ProvisionAllKeysAsync(CancellationToken ct)
    {
        var registry = await GetRegistryAsync(ct);
        if (!registry.IsSuccess) return registry.Error!;
        return await provisioner.EnsureAsync(Definitions(registry.Value).Select(s => s.Key).ToArray(), ct);
    }

    private static void SetResources(Dictionary<string, string[]> attributes, string key, IReadOnlyCollection<string> resources)
    {
        var target = resources.Where(r => !string.IsNullOrWhiteSpace(r)).Select(r => r.Trim())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var name in attributes.Keys.Where(k => k.StartsWith(ResourcePrefix, StringComparison.Ordinal)).ToArray())
        {
            if (target.Contains(name[ResourcePrefix.Length..])) continue;
            var remaining = attributes[name].Where(s => !string.Equals(s, key, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (remaining.Length == 0) attributes.Remove(name);
            else attributes[name] = remaining;
        }
        foreach (var resource in target)
        {
            var name = ResourcePrefix + resource;
            var existing = attributes.GetValueOrDefault(name, []);
            if (!existing.Contains(key, StringComparer.OrdinalIgnoreCase)) attributes[name] = [.. existing, key];
        }
    }

    private static void RemoveScope(Dictionary<string, string[]> attributes, string key)
    {
        attributes.Remove(ScopePrefix + key);
        SetResources(attributes, key, []);
    }

    private static string SerializeDefinition(string displayName, string? description, bool isActive, string valueType) =>
        JsonSerializer.Serialize(new { displayName, description, isActive, valueType }, CompactJson);

    private static Dictionary<string, string[]> Attributes(JsonElement group)
    {
        var attributes = new Dictionary<string, string[]>(StringComparer.Ordinal);
        if (!group.TryGetProperty("attributes", out var attrs) || attrs.ValueKind != JsonValueKind.Object) return attributes;
        foreach (var prop in attrs.EnumerateObject())
        {
            attributes[prop.Name] = prop.Value.ValueKind switch
            {
                JsonValueKind.Array => prop.Value.EnumerateArray().Select(v => v.GetString() ?? "").Where(s => s.Length > 0).ToArray(),
                JsonValueKind.String => [prop.Value.GetString() ?? ""],
                _ => [],
            };
        }
        return attributes;
    }
}
