using System.Text.Json;
using Identity.Application;
using Identity.Application.Scope;
using Identity.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak.Scope;

/// <summary>
/// Scope values stored on Keycloak users and groups as multivalued attributes <c>authz.scope.&lt;key&gt;</c>.
/// <list type="bullet">
/// <item><see cref="IScopedAccessStore"/> reads and writes only the user's own assignments: the per-role
/// document in <c>iam.scoped_access</c> plus the flat <c>authz.scope.*</c> union, written in one PUT.</item>
/// <item><see cref="IUserScopeReader"/> is the read-only merged view (user ∪ groups) that tokens carry.</item>
/// </list>
/// The two must never be mixed: writing the merged view back would copy group scopes onto the user.
/// </summary>
public sealed class KeycloakScopeAttributeStore(
    HttpClient http,
    IOptions<KeycloakOptions> options,
    KeycloakAdminTokenProvider tokenProvider,
    IScopedAccessSerializer serializer,
    ILogger<KeycloakScopeAttributeStore>? logger = null)
    : IUserScopeReader, IScopedAccessStore
{
    private const string ScopeAttrPrefix = "authz.scope.";
    private const string Resource = "user";

    private readonly ILogger _logger = (ILogger?)logger ?? NullLogger.Instance;
    private readonly KeycloakAdminApi _api = new(http, options.Value, tokenProvider, (ILogger?)logger ?? NullLogger.Instance);

    private static string UserPath(string id) => $"users/{Uri.EscapeDataString(id)}";

    // ---------- IScopedAccessStore: the user's own document ----------

    async Task<Result<ScopedAccessDocument>> IScopedAccessStore.GetAsync(string userId, CancellationToken ct)
    {
        var user = await GetUserAsync(userId, ct);
        return user.IsSuccess ? OwnDocument(user.Value, userId) : user.Error!;
    }

    async Task<Result> IScopedAccessStore.SetAsync(string userId, ScopedAccessDocument document, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(document);
        var user = await GetUserAsync(userId, ct);
        if (!user.IsSuccess) return user.Error!;

        var flat = Union(document.Assignments.Select(a => a.Scopes));
        var assignments = document.Assignments
            .Select(a => new ScopedRoleAssignment(a.Role, a.Scopes.Where(kv => kv.Value.Count > 0)
                .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal)))
            .ToArray();
        var serialized = assignments.Length == 0 ? null : serializer.Serialize(new ScopedAccessDocument(assignments));

        var updated = WithAttributes(user.Value, flat, serialized);
        var written = await _api.SendWithoutResultAsync(HttpMethod.Put, UserPath(userId), updated, Resource, ct);
        return written.IsSuccess ? written : NamedNotFound(written.Error!, userId);
    }

    // ---------- IUserScopeReader: merged view (user ∪ groups) ----------

    public async Task<Result<ScopedAccessDocument>> GetAsync(string userId, CancellationToken ct)
    {
        var user = await GetUserAsync(userId, ct);
        if (!user.IsSuccess) return user.Error!;
        var groups = await _api.GetAllAsync($"{UserPath(userId)}/groups?briefRepresentation=true", Resource, ct);
        if (!groups.IsSuccess) return groups.Error!;

        var sources = new List<IReadOnlyDictionary<string, IReadOnlyCollection<string>>> { ScopeAttributes(user.Value) };
        sources.AddRange(OwnDocument(user.Value, userId).Assignments.Select(a => a.Scopes));
        var groupNames = new List<string>();
        foreach (var group in groups.Value)
        {
            if (KeycloakAdminApi.GetString(group, "id") is not { Length: > 0 } groupId) continue;
            groupNames.Add(KeycloakAdminApi.GetString(group, "name") ?? groupId);
            // The brief group representation omits attributes, so each group is read once.
            var full = await _api.GetAsync($"groups/{Uri.EscapeDataString(groupId)}", "role", ct);
            if (!full.IsSuccess) return full.Error!;
            sources.Add(ScopeAttributes(full.Value));
        }

        var merged = Union(sources);
        if (merged.Count == 0) return ScopedAccessDocument.Empty;
        var roles = groupNames.Count > 0 ? groupNames : ["_user"];
        return new ScopedAccessDocument(roles.Select(r => new ScopedRoleAssignment(r, merged)).ToArray());
    }

    public async Task<Result<IReadOnlyDictionary<string, IReadOnlyCollection<string>>>> GetEffectiveAsync(string userId, CancellationToken ct)
    {
        var merged = await GetAsync(userId, ct);
        if (!merged.IsSuccess) return merged.Error!;
        return Result<IReadOnlyDictionary<string, IReadOnlyCollection<string>>>.Success(
            Union(merged.Value.Assignments.Select(a => a.Scopes)));
    }

    // ---------- helpers ----------

    private async Task<Result<JsonElement>> GetUserAsync(string userId, CancellationToken ct)
    {
        var user = await _api.GetAsync(UserPath(userId), Resource, ct);
        return user.IsSuccess ? user.Value : NamedNotFound(user.Error!, userId);
    }

    private ScopedAccessDocument OwnDocument(JsonElement user, string userId)
    {
        var raw = SingleAttribute(user, ScopedAccessConstants.AttributeName);
        if (serializer.TryDeserialize(raw, out var document)) return document;

        // A corrupt document cannot be trusted; it is reported and replaced by the next write.
        _logger.LogWarning("User {UserId} has an unreadable {Attribute} attribute; treating it as empty",
            userId, ScopedAccessConstants.AttributeName);
        return ScopedAccessDocument.Empty;
    }

    private static Error NamedNotFound(Error error, string userId) =>
        error.Kind == ErrorKind.NotFound ? Error.NotFound("user.not_found", $"User '{userId}' was not found.") : error;

    private static IReadOnlyDictionary<string, IReadOnlyCollection<string>> ScopeAttributes(JsonElement element)
    {
        var scopes = new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal);
        if (!element.TryGetProperty("attributes", out var attrs) || attrs.ValueKind != JsonValueKind.Object) return scopes;
        foreach (var p in attrs.EnumerateObject().Where(p => p.Name.StartsWith(ScopeAttrPrefix, StringComparison.Ordinal)))
        {
            scopes[p.Name[ScopeAttrPrefix.Length..]] = p.Value.ValueKind switch
            {
                JsonValueKind.Array => p.Value.EnumerateArray().Select(v => v.GetString() ?? "").Where(s => s.Length > 0).ToArray(),
                JsonValueKind.String => [p.Value.GetString() ?? ""],
                _ => [],
            };
        }
        return scopes;
    }

    private static IReadOnlyDictionary<string, IReadOnlyCollection<string>> Union(
        IEnumerable<IReadOnlyDictionary<string, IReadOnlyCollection<string>>> sources)
    {
        var merged = new Dictionary<string, SortedSet<string>>(StringComparer.Ordinal);
        foreach (var source in sources)
        foreach (var (key, values) in source)
        {
            if (!merged.TryGetValue(key, out var set)) merged[key] = set = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var v in values.Where(v => !string.IsNullOrWhiteSpace(v))) set.Add(v.Trim());
        }
        return merged.Where(kv => kv.Value.Count > 0)
            .ToDictionary(kv => kv.Key, kv => (IReadOnlyCollection<string>)kv.Value.ToArray(), StringComparer.Ordinal);
    }

    private static string? SingleAttribute(JsonElement element, string name)
    {
        if (!element.TryGetProperty("attributes", out var attrs) || attrs.ValueKind != JsonValueKind.Object) return null;
        if (!attrs.TryGetProperty(name, out var value)) return null;
        return value.ValueKind switch
        {
            JsonValueKind.Array when value.GetArrayLength() > 0 => value[0].GetString(),
            JsonValueKind.String => value.GetString(),
            _ => null,
        };
    }

    /// <summary>
    /// The user representation with every non-scope attribute kept, the authz.scope.* attributes replaced
    /// by <paramref name="scopes"/> and the per-role document set (or removed when null).
    /// </summary>
    private static Dictionary<string, object?> WithAttributes(
        JsonElement user, IReadOnlyDictionary<string, IReadOnlyCollection<string>> scopes, string? document)
    {
        var representation = JsonSerializer.Deserialize<Dictionary<string, object?>>(user.GetRawText())!;
        var attributes = new Dictionary<string, object?>(StringComparer.Ordinal);
        if (user.TryGetProperty("attributes", out var existing) && existing.ValueKind == JsonValueKind.Object)
            foreach (var a in existing.EnumerateObject())
                if (!a.Name.StartsWith(ScopeAttrPrefix, StringComparison.Ordinal) &&
                    !string.Equals(a.Name, ScopedAccessConstants.AttributeName, StringComparison.Ordinal))
                    attributes[a.Name] = a.Value;

        foreach (var (key, values) in scopes) attributes[ScopeAttrPrefix + key] = values;
        if (document is not null) attributes[ScopedAccessConstants.AttributeName] = new[] { document };

        representation["attributes"] = attributes;
        return representation;
    }
}
