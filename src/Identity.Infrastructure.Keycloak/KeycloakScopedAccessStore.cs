using System.Net.Http.Json;
using System.Text.Json;
using Identity.Application;
using Identity.Contracts;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Persists <see cref="ScopedAccessDocument"/> as a single namespaced user attribute
/// (<c>iam.scoped_access</c>). All other attributes are preserved via read-modify-write
/// against the full user representation (GET then PUT).
/// Application code never touches raw attribute dictionaries — the typed model is the boundary.
/// </summary>
public sealed class KeycloakScopedAccessStore(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    IScopedAccessSerializer serializer) : IScopedAccessStore
{
    private readonly KeycloakOptions _o = opts.Value;
    private readonly ScopedAccessOptions _scopedOpts = new();
    private string AdminBase => $"{_o.BaseUrl.TrimEnd('/')}/admin/realms";

    private string AttributeName => _scopedOpts.AttributeName ?? ScopedAccessConstants.AttributeName;

    private async Task<JsonElement?> GetUserJsonAsync(string userId, string token, CancellationToken ct)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(userId)}");
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) return null;
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            return doc.RootElement.Clone();
        }
        catch { return null; }
    }

    private async Task<bool> PutUserAsync(JsonElement userJson, string token, CancellationToken ct)
    {
        var userId = userJson.TryGetProperty("id", out var pid) ? pid.GetString() ?? "" : "";
        if (string.IsNullOrEmpty(userId)) return false;
        var json = userJson.GetRawText();
        var req = new HttpRequestMessage(HttpMethod.Put, $"{AdminBase}/{_o.Realm}/users/{Uri.EscapeDataString(userId)}")
        {
            Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
        };
        req.Headers.Add("Authorization", $"Bearer {token}");
        try
        {
            var res = await http.SendAsync(req, ct);
            return res.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    private static string? ExtractAttribute(JsonElement userJson, string attributeName)
    {
        if (!userJson.TryGetProperty("attributes", out var attrs) || attrs.ValueKind != JsonValueKind.Object)
            return null;
        if (!attrs.TryGetProperty(attributeName, out var arr)) return null;
        if (arr.ValueKind == JsonValueKind.Array && arr.GetArrayLength() > 0)
            return arr[0].GetString();
        if (arr.ValueKind == JsonValueKind.String) return arr.GetString();
        return null;
    }

    private static JsonElement SetAttribute(JsonElement userJson, string attributeName, string? value)
    {
        var doc = JsonDocument.Parse(userJson.GetRawText());
        var root = doc.RootElement;
        using var ms = new System.IO.MemoryStream();
        using var writer = new Utf8JsonWriter(ms);
        writer.WriteStartObject();
        foreach (var prop in root.EnumerateObject())
        {
            if (prop.NameEquals("attributes"))
            {
                writer.WritePropertyName("attributes");
                writer.WriteStartObject();
                var hasTarget = false;
                if (prop.Value.ValueKind == JsonValueKind.Object)
                {
                    foreach (var attr in prop.Value.EnumerateObject())
                    {
                        if (attr.NameEquals(attributeName))
                        {
                            hasTarget = true;
                            if (value is not null)
                            {
                                writer.WritePropertyName(attr.Name);
                                writer.WriteStartArray();
                                writer.WriteStringValue(value);
                                writer.WriteEndArray();
                            }
                            // if value is null, omit the attribute entirely (removal)
                        }
                        else
                        {
                            attr.WriteTo(writer);
                        }
                    }
                }
                if (!hasTarget && value is not null)
                {
                    writer.WritePropertyName(attributeName);
                    writer.WriteStartArray();
                    writer.WriteStringValue(value);
                    writer.WriteEndArray();
                }
                writer.WriteEndObject();
            }
            else
            {
                prop.WriteTo(writer);
            }
        }
        // If attributes didn't exist at all and we have a value, add it
        if (!root.TryGetProperty("attributes", out _) && value is not null)
        {
            // Already handled above by not having attributes prop; need to add
            // Re-parse: we already wrote without it, so we need to handle differently.
            // Simpler: close and re-build if needed. But our loop above already handled
            // the case where attributes missing — we didn't write it. So patch:
            // We need to re-open. Easiest: do a second pass if attributes missing.
        }
        writer.WriteEndObject();
        writer.Flush();
        var json = System.Text.Encoding.UTF8.GetString(ms.ToArray());
        // Handle missing attributes case: inject if needed
        if (!root.TryGetProperty("attributes", out _) && value is not null)
        {
            var parsed = JsonDocument.Parse(json);
            using var ms2 = new System.IO.MemoryStream();
            using var w2 = new Utf8JsonWriter(ms2);
            w2.WriteStartObject();
            foreach (var prop in parsed.RootElement.EnumerateObject()) prop.WriteTo(w2);
            w2.WritePropertyName("attributes");
            w2.WriteStartObject();
            w2.WritePropertyName(attributeName);
            w2.WriteStartArray();
            w2.WriteStringValue(value);
            w2.WriteEndArray();
            w2.WriteEndObject();
            w2.WriteEndObject();
            w2.Flush();
            json = System.Text.Encoding.UTF8.GetString(ms2.ToArray());
        }
        return JsonDocument.Parse(json).RootElement.Clone();
    }

    public async Task<ScopedAccessDocument> GetAsync(string userId, CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return ScopedAccessDocument.Empty;
        var userJson = await GetUserJsonAsync(userId, token, ct);
        if (userJson is null) return ScopedAccessDocument.Empty;
        var raw = ExtractAttribute(userJson.Value, AttributeName);
        return serializer.Deserialize(raw);
    }

    public async Task SetAsync(string userId, ScopedAccessDocument document, CancellationToken ct)
    {
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) throw new InvalidOperationException("Keycloak admin token unavailable.");
        var userJson = await GetUserJsonAsync(userId, token, ct);
        if (userJson is null) throw new InvalidOperationException($"User '{userId}' not found.");
        string? value = document.Assignments.Count == 0 ? null : serializer.Serialize(document);
        var updated = SetAttribute(userJson.Value, AttributeName, value);
        var ok = await PutUserAsync(updated, token, ct);
        if (!ok) throw new InvalidOperationException($"Failed to update scoped access for user '{userId}'.");
    }

    public async Task AddAssignmentAsync(string userId, ScopedRoleAssignmentDto assignment, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        ScopedAccessSerializer.Validate(assignment);
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) throw new InvalidOperationException("Keycloak admin token unavailable.");
        var userJson = await GetUserJsonAsync(userId, token, ct);
        if (userJson is null) throw new InvalidOperationException($"User '{userId}' not found.");
        var raw = ExtractAttribute(userJson.Value, AttributeName);
        var doc = serializer.Deserialize(raw);
        var normalized = NormalizeDto(assignment);
        // Merge: if role already exists, merge scopes; otherwise append
        var existing = doc.Assignments.FirstOrDefault(a => string.Equals(a.Role, normalized.Role, StringComparison.Ordinal));
        List<ScopedRoleAssignment> next;
        if (existing is not null)
        {
            var merged = MergeScopes(existing.Scopes, normalized.Scopes);
            next = doc.Assignments.Select(a => string.Equals(a.Role, normalized.Role, StringComparison.Ordinal)
                ? new ScopedRoleAssignment(a.Role, merged) : a).ToList();
        }
        else
        {
            next = doc.Assignments.Concat([normalized]).ToList();
        }
        var newDoc = new ScopedAccessDocument(next.OrderBy(a => a.Role, StringComparer.Ordinal).ToArray());
        var updated = SetAttribute(userJson.Value, AttributeName, serializer.Serialize(newDoc));
        var ok = await PutUserAsync(updated, token, ct);
        if (!ok) throw new InvalidOperationException($"Failed to add assignment for user '{userId}'.");
    }

    public async Task UpdateAssignmentAsync(string userId, string role, IReadOnlyDictionary<string, IReadOnlyCollection<string>> scopes, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(role);
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) throw new InvalidOperationException("Keycloak admin token unavailable.");
        var userJson = await GetUserJsonAsync(userId, token, ct);
        if (userJson is null) throw new InvalidOperationException($"User '{userId}' not found.");
        var raw = ExtractAttribute(userJson.Value, AttributeName);
        var doc = serializer.Deserialize(raw);
        var normalized = NormalizeScopesDict(scopes);
        var found = doc.Assignments.Any(a => string.Equals(a.Role, role.Trim(), StringComparison.Ordinal));
        if (!found) throw new InvalidOperationException($"Assignment for role '{role}' not found.");
        var next = doc.Assignments.Select(a => string.Equals(a.Role, role.Trim(), StringComparison.Ordinal)
            ? new ScopedRoleAssignment(a.Role, normalized) : a).ToList();
        var newDoc = new ScopedAccessDocument(next);
        var updated = SetAttribute(userJson.Value, AttributeName, serializer.Serialize(newDoc));
        var ok = await PutUserAsync(updated, token, ct);
        if (!ok) throw new InvalidOperationException($"Failed to update assignment for user '{userId}'.");
    }

    public async Task RemoveAssignmentAsync(string userId, string role, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(role);
        var token = await tokenProvider.GetTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) throw new InvalidOperationException("Keycloak admin token unavailable.");
        var userJson = await GetUserJsonAsync(userId, token, ct);
        if (userJson is null) throw new InvalidOperationException($"User '{userId}' not found.");
        var raw = ExtractAttribute(userJson.Value, AttributeName);
        var doc = serializer.Deserialize(raw);
        var next = doc.Assignments.Where(a => !string.Equals(a.Role, role.Trim(), StringComparison.Ordinal)).ToArray();
        string? value = next.Length == 0 ? null : serializer.Serialize(new ScopedAccessDocument(next));
        var updated = SetAttribute(userJson.Value, AttributeName, value);
        var ok = await PutUserAsync(updated, token, ct);
        if (!ok) throw new InvalidOperationException($"Failed to remove assignment for user '{userId}'.");
    }

    private static ScopedRoleAssignment NormalizeDto(ScopedRoleAssignmentDto dto)
    {
        var role = dto.Role.Trim();
        var scopes = NormalizeScopesDict(dto.Scopes);
        return new ScopedRoleAssignment(role, scopes);
    }

    private static IReadOnlyDictionary<string, IReadOnlyCollection<string>> NormalizeScopesDict(
        IReadOnlyDictionary<string, IReadOnlyCollection<string>>? scopes)
    {
        if (scopes is null || scopes.Count == 0)
            return new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal);
        var result = new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal);
        foreach (var kv in scopes.OrderBy(k => k.Key, StringComparer.Ordinal))
        {
            var key = kv.Key.Trim();
            if (string.IsNullOrWhiteSpace(key)) continue;
            var values = kv.Value?.Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v.Trim())
                .Distinct(StringComparer.Ordinal).OrderBy(v => v, StringComparer.Ordinal).ToArray()
                ?? Array.Empty<string>();
            if (values.Length == 0) continue;
            result[key] = values;
        }
        return result;
    }

    private static IReadOnlyDictionary<string, IReadOnlyCollection<string>> MergeScopes(
        IReadOnlyDictionary<string, IReadOnlyCollection<string>> existing,
        IReadOnlyDictionary<string, IReadOnlyCollection<string>> incoming)
    {
        var result = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var kv in existing)
            result[kv.Key] = new HashSet<string>(kv.Value, StringComparer.Ordinal);
        foreach (var kv in incoming)
        {
            if (!result.TryGetValue(kv.Key, out var set))
            {
                set = new HashSet<string>(StringComparer.Ordinal);
                result[kv.Key] = set;
            }
            foreach (var v in kv.Value) set.Add(v);
        }
        return result.ToDictionary(kv => kv.Key,
            kv => (IReadOnlyCollection<string>)kv.Value.OrderBy(x => x, StringComparer.Ordinal).ToArray(),
            StringComparer.Ordinal);
    }
}
