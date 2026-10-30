using System.Text.Json;
using System.Text.Json.Serialization;
using Identity.Contracts;

namespace Identity.Application;

public interface IScopedAccessSerializer
{
    string Serialize(ScopedAccessDocument document);
    /// <summary>Parses a stored document; malformed JSON yields an empty document.</summary>
    ScopedAccessDocument Deserialize(string? json);

    /// <summary>Parses a stored document and reports malformed JSON instead of hiding it.</summary>
    bool TryDeserialize(string? json, out ScopedAccessDocument document);
    IReadOnlyCollection<ScopedRoleAssignment> ParseClaim(string? claimValue);
}

public sealed class ScopedAccessSerializer : IScopedAccessSerializer
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false,
        Converters = { new ScopeDictionaryConverter() },
    };

    private sealed record RawAssignment(string Role, Dictionary<string, IReadOnlyCollection<string>> Scopes);

    public string Serialize(ScopedAccessDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        var normalized = document.Assignments
            .Where(a => !string.IsNullOrWhiteSpace(a.Role))
            .Select(Normalize)
            .OrderBy(a => a.Role, StringComparer.Ordinal)
            .ToArray();
        return JsonSerializer.Serialize(normalized, Options);
    }

    public ScopedAccessDocument Deserialize(string? json) =>
        TryDeserialize(json, out var document) ? document : ScopedAccessDocument.Empty;

    public bool TryDeserialize(string? json, out ScopedAccessDocument document)
    {
        document = ScopedAccessDocument.Empty;
        if (string.IsNullOrWhiteSpace(json)) return true;
        RawAssignment[]? raw;
        try
        {
            raw = JsonSerializer.Deserialize<RawAssignment[]>(json, Options);
        }
        catch (JsonException)
        {
            return false;
        }
        if (raw is null || raw.Length == 0) return true;

        document = new ScopedAccessDocument(raw
            .Where(r => !string.IsNullOrWhiteSpace(r.Role))
            .Select(r => new ScopedRoleAssignment(r.Role.Trim(), NormalizeScopes(r.Scopes)))
            .OrderBy(a => a.Role, StringComparer.Ordinal)
            .ToArray());
        return true;
    }

    public IReadOnlyCollection<ScopedRoleAssignment> ParseClaim(string? claimValue)
        => Deserialize(claimValue).Assignments;

    public static ScopedRoleAssignment Normalize(ScopedRoleAssignment assignment)
    {
        var role = assignment.Role.Trim();
        var scopes = NormalizeScopes(
            assignment.Scopes as IDictionary<string, IReadOnlyCollection<string>>
            ?? assignment.Scopes.ToDictionary(k => k.Key, v => v.Value));
        return new ScopedRoleAssignment(role, scopes);
    }

    private static IReadOnlyDictionary<string, IReadOnlyCollection<string>> NormalizeScopes(
        IDictionary<string, IReadOnlyCollection<string>>? scopes)
    {
        if (scopes is null || scopes.Count == 0)
            return new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal);
        var result = new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal);
        foreach (var kv in scopes.OrderBy(k => k.Key, StringComparer.Ordinal))
        {
            var key = kv.Key.Trim();
            if (string.IsNullOrWhiteSpace(key)) continue;
            var values = kv.Value is null
                ? Array.Empty<string>()
                : kv.Value.Where(v => !string.IsNullOrWhiteSpace(v))
                    .Select(v => v.Trim())
                    .Distinct(StringComparer.Ordinal)
                    .OrderBy(v => v, StringComparer.Ordinal)
                    .ToArray();
            if (values.Length == 0) continue;
            result[key] = values;
        }
        return result;
    }

    private static IReadOnlyDictionary<string, IReadOnlyCollection<string>> NormalizeScopes(
        Dictionary<string, IReadOnlyCollection<string>>? scopes)
    {
        if (scopes is null || scopes.Count == 0)
            return new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal);
        var result = new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal);
        foreach (var kv in scopes.OrderBy(k => k.Key, StringComparer.Ordinal))
        {
            var key = kv.Key.Trim();
            if (string.IsNullOrWhiteSpace(key)) continue;
            var values = kv.Value is null
                ? Array.Empty<string>()
                : kv.Value.Where(v => !string.IsNullOrWhiteSpace(v))
                    .Select(v => v.Trim())
                    .Distinct(StringComparer.Ordinal)
                    .OrderBy(v => v, StringComparer.Ordinal)
                    .ToArray();
            if (values.Length == 0) continue;
            result[key] = values;
        }
        return result;
    }

    public static void Validate(ScopedRoleAssignmentDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.Role))
            throw new ArgumentException("Role is required.", nameof(dto));
        if (dto.Scopes is null) return;
        foreach (var kv in dto.Scopes)
        {
            if (string.IsNullOrWhiteSpace(kv.Key))
                throw new ArgumentException("Scope key must not be empty.", nameof(dto));
            if (kv.Value is null) continue;
            foreach (var v in kv.Value)
                if (string.IsNullOrWhiteSpace(v))
                    throw new ArgumentException($"Scope values for '{kv.Key}' must not be empty.", nameof(dto));
        }
    }

    public static void ValidateDocument(IEnumerable<ScopedRoleAssignmentDto> assignments)
    {
        foreach (var a in assignments) Validate(a);
    }
}
