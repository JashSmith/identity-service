namespace Identity.Application;

/// <summary>
/// User attribute namespaces owned by the gateway. They carry authorization data (scope values,
/// the legacy scoped-access blob, access schedules) and may only be written through the dedicated,
/// validated APIs, never through a generic user update.
/// </summary>
public static class ProtectedUserAttributes
{
    private static readonly string[] Prefixes = ["authz.", "iam.", "access."];

    public static bool IsProtected(string? attributeName) =>
        !string.IsNullOrWhiteSpace(attributeName) &&
        Prefixes.Any(p => attributeName.Trim().StartsWith(p, StringComparison.OrdinalIgnoreCase));

    /// <summary>Returns the protected attribute names present in <paramref name="attributes"/>.</summary>
    public static IReadOnlyCollection<string> FindIn(IReadOnlyDictionary<string, string[]>? attributes) =>
        attributes is null
            ? Array.Empty<string>()
            : attributes.Keys.Where(IsProtected).OrderBy(k => k, StringComparer.Ordinal).ToArray();
}
