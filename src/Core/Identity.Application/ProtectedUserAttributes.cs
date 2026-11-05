namespace Identity.Application;

/// <summary>
/// User attribute namespaces owned by the gateway. They carry authorization data (scope values,
/// the legacy scoped-access blob, access schedules) or sign-in data (the SMS mobile number) and may only be
/// written through the dedicated, validated APIs, never through a generic user update.
/// </summary>
public static class ProtectedUserAttributes
{
    /// <summary>The user's mobile number (+989...); Keycloak's SMS authenticator finds users by it.</summary>
    public const string PhoneNumber = "phone_number";

    private static readonly string[] Prefixes = ["authz.", "iam.", "access."];
    private static readonly string[] Names = [PhoneNumber];

    public static bool IsProtected(string? attributeName) =>
        !string.IsNullOrWhiteSpace(attributeName) &&
        (Prefixes.Any(p => attributeName.Trim().StartsWith(p, StringComparison.OrdinalIgnoreCase)) ||
         Names.Any(n => string.Equals(attributeName.Trim(), n, StringComparison.OrdinalIgnoreCase)));

    /// <summary>Returns the protected attribute names present in <paramref name="attributes"/>.</summary>
    public static IReadOnlyCollection<string> FindIn(IReadOnlyDictionary<string, string[]>? attributes) =>
        attributes is null
            ? Array.Empty<string>()
            : attributes.Keys.Where(IsProtected).OrderBy(k => k, StringComparer.Ordinal).ToArray();
}
