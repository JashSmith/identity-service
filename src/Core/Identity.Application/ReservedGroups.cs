namespace Identity.Application;

/// <summary>
/// Keycloak groups the gateway manages itself. They are never business roles: they cannot be
/// read, created, edited, deleted or assigned through the business-role and user-assignment APIs.
/// </summary>
public static class ReservedGroups
{
    /// <summary>Unrestricted administrators; holds every permission.</summary>
    public const string SuperAdmins = "super-admins";

    /// <summary>Configuration group holding runtime scope definitions.</summary>
    public const string ScopeRegistry = "iam-scope-registry";

    private static readonly string[] All = [SuperAdmins, ScopeRegistry];

    public static bool IsReserved(string? name) =>
        !string.IsNullOrWhiteSpace(name) && All.Contains(name.Trim(), StringComparer.OrdinalIgnoreCase);
}
