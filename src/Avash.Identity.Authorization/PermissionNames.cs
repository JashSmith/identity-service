namespace Avash.Identity.Authorization;

/// <summary>Helpers for permission names <c>{application}:{Module}:{Resource}:{Action}</c>.</summary>
public static class PermissionNames
{
    /// <summary>
    /// Adds <paramref name="applicationId"/> to a local name (<c>Module:Resource:Action</c>); full names and
    /// names without an application id are returned unchanged.
    /// </summary>
    public static string Qualify(string? applicationId, string permission) =>
        string.IsNullOrWhiteSpace(applicationId) || permission.Count(c => c == ':') != 2
            ? permission
            : $"{applicationId}:{permission}";
}
