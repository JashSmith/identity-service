namespace Identity.Application;

/// <summary>
/// Maps/drops realm roles on a user. A scoped role assignment must also be reflected as a
/// realm role mapping so that composite expansion fills the <c>permissions</c> claim — the
/// scoped-access attribute carries the scope dimensions, the realm role carries the
/// effective atomic permissions.
/// </summary>
public interface IUserRoleMapping
{
    Task<IReadOnlyCollection<string>> GetRealmRolesAsync(string userId, CancellationToken ct);
    Task<bool> HasRealmRoleAsync(string userId, string roleName, CancellationToken ct);
    Task MapRealmRoleAsync(string userId, string roleName, CancellationToken ct);
    Task UnmapRealmRoleAsync(string userId, string roleName, CancellationToken ct);
    /// <summary>Looks up users that have the given realm role mapped, by user id.</summary>
    Task<IReadOnlyCollection<string>> GetUsersWithRealmRoleAsync(string roleName, CancellationToken ct);
}
