namespace Identity.Application;

/// <summary>
/// Membership of users in business roles (Keycloak groups). Reserved groups such as super-admins are
/// never assignable here (role.not_found).
/// </summary>
public interface IUserRoleMapping
{
    /// <summary>Adds the user to the role; succeeds when the user already holds it.</summary>
    Task<Result> AssignRoleAsync(string userId, string roleName, CancellationToken ct);

    /// <summary>Removes the user from the role; succeeds when the user does not hold it.</summary>
    Task<Result> UnassignRoleAsync(string userId, string roleName, CancellationToken ct);
}
