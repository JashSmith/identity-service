using Identity.Contracts;

namespace Identity.Application;

/// <summary>
/// Business roles (Keycloak groups) and the permissions assigned to them. Every operation reports
/// failures as errors: role.not_found, role.reserved, role.already_exists, role.in_use,
/// permission.not_found, permission.not_assigned, or a Keycloak availability error.
/// </summary>
public interface IBusinessRoleStore
{
    /// <summary>A role with the permissions assigned directly to it.</summary>
    Task<Result<BusinessRoleDto>> GetAsync(string name, CancellationToken ct);

    Task<Result<IReadOnlyCollection<BusinessRoleDto>>> ListAsync(CancellationToken ct);

    /// <summary>
    /// Creates the role and assigns <paramref name="permissions"/>. Unknown permissions are rejected
    /// before anything is created; a failed assignment removes the new role again.
    /// </summary>
    Task<Result<BusinessRoleDto>> CreateAsync(string name, string? description, IReadOnlyCollection<string> permissions, CancellationToken ct);

    /// <summary>Changes the description and keeps every other attribute of the role.</summary>
    Task<Result<BusinessRoleDto>> UpdateAsync(string name, string? description, CancellationToken ct);

    /// <summary>Deletes the role; fails with role.in_use while users still hold it.</summary>
    Task<Result> DeleteAsync(string name, CancellationToken ct);

    /// <summary>Assigned permissions plus those inherited through composite realm roles.</summary>
    Task<Result<IReadOnlyCollection<string>>> GetEffectivePermissionsAsync(string name, CancellationToken ct);

    Task<Result> AddPermissionsAsync(string name, IReadOnlyCollection<string> permissions, CancellationToken ct);

    Task<Result> RemovePermissionAsync(string name, string permission, CancellationToken ct);

    /// <summary>Makes the role's assigned permissions exactly <paramref name="permissions"/>.</summary>
    Task<Result> SetPermissionsAsync(string name, IReadOnlyCollection<string> permissions, CancellationToken ct);
}

public static class BusinessRoleStoreExtensions
{
    /// <summary>
    /// True when the role exists, false when it does not. Any other failure (e.g. Keycloak down) is
    /// thrown as <see cref="ErrorException"/> instead of being mistaken for "does not exist".
    /// </summary>
    public static async Task<bool> ExistsAsync(this IBusinessRoleStore roles, string name, CancellationToken ct)
    {
        var role = await roles.GetAsync(name, ct);
        if (role.IsSuccess) return true;
        if (role.Error!.Kind == ErrorKind.NotFound) return false;
        throw new ErrorException(role.Error);
    }
}
