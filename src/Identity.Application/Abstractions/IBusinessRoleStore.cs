using Identity.Contracts;

namespace Identity.Application;

/// <summary>
/// Store interface for managing business roles (groups/composites) and their fine-grained permissions.
/// </summary>
public interface IBusinessRoleStore
{
    /// <summary>
    /// Retrieves a business role definition by name.
    /// </summary>
    /// <param name="name">The unique role name (e.g. 'Manager', 'Accountant', 'Clerk').</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The BusinessRoleDto or null if not found.</returns>
    Task<BusinessRoleDto?> GetAsync(string name, CancellationToken ct);

    /// <summary>
    /// Lists all business roles defined in the system.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A collection of BusinessRoleDto records.</returns>
    Task<IReadOnlyCollection<BusinessRoleDto>> ListAsync(CancellationToken ct);

    /// <summary>
    /// Creates a new business role with optional initial permissions.
    /// </summary>
    /// <param name="name">The business role name.</param>
    /// <param name="description">The role description.</param>
    /// <param name="permissions">Initial permission names.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The created BusinessRoleDto.</returns>
    Task<BusinessRoleDto> CreateAsync(string name, string? description, IReadOnlyCollection<string> permissions, CancellationToken ct);

    /// <summary>
    /// Updates a business role's description.
    /// </summary>
    /// <param name="name">The business role name.</param>
    /// <param name="description">The new description.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The updated BusinessRoleDto or null if not found.</returns>
    Task<BusinessRoleDto?> UpdateAsync(string name, string? description, CancellationToken ct);

    /// <summary>
    /// Deletes a business role by name.
    /// </summary>
    /// <param name="name">The business role name.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True if deleted; false if not found or deletion failed.</returns>
    Task<bool> DeleteAsync(string name, CancellationToken ct);

    /// <summary>
    /// Resolves the effective list of permission names granted through this business role.
    /// </summary>
    /// <param name="name">The business role name.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A collection of effective permission names.</returns>
    Task<IReadOnlyCollection<string>> GetEffectivePermissionsAsync(string name, CancellationToken ct);

    /// <summary>
    /// Adds permissions to an existing business role.
    /// </summary>
    /// <param name="name">The business role name.</param>
    /// <param name="permissions">The permission names to add.</param>
    /// <param name="ct">Cancellation token.</param>
    Task AddPermissionsAsync(string name, IReadOnlyCollection<string> permissions, CancellationToken ct);

    /// <summary>
    /// Removes a permission from a business role.
    /// </summary>
    /// <param name="name">The business role name.</param>
    /// <param name="permission">The permission name to remove.</param>
    /// <param name="ct">Cancellation token.</param>
    Task RemovePermissionAsync(string name, string permission, CancellationToken ct);
}
