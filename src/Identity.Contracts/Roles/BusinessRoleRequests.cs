namespace Identity.Contracts;

/// <summary>
/// Request payload to create a new business role in the system.
/// </summary>
/// <param name="Name">The business role name (e.g. 'Manager', 'Accountant', 'Clerk').</param>
/// <param name="Description">Optional human-readable description of what duties this business role entails.</param>
/// <param name="Permissions">Optional collection of initial permissions to associate with this role.</param>
public sealed record CreateBusinessRoleRequest(
    string Name,
    string? Description,
    IReadOnlyCollection<string>? Permissions);

/// <summary>
/// Request payload to update an existing business role.
/// </summary>
/// <param name="Description">The updated description for the business role.</param>
/// <param name="Permissions">Optional updated collection of permission names to assign to this role.</param>
public sealed record UpdateBusinessRoleRequest(
    string? Description,
    IReadOnlyCollection<string>? Permissions = null);

/// <summary>
/// Request payload to assign permissions to a business role.
/// </summary>
/// <param name="Permissions">The collection of permission names to assign.</param>
public sealed record AssignPermissionsRequest(
    IReadOnlyCollection<string> Permissions);

/// <summary>
/// Response payload detailing the effective permissions resolved for a business role.
/// </summary>
/// <param name="Role">The name of the business role.</param>
/// <param name="Permissions">The effective permissions granted through this role and its composites.</param>
public sealed record EffectivePermissionsResponse(
    string Role,
    IReadOnlyCollection<string> Permissions);
