namespace Identity.Contracts;

/// <summary>
/// Data transfer object representing a business role (e.g., Manager, Accountant, Clerk)
/// which is realized as a composite group or role in Keycloak.
/// </summary>
/// <param name="Name">The business role name.</param>
/// <param name="Description">Optional description of the business role.</param>
/// <param name="Composite">Specifies if this role composites permissions.</param>
/// <param name="Permissions">The fine-grained permissions associated with this business role.</param>
public sealed record BusinessRoleDto(
    string Name,
    string? Description,
    bool Composite,
    IReadOnlyCollection<string> Permissions);
