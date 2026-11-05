namespace Identity.Contracts;

/// <summary>
/// Data transfer object representing a realm or client role in Keycloak.
/// </summary>
/// <param name="Id">The unique role identifier in Keycloak.</param>
/// <param name="Name">The role name.</param>
/// <param name="Description">Optional description of the role.</param>
/// <param name="ClientId">The ID of the owning client, or null if this is a realm-level role.</param>
/// <param name="Composite">Specifies whether this role composites other roles.</param>
public sealed record RoleDto(string Id, string Name, string? Description, string? ClientId, bool Composite);
