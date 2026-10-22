namespace Identity.Domain;

/// <summary>
/// Represents the definition of a specific permission declared by a service.
/// </summary>
/// <param name="Name">The unique canonical name of the permission (e.g., 'Orders.Read').</param>
/// <param name="Description">A human-readable description of what this permission authorizes.</param>
public sealed record PermissionDefinition(string Name, string Description);
