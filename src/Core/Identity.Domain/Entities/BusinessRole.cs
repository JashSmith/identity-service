namespace Identity.Domain.Entities;

/// <summary>
/// Represents a domain model for a business role (e.g. Manager, Accountant, Clerk)
/// which composites multiple fine-grained permissions across services.
/// </summary>
public sealed class BusinessRole
{
    /// <summary>
    /// Gets or sets the unique name of the business role.
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the optional human-readable description of this role's purpose.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this role is managed as a Keycloak group composite.
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// Gets or sets the collection of fine-grained permissions granted to this role.
    /// </summary>
    public HashSet<string> Permissions { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Initializes a new instance of the <see cref="BusinessRole"/> class.
    /// </summary>
    public BusinessRole() { }

    /// <summary>
    /// Initializes a new instance of the <see cref="BusinessRole"/> class with properties.
    /// </summary>
    /// <param name="name">The unique business role name.</param>
    /// <param name="description">The business role description.</param>
    /// <param name="permissions">The collection of assigned permissions.</param>
    public BusinessRole(string name, string? description, IEnumerable<string>? permissions = null)
    {
        Name = name;
        Description = description;
        if (permissions is not null)
        {
            foreach (var perm in permissions)
            {
                Permissions.Add(perm);
            }
        }
    }
}
