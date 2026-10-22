namespace Identity.Domain.Entities;

/// <summary>
/// Legacy external identity link. Prefer Keycloak federated links as source of truth.
/// Retained for auditability and external subject identity mapping.
/// </summary>
public sealed class ExternalIdentityLink
{
    /// <summary>
    /// Gets the unique link identifier.
    /// </summary>
    public Guid Id { get; private set; }

    /// <summary>
    /// Gets the user ID associated with this external link.
    /// </summary>
    public Guid UserId { get; private set; }

    /// <summary>
    /// Gets the external identity provider name (e.g. Google, GitHub, SAML).
    /// </summary>
    public string Provider { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the unique subject identifier within the external provider.
    /// </summary>
    public string Subject { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the timestamp when this link was initially established.
    /// </summary>
    public DateTimeOffset LinkedAt { get; private set; }

    /// <summary>
    /// Gets the timestamp when the user last authenticated via this link.
    /// </summary>
    public DateTimeOffset LastAuthenticatedAt { get; private set; }

    /// <summary>
    /// Prevents a default instance of the <see cref="ExternalIdentityLink"/> class from being created.
    /// </summary>
    private ExternalIdentityLink()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ExternalIdentityLink"/> class.
    /// </summary>
    /// <param name="id">The unique link identifier.</param>
    /// <param name="userId">The internal user ID.</param>
    /// <param name="provider">The external provider name.</param>
    /// <param name="subject">The external subject identifier.</param>
    /// <param name="linkedAt">The link creation timestamp.</param>
    /// <exception cref="ArgumentException">Thrown when required parameters are empty or invalid.</exception>
    public ExternalIdentityLink(Guid id, Guid userId, string provider, string subject, DateTimeOffset linkedAt)
    {
        if (id == Guid.Empty) throw new ArgumentException("Link ID is required.", nameof(id));
        if (userId == Guid.Empty) throw new ArgumentException("User ID is required.", nameof(userId));
        if (string.IsNullOrWhiteSpace(provider)) throw new ArgumentException("Provider is required.", nameof(provider));
        if (string.IsNullOrWhiteSpace(subject)) throw new ArgumentException("Subject is required.", nameof(subject));
        Id = id;
        UserId = userId;
        Provider = provider.Trim();
        Subject = subject.Trim();
        LinkedAt = linkedAt;
        LastAuthenticatedAt = linkedAt;
    }

    /// <summary>
    /// Updates the timestamp of the last successful authentication.
    /// </summary>
    /// <param name="authenticatedAt">The timestamp of the authentication event.</param>
    public void RecordAuthentication(DateTimeOffset authenticatedAt) => LastAuthenticatedAt = authenticatedAt;
}
