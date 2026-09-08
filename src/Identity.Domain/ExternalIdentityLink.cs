namespace Identity.Domain;

/// <summary>
/// Legacy external identity link. Prefer Keycloak federated links as source of truth.
/// Retained temporarily to unblock the facade transition; remove once persistence is refactored
/// to Keycloak-only identity storage.
/// </summary>
public sealed class ExternalIdentityLink
{
    private ExternalIdentityLink() { }

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

    public Guid Id { get; private set; }
    public Guid UserId { get; private set; }
    public string Provider { get; private set; } = string.Empty;
    public string Subject { get; private set; } = string.Empty;
    public DateTimeOffset LinkedAt { get; private set; }
    public DateTimeOffset LastAuthenticatedAt { get; private set; }
    public void RecordAuthentication(DateTimeOffset authenticatedAt) => LastAuthenticatedAt = authenticatedAt;
}
