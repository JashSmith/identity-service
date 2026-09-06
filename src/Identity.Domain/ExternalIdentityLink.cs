namespace Identity.Domain;

public sealed class ExternalIdentityLink
{
    private ExternalIdentityLink()
    {
    }

    public ExternalIdentityLink(
        Guid id,
        UserId userId,
        string provider,
        string subject,
        DateTimeOffset linkedAt)
    {
        if (id == Guid.Empty) throw new ArgumentException("Link ID is required.", nameof(id));
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
    public UserId UserId { get; private set; }
    public string Provider { get; private set; } = string.Empty;
    public string Subject { get; private set; } = string.Empty;
    public DateTimeOffset LinkedAt { get; private set; }
    public DateTimeOffset LastAuthenticatedAt { get; private set; }

    public void RecordAuthentication(DateTimeOffset authenticatedAt)
        => LastAuthenticatedAt = authenticatedAt;
}