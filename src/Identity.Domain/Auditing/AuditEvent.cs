namespace Identity.Domain;

/// <summary>
/// Auditable, non-secret facade event. The facade never persists raw tokens, passwords,
/// private signing keys or Vault secrets; Details must already be redacted before an
/// instance is created.
/// </summary>
/// <param name="Actor">The identity or service that initiated the audited action.</param>
/// <param name="Action">The canonical action verb (e.g. 'user.created', 'manifest.registered').</param>
/// <param name="Target">The resource identifier affected by the action.</param>
/// <param name="OccurredAt">The UTC timestamp when the event occurred.</param>
/// <param name="Details">Non-sensitive key-value metadata describing the event.</param>
public sealed record AuditEvent(
    string Actor,
    string Action,
    string Target,
    DateTimeOffset OccurredAt,
    IReadOnlyDictionary<string, string?> Details);
