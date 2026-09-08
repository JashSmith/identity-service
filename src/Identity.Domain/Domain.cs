namespace Identity.Domain;

public sealed record PermissionDefinition(string Name, string Description);

public sealed record PermissionManifest(
    string ServiceId,
    string ServiceVersion,
    string ManifestVersion,
    IReadOnlyCollection<PermissionDefinition> Permissions,
    string ManifestHash);

public sealed record ManifestRegistrationState(
    string ServiceId,
    string ManifestVersion,
    string ManifestHash,
    DateTimeOffset AcceptedAt,
    IReadOnlyCollection<string> DeprecatedPermissions);

/// <summary>
/// Auditable, non-secret facade event. The facade never persists raw tokens, passwords,
/// private signing keys or Vault secrets; Details must already be redacted before an
/// instance is created.
/// </summary>
public sealed record AuditEvent(
    string Actor,
    string Action,
    string Target,
    DateTimeOffset OccurredAt,
    IReadOnlyDictionary<string, string?> Details);
