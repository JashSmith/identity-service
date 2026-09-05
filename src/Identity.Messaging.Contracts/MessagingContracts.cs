using Identity.Contracts;

namespace Identity.Messaging.Contracts;

public sealed record ServicePermissionManifestPublished(PermissionManifestMessage Manifest);
public sealed record ServicePermissionManifestUpdated(PermissionManifestMessage Manifest);

public sealed record PermissionManifestEvent(
    Guid EventId,
    string EventType,
    int SchemaVersion,
    string ServiceId,
    string ServiceName,
    string ServiceVersion,
    string Environment,
    string ManifestVersion,
    Guid CorrelationId,
    DateTimeOffset PublishedAt,
    IReadOnlyCollection<PermissionMessage> Permissions);

public static class PermissionManifestEventTypes
{
    public const string Published = "identity.permission-manifest.published";
    public const string Updated = "identity.permission-manifest.updated";
}
