using Identity.Application;
using Identity.Contracts;
using Identity.Messaging.Contracts;

namespace Identity.Messaging;

public static class PermissionManifestEventMapper
{
    public static PermissionManifestEvent ToEvent(PermissionManifest manifest, string eventType, Guid? eventId = null)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        if (string.IsNullOrWhiteSpace(eventType))
            throw new ArgumentException("An event type is required.", nameof(eventType));

        return new PermissionManifestEvent(
            eventId ?? Guid.NewGuid(),
            eventType,
            1,
            manifest.ServiceId,
            manifest.ServiceName,
            manifest.Version,
            manifest.Environment,
            manifest.ManifestVersion,
            manifest.CorrelationId,
            manifest.PublishedAt,
            manifest.Permissions
                .Select(x => new PermissionMessage(x.Name, x.Description, x.Module))
                .ToArray());
    }

    public static PermissionManifest ToApplicationManifest(PermissionManifestEvent message)
    {
        ArgumentNullException.ThrowIfNull(message);
        return new PermissionManifest(
            message.ServiceId,
            message.ServiceName,
            message.ServiceVersion,
            message.Environment,
            message.Permissions
                .Select(x => new PermissionDefinition(x.Name, x.Description, x.Module))
                .ToArray(),
            message.ManifestVersion,
            message.CorrelationId,
            message.PublishedAt);
    }
}
