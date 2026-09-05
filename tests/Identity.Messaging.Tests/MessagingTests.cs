using Identity.Application;
using Identity.Messaging;
using Identity.Messaging.Contracts;

namespace Identity.Messaging.Tests;

public sealed class MessagingTests
{
    [Fact]
    public void Manifest_event_round_trips_to_application_model()
    {
        var correlationId = Guid.NewGuid();
        var manifest = new PermissionManifest(
            "orders",
            "Orders",
            "1.2.3",
            "Production",
            [new PermissionDefinition("orders.read", "Read orders", "Orders")],
            "7",
            correlationId,
            DateTimeOffset.UtcNow);

        var eventId = Guid.NewGuid();
        var envelope = PermissionManifestEventMapper.ToEvent(manifest, PermissionManifestEventTypes.Updated, eventId);
        var result = PermissionManifestEventMapper.ToApplicationManifest(envelope);

        Assert.Equal(eventId, envelope.EventId);
        Assert.Equal(PermissionManifestEventTypes.Updated, envelope.EventType);
        Assert.Equal(correlationId, result.CorrelationId);
        Assert.Equal(manifest.ManifestVersion, result.ManifestVersion);
        Assert.Equal(manifest.Permissions.Single().Name, result.Permissions.Single().Name);
    }

    [Fact]
    public void Event_mapping_rejects_missing_event_type()
    {
        var manifest = new PermissionManifest("id", "Identity", "1", "Test", [], "1", Guid.NewGuid(), DateTimeOffset.UtcNow);
        Assert.Throws<ArgumentException>(() => PermissionManifestEventMapper.ToEvent(manifest, " "));
    }
}
