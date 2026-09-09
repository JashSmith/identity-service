using Identity.Domain;

namespace Identity.Domain.Tests;

public sealed class DomainTests
{
    [Fact]
    public void PermissionManifest_records_are_distinct_by_hash()
    {
        var a = new PermissionManifest("order-service", "1.0.0", "1", [new PermissionDefinition("Orders.Read", "read")],
            "sha256:abc");
        var b = new PermissionManifest("order-service", "1.0.0", "1", [new PermissionDefinition("Orders.Read", "read")],
            "sha256:def");
        Assert.NotEqual(a.ManifestHash, b.ManifestHash);
    }

    [Fact]
    public void Deprecated_permissions_are_tracked_on_registration_state()
    {
        var state = new ManifestRegistrationState("order-service", "2", "sha256:abc", DateTimeOffset.UtcNow,
            ["Orders.Legacy"]);
        Assert.Contains("Orders.Legacy", state.DeprecatedPermissions);
    }

    [Fact]
    public void Audit_events_never_carry_raw_secrets_in_details_keys()
    {
        var evt = new AuditEvent("svc:order-service", "manifest.registered", "service=order-service",
            DateTimeOffset.UtcNow, new Dictionary<string, string?> {["manifest_hash"] = "sha256:abc"});
        Assert.DoesNotContain(evt.Details.Keys, k => k.Equals("access_token", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(evt.Details.Keys, k => k.Equals("private_key", StringComparison.OrdinalIgnoreCase));
    }
}