using System.Reflection;
using Avash.Identity.Abstractions;
using Avash.Identity.PermissionDiscovery;
using Avash.Identity.PermissionRegistration;
using Identity.Gateway;
using Identity.Application;
using Identity.Contracts;
using Microsoft.Extensions.Logging.Abstractions;
using Identity.Packages.Tests.Fixtures;

namespace Identity.Packages.Tests;

/// <summary>
/// Permission registration pipeline of the consumer packages: discovery of [RequirePermission]
/// attributes and manifest creation/hashing, against the ten-permission test fixture.
/// </summary>
public sealed class PermissionDiscoveryTests
{
    private static readonly Assembly FixtureAssembly = typeof(OrderService).Assembly;

    private static readonly string[] ExpectedTenPermissions =
    [
        OrderPermissions.ViewOrders,
        OrderPermissions.CreateOrders,
        OrderPermissions.EditOrders,
        OrderPermissions.CancelOrders,
        OrderPermissions.ViewInvoices,
        OrderPermissions.IssueInvoices,
        OrderPermissions.ViewShipments,
        OrderPermissions.ScheduleShipments,
        OrderPermissions.ApproveRefunds,
        OrderPermissions.ExportReports,
    ];

    [Fact]
    public void Fixture_declares_exactly_ten_distinct_permissions()
    {
        var discovered = PermissionDiscovery.Discover(FixtureAssembly);
        Assert.Equal(10, discovered.Count);
        Assert.Equal(10, discovered.Select(d => d.Name).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(ExpectedTenPermissions.OrderBy(x => x, StringComparer.Ordinal),
            discovered.Select(d => d.Name).OrderBy(x => x, StringComparer.Ordinal));
    }

    [Fact]
    public void Every_guarded_method_carries_exactly_one_permission_attribute()
    {
        var guarded = typeof(OrderService)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(m => (Method: m, Attrs: m.GetCustomAttributes<RequirePermissionAttribute>(true).ToArray()))
            .Where(x => x.Attrs.Length > 0)
            .ToArray();
        Assert.Equal(10, guarded.Length);
        Assert.All(guarded, g => Assert.Single(g.Attrs));
    }

    [Fact]
    public void Discovery_returns_sorted_descriptors_with_module()
    {
        var discovered = PermissionDiscovery.Discover(FixtureAssembly).ToList();
        Assert.Equal(discovered.Select(d => d.Name).OrderBy(x => x, StringComparer.Ordinal),
            discovered.Select(d => d.Name));
        Assert.All(discovered, d => Assert.Equal(typeof(OrderService).Namespace, d.Module));
        Assert.All(discovered, d => Assert.False(string.IsNullOrWhiteSpace(d.Description)));
    }
}

public sealed class PermissionManifestTests
{
    private static PermissionRegistrationOptions Options(string version = "1.0.0") => new()
    {
        IdentityServer = new Uri("http://localhost:5080"),
        ServiceName = "order-service",
        ServiceVersion = version,
    };

    [Fact]
    public void Create_falls_back_to_service_name_as_service_id()
    {
        var manifest = PermissionManifest.Create(Options(), typeof(OrderService).Assembly);
        Assert.Equal("order-service", manifest.ServiceId);
        Assert.Equal(10, manifest.Permissions.Count);
    }

    [Fact]
    public void Create_produces_deterministic_sha256_hash()
    {
        var a = PermissionManifest.Create(Options(), typeof(OrderService).Assembly);
        var b = PermissionManifest.Create(Options(), typeof(OrderService).Assembly);
        Assert.Equal(a.ManifestHash, b.ManifestHash);
        Assert.StartsWith("sha256:", a.ManifestHash, StringComparison.Ordinal);
        Assert.Equal(7 + 64, a.ManifestHash.Length);
    }

    [Fact]
    public void Hash_changes_when_service_version_changes()
    {
        var a = PermissionManifest.Create(Options("1.0.0"), typeof(OrderService).Assembly);
        var b = PermissionManifest.Create(Options("1.0.1"), typeof(OrderService).Assembly);
        Assert.NotEqual(a.ManifestHash, b.ManifestHash);
    }
}
