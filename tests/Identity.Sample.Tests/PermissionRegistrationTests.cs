using System.Reflection;
using Avash.Identity.Abstractions;
using Avash.Identity.PermissionDiscovery;
using Avash.Identity.PermissionRegistration;
using Identity.Gateway;
using Identity.Application;
using Identity.Contracts;
using Microsoft.Extensions.Logging.Abstractions;
using SampleApp;

namespace Identity.Sample.Tests;

/// <summary>
/// Tests for the sample consumer service (OrderService.Sample) and the permission
/// registration pipeline it exercises: discovery of [RequirePermission] attributes,
/// manifest creation/hashing, the gateway registry, and best-effort Keycloak role sync.
/// </summary>
public sealed class PermissionDiscoveryTests
{
    private static readonly Assembly SampleAssembly = typeof(OrderService).Assembly;

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
    public void Sample_declares_exactly_ten_distinct_permissions()
    {
        var discovered = PermissionDiscovery.Discover(SampleAssembly);
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
        var discovered = PermissionDiscovery.Discover(SampleAssembly).ToList();
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





public sealed class SampleServiceBehaviorTests
{
    private readonly OrderService _svc = new();

    [Fact]
    public void ListOrders_returns_seeded_orders()
    {
        Assert.Equal(3, _svc.ListOrders().Count);
    }

    [Fact]
    public void CreateOrder_validates_inputs()
    {
        Assert.Throws<ArgumentException>(() => _svc.CreateOrder(" ", 10m));
        Assert.Throws<ArgumentOutOfRangeException>(() => _svc.CreateOrder("alice", 0m));
        var order = _svc.CreateOrder("alice", 42.5m);
        Assert.Equal("open", order.Status);
        Assert.Equal(42.5m, order.Total);
    }

    [Fact]
    public void ExportReport_rejects_unknown_format()
    {
        Assert.Equal("report.csv", _svc.ExportReport("csv"));
        Assert.Equal("report.json", _svc.ExportReport("JSON"));
        Assert.Throws<ArgumentException>(() => _svc.ExportReport("xml"));
    }

    [Fact]
    public void ApproveRefund_rejects_nonpositive_amount()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _svc.ApproveRefund("ord-1", -1m));
        Assert.True(_svc.ApproveRefund("ord-1", 10m).Approved);
    }
}