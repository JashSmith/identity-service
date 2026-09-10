using System.Reflection;
using Company.Identity.Abstractions;
using Company.Identity.PermissionDiscovery;
using Company.Identity.PermissionRegistration;
using Identity.Api;
using Identity.Application;
using Identity.Contracts;
using Microsoft.Extensions.Logging.Abstractions;
using SampleApp;

namespace Identity.Sample.Tests;

/// <summary>
/// Tests for the sample consumer service (OrderService.Sample) and the permission
/// registration pipeline it exercises: discovery of [RequirePermission] attributes,
/// manifest creation/hashing, the facade registry, and best-effort Keycloak role sync.
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

public sealed class RegistryTests
{
    private static PermissionManifestRequest Manifest(string serviceId, params (string Name, string Desc)[] perms) =>
        new(serviceId, "1.0.0", "1",
            perms.Select(p => new PermissionDefinitionDto(p.Name, p.Desc)).ToList(),
            "sha256:test");

    [Fact]
    public async Task Register_upserts_permissions_and_reports_none_deprecated()
    {
        IPermissionRegistry registry = new InMemoryPermissionRegistry();
        var res = await registry.RegisterAsync(
            Manifest("order-service", ("Orders.View", "View orders"), ("Orders.Create", "Create orders")),
            "order-service", CancellationToken.None);

        Assert.True(res.Accepted);
        Assert.Empty(res.DeprecatedPermissions);

        var perms = await registry.GetPermissionsAsync("order-service", false, CancellationToken.None);
        Assert.Equal(2, perms.Count);
        Assert.All(perms, p => Assert.False(p.Deprecated));
    }

    [Fact]
    public async Task Register_soft_deprecates_missing_permissions_never_deletes()
    {
        var inner = new InMemoryPermissionRegistry();
        IPermissionRegistry registry = inner;
        await registry.RegisterAsync(
            Manifest("order-service", ("Orders.View", "View"), ("Orders.Legacy", "Gone next release")),
            "order-service", CancellationToken.None);

        var res = await registry.RegisterAsync(
            Manifest("order-service", ("Orders.View", "View")),
            "order-service", CancellationToken.None);

        Assert.Equal(["Orders.Legacy"], res.DeprecatedPermissions);
        var active = await registry.GetPermissionsAsync("order-service", false, CancellationToken.None);
        Assert.Single(active);
        var withDeprecated = await registry.GetPermissionsAsync("order-service", true, CancellationToken.None);
        Assert.Equal(2, withDeprecated.Count);
        Assert.Contains(withDeprecated, p => p is { Name: "Orders.Legacy", Deprecated: true });
    }

    [Fact]
    public async Task Register_is_idempotent_for_identical_manifest()
    {
        IPermissionRegistry registry = new InMemoryPermissionRegistry();
        var m = Manifest("order-service", ("Orders.View", "View"));
        var first = await registry.RegisterAsync(m, "order-service", CancellationToken.None);
        var second = await registry.RegisterAsync(m, "order-service", CancellationToken.None);
        Assert.True(first.Accepted);
        Assert.True(second.Accepted);
        Assert.Empty(second.DeprecatedPermissions);
        Assert.Single(await registry.GetPermissionsAsync("order-service", false, CancellationToken.None));
    }
}

public sealed class KeycloakSyncTests
{
    private sealed class RecordingProvisioner : IKeycloakRoleProvisioner
    {
        public List<(string Name, string? Description)> Calls { get; } = [];
        public bool FailAll { get; set; }

        public Task<bool> EnsureRoleAsync(string name, string? description, CancellationToken ct)
        {
            Calls.Add((name, description));
            return Task.FromResult(!FailAll);
        }
    }

    private static PermissionManifestRequest Manifest(params string[] perms) =>
        new("order-service", "1.0.0", "1",
            perms.Select(p => new PermissionDefinitionDto(p, $"Permission for {p}")).ToList(),
            "sha256:test");

    [Fact]
    public async Task Registration_provisions_every_permission_as_keycloak_role()
    {
        var provisioner = new RecordingProvisioner();
        IPermissionRegistry registry = new KeycloakSyncingPermissionRegistry(
            new InMemoryPermissionRegistry(), provisioner, NullLogger<KeycloakSyncingPermissionRegistry>.Instance);

        var res = await registry.RegisterAsync(Manifest("Orders.View", "Orders.Create"),
            "order-service", CancellationToken.None);

        Assert.True(res.Accepted);
        Assert.Equal(2, provisioner.Calls.Count);
        Assert.Contains(provisioner.Calls, c => c.Name == "Orders.View");
        Assert.Contains(provisioner.Calls, c => c.Name == "Orders.Create");
    }

    [Fact]
    public async Task Provisioning_failure_never_blocks_registration()
    {
        var provisioner = new RecordingProvisioner { FailAll = true };
        IPermissionRegistry registry = new KeycloakSyncingPermissionRegistry(
            new InMemoryPermissionRegistry(), provisioner, NullLogger<KeycloakSyncingPermissionRegistry>.Instance);

        var res = await registry.RegisterAsync(Manifest("Orders.View"), "order-service", CancellationToken.None);

        Assert.True(res.Accepted);
        Assert.Single(await registry.GetPermissionsAsync(null, false, CancellationToken.None));
    }

    [Fact]
    public async Task Deprecation_never_removes_keycloak_roles()
    {
        var provisioner = new RecordingProvisioner();
        var inner = new InMemoryPermissionRegistry();
        IPermissionRegistry registry = new KeycloakSyncingPermissionRegistry(
            inner, provisioner, NullLogger<KeycloakSyncingPermissionRegistry>.Instance);

        await registry.RegisterAsync(Manifest("Orders.View", "Orders.Legacy"),
            "order-service", CancellationToken.None);
        provisioner.Calls.Clear();

        var res = await registry.RegisterAsync(Manifest("Orders.View"), "order-service", CancellationToken.None);

        // Orders.Legacy is deprecated locally but no removal call is made against Keycloak.
        Assert.Equal(["Orders.Legacy"], res.DeprecatedPermissions);
        Assert.Equal(["Orders.View"], provisioner.Calls.Select(c => c.Name));
        var withDeprecated = await registry.GetPermissionsAsync(null, true, CancellationToken.None);
        Assert.Contains(withDeprecated, p => p is { Name: "Orders.Legacy", Deprecated: true });
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
