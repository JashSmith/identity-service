using Identity.Application.Scope;

namespace SampleApp;

public sealed class RegionOrderFilter : IScopeFilterHandler<OrderDto>
{
    public string ScopeKey => "region";
    public string ResourceKey => ResourceKeys.Orders;
    public IQueryable<OrderDto> Apply(IQueryable<OrderDto> query, IReadOnlyCollection<string> allowedValues)
        => query.Where(o => allowedValues.Contains(o.Region));
}

public sealed class BranchOrderFilter : IScopeFilterHandler<OrderDto>
{
    public string ScopeKey => "branch";
    public string ResourceKey => ResourceKeys.Orders;
    // Branch demo reuses Region field for simplicity; real entity would have BranchId.
    public IQueryable<OrderDto> Apply(IQueryable<OrderDto> query, IReadOnlyCollection<string> allowedValues)
        => query.Where(o => allowedValues.Contains(o.Region));
}

public sealed class TestKeyResourceAFilter : IScopeFilterHandler<OrderDto>
{
    public string ScopeKey => "test-key";
    public string ResourceKey => ResourceKeys.ResourceA;
    public IQueryable<OrderDto> Apply(IQueryable<OrderDto> query, IReadOnlyCollection<string> allowedValues)
        => query.Where(o => allowedValues.Contains(o.Region));
}

/// <summary>In-memory resolver for the sample — mirrors DB mapping without requiring a DB.</summary>
public sealed class SampleResourceScopeResolver : IResourceScopeResolver
{
    private static readonly Dictionary<string, HashSet<string>> Map = new(StringComparer.OrdinalIgnoreCase)
    {
        [ResourceKeys.Orders] = new(["region", "branch", "warehouse", "customer"], StringComparer.OrdinalIgnoreCase),
        [ResourceKeys.Branches] = new(["region"], StringComparer.OrdinalIgnoreCase),
        [ResourceKeys.Employees] = new(["region", "branch", "department", "organization"], StringComparer.OrdinalIgnoreCase),
        [ResourceKeys.ProjectTasks] = new(["project"], StringComparer.OrdinalIgnoreCase),
        [ResourceKeys.ProjectDocuments] = new(["project"], StringComparer.OrdinalIgnoreCase),
        [ResourceKeys.CustomerOrders] = new(["customer"], StringComparer.OrdinalIgnoreCase),
        [ResourceKeys.ResourceA] = new(["test-key"], StringComparer.OrdinalIgnoreCase),
    };
    public Task<HashSet<string>> GetScopesForResourceAsync(string resourceKey, CancellationToken ct)
        => Task.FromResult(Map.TryGetValue(resourceKey, out var s) ? new HashSet<string>(s, StringComparer.OrdinalIgnoreCase) : new HashSet<string>(StringComparer.OrdinalIgnoreCase));
}
