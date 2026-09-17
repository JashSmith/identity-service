using System.Linq.Expressions;

namespace Identity.Application.Scope;

public static class ResourceKeys
{
    public const string Orders = "Orders";
    public const string Branches = "Branches";
    public const string Employees = "Employees";
    public const string ProjectTasks = "ProjectTasks";
    public const string ProjectDocuments = "ProjectDocuments";
    public const string CustomerOrders = "CustomerOrders";
    public const string ResourceA = "ResourceA";
}

public interface IScopeFilterHandler<T>
{
    string ScopeKey { get; }
    string ResourceKey { get; }
    IQueryable<T> Apply(IQueryable<T> query, IReadOnlyCollection<string> allowedValues);
}

public sealed class ScopeFilterService(IResourceScopeResolver resourceResolver)
{
    private readonly Dictionary<(string Resource, string Scope), object> _handlers = new();

    public void Register<T>(IScopeFilterHandler<T> handler)
        => _handlers[(handler.ResourceKey, handler.ScopeKey)] = handler;

    public async Task<IQueryable<T>> ApplyAsync<T>(IQueryable<T> query, IReadOnlyDictionary<string, IReadOnlyCollection<string>> effectiveScopes, string resourceKey, CancellationToken ct)
    {
        var allowedScopes = await resourceResolver.GetScopesForResourceAsync(resourceKey, ct);
        if (allowedScopes.Count == 0)
            return query.Where(_ => false); // deny by default: no mapping => no access

        var applicable = effectiveScopes
            .Where(kv => allowedScopes.Contains(kv.Key))
            .ToDictionary(k => k.Key, v => v.Value, StringComparer.OrdinalIgnoreCase);

        if (applicable.Count == 0)
            return query.Where(_ => false); // user has no scopes for this resource => deny

        foreach (var kv in applicable)
        {
            if (!_handlers.TryGetValue((resourceKey, kv.Key), out var h)) continue;
            if (h is IScopeFilterHandler<T> handler)
                query = handler.Apply(query, kv.Value);
        }
        return query;
    }
}
