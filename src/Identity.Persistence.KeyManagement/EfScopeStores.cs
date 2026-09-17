#pragma warning disable CS0618
using Identity.Application.Scope;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace Identity.Persistence.KeyManagement;

public sealed class EfScopeDefinitionLookup(KeyMetadataDbContext db, IMemoryCache cache) : IScopeDefinitionLookup, IScopeCacheInvalidator
{
    private const string ActiveKey = "scopes:active:v1";
    private const string RoleAllowedKey = "scopes:roleAllowed:v1";
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    public void Invalidate() { cache.Remove(ActiveKey); cache.Remove(RoleAllowedKey); }

    public async Task<bool> ExistsActiveAsync(string key, CancellationToken ct)
    {
        var active = await GetActiveAsync(ct);
        return active.Any(s => string.Equals(s.Key, key, StringComparison.OrdinalIgnoreCase));
    }

    public async Task<bool> IsScopeAllowedForRoleAsync(string role, string scopeKey, CancellationToken ct)
    {
        var map = await GetRoleMapAsync(ct);
        if (!map.TryGetValue(role, out var allowed)) return true;
        if (allowed.Count == 0) return true;
        return allowed.Contains(scopeKey);
    }

    private async Task<IReadOnlyCollection<ScopeDefinitionEntity>> GetActiveAsync(CancellationToken ct)
    {
        if (cache.TryGetValue(ActiveKey, out IReadOnlyCollection<ScopeDefinitionEntity>? c) && c is not null) return c;
        var list = await db.ScopeDefinitions.Where(s => s.IsActive).ToListAsync(ct);
        cache.Set(ActiveKey, (IReadOnlyCollection<ScopeDefinitionEntity>)list, Ttl);
        return list;
    }

    private async Task<Dictionary<string, HashSet<string>>> GetRoleMapAsync(CancellationToken ct)
    {
        if (cache.TryGetValue(RoleAllowedKey, out Dictionary<string, HashSet<string>>? c) && c is not null) return c;
        var rows = await (from ra in db.RoleAllowedScopes join s in db.ScopeDefinitions on ra.ScopeDefinitionId equals s.Id select new { ra.RoleName, s.Key }).ToListAsync(ct);
        var map = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in rows)
        {
            if (!map.TryGetValue(r.RoleName, out var set)) { set = new HashSet<string>(StringComparer.OrdinalIgnoreCase); map[r.RoleName] = set; }
            set.Add(r.Key);
        }
        cache.Set(RoleAllowedKey, map, Ttl);
        return map;
    }
}

public sealed class EfResourceScopeResolver(KeyMetadataDbContext db, IMemoryCache cache) : IResourceScopeResolver
{
    private const string Key = "scopes:resourceMap:v1";
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);
    public async Task<HashSet<string>> GetScopesForResourceAsync(string resourceKey, CancellationToken ct)
    {
        if (!cache.TryGetValue(Key, out Dictionary<string, HashSet<string>>? map) || map is null)
        {
            var rows = await (from m in db.ScopeResourceMappings
                              join s in db.ScopeDefinitions on m.ScopeDefinitionId equals s.Id
                              join r in db.ApplicationResources on m.ApplicationResourceId equals r.Id
                              select new { r.Key, ScopeKey = s.Key }).ToListAsync(ct);
            map = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var x in rows)
            {
                if (!map.TryGetValue(x.Key, out var set)) { set = new HashSet<string>(StringComparer.OrdinalIgnoreCase); map[x.Key] = set; }
                set.Add(x.ScopeKey);
            }
            cache.Set(Key, map, Ttl);
        }
        return map.TryGetValue(resourceKey, out var set2) ? set2 : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    }
}

public sealed class EfUserScopeStore(KeyMetadataDbContext db) : Identity.Application.Scope.IUserScopeReader, Identity.Application.Scope.IUserScopeWriter
{
    public async Task<Identity.Contracts.ScopedAccessDocument> GetAsync(string userId, CancellationToken ct)
    {
        var assigns = await db.UserRoleAssignments.Where(a => a.UserId == userId).ToListAsync(ct);
        if (assigns.Count == 0) return Identity.Contracts.ScopedAccessDocument.Empty;
        var ids = assigns.Select(a => a.Id).ToArray();
        var scopes = await db.AssignmentScopes.Where(s => ids.Contains(s.UserRoleAssignmentId)).ToListAsync(ct);
        var scopeIds = scopes.Select(s => s.Id).ToArray();
        var values = scopeIds.Length == 0 ? new List<AssignmentScopeValueEntity>()
            : await db.AssignmentScopeValues.Where(v => scopeIds.Contains(v.AssignmentScopeId)).ToListAsync(ct);
        var defMap = await db.ScopeDefinitions.ToDictionaryAsync(s => s.Id, s => s.Key, ct);
        var byAssign = new Dictionary<Guid, Dictionary<string, List<string>>>();
        foreach (var s in scopes)
        {
            if (!defMap.TryGetValue(s.ScopeDefinitionId, out var k)) continue;
            if (!byAssign.TryGetValue(s.UserRoleAssignmentId, out var d)) { d = new Dictionary<string, List<string>>(StringComparer.Ordinal); byAssign[s.UserRoleAssignmentId] = d; }
            d[k] = values.Where(v => v.AssignmentScopeId == s.Id).Select(v => v.Value).ToList();
        }
        var result = assigns.Select(a =>
        {
            byAssign.TryGetValue(a.Id, out var d);
            IReadOnlyDictionary<string, IReadOnlyCollection<string>> dict = d is null
                ? new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal)
                : d.ToDictionary(k => k.Key, v => (IReadOnlyCollection<string>)v.Value.ToArray(), StringComparer.Ordinal);
            return new Identity.Contracts.ScopedRoleAssignment(a.RoleName, dict);
        }).OrderBy(a => a.Role, StringComparer.Ordinal).ToArray();
        return new Identity.Contracts.ScopedAccessDocument(result);
    }

    public async Task<IReadOnlyDictionary<string, IReadOnlyCollection<string>>> GetEffectiveAsync(string userId, CancellationToken ct)
    {
        var doc = await GetAsync(userId, ct);
        var merged = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var a in doc.Assignments) foreach (var kv in a.Scopes)
        {
            if (!merged.TryGetValue(kv.Key, out var set)) { set = new HashSet<string>(StringComparer.Ordinal); merged[kv.Key] = set; }
            foreach (var v in kv.Value) set.Add(v);
        }
        return merged.ToDictionary(k => k.Key, v => (IReadOnlyCollection<string>)v.Value.ToArray(), StringComparer.Ordinal);
    }

    public async Task SetAsync(string userId, IReadOnlyCollection<Identity.Contracts.ScopedRoleAssignmentDto> assignments, CancellationToken ct)
    {
        var existing = await db.UserRoleAssignments.Where(a => a.UserId == userId).ToListAsync(ct);
        var eIds = existing.Select(a => a.Id).ToArray();
        if (eIds.Length > 0)
        {
            var scs = await db.AssignmentScopes.Where(s => eIds.Contains(s.UserRoleAssignmentId)).ToListAsync(ct);
            var scIds = scs.Select(s => s.Id).ToArray();
            if (scIds.Length > 0)
            {
                var vals = await db.AssignmentScopeValues.Where(v => scIds.Contains(v.AssignmentScopeId)).ToListAsync(ct);
                db.AssignmentScopeValues.RemoveRange(vals);
            }
            db.AssignmentScopes.RemoveRange(scs);
            db.UserRoleAssignments.RemoveRange(existing);
            await db.SaveChangesAsync(ct);
        }
        if (assignments.Count == 0) return;
        var defs = await db.ScopeDefinitions.ToDictionaryAsync(s => s.Key, s => s.Id, StringComparer.OrdinalIgnoreCase, ct);
        foreach (var a in assignments)
        {
            var ura = new UserRoleAssignmentEntity { Id = Guid.NewGuid(), UserId = userId, RoleName = a.Role.Trim(), AssignedAt = DateTimeOffset.UtcNow };
            db.UserRoleAssignments.Add(ura);
            foreach (var kv in a.Scopes)
            {
                if (!defs.TryGetValue(kv.Key, out var defId)) continue;
                var assignmentScope = new AssignmentScopeEntity { Id = Guid.NewGuid(), UserRoleAssignmentId = ura.Id, ScopeDefinitionId = defId };
                db.AssignmentScopes.Add(assignmentScope);
                foreach (var v in kv.Value.Distinct(StringComparer.Ordinal))
                    db.AssignmentScopeValues.Add(new AssignmentScopeValueEntity { Id = Guid.NewGuid(), AssignmentScopeId = assignmentScope.Id, Value = v.Trim() });
            }
        }
        await db.SaveChangesAsync(ct);
    }
}
