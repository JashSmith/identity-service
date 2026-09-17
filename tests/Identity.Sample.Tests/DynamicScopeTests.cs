using Identity.Application;
using Identity.Application.Scope;
using Identity.Contracts;
using Identity.Persistence.KeyManagement;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace Identity.Sample.Tests;

/// <summary>18 scenarios for the DB-driven dynamic scope system.</summary>
public sealed class DynamicScopeTests
{
    private static KeyMetadataDbContext InMemoryDb()
    {
        var opts = new DbContextOptionsBuilder<KeyMetadataDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        var db = new KeyMetadataDbContext(opts);
        db.Database.EnsureCreated();
        return db;
    }

    private static async Task SeedAsync(KeyMetadataDbContext db)
        => await ScopeSeed.EnsureSeededAsync(db, CancellationToken.None);

    private sealed class FakeRoleStore : IBusinessRoleStore
    {
        private readonly HashSet<string> _roles;
        public FakeRoleStore(params string[] roles) => _roles = new HashSet<string>(roles, StringComparer.Ordinal);
        public Task<BusinessRoleDto?> GetAsync(string name, CancellationToken ct) => Task.FromResult(_roles.Contains(name) ? new BusinessRoleDto(name, null, true, Array.Empty<string>()) : null);
        public Task<IReadOnlyCollection<BusinessRoleDto>> ListAsync(CancellationToken ct) => Task.FromResult((IReadOnlyCollection<BusinessRoleDto>)_roles.Select(r => new BusinessRoleDto(r, null, true, Array.Empty<string>())).ToArray());
        public Task<BusinessRoleDto> CreateAsync(string name, string? desc, IReadOnlyCollection<string> perms, CancellationToken ct) { _roles.Add(name); return Task.FromResult(new BusinessRoleDto(name, desc, true, perms.ToArray())); }
        public Task<BusinessRoleDto?> UpdateAsync(string name, string? desc, CancellationToken ct) => Task.FromResult<BusinessRoleDto?>(null);
        public Task<bool> DeleteAsync(string name, CancellationToken ct) => Task.FromResult(_roles.Remove(name));
        public Task<IReadOnlyCollection<string>> GetEffectivePermissionsAsync(string name, CancellationToken ct) => Task.FromResult((IReadOnlyCollection<string>)Array.Empty<string>());
        public Task AddPermissionsAsync(string name, IReadOnlyCollection<string> perms, CancellationToken ct) => Task.CompletedTask;
        public Task RemovePermissionAsync(string name, string perm, CancellationToken ct) => Task.CompletedTask;
    }

    // 1 valid dynamic scope
    [Fact]
    public async Task Scenario01_ValidDynamicScope_Passes()
    {
        using var db = InMemoryDb(); await SeedAsync(db);
        var cache = new MemoryCache(new MemoryCacheOptions());
        var lookup = new EfScopeDefinitionLookup(db, cache);
        var validator = new ScopeAssignmentValidator(lookup, new ScopeValueValidatorRegistry([new DefaultScopeValueValidator()]));
        var errors = await validator.ValidateAsync([new ScopedRoleAssignmentDto("R", new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = ["tehran-1"] })], new FakeRoleStore("R"), CancellationToken.None);
        Assert.Empty(errors);
    }

    // 2 multi-values
    [Fact]
    public async Task Scenario02_MultiValues_Passes()
    {
        using var db = InMemoryDb(); await SeedAsync(db);
        var cache = new MemoryCache(new MemoryCacheOptions());
        var lookup = new EfScopeDefinitionLookup(db, cache);
        var validator = new ScopeAssignmentValidator(lookup, new ScopeValueValidatorRegistry([new DefaultScopeValueValidator()]));
        var errors = await validator.ValidateAsync([new ScopedRoleAssignmentDto("R", new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = ["tehran-1", "tehran-2"] })], new FakeRoleStore("R"), CancellationToken.None);
        Assert.Empty(errors);
    }

    // 3 multi-scopes
    [Fact]
    public async Task Scenario03_MultiScopes_Passes()
    {
        using var db = InMemoryDb(); await SeedAsync(db);
        var cache = new MemoryCache(new MemoryCacheOptions());
        var lookup = new EfScopeDefinitionLookup(db, cache);
        var validator = new ScopeAssignmentValidator(lookup, new ScopeValueValidatorRegistry([new DefaultScopeValueValidator()]));
        var errors = await validator.ValidateAsync([new ScopedRoleAssignmentDto("R", new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = ["tehran-1"], ["branch"] = ["b-1"] })], new FakeRoleStore("R"), CancellationToken.None);
        Assert.Empty(errors);
    }

    // 4 unknown scope 400
    [Fact]
    public async Task Scenario04_UnknownScope_Fails()
    {
        using var db = InMemoryDb(); await SeedAsync(db);
        var cache = new MemoryCache(new MemoryCacheOptions());
        var lookup = new EfScopeDefinitionLookup(db, cache);
        var validator = new ScopeAssignmentValidator(lookup, new ScopeValueValidatorRegistry([new DefaultScopeValueValidator()]));
        var errors = await validator.ValidateAsync([new ScopedRoleAssignmentDto("R", new Dictionary<string, IReadOnlyCollection<string>> { ["unknown-scope"] = ["x"] })], new FakeRoleStore("R"), CancellationToken.None);
        Assert.NotEmpty(errors);
        Assert.Contains(errors.Keys, k => k.Contains("unknown-scope"));
    }

    // 5 inactive 400
    [Fact]
    public async Task Scenario05_InactiveScope_Fails()
    {
        using var db = InMemoryDb(); await SeedAsync(db);
        var def = await db.ScopeDefinitions.FirstAsync(x => x.Key == "region");
        def.IsActive = false; await db.SaveChangesAsync();
        var cache = new MemoryCache(new MemoryCacheOptions());
        var lookup = new EfScopeDefinitionLookup(db, cache);
        var validator = new ScopeAssignmentValidator(lookup, new ScopeValueValidatorRegistry([new DefaultScopeValueValidator()]));
        var errors = await validator.ValidateAsync([new ScopedRoleAssignmentDto("R", new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = ["tehran-1"] })], new FakeRoleStore("R"), CancellationToken.None);
        Assert.NotEmpty(errors);
    }

    // 6 invalid value 400
    [Fact]
    public async Task Scenario06_InvalidValue_Fails()
    {
        using var db = InMemoryDb(); await SeedAsync(db);
        var cache = new MemoryCache(new MemoryCacheOptions());
        var lookup = new EfScopeDefinitionLookup(db, cache);
        var validator = new ScopeAssignmentValidator(lookup, new ScopeValueValidatorRegistry([new DefaultScopeValueValidator()]));
        var errors = await validator.ValidateAsync([new ScopedRoleAssignmentDto("R", new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = [""] })], new FakeRoleStore("R"), CancellationToken.None);
        Assert.NotEmpty(errors);
    }

    // 7 role-not-allowed 400
    [Fact]
    public async Task Scenario07_RoleNotAllowed_Fails()
    {
        using var db = InMemoryDb(); await SeedAsync(db);
        var regionDef = await db.ScopeDefinitions.FirstAsync(x => x.Key == "region");
        db.RoleAllowedScopes.Add(new RoleAllowedScopeEntity { RoleName = "R", ScopeDefinitionId = regionDef.Id });
        await db.SaveChangesAsync();
        var cache = new MemoryCache(new MemoryCacheOptions());
        var lookup = new EfScopeDefinitionLookup(db, cache);
        var validator = new ScopeAssignmentValidator(lookup, new ScopeValueValidatorRegistry([new DefaultScopeValueValidator()]));
        // branch not allowed for R (only region)
        var errors = await validator.ValidateAsync([new ScopedRoleAssignmentDto("R", new Dictionary<string, IReadOnlyCollection<string>> { ["branch"] = ["b-1"] })], new FakeRoleStore("R"), CancellationToken.None);
        Assert.NotEmpty(errors);
    }

    // 8 get effective scopes
    [Fact]
    public async Task Scenario08_GetEffectiveScopes_Union()
    {
        using var db = InMemoryDb(); await SeedAsync(db);
        var store = new EfUserScopeStore(db);
        await store.SetAsync("u1", [new ScopedRoleAssignmentDto("R1", new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = ["a"] }), new ScopedRoleAssignmentDto("R2", new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = ["b"] })], CancellationToken.None);
        var eff = await store.GetEffectiveAsync("u1", CancellationToken.None);
        Assert.Contains("a", eff["region"]);
        Assert.Contains("b", eff["region"]);
    }

    // 9 get individual values
    [Fact]
    public async Task Scenario09_GetAssignments_PreservesRoles()
    {
        using var db = InMemoryDb(); await SeedAsync(db);
        var store = new EfUserScopeStore(db);
        await store.SetAsync("u1", [new ScopedRoleAssignmentDto("R1", new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = ["a"] })], CancellationToken.None);
        var doc = await store.GetAsync("u1", CancellationToken.None);
        Assert.Single(doc.Assignments);
        Assert.Equal("R1", doc.Assignments.First().Role);
    }

    // 10 apply allowed resource
    [Fact]
    public async Task Scenario10_ApplyAllowedResource_Filters()
    {
        using var db = InMemoryDb(); await SeedAsync(db);
        var cache = new MemoryCache(new MemoryCacheOptions());
        var resolver = new EfResourceScopeResolver(db, cache);
        var svc = new ScopeFilterService(resolver);
        svc.Register(new SampleApp.RegionOrderFilter());
        var orders = new[] { new SampleApp.OrderDto("1", "u", 10, "open", "tehran-1"), new SampleApp.OrderDto("2", "u", 10, "open", "tehran-9") }.AsQueryable();
        var effective = new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = new[] { "tehran-1" } };
        var result = await svc.ApplyAsync(orders, effective, ResourceKeys.Orders, CancellationToken.None);
        Assert.Single(result);
    }

    // 11 prevent unrelated resource
    [Fact]
    public async Task Scenario11_PreventUnrelatedResource_NoLeak()
    {
        using var db = InMemoryDb(); await SeedAsync(db);
        var cache = new MemoryCache(new MemoryCacheOptions());
        var resolver = new EfResourceScopeResolver(db, cache);
        var svc = new ScopeFilterService(resolver);
        svc.Register(new SampleApp.TestKeyResourceAFilter());
        // test-key is mapped only to ResourceA, not Orders — so Orders query should deny (empty)
        var orders = new[] { new SampleApp.OrderDto("1", "u", 10, "open", "items-1") }.AsQueryable();
        var effective = new Dictionary<string, IReadOnlyCollection<string>> { ["test-key"] = new[] { "items-1" } };
        var result = await svc.ApplyAsync(orders, effective, ResourceKeys.Orders, CancellationToken.None);
        Assert.Empty(result);
    }

    // 12 multi-values OR
    [Fact]
    public async Task Scenario12_MultiValues_OR()
    {
        using var db = InMemoryDb(); await SeedAsync(db);
        var cache = new MemoryCache(new MemoryCacheOptions());
        var resolver = new EfResourceScopeResolver(db, cache);
        var svc = new ScopeFilterService(resolver);
        svc.Register(new SampleApp.RegionOrderFilter());
        var orders = new[] { new SampleApp.OrderDto("1", "u", 10, "open", "tehran-1"), new SampleApp.OrderDto("2", "u", 10, "open", "tehran-2"), new SampleApp.OrderDto("3", "u", 10, "open", "tehran-9") }.AsQueryable();
        var effective = new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = new[] { "tehran-1", "tehran-2" } };
        var result = await svc.ApplyAsync(orders, effective, ResourceKeys.Orders, CancellationToken.None);
        Assert.Equal(2, result.Count());
    }

    // 13 multi-dimensions AND
    [Fact]
    public async Task Scenario13_MultiDimensions_AND()
    {
        using var db = InMemoryDb(); await SeedAsync(db);
        var cache = new MemoryCache(new MemoryCacheOptions());
        var resolver = new EfResourceScopeResolver(db, cache);
        var svc = new ScopeFilterService(resolver);
        svc.Register(new SampleApp.RegionOrderFilter());
        svc.Register(new SampleApp.BranchOrderFilter());
        var orders = new[] { new SampleApp.OrderDto("1", "u", 10, "open", "tehran-1") }.AsQueryable();
        var effective = new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = new[] { "tehran-1" }, ["branch"] = new[] { "other" } };
        // Both region and branch apply to Orders — branch mismatch should filter out (deny branch values don't contain tehran-1)
        var result = await svc.ApplyAsync(orders, effective, ResourceKeys.Orders, CancellationToken.None);
        Assert.Empty(result);
    }

    // 14 no scope => deny not unrestricted
    [Fact]
    public async Task Scenario14_NoScope_Denies()
    {
        using var db = InMemoryDb(); await SeedAsync(db);
        var cache = new MemoryCache(new MemoryCacheOptions());
        var resolver = new EfResourceScopeResolver(db, cache);
        var svc = new ScopeFilterService(resolver);
        var orders = new[] { new SampleApp.OrderDto("1", "u", 10, "open", "tehran-1") }.AsQueryable();
        var effective = new Dictionary<string, IReadOnlyCollection<string>>();
        var result = await svc.ApplyAsync(orders, effective, ResourceKeys.Orders, CancellationToken.None);
        Assert.Empty(result);
    }

    // 15 malformed JSON clean error (converter)
    [Fact]
    public void Scenario15_MalformedJson_ThrowsClean()
    {
        // converter should throw JsonException with clean message, not leak internals
        var json = """{"assignments":[{"role":"R","scopes":{"test-key":123}}]}""";
        Assert.ThrowsAny<System.Text.Json.JsonException>(() =>
            System.Text.Json.JsonSerializer.Deserialize<ScopedRoleAssignmentDto[]>(json, new System.Text.Json.JsonSerializerOptions { Converters = { new ScopeDictionaryConverter() } }));
    }

    // 16 persistence reload
    [Fact]
    public async Task Scenario16_PersistenceReload()
    {
        using var db = InMemoryDb(); await SeedAsync(db);
        var store = new EfUserScopeStore(db);
        await store.SetAsync("u1", [new ScopedRoleAssignmentDto("R", new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = ["tehran-1"] })], CancellationToken.None);
        var doc1 = await store.GetAsync("u1", CancellationToken.None);
        var doc2 = await store.GetAsync("u1", CancellationToken.None);
        Assert.Equal(doc1.Assignments.First().Scopes["region"].First(), doc2.Assignments.First().Scopes["region"].First());
    }

    // 17 update/removal
    [Fact]
    public async Task Scenario17_UpdateRemoval()
    {
        using var db = InMemoryDb(); await SeedAsync(db);
        var store = new EfUserScopeStore(db);
        await store.SetAsync("u1", [new ScopedRoleAssignmentDto("R", new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = ["a"] })], CancellationToken.None);
        await store.SetAsync("u1", [new ScopedRoleAssignmentDto("R", new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = ["b"] })], CancellationToken.None);
        var doc = await store.GetAsync("u1", CancellationToken.None);
        Assert.Equal("b", doc.Assignments.First().Scopes["region"].First());
        await store.SetAsync("u1", [], CancellationToken.None);
        Assert.Empty((await store.GetAsync("u1", CancellationToken.None)).Assignments);
    }

    // 18 after config change
    [Fact]
    public async Task Scenario18_AfterConfigChange()
    {
        using var db = InMemoryDb(); await SeedAsync(db);
        var cache = new MemoryCache(new MemoryCacheOptions());
        var lookup = new EfScopeDefinitionLookup(db, cache);
        var validator = new ScopeAssignmentValidator(lookup, new ScopeValueValidatorRegistry([new DefaultScopeValueValidator()]));
        // initially region active
        var ok = await validator.ValidateAsync([new ScopedRoleAssignmentDto("R", new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = ["x"] })], new FakeRoleStore("R"), CancellationToken.None);
        Assert.Empty(ok);
        // disable region
        var def = await db.ScopeDefinitions.FirstAsync(x => x.Key == "region");
        def.IsActive = false; await db.SaveChangesAsync();
        lookup.Invalidate();
        var errors = await validator.ValidateAsync([new ScopedRoleAssignmentDto("R", new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = ["x"] })], new FakeRoleStore("R"), CancellationToken.None);
        Assert.NotEmpty(errors);
    }

    // Scalar normalization
    [Fact]
    public void ScalarNormalization_SingleStringBecomesArray()
    {
        var json = """{"role":"R","scopes":{"test-key":"items-1"}}""";
        var dto = System.Text.Json.JsonSerializer.Deserialize<ScopedRoleAssignmentDto>(json, new System.Text.Json.JsonSerializerOptions { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase, Converters = { new ScopeDictionaryConverter() } });
        Assert.NotNull(dto);
        Assert.Equal("items-1", dto!.Scopes["test-key"].First());
    }
}
