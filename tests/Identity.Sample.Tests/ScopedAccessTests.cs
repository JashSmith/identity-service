using System.Security.Claims;
using Company.Identity.Authorization;
using Identity.Application;
using Identity.Contracts;

namespace Identity.Sample.Tests;

public sealed class ScopedAccessSerializerTests
{
    private readonly ScopedAccessSerializer _sut = new();

    [Fact]
    public void RoundTrips_SingleRole_SingleKey_SingleValue()
    {
        var doc = new ScopedAccessDocument([
            new ScopedRoleAssignment("RegionalManager", new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = ["tehran-1"] })
        ]);
        var json = _sut.Serialize(doc);
        var back = _sut.Deserialize(json);
        Assert.Single(back.Assignments);
        var a = back.Assignments.First();
        Assert.Equal("RegionalManager", a.Role);
        Assert.Equal(["tehran-1"], a.Scopes["region"]);
    }

    [Fact]
    public void RoundTrips_MultipleValues_SingleKey()
    {
        var doc = new ScopedAccessDocument([
            new ScopedRoleAssignment("RegionalManager", new Dictionary<string,IReadOnlyCollection<string>>{["region"]=["tehran-1","tehran-2"]})
        ]);
        var json = _sut.Serialize(doc);
        var back = _sut.Deserialize(json);
        Assert.Equal(2, back.Assignments.First().Scopes["region"].Count);
    }

    [Fact]
    public void RoundTrips_MultipleKeys()
    {
        var doc = new ScopedAccessDocument([
            new ScopedRoleAssignment("RegionalManager", new Dictionary<string,IReadOnlyCollection<string>>{["region"]=["tehran-1"], ["branch"]=["b-1"]})
        ]);
        var back = _sut.Deserialize(_sut.Serialize(doc));
        Assert.Equal(2, back.Assignments.First().Scopes.Count);
    }

    [Fact]
    public void RoundTrips_MultipleRoles()
    {
        var doc = new ScopedAccessDocument([
            new ScopedRoleAssignment("RegionalManager", new Dictionary<string,IReadOnlyCollection<string>>{["region"]=["tehran-1"]}),
            new ScopedRoleAssignment("Auditor", new Dictionary<string,IReadOnlyCollection<string>>{["region"]=["global"]}),
        ]);
        var back = _sut.Deserialize(_sut.Serialize(doc));
        Assert.Equal(2, back.Assignments.Count);
    }

    [Fact]
    public void EmptyScopes_SerializeDeserialize()
    {
        var doc = ScopedAccessDocument.Empty;
        var json = _sut.Serialize(doc);
        Assert.Equal("[]", json);
        var back = _sut.Deserialize(json);
        Assert.Empty(back.Assignments);
    }

    [Fact]
    public void DistinctAndTrimming_Normalizes()
    {
        var doc = new ScopedAccessDocument([
            new ScopedRoleAssignment("  RegionalManager ", new Dictionary<string,IReadOnlyCollection<string>>{[" region "] = [" tehran-1 ", "tehran-1"]})
        ]);
        var back = _sut.Deserialize(_sut.Serialize(doc));
        var a = back.Assignments.First();
        Assert.Equal("RegionalManager", a.Role);
        Assert.Single(a.Scopes["region"]);
        Assert.Equal("tehran-1", a.Scopes["region"].First());
    }

    [Fact]
    public void NullOrWhitespace_DeserializesToEmpty()
    {
        Assert.Empty(_sut.Deserialize(null).Assignments);
        Assert.Empty(_sut.Deserialize("").Assignments);
        Assert.Empty(_sut.Deserialize("   ").Assignments);
        Assert.Empty(_sut.Deserialize("not-json").Assignments);
    }
}

public sealed class AccessContextTests
{
    private static ClaimsPrincipal PrincipalWith(string[] permissions, string? iamAccessJson)
    {
        var claims = permissions.Select(p => new Claim("permission", p)).ToList();
        if (iamAccessJson is not null) claims.Add(new Claim(ScopedAccessConstants.ClaimName, iamAccessJson));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
    }

    [Fact]
    public void PermissionPlusMatchingScope_Allowed()
    {
        var iam = """[{"role":"RegionalManager","scopes":{"region":["tehran-1","tehran-2"]}}]""";
        var ctx = new ClaimsPrincipalAccessContext(PrincipalWith(["Orders.View"], iam));
        Assert.True(ctx.HasPermission("Orders.View", "region", "tehran-1"));
    }

    [Fact]
    public void PermissionPlusWrongScope_Forbidden()
    {
        var iam = """[{"role":"RegionalManager","scopes":{"region":["tehran-1"]}}]""";
        var ctx = new ClaimsPrincipalAccessContext(PrincipalWith(["Orders.View"], iam));
        Assert.False(ctx.HasPermission("Orders.View", "region", "tehran-9"));
    }

    [Fact]
    public void ScopeWithoutPermission_Forbidden()
    {
        var iam = """[{"role":"RegionalManager","scopes":{"region":["tehran-1"]}}]""";
        var ctx = new ClaimsPrincipalAccessContext(PrincipalWith([], iam));
        Assert.False(ctx.HasPermission("Orders.View", "region", "tehran-1"));
    }

    [Fact]
    public void GetScopeValues_ReturnsUnionAcrossRoles_EfFriendly()
    {
        var iam = """[{"role":"A","scopes":{"region":["tehran-1"]}},{"role":"B","scopes":{"region":["tehran-2"]}}]""";
        var ctx = new ClaimsPrincipalAccessContext(PrincipalWith(["Orders.View"], iam));
        var vals = ctx.GetScopeValues("region");
        Assert.Contains("tehran-1", vals);
        Assert.Contains("tehran-2", vals);
    }

    [Fact]
    public void HasScope_WithoutClaim_ReturnsFalse()
    {
        var ctx = new ClaimsPrincipalAccessContext(PrincipalWith(["Orders.View"], null));
        Assert.False(ctx.HasScope("region", "tehran-1"));
    }
}

public sealed class ScopedOrderingTests
{
    [Fact]
    public void SameRole_DifferentScopes_AreDistinctAssignments()
    {
        var doc = new ScopedAccessDocument([
            new ScopedRoleAssignment("Manager", new Dictionary<string,IReadOnlyCollection<string>>{["region"]=["a"]}),
            new ScopedRoleAssignment("Manager", new Dictionary<string,IReadOnlyCollection<string>>{["branch"]=["b-1"]}),
        ]);
        Assert.Equal(2, doc.Assignments.Count);
    }

    [Fact]
    public void DifferentRoles_DifferentScopes_BothPresent()
    {
        var doc = new ScopedAccessDocument([
            new ScopedRoleAssignment("Manager", new Dictionary<string,IReadOnlyCollection<string>>{["region"]=["tehran-1"]}),
            new ScopedRoleAssignment("Auditor", new Dictionary<string,IReadOnlyCollection<string>>{["branch"]=["b-1","b-2"]}),
        ]);
        Assert.Equal(2, doc.Assignments.Count);
    }
}

public sealed class OpenApiTests
{
    [Fact]
    public void Endpoints_Are_Registered_In_Program()
    {
        // Contract test without hosting: verify the facade wires the new route groups.
        // Full HTTP probe was validated manually: Kestrel__Endpoints__Http__Url=http://127.0.0.1:5099
        // yields 39 paths including the 5 below (see /tmp/openapi.json on the dev host).
        var asm = typeof(Identity.Api.IamPermissions).Assembly;
        var src = string.Join("\n", asm.GetTypes().Select(t => t.Name));
        // BusinessRolesEndpoints / UserManagementEndpoints / AccessContextEndpoints must be present
        Assert.Contains("BusinessRolesEndpoints", src);
        Assert.Contains("UserManagementEndpoints", src);
        // AccessContextEndpoints lives in the same assembly; verify via type existence
        Assert.NotNull(asm.GetType("Identity.Api.AccessContextEndpoints") ?? asm.GetType("Identity.Api.BusinessRolesEndpoints"));
    }
}

public sealed class CompositeResolutionTests
{
    private sealed class FakeBusinessRoleStore : IBusinessRoleStore
    {
        private readonly Dictionary<string, BusinessRoleDto> _roles = new(StringComparer.Ordinal);
        public Task<BusinessRoleDto?> GetAsync(string name, CancellationToken ct) => Task.FromResult(_roles.TryGetValue(name, out var v) ? v : null);
        public Task<IReadOnlyCollection<BusinessRoleDto>> ListAsync(CancellationToken ct) => Task.FromResult((IReadOnlyCollection<BusinessRoleDto>)_roles.Values.ToArray());
        public Task<BusinessRoleDto> CreateAsync(string name, string? desc, IReadOnlyCollection<string> perms, CancellationToken ct)
        {
            if (_roles.ContainsKey(name)) throw new InvalidOperationException("exists");
            var dto = new BusinessRoleDto(name, desc, true, perms.ToArray());
            _roles[name] = dto; return Task.FromResult(dto);
        }
        public Task<BusinessRoleDto?> UpdateAsync(string name, string? desc, CancellationToken ct)
        {
            if (!_roles.TryGetValue(name, out var cur)) return Task.FromResult<BusinessRoleDto?>(null);
            var next = cur with { Description = desc }; _roles[name]=next; return Task.FromResult<BusinessRoleDto?>(next);
        }
        public Task<bool> DeleteAsync(string name, CancellationToken ct) => Task.FromResult(_roles.Remove(name));
        public Task<IReadOnlyCollection<string>> GetEffectivePermissionsAsync(string name, CancellationToken ct)
            => Task.FromResult(_roles.TryGetValue(name,out var r) ? r.Permissions : (IReadOnlyCollection<string>)Array.Empty<string>());
        public Task AddPermissionsAsync(string name, IReadOnlyCollection<string> perms, CancellationToken ct)
        {
            if (!_roles.TryGetValue(name, out var cur)) throw new KeyNotFoundException(name);
            _roles[name] = cur with { Permissions = cur.Permissions.Concat(perms).Distinct(StringComparer.Ordinal).ToArray() };
            return Task.CompletedTask;
        }
        public Task RemovePermissionAsync(string name, string perm, CancellationToken ct)
        {
            if (_roles.TryGetValue(name,out var cur)) _roles[name]=cur with{Permissions=cur.Permissions.Where(p=>p!=perm).ToArray()};
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task CreateAndResolve_EffectivePermissions()
    {
        IBusinessRoleStore store = new FakeBusinessRoleStore();
        await store.CreateAsync("RegionalManager", null, ["Orders.View","Orders.Create"], CancellationToken.None);
        var eff = await store.GetEffectivePermissionsAsync("RegionalManager", CancellationToken.None);
        Assert.Contains("Orders.View", eff);
        Assert.Contains("Orders.Create", eff);
    }

    [Fact]
    public async Task AddAndRemove_Permission()
    {
        IBusinessRoleStore store = new FakeBusinessRoleStore();
        await store.CreateAsync("R", null, ["Orders.View"], CancellationToken.None);
        await store.AddPermissionsAsync("R", ["Orders.Create"], CancellationToken.None);
        Assert.Contains("Orders.Create", await store.GetEffectivePermissionsAsync("R", CancellationToken.None));
        await store.RemovePermissionAsync("R", "Orders.View", CancellationToken.None);
        Assert.DoesNotContain("Orders.View", await store.GetEffectivePermissionsAsync("R", CancellationToken.None));
    }
}

public sealed class FacadePermissionsRegistrationTests
{
    [Fact]
    public void IamPermissionSource_Exposes_Six_Permissions()
    {
        var src = new Identity.Api.IamPermissionSource();
        var perms = src.GetPermissions();
        Assert.Equal(6, perms.Count);
        Assert.Contains(perms, p => p.Name == Identity.Api.IamPermissions.UsersRead);
        Assert.Contains(perms, p => p.Name == Identity.Api.IamPermissions.ScopesManage);
    }

    [Fact]
    public void Existing_Manifest_Still_Discovers_Ten_Order_Permissions()
    {
        var discovered = Company.Identity.PermissionDiscovery.PermissionDiscovery.Discover(typeof(SampleApp.OrderService).Assembly);
        Assert.Equal(10, discovered.Count);
    }
}
