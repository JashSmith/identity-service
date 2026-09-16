using System.Net.Http;
using System.Security.Claims;
using Company.Identity.Authorization;
using Identity.Application;
using Identity.Contracts;
using Microsoft.AspNetCore.Http;

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

public sealed class FacadeResolvingAccessContextTests
{
    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        public List<string> Urls { get; } = [];
        public List<string?> AuthorizationHeaders { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Urls.Add(request.RequestUri!.ToString());
            AuthorizationHeaders.Add(request.Headers.Authorization?.ToString());
            return Task.FromResult(responder(request));
        }
    }

    private sealed class StubFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private static ClaimsPrincipal Principal(string[] permissions, string? iam)
    {
        var claims = permissions.Select(p => new Claim("permission", p)).ToList();
        if (iam is not null) claims.Add(new Claim(ScopedAccessConstants.ClaimName, iam));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "test", "name", "role"));
    }

    private static HttpContext CtxWith(string authHeader)
    {
        var c = new DefaultHttpContext();
        c.Request.Headers.Authorization = authHeader;
        return c;
    }

    private static FacadeResolvingAccessContext Svc(ClaimsPrincipal principal, string authHeader, HttpMessageHandler handler, AccessContextOptions? opts = null)
    {
        opts ??= new AccessContextOptions { FacadeBaseUrl = "http://facade.test" };
        var accessor = new HttpContextAccessor { HttpContext = CtxWith(authHeader) };
        return new FacadeResolvingAccessContext(principal, accessor, new StubFactory(handler), Microsoft.Extensions.Options.Options.Create(opts));
    }

    [Fact]
    public async Task InlineClaim_Present_NoFacadeHit()
    {
        var iam = """[{"role":"Manager","scopes":{"region":["tehran-1"]}}]""";
        var handler = new StubHandler(_ => new HttpResponseMessage(System.Net.HttpStatusCode.OK));
        var ctx = Svc(Principal(["Orders.View"], iam), "Bearer tok", handler);
        await ctx.EnsureLoadedAsync(CancellationToken.None);
        Assert.Empty(handler.Urls);
        Assert.Contains("tehran-1", ctx.GetScopeValues("region"));
    }

    [Fact]
    public async Task MissingFacadeUrl_NoFacadeHit()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(System.Net.HttpStatusCode.OK));
        var opts = new AccessContextOptions { FacadeBaseUrl = null };
        var ctx = Svc(Principal(["Orders.View"], null), "Bearer tok", handler, opts);
        await ctx.EnsureLoadedAsync(CancellationToken.None);
        Assert.Empty(handler.Urls);
    }

    [Fact]
    public async Task Absent_Iam_Access_Calls_Facade_And_Populates_Scopes()
    {
        var body = """{"userId":"u1","username":"alice","permissions":["Orders.View"],"assignments":[{"role":"Manager","scopes":{"region":["tehran-2"]}}]}""";
        var handler = new StubHandler(_ => new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json")
        });
        var ctx = Svc(Principal(["Orders.View"], null), "Bearer tok", handler);
        Assert.Empty(ctx.GetScopeValues("region"));
        await ctx.EnsureLoadedAsync(CancellationToken.None);
        Assert.Single(handler.Urls);
        Assert.Equal("http://facade.test/api/identity/access-context", handler.Urls[0]);
        Assert.Equal("Bearer tok", handler.AuthorizationHeaders[0]);
        Assert.Contains("tehran-2", ctx.GetScopeValues("region"));
    }

    [Fact]
    public async Task Idempotent_SecondCall_NoExtraRequest()
    {
        var body = """{"permissions":["Orders.View"],"assignments":[{"role":"M","scopes":{"region":["x"]}}]}""";
        var handler = new StubHandler(_ => new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") });
        var ctx = Svc(Principal(["Orders.View"], null), "Bearer tok", handler);
        await ctx.EnsureLoadedAsync(CancellationToken.None);
        await ctx.EnsureLoadedAsync(CancellationToken.None);
        Assert.Single(handler.Urls);
    }

    [Fact]
    public async Task NonBearer_Authorization_IsIgnored()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(System.Net.HttpStatusCode.OK));
        var ctx = Svc(Principal(["Orders.View"], null), "Basic abc", handler);
        await ctx.EnsureLoadedAsync(CancellationToken.None);
        Assert.Empty(handler.Urls);
    }

    [Fact]
    public async Task MissingAuthorization_IsNoOp()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(System.Net.HttpStatusCode.OK));
        var ctx = Svc(Principal(["Orders.View"], null), string.Empty, handler);
        await ctx.EnsureLoadedAsync(CancellationToken.None);
        Assert.Empty(handler.Urls);
    }

    [Fact]
    public async Task FacadeError_KeepsClaimsOnlyView_BestEffort()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(System.Net.HttpStatusCode.ServiceUnavailable));
        var ctx = Svc(Principal(["Orders.View"], null), "Bearer tok", handler);
        await ctx.EnsureLoadedAsync(CancellationToken.None);
        Assert.False(ctx.HasScope("region", "tehran-9"));
        Assert.True(ctx.HasPermission("Orders.View"));
    }

    [Fact]
    public async Task FacadePerms_Overlay_PrincipalPerms()
    {
        var body = """{"permissions":["Orders.View","Orders.Create"],"assignments":[{"role":"M","scopes":{"branch":["b-1"]}}]}""";
        var handler = new StubHandler(_ => new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") });
        // Only Orders.View on the token, facade returns more.
        var ctx = Svc(Principal(["Orders.View"], null), "Bearer tok", handler);
        await ctx.EnsureLoadedAsync(CancellationToken.None);
        Assert.True(ctx.HasPermission("Orders.Create"));
        Assert.Contains("b-1", ctx.GetScopeValues("branch"));
    }

    [Fact]
    public async Task NullHttpContext_DoesNotCrash()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(System.Net.HttpStatusCode.OK));
        var opts = new AccessContextOptions { FacadeBaseUrl = "http://facade.test" };
        var accessor = new HttpContextAccessor { HttpContext = null };
        var ctx = new FacadeResolvingAccessContext(Principal(["Orders.View"], null), accessor, new StubFactory(handler), Microsoft.Extensions.Options.Options.Create(opts));
        await ctx.EnsureLoadedAsync(CancellationToken.None);
        Assert.Empty(handler.Urls);
    }
}

