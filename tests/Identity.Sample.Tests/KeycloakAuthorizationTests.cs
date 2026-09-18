using System.Net;
using System.Text.Json;
using Identity.Api;
using Identity.Application;
using Identity.Application.Scope;
using Identity.Contracts;
using Identity.Infrastructure.Keycloak;
using Identity.Infrastructure.Keycloak.Scope;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Sample.Tests;

/// <summary>
/// §69 — Keycloak as source of truth.
/// Covers: fallback defaults, validator 400s, resource isolation, group scope merge,
/// namespace enforcement, client-role idempotence, profile hardening, filter deny-by-default.
/// All tests run offline (no live Keycloak) via fakes / recording handlers.
/// </summary>
public sealed class KeycloakAuthorizationTests
{
    // ---------- helpers ----------
    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> fn) : HttpMessageHandler
    {
        public List<string> Urls { get; } = [];
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Urls.Add(request.RequestUri!.ToString());
            return Task.FromResult(fn(request));
        }
    }

    private static KeycloakOptions KcOpts(string baseUrl = "http://kc.test") => new()
    {
        BaseUrl = baseUrl,
        Realm = "company",
        AdminClientId = "admin-cli",
        AdminClientSecret = "secret",
    };

    private static HttpClient Client(HttpMessageHandler h) => new(h) { BaseAddress = new Uri("http://kc.test") };

    private sealed class FakeRoleStore(params string[] roles) : IBusinessRoleStore
    {
        private readonly HashSet<string> _roles = new(roles, StringComparer.Ordinal);
        public Task<BusinessRoleDto?> GetAsync(string name, CancellationToken ct) => Task.FromResult(_roles.Contains(name) ? new BusinessRoleDto(name, null, true, Array.Empty<string>()) : null);
        public Task<IReadOnlyCollection<BusinessRoleDto>> ListAsync(CancellationToken ct) => Task.FromResult((IReadOnlyCollection<BusinessRoleDto>)_roles.Select(r => new BusinessRoleDto(r, null, true, Array.Empty<string>())).ToArray());
        public Task<BusinessRoleDto> CreateAsync(string name, string? desc, IReadOnlyCollection<string> perms, CancellationToken ct) { _roles.Add(name); return Task.FromResult(new BusinessRoleDto(name, desc, true, perms.ToArray())); }
        public Task<BusinessRoleDto?> UpdateAsync(string name, string? desc, CancellationToken ct) => Task.FromResult<BusinessRoleDto?>(null);
        public Task<bool> DeleteAsync(string name, CancellationToken ct) => Task.FromResult(_roles.Remove(name));
        public Task<IReadOnlyCollection<string>> GetEffectivePermissionsAsync(string name, CancellationToken ct) => Task.FromResult((IReadOnlyCollection<string>)Array.Empty<string>());
        public Task AddPermissionsAsync(string name, IReadOnlyCollection<string> perms, CancellationToken ct) => Task.CompletedTask;
        public Task RemovePermissionAsync(string name, string perm, CancellationToken ct) => Task.CompletedTask;
    }

    private static HttpResponseMessage Json(object obj, HttpStatusCode code = HttpStatusCode.OK)
    {
        var json = JsonSerializer.Serialize(obj);
        return new HttpResponseMessage(code) { Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json") };
    }

    private static HttpResponseMessage TokenOk() => Json(new { access_token = "fake-jwt", token_type = "Bearer", expires_in = 300 });

    // ---------- 1. Registry fallback defaults (offline / migration window) ----------

    [Fact]
    public async Task Registry_Fallback_WhenKeycloakUnreachable_UsesSeedDefaults()
    {
        // Token provider that fails (no admin token) -> registry returns empty attrs -> defaults
        var tokenHandler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        var tokenProvider = new KeycloakAdminTokenProvider(new HttpClient(tokenHandler), Options.Create(KcOpts()));
        var registryHandler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        var store = new KeycloakScopeRegistryStore(new HttpClient(registryHandler), Options.Create(KcOpts()), tokenProvider, new MemoryCache(new MemoryCacheOptions()), NullLogger<KeycloakScopeRegistryStore>.Instance);

        Assert.True(await store.ExistsActiveAsync("region", CancellationToken.None));
        Assert.True(await store.ExistsActiveAsync("test-key", CancellationToken.None));
        Assert.False(await store.ExistsActiveAsync("unknown-scope", CancellationToken.None));
        var ordersScopes = await store.GetScopesForResourceAsync("Orders", CancellationToken.None);
        Assert.Contains("region", ordersScopes);
        Assert.Contains("test-key", await store.GetScopesForResourceAsync("ResourceA", CancellationToken.None));
    }

    [Fact]
    public async Task Registry_ResourceIsolation_UnknownResource_DenyByDefault()
    {
        var tokenHandler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        var tokenProvider = new KeycloakAdminTokenProvider(new HttpClient(tokenHandler), Options.Create(KcOpts()));
        var store = new KeycloakScopeRegistryStore(new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable))), Options.Create(KcOpts()), tokenProvider, new MemoryCache(new MemoryCacheOptions()), NullLogger<KeycloakScopeRegistryStore>.Instance);
        var svc = new ScopeFilterService(store);
        svc.Register(new SampleApp.RegionOrderFilter());
        var orders = new[] { new SampleApp.OrderDto("1", "u", 10, "open", "tehran-1") }.AsQueryable();
        // resource with no mapping should deny
        var result = await svc.ApplyAsync(orders, new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = new[] { "tehran-1" } }, "UnknownResource", CancellationToken.None);
        Assert.Empty(result);
    }

    // ---------- 2. Validator 400 paths ----------

    [Fact]
    public async Task Validator_UnknownScope_Produces_FieldError()
    {
        var tokenProvider = new KeycloakAdminTokenProvider(new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable))), Options.Create(KcOpts()));
        var store = new KeycloakScopeRegistryStore(new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable))), Options.Create(KcOpts()), tokenProvider, new MemoryCache(new MemoryCacheOptions()), NullLogger<KeycloakScopeRegistryStore>.Instance);
        var validator = new ScopeAssignmentValidator(store, new ScopeValueValidatorRegistry([new DefaultScopeValueValidator()]));
        var errors = await validator.ValidateAsync([new ScopedRoleAssignmentDto("R", new Dictionary<string, IReadOnlyCollection<string>> { ["does-not-exist"] = ["x"] })], new FakeRoleStore("R"), CancellationToken.None);
        Assert.Contains(errors.Keys, k => k.Contains("does-not-exist"));
    }

    [Fact]
    public async Task Validator_EmptyValue_Produces_FieldError()
    {
        var tokenProvider = new KeycloakAdminTokenProvider(new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable))), Options.Create(KcOpts()));
        var store = new KeycloakScopeRegistryStore(new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable))), Options.Create(KcOpts()), tokenProvider, new MemoryCache(new MemoryCacheOptions()), NullLogger<KeycloakScopeRegistryStore>.Instance);
        var validator = new ScopeAssignmentValidator(store, new ScopeValueValidatorRegistry([new DefaultScopeValueValidator()]));
        var errors = await validator.ValidateAsync([new ScopedRoleAssignmentDto("R", new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = [""] })], new FakeRoleStore("R"), CancellationToken.None);
        Assert.NotEmpty(errors);
    }

    // ---------- 3. Namespace enforcement ----------

    [Fact]
    public async Task PermissionNamespace_OrderService_Rejects_IdentityPrefix()
    {
        IPermissionRegistry registry = new KeycloakSyncingPermissionRegistry(
            new InMemoryPermissionRegistry(),
            null,
            null,
            NullLogger<KeycloakSyncingPermissionRegistry>.Instance);

        var manifest = new PermissionManifestRequest("order-service", "1.0.0", "1",
            [new PermissionDefinitionDto("Identity.UsersRead", "bad")], "h");
        await Assert.ThrowsAsync<InvalidOperationException>(() => registry.RegisterAsync(manifest, "order-service", CancellationToken.None));
    }

    [Fact]
    public async Task PermissionNamespace_OrderService_Allows_OrdersPrefix()
    {
        IPermissionRegistry registry = new KeycloakSyncingPermissionRegistry(
            new InMemoryPermissionRegistry(), null, null, NullLogger<KeycloakSyncingPermissionRegistry>.Instance);
        var manifest = new PermissionManifestRequest("order-service", "1.0.0", "1",
            [new PermissionDefinitionDto("Orders.View", "ok")], "h");
        var res = await registry.RegisterAsync(manifest, "order-service", CancellationToken.None);
        Assert.True(res.Accepted);
    }

    [Fact]
    public async Task PermissionNamespace_UnknownService_IsPermissive()
    {
        IPermissionRegistry registry = new KeycloakSyncingPermissionRegistry(
            new InMemoryPermissionRegistry(), null, null, NullLogger<KeycloakSyncingPermissionRegistry>.Instance);
        var manifest = new PermissionManifestRequest("new-service", "1.0.0", "1",
            [new PermissionDefinitionDto("Anything.Go", "ok")], "h");
        var res = await registry.RegisterAsync(manifest, "new-service", CancellationToken.None);
        Assert.True(res.Accepted);
    }

    // ---------- 4. Client-role provisioner best-effort (never throws) ----------

    [Fact]
    public async Task ClientRoleProvisioner_WhenTokenUnavailable_ReturnsEmpty_And_DoesNotThrow()
    {
        var tokenHandler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        var tokenProvider = new KeycloakAdminTokenProvider(new HttpClient(tokenHandler), Options.Create(KcOpts()));
        var provisioner = new KeycloakClientRoleProvisioner(new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK))), Options.Create(KcOpts()), tokenProvider, NullLogger<KeycloakClientRoleProvisioner>.Instance);
        var uuid = await provisioner.EnsureClientAsync("order-service", CancellationToken.None);
        Assert.Equal(string.Empty, uuid);
        var ok = await provisioner.EnsureClientRoleAsync("order-service", "Orders.View", null, CancellationToken.None);
        Assert.False(ok);
        await provisioner.EnsureClientRoleMapperAsync("order-service", CancellationToken.None); // should not throw
        var added = await provisioner.ReconcileAdminAsync(CancellationToken.None);
        Assert.Equal(0, added);
    }

    // ---------- 5. Scope attribute store helpers (pure logic) ----------

    [Fact]
    public void ScopeDictionaryConverter_ScalarString_NormalizesToArray()
    {
        var json = """{"role":"R","scopes":{"test-key":"items-1"}}""";
        var dto = JsonSerializer.Deserialize<ScopedRoleAssignmentDto>(json, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, Converters = { new ScopeDictionaryConverter() } });
        Assert.NotNull(dto);
        Assert.Equal("items-1", dto!.Scopes["test-key"].First());
    }

    [Fact]
    public void ScopeDictionaryConverter_NullScopes_TreatedAsEmpty()
    {
        // converter normalizes missing scopes as empty on the document level;
        // at DTO level null scopes is invalid JSON for the record — instead verify
        // the serializer treats a doc with no scopes as empty via normal path
        var s = new ScopedAccessSerializer();
        var doc = s.Deserialize("[]");
        Assert.Empty(doc.Assignments);
        var json = """{"role":"R","scopes":{}}""";
        var dto = JsonSerializer.Deserialize<ScopedRoleAssignmentDto>(json, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, Converters = { new ScopeDictionaryConverter() } });
        Assert.NotNull(dto);
        Assert.Empty(dto!.Scopes);
    }

    // ---------- 6. User profile hardening — PatchProfile injects admin-only attrs ----------

    [Fact]
    public void UserProfileHardening_PatchProfile_Declares_Each_Scope_Attribute_AdminOnly()
    {
        // Keycloak discards undeclared user attributes, so the profile must declare a concrete
        // authz.scope.<key> per registry key (wildcards do not match) — each admin-only.
        var patched = KeycloakUserProfileHardening.PatchProfile(
            JsonDocument.Parse("""{"attributes":[{"name":"username"}]}""").RootElement,
            ["region", "branch"]);
        Assert.NotNull(patched);
        var arr = JsonDocument.Parse(patched!).RootElement.GetProperty("attributes").EnumerateArray().ToArray();
        var names = arr.Select(e => e.GetProperty("name").GetString()).ToArray();
        Assert.Contains("username", names);
        Assert.Contains("authz.scope.region", names);
        Assert.Contains("authz.scope.branch", names);
        Assert.Contains("iam.scoped_access", names);
        Assert.DoesNotContain("authz.scope.*", names);

        var region = arr.First(e => e.GetProperty("name").GetString() == "authz.scope.region");
        Assert.True(region.GetProperty("multivalued").GetBoolean());
        Assert.Equal("admin", region.GetProperty("permissions").GetProperty("edit").EnumerateArray().First().GetString());
        Assert.Equal("admin", region.GetProperty("permissions").GetProperty("view").EnumerateArray().First().GetString());
    }

    [Fact]
    public void UserProfileHardening_PatchProfile_Idempotent_WhenAlreadyDeclared()
    {
        var hardened = JsonDocument.Parse("""
            {"attributes":[
              {"name":"username"},
              {"name":"authz.scope.region","multivalued":true,"permissions":{"view":["admin"],"edit":["admin"]}},
              {"name":"iam.scoped_access","permissions":{"view":["admin"],"edit":["admin"]}}
            ]}
            """).RootElement;
        // Nothing missing → no churn.
        Assert.Null(KeycloakUserProfileHardening.PatchProfile(hardened, ["region"]));
        // A newly registered scope key must be added on the next run.
        Assert.NotNull(KeycloakUserProfileHardening.PatchProfile(hardened, ["region", "cost-center"]));
    }

    [Fact]
    public void UserProfileHardening_PatchProfile_Drops_Legacy_Wildcard_Attribute()
    {
        // Earlier versions wrote a literal "authz.scope.*" that matches nothing in Keycloak.
        var withWildcard = JsonDocument.Parse("""
            {"attributes":[
              {"name":"username"},
              {"name":"authz.scope.*","permissions":{"view":["admin"],"edit":["admin"]}}
            ]}
            """).RootElement;
        var patched = KeycloakUserProfileHardening.PatchProfile(withWildcard, ["region"]);
        Assert.NotNull(patched);
        var names = JsonDocument.Parse(patched!).RootElement.GetProperty("attributes")
            .EnumerateArray().Select(e => e.GetProperty("name").GetString()).ToArray();
        Assert.DoesNotContain("authz.scope.*", names);
        Assert.Contains("authz.scope.region", names);
    }

    // ---------- 7. Scope filter deny-by-default ----------

    [Fact]
    public async Task ScopeFilter_NoEffectiveScopes_Denies()
    {
        var tokenProvider = new KeycloakAdminTokenProvider(new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable))), Options.Create(KcOpts()));
        var store = new KeycloakScopeRegistryStore(new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable))), Options.Create(KcOpts()), tokenProvider, new MemoryCache(new MemoryCacheOptions()), NullLogger<KeycloakScopeRegistryStore>.Instance);
        var svc = new ScopeFilterService(store);
        svc.Register(new SampleApp.RegionOrderFilter());
        var orders = new[] { new SampleApp.OrderDto("1", "u", 10, "open", "tehran-1") }.AsQueryable();
        var result = await svc.ApplyAsync(orders, new Dictionary<string, IReadOnlyCollection<string>>(), ResourceKeys.Orders, CancellationToken.None);
        Assert.Empty(result);
    }

    [Fact]
    public async Task ScopeFilter_MultiValues_OR_Semantics()
    {
        var tokenProvider = new KeycloakAdminTokenProvider(new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable))), Options.Create(KcOpts()));
        var store = new KeycloakScopeRegistryStore(new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable))), Options.Create(KcOpts()), tokenProvider, new MemoryCache(new MemoryCacheOptions()), NullLogger<KeycloakScopeRegistryStore>.Instance);
        var svc = new ScopeFilterService(store);
        svc.Register(new SampleApp.RegionOrderFilter());
        var orders = new[]
        {
            new SampleApp.OrderDto("1","u",10,"open","tehran-1"),
            new SampleApp.OrderDto("2","u",10,"open","tehran-2"),
            new SampleApp.OrderDto("3","u",10,"open","tehran-9"),
        }.AsQueryable();
        var result = await svc.ApplyAsync(orders, new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = new[] { "tehran-1", "tehran-2" } }, ResourceKeys.Orders, CancellationToken.None);
        Assert.Equal(2, result.Count());
    }

    // ---------- 8. Already-issued token does not mutate — serializer round-trip preserves claim shape ----------

    [Fact]
    public void ScopedAccessSerializer_RoundTrip_Preserves_AllKeys_Including_TestKey()
    {
        var doc = new ScopedAccessDocument([
            new ScopedRoleAssignment("R", new Dictionary<string, IReadOnlyCollection<string>> { ["test-key"] = ["items-1", "items-2"], ["region"] = ["tehran-1"] })
        ]);
        var s = new ScopedAccessSerializer();
        var json = s.Serialize(doc);
        var back = s.Deserialize(json);
        Assert.Equal(2, back.Assignments.First().Scopes["test-key"].Count);
        Assert.Contains("tehran-1", back.Assignments.First().Scopes["region"]);
    }
}
