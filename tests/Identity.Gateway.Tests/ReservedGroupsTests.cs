using System.Net;
using System.Text.Json;
using Identity.Application;
using Identity.Infrastructure.Keycloak;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Gateway.Tests;

/// <summary>
/// Reserved Keycloak groups (super-admins, iam-scope-registry) must never be reachable through the
/// business-role or user-assignment paths, even though Keycloak itself returns them.
/// </summary>
public sealed class ReservedGroupsTests
{
    private sealed class FakeKeycloak : HttpMessageHandler
    {
        public List<(HttpMethod Method, string Url)> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var url = request.RequestUri!.ToString();
            Requests.Add((request.Method, url));

            if (url.Contains("/protocol/openid-connect/token", StringComparison.Ordinal))
                return Task.FromResult(Json(new { access_token = "admin-token", expires_in = 300 }));

            if (request.Method == HttpMethod.Get && url.Contains("/groups?", StringComparison.Ordinal))
                return Task.FromResult(Json(new[]
                {
                    new { id = "g-super", name = ReservedGroups.SuperAdmins, path = "/super-admins" },
                    new { id = "g-registry", name = ReservedGroups.ScopeRegistry, path = "/iam-scope-registry" },
                }));

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
        }

        public bool AnyWrite => Requests.Any(r => r.Method != HttpMethod.Get && !r.Url.Contains("/token", StringComparison.Ordinal));

        private static HttpResponseMessage Json(object body) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), System.Text.Encoding.UTF8, "application/json")
        };
    }

    private static IOptions<KeycloakOptions> Options() => Microsoft.Extensions.Options.Options.Create(new KeycloakOptions
    {
        BaseUrl = "http://kc.test",
        Realm = "company",
        AdminClientSecret = "secret",
    });

    private static KeycloakGroupBusinessRoleStore Store(FakeKeycloak kc) => new(
        new HttpClient(kc), Options(), new KeycloakAdminTokenProvider(new HttpClient(kc), Options()),
        NullLogger<KeycloakGroupBusinessRoleStore>.Instance);

    private static KeycloakUserGroupMembership Membership(FakeKeycloak kc) => new(
        new HttpClient(kc), Options(), new KeycloakAdminTokenProvider(new HttpClient(kc), Options()));

    [Theory]
    [InlineData("super-admins")]
    [InlineData("Super-Admins")]
    [InlineData(" super-admins ")]
    [InlineData("iam-scope-registry")]
    public void Reserved_names_are_recognised(string name) => Assert.True(ReservedGroups.IsReserved(name));

    [Theory]
    [InlineData("accountant")]
    [InlineData("super-admins-tehran")]
    [InlineData("")]
    [InlineData(null)]
    public void Ordinary_names_are_not_reserved(string? name) => Assert.False(ReservedGroups.IsReserved(name));

    [Theory]
    [InlineData("super-admins")]
    [InlineData("iam-scope-registry")]
    public async Task Role_store_treats_reserved_groups_as_absent(string name)
    {
        var kc = new FakeKeycloak();
        var store = Store(kc);

        Assert.Equal("role.not_found", (await store.GetAsync(name, CancellationToken.None)).Error?.Code);
        Assert.Equal("role.not_found", (await store.UpdateAsync(name, "hijacked", CancellationToken.None)).Error?.Code);
        Assert.Equal("role.not_found", (await store.DeleteAsync(name, CancellationToken.None)).Error?.Code);
        Assert.Equal("role.not_found", (await store.GetEffectivePermissionsAsync(name, CancellationToken.None)).Error?.Code);
        Assert.Equal("role.not_found", (await store.AddPermissionsAsync(name, ["orders.read"], CancellationToken.None)).Error?.Code);
        Assert.Equal("role.not_found", (await store.SetPermissionsAsync(name, [], CancellationToken.None)).Error?.Code);
        Assert.False(kc.AnyWrite);
    }

    [Fact]
    public async Task Role_store_never_lists_reserved_groups()
    {
        var roles = await Store(new FakeKeycloak()).ListAsync(CancellationToken.None);

        Assert.True(roles.IsSuccess);
        Assert.DoesNotContain(roles.Value, r => ReservedGroups.IsReserved(r.Name));
    }

    [Fact]
    public async Task Creating_a_role_with_a_reserved_name_is_rejected()
    {
        var kc = new FakeKeycloak();

        var created = await Store(kc).CreateAsync("super-admins", null, ["identity.users.manage"], CancellationToken.None);

        Assert.Equal("role.reserved", created.Error?.Code);
        Assert.False(kc.AnyWrite);
    }

    [Fact]
    public async Task Users_cannot_be_added_to_a_reserved_group()
    {
        var kc = new FakeKeycloak();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Membership(kc).MapRealmRoleAsync("user-1", "super-admins", CancellationToken.None));

        Assert.False(kc.AnyWrite);
    }

    [Fact]
    public async Task Users_cannot_be_removed_from_a_reserved_group()
    {
        var kc = new FakeKeycloak();

        await Membership(kc).UnmapRealmRoleAsync("real-super-admin", "super-admins", CancellationToken.None);

        Assert.False(kc.AnyWrite);
    }
}
