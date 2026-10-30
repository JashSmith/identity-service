using System.Net;
using System.Text.Json;
using Identity.Application;
using Identity.Contracts;
using Identity.Infrastructure.Keycloak;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Gateway.Tests;

/// <summary>Behaviour of the Keycloak-backed business role store against a simulated Admin API.</summary>
public sealed class BusinessRoleStoreTests
{
    /// <summary>
    /// Minimal in-memory Keycloak Admin API: groups with role mappings and members, clients with roles,
    /// realm roles. Records every request; individual routes can be forced to fail.
    /// </summary>
    private sealed class FakeKeycloak : HttpMessageHandler
    {
        public sealed record Group(string Id, string Name, List<(string Id, string Name, string? Client)> Mappings, int Members = 0);

        public List<Group> Groups { get; } = [];
        public Dictionary<string, List<(string Id, string Name)>> ClientRoles { get; } = new() { ["c-orders"] = [] };
        public Dictionary<string, string> ClientIds { get; } = new() { ["c-orders"] = "orders" };
        public List<(string Id, string Name)> RealmRoles { get; } = [];
        public List<(HttpMethod Method, string Path, string? Body)> Requests { get; } = [];
        public Func<HttpMethod, string, HttpStatusCode?> FailWith { get; set; } = (_, _) => null;

        public IEnumerable<(HttpMethod Method, string Path)> Writes =>
            Requests.Where(r => r.Method != HttpMethod.Get && !r.Path.EndsWith("/token", StringComparison.Ordinal))
                .Select(r => (r.Method, r.Path));

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            var query = System.Web.HttpUtility.ParseQueryString(request.RequestUri.Query);
            Requests.Add((request.Method, path, request.Content is null ? null : await request.Content.ReadAsStringAsync(ct)));

            if (path.EndsWith("/protocol/openid-connect/token", StringComparison.Ordinal))
                return Json(new { access_token = "t", expires_in = 300 });
            if (FailWith(request.Method, path) is { } failure) return new HttpResponseMessage(failure);

            const string realm = "/admin/realms/company/";
            var rel = path[(path.IndexOf(realm, StringComparison.Ordinal) + realm.Length)..];
            var parts = rel.Split('/');
            var first = int.TryParse(query["first"], out var f) ? f : 0;
            var max = int.TryParse(query["max"], out var m) ? m : int.MaxValue;
            T[] Page<T>(IEnumerable<T> items) => items.Skip(first).Take(max).ToArray();

            switch (parts)
            {
                case ["groups"] when request.Method == HttpMethod.Get:
                    var search = query["search"];
                    var groups = search is null ? Groups : Groups.Where(g => g.Name == search).ToList();
                    return Json(Page(groups.Select(g => new { id = g.Id, name = g.Name, path = "/" + g.Name, attributes = new { } })));
                case ["groups"] when request.Method == HttpMethod.Post:
                    var name = JsonDocument.Parse(Requests[^1].Body!).RootElement.GetProperty("name").GetString()!;
                    Groups.Add(new Group("g-" + name, name, []));
                    return new HttpResponseMessage(HttpStatusCode.Created);
                case ["groups", var id] when request.Method == HttpMethod.Delete:
                    Groups.RemoveAll(g => g.Id == id);
                    return new HttpResponseMessage(HttpStatusCode.NoContent);
                case ["groups", var id] when request.Method == HttpMethod.Put:
                    return new HttpResponseMessage(HttpStatusCode.NoContent);
                case ["groups", var id, "members"]:
                    var g1 = Groups.Single(g => g.Id == id);
                    return Json(Enumerable.Range(0, g1.Members).Select(i => new { id = $"u{i}" }).Take(max));
                case ["groups", var id, "role-mappings"]:
                    var g2 = Groups.Single(g => g.Id == id);
                    return Json(new
                    {
                        realmMappings = g2.Mappings.Where(r => r.Client is null).Select(r => new { id = r.Id, name = r.Name }),
                        clientMappings = g2.Mappings.Where(r => r.Client is not null).GroupBy(r => r.Client!)
                            .ToDictionary(c => ClientIds[c.Key], c => new { id = c.Key, client = ClientIds[c.Key], mappings = c.Select(r => new { id = r.Id, name = r.Name }) }),
                    });
                case ["groups", var id, "role-mappings", "realm", "composite"]:
                    return Json(Groups.Single(g => g.Id == id).Mappings.Where(r => r.Client is null).Select(r => new { id = r.Id, name = r.Name }));
                case ["groups", var id, "role-mappings", "clients", var client]:
                    return ChangeMappings(Groups.Single(g => g.Id == id), request.Method, client);
                case ["groups", var id, "role-mappings", "realm"]:
                    return ChangeMappings(Groups.Single(g => g.Id == id), request.Method, null);
                case ["clients"]:
                    var byClientId = query["clientId"];
                    return Json(Page(ClientRoles.Keys.Where(c => byClientId is null || ClientIds[c] == byClientId)
                        .Select(c => new { id = c, clientId = ClientIds[c] })));
                case ["clients", var client, "roles", var roleName]:
                    var single = ClientRoles[client].Where(r => r.Name == Uri.UnescapeDataString(roleName)).ToArray();
                    return single.Length == 0 ? new HttpResponseMessage(HttpStatusCode.NotFound) : Json(new { id = single[0].Id, name = single[0].Name });
                case ["clients", var client, "roles"]:
                    return Json(Page(ClientRoles[client].Select(r => new { id = r.Id, name = r.Name })));
                case ["roles"]:
                    return Json(Page(RealmRoles.Select(r => new { id = r.Id, name = r.Name })));
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        private HttpResponseMessage ChangeMappings(Group group, HttpMethod method, string? client)
        {
            var roles = JsonDocument.Parse(Requests[^1].Body!).RootElement.EnumerateArray()
                .Select(r => (r.GetProperty("id").GetString()!, r.GetProperty("name").GetString()!, client)).ToArray();
            if (method == HttpMethod.Post) group.Mappings.AddRange(roles);
            else group.Mappings.RemoveAll(r => roles.Any(x => x.Item1 == r.Id));
            return new HttpResponseMessage(HttpStatusCode.NoContent);
        }

        private static HttpResponseMessage Json(object body) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), System.Text.Encoding.UTF8, "application/json")
        };
    }

    private static KeycloakGroupBusinessRoleStore Store(FakeKeycloak kc)
    {
        var options = Options.Create(new KeycloakOptions { BaseUrl = "http://kc.test", Realm = "company", AdminClientSecret = "s" });
        return new KeycloakGroupBusinessRoleStore(new HttpClient(kc), options,
            new KeycloakAdminTokenProvider(new HttpClient(kc), options), NullLogger<KeycloakGroupBusinessRoleStore>.Instance);
    }

    private static FakeKeycloak WithOrdersPermissions()
    {
        var kc = new FakeKeycloak();
        kc.ClientRoles["c-orders"].AddRange([("r-read", "Sales:Order:Read"), ("r-write", "Sales:Order:Write")]);
        return kc;
    }

    private static readonly CancellationToken Ct = CancellationToken.None;

    [Fact]
    public async Task List_reads_each_role_with_one_mapping_call_and_pages_through_all_groups()
    {
        var kc = WithOrdersPermissions();
        for (var i = 0; i < 150; i++) kc.Groups.Add(new($"g{i}", $"role-{i:000}", [("r-read", "Sales:Order:Read", "c-orders")]));
        kc.Groups.Add(new("g-super", ReservedGroups.SuperAdmins, []));

        var roles = await Store(kc).ListAsync(Ct);

        Assert.True(roles.IsSuccess);
        Assert.Equal(150, roles.Value.Count);
        Assert.All(roles.Value, r => Assert.Equal(["orders:Sales:Order:Read"], r.Permissions));
        Assert.Equal(150, kc.Requests.Count(r => r.Path.EndsWith("/role-mappings", StringComparison.Ordinal)));
        Assert.DoesNotContain(kc.Requests, r => r.Path.Contains("/clients", StringComparison.Ordinal) && !r.Path.Contains("/role-mappings", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Keycloak_outage_is_reported_instead_of_an_empty_list()
    {
        var kc = new FakeKeycloak { FailWith = (_, _) => HttpStatusCode.ServiceUnavailable };

        var roles = await Store(kc).ListAsync(Ct);

        Assert.False(roles.IsSuccess);
        Assert.Equal(ErrorKind.Unavailable, roles.Error!.Kind);
    }

    [Fact]
    public async Task Unknown_role_is_role_not_found()
    {
        var role = await Store(new FakeKeycloak()).GetAsync("nope", Ct);

        Assert.Equal("role.not_found", role.Error?.Code);
    }

    [Fact]
    public async Task Create_assigns_permissions_and_returns_the_role()
    {
        var kc = WithOrdersPermissions();

        var created = await Store(kc).CreateAsync("Accountant", "desc", ["orders:Sales:Order:Read"], Ct);

        Assert.True(created.IsSuccess);
        Assert.Equal(["orders:Sales:Order:Read"], created.Value.Permissions);
    }

    [Fact]
    public async Task Create_with_unknown_permission_creates_nothing()
    {
        var kc = WithOrdersPermissions();

        var created = await Store(kc).CreateAsync("Accountant", null, ["orders:Sales:Order:Read", "orders:Sales:Order:Fly"], Ct);

        Assert.Equal("permission.not_found", created.Error?.Code);
        Assert.Contains("orders:Sales:Order:Fly", created.Error!.Message);
        Assert.Empty(kc.Writes);
    }

    [Fact]
    public async Task Create_removes_the_new_role_when_assigning_permissions_fails()
    {
        var kc = WithOrdersPermissions();
        kc.FailWith = (method, path) => method == HttpMethod.Post && path.Contains("/role-mappings/", StringComparison.Ordinal)
            ? HttpStatusCode.Forbidden : null;

        var created = await Store(kc).CreateAsync("Accountant", null, ["orders:Sales:Order:Read"], Ct);

        Assert.Equal("keycloak.access_denied", created.Error?.Code);
        Assert.Empty(kc.Groups);
        Assert.Contains(kc.Writes, w => w.Method == HttpMethod.Delete && w.Path.EndsWith("/groups/g-Accountant", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Creating_an_existing_role_is_a_conflict()
    {
        var kc = new FakeKeycloak();
        kc.Groups.Add(new("g1", "Accountant", []));

        var created = await Store(kc).CreateAsync("Accountant", null, [], Ct);

        Assert.Equal("role.already_exists", created.Error?.Code);
        Assert.Empty(kc.Writes);
    }

    [Fact]
    public async Task Role_held_by_users_is_not_deleted()
    {
        var kc = new FakeKeycloak();
        kc.Groups.Add(new("g1", "Accountant", [], Members: 3));

        var deleted = await Store(kc).DeleteAsync("Accountant", Ct);

        Assert.Equal("role.in_use", deleted.Error?.Code);
        Assert.Single(kc.Groups);
        Assert.Empty(kc.Writes);
    }

    [Fact]
    public async Task Unused_role_is_deleted()
    {
        var kc = new FakeKeycloak();
        kc.Groups.Add(new("g1", "Accountant", []));

        Assert.True((await Store(kc).DeleteAsync("Accountant", Ct)).IsSuccess);
        Assert.Empty(kc.Groups);
    }

    [Fact]
    public async Task SetPermissions_adds_and_removes_to_match_exactly()
    {
        var kc = WithOrdersPermissions();
        kc.Groups.Add(new("g1", "Accountant", [("r-read", "Sales:Order:Read", "c-orders")]));

        var set = await Store(kc).SetPermissionsAsync("Accountant", ["orders:Sales:Order:Write"], Ct);

        Assert.True(set.IsSuccess);
        Assert.Equal(["Sales:Order:Write"], kc.Groups[0].Mappings.Select(m => m.Name));
    }

    [Fact]
    public async Task SetPermissions_with_unknown_permission_changes_nothing()
    {
        var kc = WithOrdersPermissions();
        kc.Groups.Add(new("g1", "Accountant", [("r-read", "Sales:Order:Read", "c-orders")]));

        var set = await Store(kc).SetPermissionsAsync("Accountant", ["orders:Sales:Order:Fly"], Ct);

        Assert.Equal("permission.not_found", set.Error?.Code);
        Assert.Equal(["Sales:Order:Read"], kc.Groups[0].Mappings.Select(m => m.Name));
        Assert.Empty(kc.Writes);
    }

    [Fact]
    public async Task Removing_a_permission_the_role_does_not_have_is_reported()
    {
        var kc = WithOrdersPermissions();
        kc.Groups.Add(new("g1", "Accountant", []));

        var removed = await Store(kc).RemovePermissionAsync("Accountant", "orders:Sales:Order:Read", Ct);

        Assert.Equal("permission.not_assigned", removed.Error?.Code);
    }

    [Fact]
    public async Task ExistsAsync_raises_outages_instead_of_answering_false()
    {
        IBusinessRoleStore store = Store(new FakeKeycloak { FailWith = (_, _) => HttpStatusCode.BadGateway });

        var ex = await Assert.ThrowsAsync<ErrorException>(() => store.ExistsAsync("Accountant", Ct));

        Assert.Equal(ErrorKind.Unavailable, ex.Error.Kind);
    }

    [Theory]
    [InlineData("Accountant", true)]
    [InlineData("مدیر تهران", true)]
    [InlineData("branch_manager-2.a", true)]
    [InlineData("", false)]
    [InlineData("tehran/admins", false)]
    [InlineData(" leading-space", false)]
    [InlineData("super-admins", false)]
    public void Role_names_are_validated(string name, bool valid)
    {
        var result = new Identity.Application.Roles.CreateBusinessRoleRequestValidator()
            .Validate(new CreateBusinessRoleRequest(name, null, null));

        Assert.Equal(valid, result.IsValid);
    }
}
