using System.Net;
using System.Text.Json;
using Identity.Application;
using Identity.Infrastructure.Keycloak;
using Microsoft.Extensions.Options;

namespace Identity.Gateway.Tests;

/// <summary>Reads of users, sessions and permissions against a simulated Keycloak Admin API.</summary>
public sealed class DirectoryAdapterTests
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    private sealed class FakeKeycloak : HttpMessageHandler
    {
        public int UserCount { get; init; } = 3;
        public HttpStatusCode? FailEverything { get; init; }
        public List<string> Paths { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            Paths.Add(path);
            if (path.EndsWith("/protocol/openid-connect/token", StringComparison.Ordinal))
                return Json(new { access_token = "t", expires_in = 300 });
            if (FailEverything is { } status) return Task.FromResult(new HttpResponseMessage(status));

            var rel = path[(path.IndexOf("/admin/realms/company/", StringComparison.Ordinal) + "/admin/realms/company/".Length)..];
            return rel.Split('/') switch
            {
                ["users"] => Json(Enumerable.Range(0, UserCount).Select(i => new { id = $"u{i}", username = $"user{i}", enabled = true })),
                ["users", "count"] => Json(UserCount),
                ["users", "missing", ..] => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)),
                ["users", var id] => Json(new { id, username = "user", enabled = true }),
                ["users", _, "sessions"] => Json(new[] { new { id = "s1", username = "user", userId = "u0", start = 0L, lastAccess = 0L } }),
                ["users", _, "role-mappings", "realm", "composite"] => Json(new[] { new { id = "r1", name = "offline_access" } }),
                ["users", _, "role-mappings", "clients", var client, "composite"] => Json(new[] { new { id = "cr-" + client, name = "perm-of-" + client } }),
                ["users", _, "role-mappings"] => Json(new { clientMappings = new Dictionary<string, object> { ["orders"] = new { id = "c-orders", mappings = Array.Empty<object>() } } }),
                ["users", _, "groups"] => Json(new[] { new { id = "g1", name = "Accountant" } }),
                ["groups", "g1", "role-mappings"] => Json(new { clientMappings = new Dictionary<string, object> { ["billing"] = new { id = "c-billing", mappings = Array.Empty<object>() } } }),
                ["clients"] => Json(Enumerable.Range(0, 50).Select(i => new { id = $"c{i}" })),
                _ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)),
            };
        }

        private static Task<HttpResponseMessage> Json(object body) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), System.Text.Encoding.UTF8, "application/json")
        });
    }

    private static KeycloakDirectoryAdapter Adapter(FakeKeycloak kc)
    {
        var options = Options.Create(new KeycloakOptions { BaseUrl = "http://kc.test", Realm = "company", AdminClientSecret = "s" });
        return new KeycloakDirectoryAdapter(new HttpClient(kc), options, new KeycloakAdminTokenProvider(new HttpClient(kc), options));
    }

    [Fact]
    public async Task User_list_without_sessions_makes_no_per_user_calls_and_reports_the_total()
    {
        var kc = new FakeKeycloak { UserCount = 3 };

        var page = await Adapter(kc).GetUsersAsync(null, 1, 20, includeSessions: false, Ct);

        Assert.True(page.IsSuccess);
        Assert.Equal(3, page.Value.Items.Count);
        Assert.Equal(3, page.Value.Total);
        Assert.DoesNotContain(kc.Paths, p => p.EndsWith("/sessions", StringComparison.Ordinal));
        Assert.All(page.Value.Items, u => Assert.Null(u.IsOnline));
    }

    [Fact]
    public async Task User_list_with_sessions_looks_up_each_user_once()
    {
        var kc = new FakeKeycloak { UserCount = 12 };

        var page = await Adapter(kc).GetUsersAsync(null, 1, 20, includeSessions: true, Ct);

        Assert.True(page.IsSuccess);
        Assert.All(page.Value.Items, u => Assert.True(u.IsOnline));
        Assert.Equal(12, kc.Paths.Count(p => p.EndsWith("/sessions", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task Keycloak_outage_is_reported_instead_of_an_empty_page()
    {
        var page = await Adapter(new FakeKeycloak { FailEverything = HttpStatusCode.ServiceUnavailable })
            .GetUsersAsync(null, 1, 20, includeSessions: false, Ct);

        Assert.Equal(ErrorKind.Unavailable, page.Error?.Kind);
    }

    [Fact]
    public async Task Unknown_user_is_user_not_found()
    {
        var kc = new FakeKeycloak();

        Assert.Equal("user.not_found", (await Adapter(kc).GetUserAsync("missing", Ct)).Error?.Code);
        Assert.Equal("user.not_found", (await Adapter(kc).GetUserSessionsAsync("missing", Ct)).Error?.Code);
        Assert.Equal("user.not_found", (await Adapter(kc).GetUserPermissionsAsync("missing", Ct)).Error?.Code);
    }

    [Fact]
    public async Task Permissions_query_only_clients_the_user_or_its_groups_hold_roles_of()
    {
        var kc = new FakeKeycloak();

        var permissions = await Adapter(kc).GetUserPermissionsAsync("u0", Ct);

        Assert.True(permissions.IsSuccess);
        Assert.Equal(["offline_access", "perm-of-c-billing", "perm-of-c-orders"], permissions.Value.Select(p => p.Name));
        Assert.Equal(2, kc.Paths.Count(p => p.Contains("/role-mappings/clients/", StringComparison.Ordinal)));
        Assert.DoesNotContain(kc.Paths, p => p.EndsWith("/admin/realms/company/clients", StringComparison.Ordinal));
    }
}
