using System.Net;
using System.Text.Json;
using Identity.Application;
using Identity.Application.Scope;
using Identity.Contracts;
using Identity.Infrastructure.Keycloak;
using Identity.Infrastructure.Keycloak.Scope;
using Microsoft.Extensions.Options;

namespace Identity.Gateway.Tests;

/// <summary>
/// The user's own scope document and the merged (user ∪ groups) view must stay separate: writing the
/// merged view back would copy group scopes onto the user.
/// </summary>
public sealed class ScopeAttributeStoreTests
{
    private static readonly CancellationToken Ct = CancellationToken.None;
    private static readonly ScopedAccessSerializer Serializer = new();

    /// <summary>User u1 owns "Accountant: region=tehran"; its group "Inspectors" grants region=*.</summary>
    private sealed class FakeKeycloak : HttpMessageHandler
    {
        public string? LastPutBody { get; private set; }
        public string OwnDocument { get; set; } = Serializer.Serialize(new ScopedAccessDocument(
            [new ScopedRoleAssignment("Accountant", new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = ["tehran"] })]));

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/protocol/openid-connect/token", StringComparison.Ordinal))
                return Json(new { access_token = "t", expires_in = 300 });
            if (request.Method == HttpMethod.Put)
            {
                LastPutBody = await request.Content!.ReadAsStringAsync(ct);
                return new HttpResponseMessage(HttpStatusCode.NoContent);
            }

            return path switch
            {
                _ when path.EndsWith("/users/missing", StringComparison.Ordinal) => new HttpResponseMessage(HttpStatusCode.NotFound),
                _ when path.EndsWith("/users/u1", StringComparison.Ordinal) => Json(new
                {
                    id = "u1", username = "ali", email = "ali@test.local",
                    attributes = new Dictionary<string, string[]>
                    {
                        ["authz.scope.region"] = ["tehran"],
                        ["iam.scoped_access"] = [OwnDocument],
                        ["department"] = ["finance"],
                    },
                }),
                _ when path.EndsWith("/users/u1/groups", StringComparison.Ordinal) => Json(new[] { new { id = "g1", name = "Inspectors" } }),
                _ when path.EndsWith("/groups/g1", StringComparison.Ordinal) => Json(new
                {
                    id = "g1", name = "Inspectors",
                    attributes = new Dictionary<string, string[]> { ["authz.scope.region"] = ["*"] },
                }),
                _ => new HttpResponseMessage(HttpStatusCode.NotFound),
            };
        }

        private static HttpResponseMessage Json(object body) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), System.Text.Encoding.UTF8, "application/json")
        };
    }

    private static KeycloakScopeAttributeStore Store(FakeKeycloak kc)
    {
        var options = Options.Create(new KeycloakOptions { BaseUrl = "http://kc.test", Realm = "company", AdminClientSecret = "s" });
        return new KeycloakScopeAttributeStore(new HttpClient(kc), options,
            new KeycloakAdminTokenProvider(new HttpClient(kc), options), Serializer);
    }

    [Fact]
    public async Task Own_document_does_not_contain_group_scopes()
    {
        IScopedAccessStore store = Store(new FakeKeycloak());

        var own = await store.GetAsync("u1", Ct);

        var assignment = Assert.Single(own.Value.Assignments);
        Assert.Equal("Accountant", assignment.Role);
        Assert.Equal(["tehran"], assignment.Scopes["region"]);
    }

    [Fact]
    public async Task Merged_view_includes_group_scopes()
    {
        IUserScopeReader reader = Store(new FakeKeycloak());

        var effective = await reader.GetEffectiveAsync("u1", Ct);

        Assert.Equal(["*", "tehran"], effective.Value["region"]);
    }

    [Fact]
    public async Task Rewriting_the_own_document_never_copies_group_scopes_to_the_user()
    {
        var kc = new FakeKeycloak();
        IScopedAccessStore store = Store(kc);
        var own = await store.GetAsync("u1", Ct);

        var written = await store.SetAsync("u1", own.Value, Ct);

        Assert.True(written.IsSuccess);
        Assert.DoesNotContain("\"*\"", kc.LastPutBody);
        Assert.Contains("\"department\"", kc.LastPutBody);
    }

    [Fact]
    public async Task Writing_an_empty_document_clears_scopes_but_keeps_other_attributes()
    {
        var kc = new FakeKeycloak();
        IScopedAccessStore store = Store(kc);

        await store.SetAsync("u1", ScopedAccessDocument.Empty, Ct);

        using var body = JsonDocument.Parse(kc.LastPutBody!);
        var attributes = body.RootElement.GetProperty("attributes");
        Assert.False(attributes.TryGetProperty("authz.scope.region", out _));
        Assert.False(attributes.TryGetProperty("iam.scoped_access", out _));
        Assert.Equal("finance", attributes.GetProperty("department")[0].GetString());
    }

    [Fact]
    public async Task Corrupt_document_is_treated_as_empty_instead_of_crashing()
    {
        IScopedAccessStore store = Store(new FakeKeycloak { OwnDocument = "{not json" });

        var own = await store.GetAsync("u1", Ct);

        Assert.True(own.IsSuccess);
        Assert.Empty(own.Value.Assignments);
    }

    [Fact]
    public async Task Unknown_user_is_user_not_found()
    {
        IScopedAccessStore store = Store(new FakeKeycloak());

        Assert.Equal("user.not_found", (await store.GetAsync("missing", Ct)).Error?.Code);
        Assert.Equal("user.not_found", (await store.SetAsync("missing", ScopedAccessDocument.Empty, Ct)).Error?.Code);
    }
}
