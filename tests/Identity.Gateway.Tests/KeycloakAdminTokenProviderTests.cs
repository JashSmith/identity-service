using System.Net;
using Identity.Infrastructure.Keycloak;
using Microsoft.Extensions.Options;

namespace Identity.Gateway.Tests;

public sealed class KeycloakAdminTokenProviderTests
{
    private sealed class ManualClock(DateTimeOffset start) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = start;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class TokenEndpoint : HttpMessageHandler
    {
        public List<(string Url, string Body)> Requests { get; } = [];
        public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;
        public int ExpiresIn { get; set; } = 300;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add((request.RequestUri!.ToString(), await request.Content!.ReadAsStringAsync(ct)));
            return new HttpResponseMessage(Status)
            {
                Content = new StringContent(
                    $$"""{"access_token":"token-{{Requests.Count}}","expires_in":{{ExpiresIn}}}""",
                    System.Text.Encoding.UTF8, "application/json")
            };
        }
    }

    private static readonly DateTimeOffset T0 = new(2026, 10, 30, 12, 0, 0, TimeSpan.Zero);

    private static KeycloakAdminTokenProvider Provider(TokenEndpoint endpoint, ManualClock clock,
        KeycloakAdminTokenCache? cache = null, string secret = "admin-secret") =>
        new(new HttpClient(endpoint),
            Options.Create(new KeycloakOptions
            {
                BaseUrl = "http://kc.test", Realm = "tenant-a",
                AdminClientId = "identity-gateway-admin", AdminClientSecret = secret,
            }),
            cache ?? new KeycloakAdminTokenCache(), clock);

    [Fact]
    public async Task Uses_client_credentials_in_the_tenant_realm_not_master()
    {
        var endpoint = new TokenEndpoint();

        await Provider(endpoint, new ManualClock(T0)).GetTokenAsync(CancellationToken.None);

        var (url, body) = Assert.Single(endpoint.Requests);
        Assert.Equal("http://kc.test/realms/tenant-a/protocol/openid-connect/token", url);
        Assert.Contains("grant_type=client_credentials", body);
        Assert.Contains("client_id=identity-gateway-admin", body);
        Assert.DoesNotContain("password", body);
    }

    [Fact]
    public async Task Token_is_reused_until_shortly_before_expiry()
    {
        var endpoint = new TokenEndpoint { ExpiresIn = 300 };
        var clock = new ManualClock(T0);
        var cache = new KeycloakAdminTokenCache();

        var first = await Provider(endpoint, clock, cache).GetTokenAsync(CancellationToken.None);
        clock.Now = T0.AddSeconds(260);
        var second = await Provider(endpoint, clock, cache).GetTokenAsync(CancellationToken.None);
        clock.Now = T0.AddSeconds(275);
        var third = await Provider(endpoint, clock, cache).GetTokenAsync(CancellationToken.None);

        Assert.Equal("token-1", first);
        Assert.Equal("token-1", second);
        Assert.Equal("token-2", third);
        Assert.Equal(2, endpoint.Requests.Count);
    }

    [Fact]
    public async Task Concurrent_callers_share_one_token_request()
    {
        var endpoint = new TokenEndpoint();
        var clock = new ManualClock(T0);
        var cache = new KeycloakAdminTokenCache();

        var tokens = await Task.WhenAll(Enumerable.Range(0, 20)
            .Select(_ => Provider(endpoint, clock, cache).GetTokenAsync(CancellationToken.None)));

        Assert.All(tokens, t => Assert.Equal("token-1", t));
        Assert.Single(endpoint.Requests);
    }

    [Fact]
    public async Task Failures_are_not_cached()
    {
        var endpoint = new TokenEndpoint { Status = HttpStatusCode.Unauthorized };
        var clock = new ManualClock(T0);
        var cache = new KeycloakAdminTokenCache();

        Assert.Equal(string.Empty, await Provider(endpoint, clock, cache).GetTokenAsync(CancellationToken.None));
        endpoint.Status = HttpStatusCode.OK;
        Assert.Equal("token-2", await Provider(endpoint, clock, cache).GetTokenAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Missing_client_secret_makes_no_request()
    {
        var endpoint = new TokenEndpoint();

        var token = await Provider(endpoint, new ManualClock(T0), secret: "").GetTokenAsync(CancellationToken.None);

        Assert.Equal(string.Empty, token);
        Assert.Empty(endpoint.Requests);
    }
}
