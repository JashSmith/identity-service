using System.Net;
using System.Text.Json;
using Identity.Application.Settings;
using Identity.Contracts;
using Identity.Infrastructure.Keycloak;
using Microsoft.Extensions.Options;

namespace Identity.Gateway.Tests;

/// <summary>Password policy conversion and secret handling of authentication settings.</summary>
public sealed class AuthSettingsTests
{
    [Fact]
    public void Password_policy_is_read_from_keycloaks_string()
    {
        var dto = PasswordPolicyFormat.Parse("length(10) and digits(2) and notUsername(undefined) and passwordHistory(5) and hashIterations(27500)");

        Assert.Equal(new PasswordPolicyDto(MinLength: 10, Digits: 2, NotUsername: true, History: 5), dto);
    }

    [Fact]
    public void Writing_the_policy_keeps_rules_the_api_does_not_model()
    {
        var text = PasswordPolicyFormat.Format(new PasswordPolicyDto(MinLength: 12, SpecialChars: 1, NotEmail: true),
            "length(8) and regexPattern(^[^ ]+$) and digits(1)");

        Assert.Equal("regexPattern(^[^ ]+$) and length(12) and specialChars(1) and notEmail(undefined)", text);
        Assert.Equal("", PasswordPolicyFormat.Format(new PasswordPolicyDto(), null));
    }

    private sealed class FakeKeycloak : HttpMessageHandler
    {
        public List<(HttpMethod Method, string Path, string? Body)> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            Requests.Add((request.Method, path, request.Content is null ? null : await request.Content.ReadAsStringAsync(ct)));
            if (path.EndsWith("/token", StringComparison.Ordinal)) return Json(new { access_token = "t", expires_in = 300 });
            if (request.Method == HttpMethod.Get && path.EndsWith("/identity-provider/instances/corp", StringComparison.Ordinal))
                return Json(new
                {
                    alias = "corp", internalId = "i-1", providerId = "oidc", enabled = true,
                    config = new Dictionary<string, string> { ["clientId"] = "gw", ["clientSecret"] = "s3cr3t", ["issuer"] = "https://idp" },
                });
            return request.Method == HttpMethod.Put ? new HttpResponseMessage(HttpStatusCode.NoContent) : new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        private static HttpResponseMessage Json(object body) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), System.Text.Encoding.UTF8, "application/json")
        };
    }

    private static KeycloakAuthSettingsAdapter Adapter(FakeKeycloak kc)
    {
        var options = Options.Create(new KeycloakOptions { BaseUrl = "http://kc.test", Realm = "company", AdminClientSecret = "s" });
        return new KeycloakAuthSettingsAdapter(new HttpClient(kc), options, new KeycloakAdminTokenProvider(new HttpClient(kc), options));
    }

    [Fact]
    public async Task Identity_provider_secrets_are_never_returned()
    {
        var idp = await Adapter(new FakeKeycloak()).GetIdentityProviderAsync("corp", CancellationToken.None);

        Assert.Equal("**********", idp.Value.Config!["clientSecret"]);
        Assert.Equal("gw", idp.Value.Config["clientId"]);
    }

    [Fact]
    public async Task Updating_an_identity_provider_keeps_config_that_is_not_sent()
    {
        var kc = new FakeKeycloak();

        await Adapter(kc).UpdateIdentityProviderAsync("corp",
            new IdentityProviderDto("corp", "oidc", "Corporate SSO", true, false, new Dictionary<string, string> { ["issuer"] = "https://idp2" }),
            CancellationToken.None);

        var body = JsonDocument.Parse(kc.Requests.Single(r => r.Method == HttpMethod.Put).Body!).RootElement;
        Assert.Equal("https://idp2", body.GetProperty("config").GetProperty("issuer").GetString());
        Assert.Equal("gw", body.GetProperty("config").GetProperty("clientId").GetString());
        Assert.Equal("i-1", body.GetProperty("internalId").GetString());
    }
}
