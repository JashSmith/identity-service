using System.Net;
using System.Text.Json;
using Identity.Application;
using Identity.Contracts;
using Identity.Infrastructure.Keycloak;
using Microsoft.Extensions.Options;

namespace Identity.Gateway.Tests;

/// <summary>Lockout, credential and required-action handling against a simulated Keycloak Admin API.</summary>
public sealed class UserLifecycleAdapterTests
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    private sealed class FakeKeycloak : HttpMessageHandler
    {
        public List<(HttpMethod Method, string Path, string? Body)> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            Requests.Add((request.Method, path + request.RequestUri.Query, request.Content is null ? null : await request.Content.ReadAsStringAsync(ct)));
            if (path.EndsWith("/token", StringComparison.Ordinal)) return Json(new { access_token = "t", expires_in = 300 });

            var rel = path[(path.IndexOf("/admin/realms/company/", StringComparison.Ordinal) + 22)..];
            return (request.Method.Method, rel) switch
            {
                ("GET", "users/u1") => Json(new { id = "u1", username = "ali", email = "ali@t.local", requiredActions = new[] { "VERIFY_EMAIL" } }),
                ("PUT", "users/u1") => new HttpResponseMessage(HttpStatusCode.NoContent),
                ("GET", "users/u1/credentials") => Json(new object[]
                {
                    new { id = "c-pass", type = "password", createdDate = 1_700_000_000_000, secretData = "hash" },
                    new { id = "c-otp", type = "otp", userLabel = "Phone", createdDate = 1_700_000_000_000, secretData = "seed" },
                }),
                ("DELETE", "users/u1/credentials/c-otp") => new HttpResponseMessage(HttpStatusCode.NoContent),
                ("GET", "attack-detection/brute-force/users/u1") => Json(new { disabled = true, numFailures = 5, lastFailure = 1_700_000_000_000, lastIPFailure = "10.0.0.7" }),
                ("GET", "authentication/required-actions") => Json(new object[]
                {
                    new { alias = "UPDATE_PASSWORD", name = "Update Password", enabled = true },
                    new { alias = "CONFIGURE_TOTP", name = "Configure OTP", enabled = true },
                    new { alias = "TERMS_AND_CONDITIONS", name = "Terms", enabled = false },
                }),
                _ => new HttpResponseMessage(HttpStatusCode.NotFound),
            };
        }

        private static HttpResponseMessage Json(object body) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), System.Text.Encoding.UTF8, "application/json")
        };
    }

    private static KeycloakUserLifecycleAdapter Adapter(FakeKeycloak kc)
    {
        var options = Options.Create(new KeycloakOptions { BaseUrl = "http://kc.test", Realm = "company", AdminClientSecret = "s" });
        return new KeycloakUserLifecycleAdapter(new HttpClient(kc), options, new KeycloakAdminTokenProvider(new HttpClient(kc), options));
    }

    [Fact]
    public async Task Lockout_state_is_mapped()
    {
        var lockout = await Adapter(new FakeKeycloak()).GetLockoutAsync("u1", Ct);

        Assert.Equal(new UserLockoutDto(true, 5, DateTimeOffset.FromUnixTimeMilliseconds(1_700_000_000_000), "10.0.0.7"), lockout.Value);
    }

    [Fact]
    public async Task Lockout_of_an_unknown_user_is_user_not_found()
    {
        var lockout = await Adapter(new FakeKeycloak()).GetLockoutAsync("ghost", Ct);

        Assert.Equal("user.not_found", lockout.Error?.Code);
    }

    [Fact]
    public async Task Credentials_carry_metadata_only()
    {
        var credentials = await Adapter(new FakeKeycloak()).GetCredentialsAsync("u1", Ct);

        Assert.Equal(["password", "otp"], credentials.Value.Select(c => c.Type));
        Assert.Equal("Phone", credentials.Value.Last().Label);
        Assert.DoesNotContain("seed", JsonSerializer.Serialize(credentials.Value), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Deleting_a_credential_of_another_user_is_not_found_and_sends_no_delete()
    {
        var kc = new FakeKeycloak();

        var deleted = await Adapter(kc).DeleteCredentialAsync("u1", "c-foreign", Ct);

        Assert.Equal("credential.not_found", deleted.Error?.Code);
        Assert.DoesNotContain(kc.Requests, r => r.Method == HttpMethod.Delete);
    }

    [Fact]
    public async Task Required_actions_keep_the_rest_of_the_user()
    {
        var kc = new FakeKeycloak();

        var set = await Adapter(kc).SetRequiredActionsAsync("u1", ["UPDATE_PASSWORD", "CONFIGURE_TOTP"], Ct);

        Assert.True(set.IsSuccess);
        var body = JsonDocument.Parse(kc.Requests.Single(r => r.Method == HttpMethod.Put).Body!).RootElement;
        Assert.Equal("ali@t.local", body.GetProperty("email").GetString());
        Assert.Equal(["UPDATE_PASSWORD", "CONFIGURE_TOTP"], body.GetProperty("requiredActions").EnumerateArray().Select(a => a.GetString()));
    }

    [Fact]
    public async Task Unknown_or_disabled_required_actions_are_rejected_without_writes()
    {
        var kc = new FakeKeycloak();

        var set = await Adapter(kc).SetRequiredActionsAsync("u1", ["TERMS_AND_CONDITIONS", "FLY"], Ct);
        var mail = await Adapter(kc).SendActionsEmailAsync("u1", new SendActionsEmailRequest(["FLY"]), Ct);

        Assert.Equal("user.unknown_required_action", set.Error?.Code);
        Assert.Equal("user.unknown_required_action", mail.Error?.Code);
        Assert.DoesNotContain(kc.Requests, r => r.Method == HttpMethod.Put);
    }
}
