using System.Net;
using System.Text.Json;
using Identity.Application.Schedules;
using Identity.Infrastructure.Keycloak;
using Microsoft.Extensions.Options;

namespace Identity.Gateway.Tests;

/// <summary>The browser-flow setup never touches a realm it should leave alone.</summary>
public sealed class ScheduleAuthenticatorSetupTests
{
    private sealed class FakeKeycloak(bool extensionInstalled, string browserFlow) : HttpMessageHandler
    {
        public List<(HttpMethod Method, string Path)> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            Requests.Add((request.Method, path));
            if (path.EndsWith("/token", StringComparison.Ordinal)) return Json(new { access_token = "t", expires_in = 300 });
            if (path.EndsWith("/authentication/authenticator-providers", StringComparison.Ordinal))
                return Json(extensionInstalled
                    ? new object[] { new { id = "auth-otp-form" }, new { id = KeycloakScheduleAuthenticatorSetup.ProviderId } }
                    : new object[] { new { id = "auth-otp-form" } });
            if (path.EndsWith("/admin/realms/company", StringComparison.Ordinal) && request.Method == HttpMethod.Get)
                return Json(new { realm = "company", browserFlow });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError));
        }

        private static Task<HttpResponseMessage> Json(object body) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), System.Text.Encoding.UTF8, "application/json")
        });
    }

    private static KeycloakScheduleAuthenticatorSetup Setup(FakeKeycloak kc)
    {
        var options = Options.Create(new KeycloakOptions { BaseUrl = "http://kc.test", Realm = "company", AdminClientSecret = "s" });
        return new KeycloakScheduleAuthenticatorSetup(new HttpClient(kc), options,
            new KeycloakAdminTokenProvider(new HttpClient(kc), options), new AccessScheduleOptions());
    }

    [Theory]
    [InlineData(false, "browser")]
    [InlineData(true, "corporate-mfa")]
    public async Task Missing_extension_or_a_custom_flow_is_left_alone(bool installed, string browserFlow)
    {
        var kc = new FakeKeycloak(installed, browserFlow);

        var result = await Setup(kc).EnsureAsync(CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.DoesNotContain(kc.Requests, r => r.Method != HttpMethod.Get && !r.Path.EndsWith("/token", StringComparison.Ordinal));
    }
}
