using System.Net;
using Identity.Application;
using Identity.Contracts;
using Identity.Infrastructure.Keycloak;
using Microsoft.Extensions.Options;

namespace Identity.Gateway.Tests;

/// <summary>
/// Scope values and other authorization attributes must not be writable through PUT /users/{id};
/// otherwise the scope-assignment validation can be bypassed.
/// </summary>
public sealed class ProtectedUserAttributesTests
{
    [Theory]
    [InlineData("authz.scope.region")]
    [InlineData("AUTHZ.scope.branch")]
    [InlineData("authz.allowed-scopes")]
    [InlineData("iam.scoped_access")]
    [InlineData("access.schedule")]
    [InlineData(" authz.scope.city")]
    public void Authorization_attributes_are_protected(string name) => Assert.True(ProtectedUserAttributes.IsProtected(name));

    [Theory]
    [InlineData("department")]
    [InlineData("phoneNumber")]
    [InlineData("authz")]
    [InlineData("")]
    [InlineData(null)]
    public void Ordinary_attributes_are_not_protected(string? name) => Assert.False(ProtectedUserAttributes.IsProtected(name));

    [Fact]
    public void FindIn_lists_only_the_protected_keys()
    {
        var attrs = new Dictionary<string, string[]>
        {
            ["department"] = ["finance"],
            ["authz.scope.region"] = ["*"],
            ["iam.scoped_access"] = ["{}"],
        };

        Assert.Equal(["authz.scope.region", "iam.scoped_access"], ProtectedUserAttributes.FindIn(attrs));
    }

    [Fact]
    public async Task Provisioner_refuses_to_write_scope_attributes()
    {
        var requests = new List<HttpMethod>();
        var handler = new RecordingHandler(requests);
        var options = Options.Create(new KeycloakOptions { BaseUrl = "http://kc.test", AdminClientSecret = "s" });
        var provisioner = new KeycloakUserProvisioner(new HttpClient(handler), options,
            new KeycloakAdminTokenProvider(new HttpClient(handler), options));
        var request = new UpdateUserRequest(null, null, null, null,
            Attributes: new Dictionary<string, string[]> { ["authz.scope.region"] = ["*"] });

        var updated = await provisioner.UpdateUserAsync("user-1", request, CancellationToken.None);

        Assert.Equal("user.protected_attributes", updated.Error?.Code);

        Assert.DoesNotContain(HttpMethod.Put, requests);
    }

    private sealed class RecordingHandler(List<HttpMethod> requests) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            requests.Add(request.Method);
            var body = request.RequestUri!.AbsolutePath.EndsWith("/token", StringComparison.Ordinal)
                ? """{"access_token":"t","expires_in":300}"""
                : """{"id":"user-1","username":"u","attributes":{}}""";
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json")
            });
        }
    }
}
