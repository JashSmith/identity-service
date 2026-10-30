using Identity.Gateway;
using Outcome = Identity.Gateway.GatewayClientCredentials.Outcome;

namespace Identity.Gateway.Tests;

public sealed class GatewayClientCredentialsTests
{
    private const string GatewayClient = "identity-gateway";
    private const string GatewaySecret = "gateway-secret";

    [Fact]
    public void Password_grant_without_client_uses_gateway_client_and_secret()
    {
        var form = new Dictionary<string, string> { ["grant_type"] = "password", ["username"] = "u", ["password"] = "p" };

        var outcome = GatewayClientCredentials.Apply(form, GatewayClient, GatewaySecret);

        Assert.Equal(Outcome.Forward, outcome);
        Assert.Equal(GatewayClient, form["client_id"]);
        Assert.Equal(GatewaySecret, form["client_secret"]);
    }

    [Theory]
    [InlineData("identity-gateway")]
    [InlineData("Identity-Gateway")]
    [InlineData("")]
    public void Client_credentials_for_gateway_client_is_rejected(string clientId)
    {
        var form = new Dictionary<string, string> { ["grant_type"] = "client_credentials", ["client_id"] = clientId };

        var outcome = GatewayClientCredentials.Apply(form, GatewayClient, GatewaySecret);

        Assert.Equal(Outcome.ClientCredentialsNotAllowed, outcome);
        Assert.False(form.ContainsKey("client_secret"));
    }

    [Fact]
    public void Client_credentials_for_another_client_is_forwarded_untouched()
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials", ["client_id"] = "order-service", ["client_secret"] = "own-secret"
        };

        var outcome = GatewayClientCredentials.Apply(form, GatewayClient, GatewaySecret);

        Assert.Equal(Outcome.Forward, outcome);
        Assert.Equal("order-service", form["client_id"]);
        Assert.Equal("own-secret", form["client_secret"]);
    }

    [Fact]
    public void Another_client_without_secret_never_receives_the_gateway_secret()
    {
        var form = new Dictionary<string, string> { ["grant_type"] = "password", ["client_id"] = "order-service" };

        GatewayClientCredentials.Apply(form, GatewayClient, GatewaySecret);

        Assert.False(form.ContainsKey("client_secret"));
    }

    [Fact]
    public void Refresh_grant_for_gateway_client_gets_gateway_secret()
    {
        var form = new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["refresh_token"] = "rt" };

        var outcome = GatewayClientCredentials.Apply(form, GatewayClient, GatewaySecret);

        Assert.Equal(Outcome.Forward, outcome);
        Assert.Equal(GatewaySecret, form["client_secret"]);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Missing_gateway_secret_is_reported_instead_of_using_a_default(string? secret)
    {
        var form = new Dictionary<string, string> { ["grant_type"] = "password" };

        var outcome = GatewayClientCredentials.Apply(form, GatewayClient, secret);

        Assert.Equal(Outcome.MissingGatewaySecret, outcome);
        Assert.False(form.ContainsKey("client_secret"));
    }
}
