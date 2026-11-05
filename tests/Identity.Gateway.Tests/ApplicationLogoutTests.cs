using System.Text.Json;
using Identity.Application.Permissions;
using Identity.Contracts;
using Identity.Infrastructure.Keycloak;

namespace Identity.Gateway.Tests;

/// <summary>Single-logout settings on the application's Keycloak client.</summary>
public sealed class ApplicationLogoutTests
{
    [Fact]
    public void Keycloak_attributes_are_read_as_url_lists()
    {
        var client = JsonDocument.Parse("""
            { "clientId": "crm", "attributes": {
                "post.logout.redirect.uris": "https://crm.example/##https://crm.example/bye##+",
                "backchannel.logout.url": "https://crm.example/auth/backchannel-logout" } }
            """).RootElement;

        var logout = KeycloakApplicationCatalog.ToLogout(client);

        Assert.Equal(["https://crm.example/", "https://crm.example/bye"], logout.PostLogoutRedirectUris);
        Assert.Equal("https://crm.example/auth/backchannel-logout", logout.BackchannelLogoutUrl);
    }

    [Fact]
    public void A_client_without_logout_settings_has_none()
    {
        var logout = KeycloakApplicationCatalog.ToLogout(JsonDocument.Parse("""{ "clientId": "crm" }""").RootElement);

        Assert.Empty(logout.PostLogoutRedirectUris);
        Assert.Null(logout.BackchannelLogoutUrl);
    }

    [Theory]
    [InlineData("https://crm.example/auth/backchannel-logout", true)]
    [InlineData("http://crm.internal:8080/auth/backchannel-logout", true)]
    [InlineData("javascript:alert(1)", false)]
    [InlineData("/relative/path", false)]
    [InlineData("https://a.example/##https://b.example/", false)]
    public void Logout_urls_are_absolute_http_urls(string url, bool valid)
    {
        var validator = new ApplicationLogoutValidator();

        Assert.Equal(valid, validator.Validate(new ApplicationLogoutDto([], url)).IsValid);
        Assert.Equal(valid, validator.Validate(new ApplicationLogoutDto([url], null)).IsValid);
    }

    [Fact]
    public void At_most_twenty_post_logout_urls()
    {
        var urls = Enumerable.Range(0, 21).Select(i => $"https://crm.example/{i}").ToArray();

        Assert.False(new ApplicationLogoutValidator().Validate(new ApplicationLogoutDto(urls, null)).IsValid);
    }
}
