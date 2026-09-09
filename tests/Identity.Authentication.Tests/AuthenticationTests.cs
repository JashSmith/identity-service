using Company.Identity.Authentication;

namespace Identity.Authentication.Tests;

public class AuthenticationTests
{
    [Fact]
    public void Defaults_require_https_metadata()
    {
        var options = new IdentityAuthenticationOptions { Authority = "https://identity.example" };
        Assert.True(options.RequireHttpsMetadata);
    }
}