using Avash.Identity.Authentication.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Identity.Authentication.Tests;

public class TokenLoggingTests
{
    [Fact]
    public async Task Rejected_token_is_not_written_to_the_console()
    {
        const string token = "eyJ.secret-token-value.sig";
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAvashAuthentication(o =>
        {
            o.Authority = "https://kc.test/realms/company";
            o.Audience = "identity-gateway";
        });
        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);
        var http = new DefaultHttpContext { RequestServices = provider };
        http.Request.Headers.Authorization = $"Bearer {token}";
        var scheme = new AuthenticationScheme(JwtBearerDefaults.AuthenticationScheme, null, typeof(JwtBearerHandler));
        var context = new AuthenticationFailedContext(http, scheme, options)
        {
            Exception = new SecurityTokenExpiredException("expired")
        };

        var console = new StringWriter();
        var original = Console.Out;
        Console.SetOut(console);
        try
        {
            await options.Events.OnAuthenticationFailed(context);
        }
        finally
        {
            Console.SetOut(original);
        }

        Assert.DoesNotContain(token, console.ToString());
    }
}
