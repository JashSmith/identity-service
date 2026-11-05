using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Identity.E2E.Tests;

/// <summary>
/// Real single sign-on through Keycloak's login page with two independent web applications that use the
/// Avash.Identity web SSO package: sign in once, enter the second application without a password, sign out
/// everywhere at once.
/// </summary>
[Collection(StackCollection.Name)]
public sealed class SingleSignOnTests(IdentityStack stack)
{
    private static readonly string Run = Guid.NewGuid().ToString("N")[..8];

    private async Task<(WebSsoHost Host, string ClientId)> RegisterWebAppAsync(string admin, string name, bool backchannel = false)
    {
        var port = WebSsoHost.FreePort();
        var clientId = $"e2e-sso-{name}-{Run}";
        var origin = $"http://127.0.0.1:{port}";
        string secret;
        using (var created = await stack.CallAsync(HttpMethod.Post, "/api/identity/applications", admin,
                   new { clientId, displayName = $"E2E SSO {name}", kind = "web", redirectUris = new[] { $"{origin}/*" } }))
        {
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
            secret = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("clientSecret").GetString()!;
        }
        using (var logout = await stack.CallAsync(HttpMethod.Put, $"/api/identity/applications/{clientId}/logout", admin,
                   new
                   {
                       postLogoutRedirectUris = new[] { $"{origin}/signout-callback-oidc" },
                       // Keycloak runs in a container: it reaches the test process through host.docker.internal.
                       backchannelLogoutUrl = backchannel ? $"http://host.docker.internal:{port}/auth/backchannel-logout" : null,
                   }))
            Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
        return (await WebSsoHost.StartAsync(port, stack.Gateway.BaseAddress!, clientId, secret, listenOnAllInterfaces: backchannel), clientId);
    }

    [E2EFact]
    public async Task Signing_in_once_opens_every_application_and_signing_out_ends_the_sso_session()
    {
        var admin = await stack.LoginAsync("admin", "admin");
        var (crmHost, _) = await RegisterWebAppAsync(admin, "crm");
        var (hrHost, _) = await RegisterWebAppAsync(admin, "hr");
        await using var crm = crmHost;
        await using var hr = hrHost;
        using var browser = new Browser();

        // 1. First application: redirected to the organisation's login page, the user types the password.
        var (loginPage, loginUrl) = await browser.GetAsync(new Uri(crm.BaseAddress, "/auth/login?returnUrl=/me"));
        var action = Browser.LoginFormAction(await loginPage.Content.ReadAsStringAsync(), loginUrl);
        Assert.NotNull(action);
        Assert.Equal(stack.Keycloak.BaseAddress!.Port, loginUrl.Port); // the organisation's login page (Keycloak)
        var (me, meUrl) = await browser.PostFormAsync(action!, new() { ["username"] = "admin", ["password"] = "admin", ["credentialId"] = "" });
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.Equal(new Uri(crm.BaseAddress, "/me"), meUrl);
        Assert.Equal("admin", (await me.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("name").GetString());

        // 2. Second application: Keycloak recognises the SSO session, no login form is shown.
        var (hrMe, hrUrl) = await browser.GetAsync(new Uri(hr.BaseAddress, "/auth/login?returnUrl=/me"));
        Assert.Equal(HttpStatusCode.OK, hrMe.StatusCode);
        Assert.Equal(new Uri(hr.BaseAddress, "/me"), hrUrl);
        Assert.Contains(browser.Visited, u => u.Port == stack.Keycloak.BaseAddress!.Port); // it did pass through Keycloak

        // 3. Signing out of the first application ends the organisation's session: the second one asks again.
        var (signedOut, _) = await browser.PostFormAsync(new Uri(crm.BaseAddress, "/auth/logout"), new());
        Assert.True(signedOut.IsSuccessStatusCode || signedOut.StatusCode == HttpStatusCode.NotFound,
            $"sign-out ended with {(int)signedOut.StatusCode}");
        var (again, againUrl) = await browser.GetAsync(new Uri(hr.BaseAddress, "/auth/login?returnUrl=/me"));
        Assert.NotNull(Browser.LoginFormAction(await again.Content.ReadAsStringAsync(), againUrl));

        // 4. An anonymous visitor of a protected page is sent to the login page.
        await AnonymousVisitorIsSentToLogin(crm);
    }

    // Keycloak runs in a container and reaches the test process through host.docker.internal (Aspire container networking).
    [E2EFact]
    public async Task Signing_out_of_one_application_ends_the_other_applications_session_through_back_channel_logout()
    {
        var admin = await stack.LoginAsync("admin", "admin");
        var (crmHost, _) = await RegisterWebAppAsync(admin, "bc-crm", backchannel: true);
        var (hrHost, _) = await RegisterWebAppAsync(admin, "bc-hr", backchannel: true);
        await using var crm = crmHost;
        await using var hr = hrHost;
        using var browser = new Browser();
        var (loginPage, loginUrl) = await browser.GetAsync(new Uri(crm.BaseAddress, "/auth/login?returnUrl=/me"));
        var action = Browser.LoginFormAction(await loginPage.Content.ReadAsStringAsync(), loginUrl)!;
        await browser.PostFormAsync(action, new() { ["username"] = "admin", ["password"] = "admin", ["credentialId"] = "" });
        var (hrMe, _) = await browser.GetAsync(new Uri(hr.BaseAddress, "/auth/login?returnUrl=/me"));
        Assert.Equal(HttpStatusCode.OK, hrMe.StatusCode);

        await browser.PostFormAsync(new Uri(crm.BaseAddress, "/auth/logout"), new());

        // HR still holds its own cookie; only the back-channel logout token from Keycloak can invalidate it.
        var (after, afterUrl) = await browser.GetAsync(new Uri(hr.BaseAddress, "/me"));
        Assert.NotEqual(new Uri(hr.BaseAddress, "/me"), afterUrl);
        Assert.NotNull(Browser.LoginFormAction(await after.Content.ReadAsStringAsync(), afterUrl));
    }

    private static async Task AnonymousVisitorIsSentToLogin(WebSsoHost crm)
    {
        using var anonymous = new Browser();
        var (anonymousPage, anonymousUrl) = await anonymous.GetAsync(new Uri(crm.BaseAddress, "/me"));
        Assert.NotNull(Browser.LoginFormAction(await anonymousPage.Content.ReadAsStringAsync(), anonymousUrl));
    }
}
