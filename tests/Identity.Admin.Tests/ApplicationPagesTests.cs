using System.Net;
using System.Text.Json;
using Identity.Admin.Components.Pages.Applications;
using Identity.Admin.Services;
using Identity.Contracts;
using Microsoft.Extensions.DependencyInjection;

namespace Identity.Admin.Tests;

/// <summary>The application login-page editor and the integration guide in their states.</summary>
public sealed class ApplicationPagesTests : ConsoleTestContext
{
    private static readonly ApplicationDto Crm = new("crm", "سامانه مشتریان", null, "web", true, ["https://crm.example/*"], "avash");

    private void CrmGateway(string mode = "branded", string color = "#26428B", string? tenant = null)
    {
        Gateway.Json("GET api/identity/applications/crm", Crm)
            .Json("GET api/identity/applications/crm/login-page", new ApplicationLoginPageDto("crm", mode, mode == "branded" ? "avash" : null,
                new LoginPageBrandingDto("سامانه مشتریان", "خوش آمدید", null, color, "pattern"), mode == "embedded"))
            .Json("GET api/identity/settings/login-themes", new LoginThemesDto(["avash", "base", "keycloak.v2"], "avash"))
            .Json("GET api/identity/applications/crm/integration", new ApplicationIntegrationDto("crm", "web", "https://identity.example",
                "https://identity.example/.well-known/openid-configuration" + (tenant is null ? "" : $"?tenant={tenant}"), tenant,
                ["https://crm.example/signin-oidc"], new ApplicationLogoutDto([], null)));
    }

    private IRenderedComponent<LoginPageEditor> Editor() => Render<LoginPageEditor>(p => p.Add(c => c.ClientId, "crm"));

    [Fact]
    public void Branded_page_loads_with_its_preview_and_a_link_to_the_real_login_page()
    {
        SignIn(Permissions.ApplicationsRead, Permissions.ApplicationsManage);
        CrmGateway();

        var editor = Editor();

        editor.WaitForAssertion(() => Assert.Contains("av-mode--selected", editor.FindAll("label.av-mode")[1].ClassName));
        Assert.Equal("سامانه مشتریان", editor.Find(".av-preview__title").TextContent);
        Assert.Contains("--preview-brand: #26428B", editor.Find(".av-preview").GetAttribute("style"));
        var test = editor.Find("a[target=_blank]").GetAttribute("href")!;
        Assert.StartsWith("https://kc.test/realms/company/protocol/openid-connect/auth?client_id=crm", test);
        Assert.Contains("redirect_uri=https%3A%2F%2Fcrm.example%2F", test);
        Assert.Empty(editor.FindAll("[role=alert]")); // lapis is dark enough
    }

    [Fact]
    public void A_light_brand_colour_warns_before_saving()
    {
        SignIn(Permissions.ApplicationsRead, Permissions.ApplicationsManage);
        CrmGateway(color: "#F2B84B");

        var editor = Editor();

        editor.WaitForAssertion(() => Assert.Contains("کنتراست کمتر از ۳ به ۱", editor.Find("[role=alert]").TextContent));
    }

    [Fact]
    public void Saving_sends_the_chosen_mode_and_branding()
    {
        SignIn(Permissions.ApplicationsRead, Permissions.ApplicationsManage);
        CrmGateway();
        Gateway.Json("PUT api/identity/applications/crm/login-page", new ApplicationLoginPageDto("crm", "branded", "avash",
            new LoginPageBrandingDto("سامانه مشتریان", "خوش آمدید", null, "#26428B", "pattern"), false));
        var editor = Editor();
        editor.WaitForAssertion(() => Assert.NotNull(editor.Find(".av-actions-bar button")));

        editor.Find(".av-actions-bar button").Click();

        editor.WaitForAssertion(() => Assert.Contains(Gateway.Requests, r => r.Route == "PUT api/identity/applications/crm/login-page"));
        using var body = JsonDocument.Parse(Gateway.Requests.Single(r => r.Route.StartsWith("PUT", StringComparison.Ordinal)).Body!);
        Assert.Equal("branded", body.RootElement.GetProperty("mode").GetString());
        Assert.Equal("#26428B", body.RootElement.GetProperty("branding").GetProperty("primaryColor").GetString());
    }

    [Fact]
    public void Embedded_mode_warns_and_shows_the_direct_login_request()
    {
        SignIn(Permissions.ApplicationsRead, Permissions.ApplicationsManage);
        CrmGateway(mode: "embedded");

        var editor = Editor();

        editor.WaitForAssertion(() => Assert.Contains("فقط برای اپلیکیشن‌های داخلی و مورد اعتماد", editor.Markup));
        Assert.Contains("client_id=crm", editor.Find("pre.av-code").TextContent);
        Assert.Empty(editor.FindAll("a[target=_blank]")); // no browser login page to test in embedded mode
    }

    [Fact]
    public void Readers_without_manage_rights_see_the_settings_read_only()
    {
        SignIn(Permissions.ApplicationsRead);
        CrmGateway();

        var editor = Editor();

        editor.WaitForAssertion(() => Assert.True(editor.Find("fieldset.av-modes").HasAttribute("disabled")));
        Assert.Empty(editor.FindAll(".av-actions-bar"));
    }

    [Fact]
    public void An_unknown_application_shows_an_error_state_with_a_way_back()
    {
        SignIn(Permissions.ApplicationsRead);
        Gateway.Problem("GET api/identity/applications/ghost", HttpStatusCode.NotFound, "application.not_found");

        var editor = Render<LoginPageEditor>(p => p.Add(c => c.ClientId, "ghost"));

        editor.WaitForAssertion(() => Assert.Contains("تنظیمات صفحه ورود خوانده نشد", editor.Markup));
        Assert.Contains("بازگشت به اپلیکیشن‌ها", editor.Find(".av-empty__action").TextContent);
    }

    [Fact]
    public void Without_read_rights_both_pages_explain_the_access_boundary_and_call_nothing()
    {
        SignIn(Permissions.UsersRead);

        var editor = Editor();
        var guide = Render<IntegrationGuide>(p => p.Add(c => c.ClientId, "crm"));

        editor.WaitForAssertion(() => Assert.Contains("به این بخش دسترسی ندارید", editor.Markup));
        guide.WaitForAssertion(() => Assert.Contains("به این بخش دسترسی ندارید", guide.Markup));
        Assert.Empty(Gateway.Requests);
    }

    [Fact]
    public async Task A_bodiless_gateway_refusal_has_a_persian_title_and_no_english_detail()
    {
        SignIn(Permissions.ApplicationsRead);
        var api = Services.GetRequiredService<GatewayApi>();

        var error = await Assert.ThrowsAsync<ApiException>(() => api.GetAsync<object>("api/identity/forbidden"));

        Assert.Equal("مورد درخواستی یافت نشد", error.PersianTitle);
        Assert.Equal("", new ApiException(403, "", "", new Dictionary<string, string[]>()).Details);
    }

    [Fact]
    public void Integration_guide_fills_the_code_with_the_applications_values()
    {
        SignIn(Permissions.ApplicationsRead);
        CrmGateway(tenant: "acme");

        var guide = Render<IntegrationGuide>(p => p.Add(c => c.ClientId, "crm"));

        guide.WaitForAssertion(() => Assert.NotEmpty(guide.FindAll("pre.av-code")));
        var web = guide.FindAll("pre.av-code")[0].TextContent;
        Assert.Contains("o.Authority = \"https://identity.example\";", web);
        Assert.Contains("o.Tenant = \"acme\";", web);
        Assert.Contains("o.ClientId = \"crm\";", web);
        Assert.DoesNotContain("ClientSecret = \"", web); // the secret is read from configuration, never pasted
        Assert.Contains(guide.FindAll("button.av-copy"), b => b.GetAttribute("data-copy") == "https://identity.example/.well-known/openid-configuration?tenant=acme");
        Assert.Empty(guide.FindAll(".av-panel button.rz-button")); // logout settings are read-only for readers
    }

    [Fact]
    public void Integration_guide_saves_single_logout_settings()
    {
        SignIn(Permissions.ApplicationsRead, Permissions.ApplicationsManage);
        CrmGateway();
        Gateway.Json("PUT api/identity/applications/crm/logout", new ApplicationLogoutDto(["https://crm.example/"], "https://crm.example/auth/backchannel-logout"));
        var guide = Render<IntegrationGuide>(p => p.Add(c => c.ClientId, "crm"));
        guide.WaitForAssertion(() => Assert.NotEmpty(guide.FindAll("input")));

        guide.Find("input").Change("https://crm.example/auth/backchannel-logout");
        guide.Find("textarea").Change("https://crm.example/\n\n");
        guide.FindAll("button").First(b => b.TextContent.Contains("ذخیره")).Click();

        guide.WaitForAssertion(() => Assert.Contains(Gateway.Requests, r => r.Route == "PUT api/identity/applications/crm/logout"));
        using var body = JsonDocument.Parse(Gateway.Requests.Single(r => r.Route.StartsWith("PUT", StringComparison.Ordinal)).Body!);
        Assert.Equal("https://crm.example/auth/backchannel-logout", body.RootElement.GetProperty("backchannelLogoutUrl").GetString());
        Assert.Equal(["https://crm.example/"], body.RootElement.GetProperty("postLogoutRedirectUris").EnumerateArray().Select(e => e.GetString()));
    }
}
