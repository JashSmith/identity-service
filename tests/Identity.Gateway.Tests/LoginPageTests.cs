using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Identity.Application;
using Identity.Application.Permissions;
using Identity.Contracts;
using Identity.Infrastructure.Keycloak;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Gateway.Tests;

/// <summary>Per-application login pages: the four modes on the Keycloak client and the branding rules.</summary>
public sealed class LoginPageTests
{
    /// <summary>One application client ("crm") whose representation is updated by PUT, like Keycloak does.</summary>
    private sealed class FakeKeycloak : HttpMessageHandler
    {
        public JsonObject Client { get; set; } = JsonNode.Parse("""
            { "id": "uuid-crm", "clientId": "crm", "name": "CRM", "enabled": true, "directAccessGrantsEnabled": false,
              "redirectUris": ["https://crm.example/*"], "attributes": { "iam.application": "true", "iam.kind": "web" } }
            """)!.AsObject();

        public List<(HttpMethod Method, string Path)> Requests { get; } = [];
        public string[] Themes { get; set; } = ["avash", "base", "keycloak.v2", "crm-theme"];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            Requests.Add((request.Method, path));
            if (path.EndsWith("/token", StringComparison.Ordinal)) return Json(new { access_token = "t", expires_in = 300 });
            if (path == "/admin/serverinfo")
                return Json(new { themes = new { login = Themes.Select(t => new { name = t }) } });
            if (path.EndsWith("/clients", StringComparison.Ordinal) && request.Method == HttpMethod.Get)
                return request.RequestUri.Query.Contains("clientId=crm") ? Json(new[] { Client }) : Json(Array.Empty<object>());
            if (path.EndsWith("/clients/uuid-crm", StringComparison.Ordinal) && request.Method == HttpMethod.Put)
            {
                Client = JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))!.AsObject();
                return new HttpResponseMessage(HttpStatusCode.NoContent);
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        private static HttpResponseMessage Json(object body) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), System.Text.Encoding.UTF8, "application/json"),
        };

        public string? Attribute(string name) => Client["attributes"]?[name]?.GetValue<string>();
        public bool DirectGrants => Client["directAccessGrantsEnabled"]?.GetValue<bool>() ?? false;
    }

    private sealed class NoSuperAdmins : IKeycloakClientRoleProvisioner
    {
        public Task<Result<int>> ReconcileAdminAsync(CancellationToken ct) => Task.FromResult(Result<int>.Success(0));
        public Task<Result> EnsureSuperAdminGroupAsync(CancellationToken ct) => Task.FromResult(Result.Success());
    }

    private static KeycloakApplicationCatalog Catalog(FakeKeycloak kc)
    {
        var options = Options.Create(new KeycloakOptions { BaseUrl = "http://kc.test", Realm = "company", AdminClientSecret = "s" });
        return new KeycloakApplicationCatalog(new HttpClient(kc), options,
            new KeycloakAdminTokenProvider(new HttpClient(kc), options), new NoSuperAdmins(), NullLogger<KeycloakApplicationCatalog>.Instance);
    }

    private static readonly LoginPageBrandingDto Brand = new("سامانه مشتریان", "خوش آمدید", "https://cdn.example/logo.svg", "#26428b", "gradient");

    [Fact]
    public async Task A_new_application_inherits_the_central_login_page()
    {
        var page = await Catalog(new FakeKeycloak()).GetLoginPageAsync("crm", CancellationToken.None);

        Assert.Equal((LoginPageModes.Inherit, null, false), (page.Value.Mode, page.Value.Theme, page.Value.DirectLogin));
        Assert.Equal("pattern", page.Value.Branding.Background);
    }

    [Fact]
    public async Task Branded_mode_uses_the_avash_theme_and_stores_the_branding_on_the_client()
    {
        var kc = new FakeKeycloak();

        var page = await Catalog(kc).SetLoginPageAsync("crm", new UpdateLoginPageRequest(LoginPageModes.Branded, null, Brand), CancellationToken.None);

        Assert.True(page.IsSuccess);
        Assert.Equal("avash", kc.Attribute("login_theme"));
        Assert.Equal("branded", kc.Attribute("iam.login.mode"));
        Assert.Equal("سامانه مشتریان", kc.Attribute("iam.login.title"));
        Assert.Equal("#26428B", kc.Attribute("iam.login.primary_color"));
        Assert.Equal("gradient", kc.Attribute("iam.login.background"));
        Assert.Equal("true", kc.Attribute("iam.application")); // other attributes are kept
        Assert.False(kc.DirectGrants);
        Assert.Equal(LoginPageModes.Branded, page.Value.Mode);
    }

    [Fact]
    public async Task Theme_mode_requires_an_installed_theme()
    {
        var kc = new FakeKeycloak();
        var catalog = Catalog(kc);

        var unknown = await catalog.SetLoginPageAsync("crm", new UpdateLoginPageRequest(LoginPageModes.Theme, "missing"), CancellationToken.None);
        var custom = await catalog.SetLoginPageAsync("crm", new UpdateLoginPageRequest(LoginPageModes.Theme, "crm-theme"), CancellationToken.None);

        Assert.Equal("login_page.unknown_theme", unknown.Error!.Code);
        Assert.Equal("crm-theme", kc.Attribute("login_theme"));
        Assert.Equal((LoginPageModes.Theme, "crm-theme"), (custom.Value.Mode, custom.Value.Theme));
    }

    [Fact]
    public async Task Embedded_mode_enables_direct_login_and_leaving_it_disables_it_again()
    {
        var kc = new FakeKeycloak();
        var catalog = Catalog(kc);

        var embedded = await catalog.SetLoginPageAsync("crm", new UpdateLoginPageRequest(LoginPageModes.Embedded), CancellationToken.None);
        Assert.True(kc.DirectGrants);
        Assert.True(embedded.Value.DirectLogin);
        Assert.Equal("", kc.Attribute("login_theme"));

        var inherit = await catalog.SetLoginPageAsync("crm", new UpdateLoginPageRequest(LoginPageModes.Inherit), CancellationToken.None);
        Assert.False(kc.DirectGrants);
        Assert.False(inherit.Value.DirectLogin);
    }

    [Fact]
    public async Task Direct_login_set_by_an_administrator_is_not_touched_by_other_mode_changes()
    {
        var kc = new FakeKeycloak();
        kc.Client["directAccessGrantsEnabled"] = true;

        await Catalog(kc).SetLoginPageAsync("crm", new UpdateLoginPageRequest(LoginPageModes.Branded, null, Brand), CancellationToken.None);

        Assert.True(kc.DirectGrants);
    }

    [Fact]
    public async Task Branding_is_kept_when_switching_modes_so_switching_back_restores_it()
    {
        var kc = new FakeKeycloak();
        var catalog = Catalog(kc);
        await catalog.SetLoginPageAsync("crm", new UpdateLoginPageRequest(LoginPageModes.Branded, null, Brand), CancellationToken.None);

        var inherit = await catalog.SetLoginPageAsync("crm", new UpdateLoginPageRequest(LoginPageModes.Inherit), CancellationToken.None);

        Assert.Equal("", kc.Attribute("login_theme"));
        Assert.Equal("سامانه مشتریان", inherit.Value.Branding.Title);
    }

    [Theory]
    [InlineData("identity-gateway")]
    [InlineData("identity-admin-console")]
    public async Task The_gateways_own_clients_keep_their_sign_in(string clientId)
    {
        var kc = new FakeKeycloak();

        var result = await Catalog(kc).SetLoginPageAsync(clientId, new UpdateLoginPageRequest(LoginPageModes.Inherit), CancellationToken.None);

        Assert.Equal("login_page.reserved", result.Error!.Code);
        Assert.DoesNotContain(kc.Requests, r => r.Method == HttpMethod.Put);
    }

    [Fact]
    public async Task Unknown_application_is_not_found()
    {
        var result = await Catalog(new FakeKeycloak()).GetLoginPageAsync("ghost", CancellationToken.None);

        Assert.Equal(ErrorKind.NotFound, result.Error!.Kind);
    }

    [Fact]
    public void Applications_from_before_login_modes_map_an_explicit_theme_to_theme_mode()
    {
        var legacy = JsonDocument.Parse("""{ "clientId": "old", "attributes": { "login_theme": "keycloak" } }""").RootElement;

        var page = KeycloakApplicationCatalog.ToLoginPage(legacy);

        Assert.Equal((LoginPageModes.Theme, "keycloak"), (page.Mode, page.Theme));
    }

    [Fact]
    public async Task Installed_themes_come_from_serverinfo_sorted()
    {
        var kc = new FakeKeycloak { Themes = ["keycloak.v2", "avash", "crm-theme"] };

        var themes = await Catalog(kc).ListLoginThemesAsync(CancellationToken.None);

        Assert.Equal(["avash", "crm-theme", "keycloak.v2"], themes.Value.Themes);
        Assert.Equal("avash", themes.Value.BrandedTheme);
        Assert.Contains(kc.Requests, r => r.Path == "/admin/serverinfo");
    }

    // ---------- validation ----------

    private static IReadOnlyCollection<string> Errors(UpdateLoginPageRequest request) =>
        new UpdateLoginPageRequestValidator().Validate(request).Errors.Select(e => e.PropertyName).ToArray();

    [Fact]
    public void Valid_requests_for_every_mode_pass()
    {
        Assert.Empty(Errors(new UpdateLoginPageRequest(LoginPageModes.Inherit)));
        Assert.Empty(Errors(new UpdateLoginPageRequest(LoginPageModes.Branded, null, Brand)));
        Assert.Empty(Errors(new UpdateLoginPageRequest(LoginPageModes.Theme, "crm-theme")));
        Assert.Empty(Errors(new UpdateLoginPageRequest(LoginPageModes.Embedded)));
    }

    [Theory]
    [InlineData("<b>bold</b>")]
    [InlineData("line\nbreak")]
    public void Branding_texts_are_plain_text(string title) =>
        Assert.Contains("Branding.Title", Errors(new UpdateLoginPageRequest(LoginPageModes.Branded, null, Brand with { Title = title })));

    [Theory]
    [InlineData("http://cdn.example/logo.png")]
    [InlineData("javascript:alert(1)")]
    [InlineData("https://cdn.example/a\".png")]
    [InlineData("https://cdn.example/a).png")]
    [InlineData("data:image/png;base64,AAAA")]
    public void Logo_must_be_a_safe_https_url(string url) =>
        Assert.Contains("Branding.LogoUrl", Errors(new UpdateLoginPageRequest(LoginPageModes.Branded, null, Brand with { LogoUrl = url })));

    [Theory]
    [InlineData("#FFFFFF", false)]
    [InlineData("#F2B84B", false)] // saffron: too light for white text
    [InlineData("#0A7471", true)]  // turquoise
    [InlineData("#26428B", true)]  // lapis
    [InlineData("26428B", false)]
    public void Brand_colour_keeps_white_button_text_readable(string color, bool valid) =>
        Assert.Equal(valid, !Errors(new UpdateLoginPageRequest(LoginPageModes.Branded, null, Brand with { PrimaryColor = color }))
            .Contains("Branding.PrimaryColor"));

    [Fact]
    public void Contrast_follows_wcag()
    {
        Assert.Equal(21, LoginPageBrandingValidator.ContrastWithWhite("#000000"), 1);
        Assert.Equal(1, LoginPageBrandingValidator.ContrastWithWhite("#FFFFFF"), 1);
    }

    [Fact]
    public void Theme_mode_needs_a_theme_name_and_mode_must_be_known()
    {
        Assert.Contains("Theme", Errors(new UpdateLoginPageRequest(LoginPageModes.Theme)));
        Assert.Contains("Theme", Errors(new UpdateLoginPageRequest(LoginPageModes.Theme, "../../etc")));
        Assert.Contains("Mode", Errors(new UpdateLoginPageRequest("magic")));
        Assert.Contains("Branding.Background", Errors(new UpdateLoginPageRequest(LoginPageModes.Branded, null, Brand with { Background = "video" })));
    }
}
