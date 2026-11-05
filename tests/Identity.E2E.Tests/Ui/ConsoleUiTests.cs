using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Playwright;

namespace Identity.E2E.Tests.Ui;

/// <summary>
/// The whole product through a real browser (Playwright + Chrome), as an administrator would use it: sign-in through
/// Keycloak, every console section, theme, login pages, SMS, access boundaries, keyboard and phone layout.
/// Each test fails on any HTTP error (e.g. 431, 500) or script error seen on the way, not only on its own assertions.
/// Run: IDENTITY_E2E=1 dotnet test tests/Identity.E2E.Tests --filter "FullyQualifiedName~Ui"
/// </summary>
[Collection(StackCollection.Name)]
public sealed class ConsoleUiTests(IdentityStack stack, BrowserSession browser)
{
    private static readonly string Run = Guid.NewGuid().ToString("N")[..8];

    private static readonly (string Path, string Title)[] Sections =
    [
        ("/", "داشبورد"),
        ("/users", "کاربران"),
        ("/roles", "نقش‌ها"),
        ("/scopes", "محدوده‌های دسترسی"),
        ("/applications", "اپلیکیشن‌ها و دسترسی‌ها"),
        ("/schedules", "برنامه زمانی دسترسی"),
        ("/settings", "تنظیمات احراز هویت"),
        ("/tenants", "سازمان‌ها"),
    ];

    [E2EFact]
    public async Task Administrator_signs_in_through_keycloak_and_every_section_renders_without_errors()
    {
        await using var ui = await browser.NewContextAsync();

        await ui.SignInAsync();

        Assert.Equal("rtl", await ui.Page.Locator("html").GetAttributeAsync("dir"));
        await Assertions.Expect(ui.Page.Locator("h1")).ToContainTextAsync("داشبورد");
        await Assertions.Expect(ui.Page.Locator("article.av-stat .av-stat__value").First).Not.ToHaveClassAsync(new System.Text.RegularExpressions.Regex("av-skeleton"));
        Assert.True(await ui.Page.Locator("article.av-stat").CountAsync() >= 4);
        foreach (var (path, title) in Sections)
        {
            await ui.Page.Locator($"nav.av-nav a[href='{path}']").ClickAsync();
            await ui.Page.WaitForURLAsync(u => new Uri(u).AbsolutePath == path);
            var h1 = ui.Page.Locator("h1");
            await Assertions.Expect(h1).ToHaveCountAsync(1);
            await Assertions.Expect(h1).ToContainTextAsync(title);
            await ui.Page.WaitForLoadStateAsync(LoadState.NetworkIdle);
            Assert.Equal(0, await ui.Page.Locator(".rz-notification-item .rzi-times-circle, .rz-notification-error").CountAsync());
            Assert.False(await ui.OverflowsAsync(), $"{path} scrolls horizontally");
        }
        await ui.AssertNoProblemsAsync("sections");
    }

    [E2EFact]
    public async Task Signing_in_and_out_repeatedly_never_makes_the_request_headers_too_large()
    {
        await using var ui = await browser.NewContextAsync();

        for (var round = 1; round <= 4; round++)
        {
            await ui.SignInAsync();
            await Assertions.Expect(ui.Page.Locator("h1")).ToContainTextAsync("داشبورد");
            await ui.SignOutAsync();
        }

        // Keycloak refuses Cookie headers of about 8 KB (431). The console cookie is a short key now.
        Assert.True(ui.LargestKeycloakCookieHeader < 5000, $"Cookie header to Keycloak reached {ui.LargestKeycloakCookieHeader} bytes");
        var consoleCookie = (await ui.Context.CookiesAsync([BrowserSession.Console])).FirstOrDefault(c => c.Name == "avash-admin");
        Assert.True(consoleCookie is null || consoleCookie.Value.Length < 1200, $"console cookie is {consoleCookie?.Value.Length} bytes");
        await ui.AssertNoProblemsAsync("repeated-sign-in");
    }

    [E2EFact]
    public async Task The_chosen_theme_is_applied_and_survives_a_reload()
    {
        await using var ui = await browser.NewContextAsync();
        await ui.SignInAsync();

        await ui.Page.Locator("[data-theme-option='dark']").ClickAsync();
        Assert.Equal("dark", await ui.Page.Locator("html").GetAttributeAsync("data-theme"));
        Assert.Equal("true", await ui.Page.Locator("[data-theme-option='dark']").GetAttributeAsync("aria-pressed"));
        await ui.Page.ReloadAsync();
        await ui.Page.Locator("nav.av-nav").WaitForAsync();

        Assert.Equal("dark", await ui.Page.Locator("html").GetAttributeAsync("data-theme"));
        var background = await ui.Page.EvaluateAsync<string>("getComputedStyle(document.body).backgroundColor");
        Assert.Equal("rgb(14, 20, 27)", background); // indigo night
        await ui.AssertNoProblemsAsync("theme");
    }

    [E2EFact]
    public async Task An_application_gets_a_branded_login_page_from_the_console()
    {
        var admin = await stack.LoginAsync("admin", "admin");
        var application = $"ui-crm-{Run}";
        using (var created = await stack.CallAsync(HttpMethod.Post, "/api/identity/applications", admin,
                   new { clientId = application, displayName = "UI CRM", kind = "web", redirectUris = new[] { "http://localhost:5999/callback" } }))
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        await using var ui = await browser.NewContextAsync();
        await ui.SignInAsync();

        await ui.Page.GotoAsync($"{BrowserSession.Console}/applications/{application}/login-page");
        await ui.Page.Locator("label.av-mode", new() { HasText = "ورود مرکزی با برند اختصاصی" }).ClickAsync();
        await ui.Page.Locator(".rz-form-field", new() { HasText = "عنوان (مثلاً نام اپلیکیشن)" }).Locator("input")
            .FillAsync($"سامانه {Run}");
        await ui.Page.Locator("button.av-swatch[title='لاجوردی']").ClickAsync();
        await ui.Page.Locator(".av-actions-bar button").ClickAsync();
        await Assertions.Expect(ui.Page.Locator(".rz-notification")).ToContainTextAsync("صفحه ورود ذخیره شد");
        await Assertions.Expect(ui.Page.Locator(".av-preview__title")).ToHaveTextAsync($"سامانه {Run}");

        // A fresh profile: in the console's profile the administrator's SSO session would sign straight in to the
        // application and leave for its (absent) callback instead of showing the login page.
        var testLink = await ui.Page.Locator("a[target=_blank]").GetAttributeAsync("href") ?? "";
        await using var visitor = await browser.NewContextAsync();
        var real = visitor.Page;
        await real.GotoAsync(testLink);
        await Assertions.Expect(real.Locator(".avash-brand__title")).ToHaveTextAsync($"سامانه {Run}");
        Assert.Contains("--avash-brand: #26428B", await real.ContentAsync());
        await ui.AssertNoProblemsAsync("login-page");
        await visitor.AssertNoProblemsAsync("login-page-visitor");
    }

    [E2EFact]
    public async Task Sms_is_configured_and_tested_from_the_console_with_the_development_provider()
    {
        await using var ui = await browser.NewContextAsync();
        await ui.SignInAsync();

        await ui.Page.GotoAsync($"{BrowserSession.Console}/settings?tab=sms");
        await ui.Page.Locator("label.av-mode", new() { HasText = "حالت آزمایشی" }).ClickAsync();
        await Assertions.Expect(ui.Page.Locator("[role=note]")).ToContainTextAsync("هیچ پیامکی ارسال نمی‌شود");
        var enabled = ui.Page.Locator(".rz-switch").Filter(new() { Has = ui.Page.Locator("input[name='sms-enabled']") });
        if (!(await enabled.GetAttributeAsync("class") ?? "").Contains("rz-switch-checked")) await enabled.ClickAsync();
        await ui.Page.Locator("button", new() { HasText = "ذخیره" }).First.ClickAsync();
        await Assertions.Expect(ui.Page.Locator(".rz-notification")).ToContainTextAsync("تنظیمات پیامک ذخیره شد");
        await ui.Page.Locator("input[name=sms-test-number]").FillAsync("09121234567");
        await ui.Page.Locator("button", new() { HasText = "ارسال آزمایشی" }).ClickAsync();

        await Assertions.Expect(ui.Page.Locator("[role=status]")).ToContainTextAsync("پیام در حالت آزمایشی ثبت شد");
        await Assertions.Expect(ui.Page.Locator(".av-feed")).ToContainTextAsync("+98912***4567");
        await ui.AssertNoProblemsAsync("sms");

        var admin = await stack.LoginAsync("admin", "admin");
        using (await stack.CallAsync(HttpMethod.Put, "/api/identity/settings/sms", admin,
                   new { enabled = false, provider = "development", settings = new Dictionary<string, object>() })) { }
    }

    [E2EFact]
    public async Task An_administrator_with_only_user_read_rights_sees_only_their_sections()
    {
        var (username, password) = await CreateReaderAsync();
        await using var ui = await browser.NewContextAsync();

        await ui.SignInAsync(username, password);

        var links = await ui.Page.Locator("nav.av-nav a").EvaluateAllAsync<string[]>("els => els.map(e => e.getAttribute('href'))");
        Assert.Equal(["/", "/users"], links);
        await ui.Page.GotoAsync($"{BrowserSession.Console}/applications/anything/login-page");
        await Assertions.Expect(ui.Page.Locator(".av-empty__title")).ToHaveTextAsync("به این بخش دسترسی ندارید");
        await ui.AssertNoProblemsAsync("reader");
    }

    [E2EFact]
    public async Task The_console_works_with_the_keyboard_alone()
    {
        await using var ui = await browser.NewContextAsync();
        await ui.SignInAsync();
        await ui.Page.Locator("article.av-stat").First.WaitForAsync();
        // Start from the top of the document, like a fresh visit.
        await ui.Page.EvaluateAsync("() => { const s = document.createElement('span'); s.tabIndex = -1; document.body.prepend(s); s.focus(); s.remove(); }");

        await ui.Page.Keyboard.PressAsync("Tab");
        Assert.Equal("av-skip-link", await ui.Page.EvaluateAsync<string>("document.activeElement.className"));
        await ui.Page.Keyboard.PressAsync("Enter");
        Assert.Equal("main", await ui.Page.EvaluateAsync<string>("document.activeElement.id"));

        await ui.Page.Locator("[data-theme-option='dark']").FocusAsync();
        await ui.Page.Keyboard.PressAsync("Enter");
        Assert.Equal("dark", await ui.Page.Locator("html").GetAttributeAsync("data-theme"));
        await ui.Page.Keyboard.PressAsync("Shift+Tab");
        await ui.Page.Keyboard.PressAsync("Space");
        Assert.Equal("system", await ui.Page.Locator("html").GetAttributeAsync("data-theme"));
        await ui.AssertNoProblemsAsync("keyboard");
    }

    [E2EFact]
    public async Task On_a_phone_the_dashboard_fits_and_the_menu_opens_from_the_toggle()
    {
        await using var ui = await browser.NewContextAsync(390, 844);
        await ui.SignInAsync();
        await ui.Page.Locator("article.av-stat").First.WaitForAsync();

        Assert.False(await ui.OverflowsAsync(), "the dashboard scrolls horizontally on a phone");
        await ui.Page.Locator(".rz-sidebar-toggle").ClickAsync();
        await Assertions.Expect(ui.Page.Locator("nav.av-nav a[href='/users']")).ToBeVisibleAsync();
        await ui.AssertNoProblemsAsync("phone");
    }

    private async Task<(string Username, string Password)> CreateReaderAsync()
    {
        var admin = await stack.LoginAsync("admin", "admin");
        var role = $"ui-reader-{Run}";
        var username = $"ui-reader-{Run}";
        var password = $"Reader#{Run}-pass";
        using (var created = await stack.CallAsync(HttpMethod.Post, "/api/identity/business-roles", admin,
                   new { name = role, permissions = new[] { "identity-gateway:Users:User:Read" } }))
            Assert.True(created.IsSuccessStatusCode || created.StatusCode == HttpStatusCode.Conflict);
        using var user = await stack.CallAsync(HttpMethod.Post, "/api/identity/users", admin, new
        {
            username, email = $"{username}@ui.local", firstName = "UI", lastName = "Reader", enabled = true,
            credentials = new { password, temporary = false },
            assignments = new[] { new { role, scopes = new Dictionary<string, string[]> { ["region"] = ["tehran"] } } },
        });
        if (user.IsSuccessStatusCode)
        {
            var id = (await user.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString();
            // Keycloak's own login page follows the realm's weekly schedule; this account may sign in at any time.
            using (await stack.CallAsync(HttpMethod.Put, $"/api/identity/schedules/users/{id}", admin, new { unrestricted = true })) { }
        }
        return (username, password);
    }
}
