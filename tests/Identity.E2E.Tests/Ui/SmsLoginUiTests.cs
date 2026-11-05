using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Playwright;

namespace Identity.E2E.Tests.Ui;

/// <summary>
/// SMS sign-in in a real browser: passwordless and second factor on Keycloak's (Persian) login page, and the console
/// pages that switch it on and register a user's mobile number. Codes are read from the development SMS outbox.
/// </summary>
[Collection(StackCollection.Name)]
public sealed class SmsLoginUiTests(IdentityStack stack, BrowserSession browser)
{
    private static readonly string Run = Guid.NewGuid().ToString("N")[..8];

    private async Task<(string Username, string Password, string Phone)> UserAsync(string admin, int purpose)
    {
        var phone = SmsSignIn.Phone(Run, 10 + purpose);
        var role = $"ui-sms-reader-{Run}";
        using (var created = await stack.CallAsync(HttpMethod.Post, "/api/identity/business-roles", admin,
                   new { name = role, permissions = new[] { "identity-gateway:Users:User:Read" } }))
            Assert.True(created.IsSuccessStatusCode || created.StatusCode == HttpStatusCode.Conflict);
        var (_, username, password) = await SmsSignIn.CreateUserAsync(stack, admin, $"ui-sms-{purpose}-{Run}", phone, role);
        return (username, password, phone);
    }

    private static async Task OpenKeycloakAsync(UiContext ui)
    {
        await ui.Page.GotoAsync($"{BrowserSession.Console}/login");
        await ui.Page.Locator("a.av-login__tenant[href*='/auth/login/company']").ClickAsync();
        await ui.Page.WaitForURLAsync(u => u.StartsWith(BrowserSession.Keycloak, StringComparison.Ordinal));
    }

    private static Task InConsoleAsync(UiContext ui) => ui.Page.Locator("nav.av-nav").WaitForAsync();

    /// <summary>The console saves on the server (Blazor), so the test waits until the gateway reports the expected mode.</summary>
    private async Task<string?> SavedModeAsync(string admin, string expected)
    {
        string? mode = null;
        for (var attempt = 0; attempt < 40 && mode != expected; attempt++)
        {
            if (attempt > 0) await Task.Delay(250);
            using var read = await stack.CallAsync(HttpMethod.Get, "/api/identity/settings/sms/login", admin);
            mode = (await read.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("mode").GetString();
        }
        return mode;
    }

    [E2EFact]
    public async Task A_user_signs_in_on_the_login_page_with_a_mobile_number_and_an_sms_code()
    {
        var admin = await stack.LoginAsync("admin", "admin");
        var (username, _, phone) = await UserAsync(admin, 1);
        await SmsSignIn.SetModeAsync(stack, admin, "passwordless");
        try
        {
            await using var ui = await browser.NewContextAsync();
            await OpenKeycloakAsync(ui);

            await ui.Page.Locator("#try-another-way").ClickAsync();
            await ui.Page.Locator("h2", new() { HasText = "ورود با کد پیامکی" }).ClickAsync();
            var before = DateTimeOffset.UtcNow.AddSeconds(-5);
            await ui.Page.Locator("#phone").FillAsync(phone);
            await ui.Page.Locator("#kc-sms-send").ClickAsync();
            await Assertions.Expect(ui.Page.Locator("#kc-sms-sent")).ToContainTextAsync(phone[..4] + "***" + phone[^4..]);
            // The resend button waits; the page never shows whose number it is.
            await Assertions.Expect(ui.Page.Locator("#kc-sms-resend")).ToBeDisabledAsync();
            var code = await SmsSignIn.CodeAsync(stack, admin, phone, before);

            await ui.Page.Locator("#code").FillAsync(code == "000000" ? "111111" : "000000");
            await ui.Page.Locator("#kc-sms-login").ClickAsync();
            await Assertions.Expect(ui.Page.Locator("body")).ToContainTextAsync("کد درست نیست");
            Assert.DoesNotContain(username, await ui.Page.ContentAsync());

            await ui.Page.Locator("#code").FillAsync(code);
            await ui.Page.Locator("#kc-sms-login").ClickAsync();
            await InConsoleAsync(ui);
            await Assertions.Expect(ui.Page.Locator(".av-user")).ToContainTextAsync(username);
            await ui.AssertNoProblemsAsync("sms-passwordless");
        }
        finally
        {
            await SmsSignIn.RestoreAsync(stack, admin);
        }
    }

    [E2EFact]
    public async Task With_the_second_factor_the_login_page_asks_for_the_sms_code_after_the_password()
    {
        var admin = await stack.LoginAsync("admin", "admin");
        var (username, password, phone) = await UserAsync(admin, 2);
        await SmsSignIn.SetModeAsync(stack, admin, "second-factor");
        try
        {
            await using var ui = await browser.NewContextAsync();
            await OpenKeycloakAsync(ui);
            var before = DateTimeOffset.UtcNow.AddSeconds(-5);
            await ui.Page.Locator("#username").FillAsync(username);
            await ui.Page.Locator("#password").FillAsync(password);
            await ui.Page.Locator("#kc-login").ClickAsync();

            await Assertions.Expect(ui.Page.Locator("#kc-page-title")).ToContainTextAsync("تأیید با کد پیامکی");
            await ui.Page.Locator("#code").FillAsync(await SmsSignIn.CodeAsync(stack, admin, phone, before));
            await ui.Page.Locator("#kc-sms-login").ClickAsync();
            await InConsoleAsync(ui);
            await ui.AssertNoProblemsAsync("sms-second-factor");
        }
        finally
        {
            await SmsSignIn.RestoreAsync(stack, admin);
        }
    }

    [E2EFact]
    public async Task The_console_registers_a_mobile_number_and_turns_sms_sign_in_on_and_off()
    {
        var admin = await stack.LoginAsync("admin", "admin");
        var (id, _, _) = await SmsSignIn.CreateUserAsync(stack, admin, $"ui-sms-phone-{Run}", null);
        var phone = SmsSignIn.Phone(Run, 20);
        try
        {
            await using var ui = await browser.NewContextAsync();
            await ui.SignInAsync();

            await ui.Page.GotoAsync($"{BrowserSession.Console}/users/{id}");
            await ui.Page.Locator("input[name=user-phone]").FillAsync(phone);
            await ui.Page.Locator("button", new() { HasText = "ذخیره مشخصات" }).ClickAsync();
            await Assertions.Expect(ui.Page.Locator(".rz-notification")).ToContainTextAsync("مشخصات ذخیره شد");
            using (var read = await stack.CallAsync(HttpMethod.Get, $"/api/identity/users/{id}", admin))
                Assert.Equal("+98" + phone[1..], (await read.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("phoneNumber").GetString());

            // SMS sending first, then SMS sign-in on the same tab.
            await ui.Page.GotoAsync($"{BrowserSession.Console}/settings?tab=sms");
            await ui.Page.Locator("label.av-mode", new() { HasText = "حالت آزمایشی" }).ClickAsync();
            var enabled = ui.Page.Locator(".rz-switch").Filter(new() { Has = ui.Page.Locator("input[name='sms-enabled']") });
            if (!(await enabled.GetAttributeAsync("class") ?? "").Contains("rz-switch-checked")) await enabled.ClickAsync();
            await ui.Page.Locator("button[name=sms-save]").ClickAsync();
            await Assertions.Expect(ui.Page.Locator(".rz-notification").Last).ToContainTextAsync("تنظیمات پیامک ذخیره شد");

            await ui.Page.Locator("label.av-mode", new() { HasText = "ورود بدون رمز" }).ClickAsync();
            await ui.Page.Locator("button[name=sms-login-save]").ClickAsync();
            await Assertions.Expect(ui.Page.Locator(".rz-notification", new() { HasText = "تنظیمات ورود با پیامک ذخیره شد" })).ToHaveCountAsync(1);
            Assert.Equal("passwordless", await SavedModeAsync(admin, "passwordless"));

            await ui.Page.Locator("label.av-mode", new() { HasText = "خاموش" }).ClickAsync();
            await Assertions.Expect(ui.Page.Locator("input[name=sms-login-mode][value=off]")).ToBeCheckedAsync();
            await ui.Page.Locator("button[name=sms-login-save]").ClickAsync();
            Assert.Equal("off", await SavedModeAsync(admin, "off"));
            await ui.AssertNoProblemsAsync("sms-console");
        }
        finally
        {
            await SmsSignIn.RestoreAsync(stack, admin);
        }
    }
}
