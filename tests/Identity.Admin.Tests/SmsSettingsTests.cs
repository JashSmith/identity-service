using System.Net;
using System.Text.Json;
using Identity.Admin.Components.Pages.Settings;
using Identity.Admin.Services;
using Identity.Contracts;

namespace Identity.Admin.Tests;

/// <summary>The SMS settings tab: provider cards, a form built from the provider's fields, secrets, test and outbox.</summary>
public sealed class SmsSettingsTests : ConsoleTestContext
{
    private static readonly SmsProviderDto Kavenegar = new("kavenegar", "کاوه‌نگار", "سرویس کاوه‌نگار", true,
    [
        new SmsFieldDto("apiKey", "کلید API", "secret", true),
        new SmsFieldDto("sender", "شماره فرستنده", "phone", false, "10004346", "خالی یعنی شماره پیش‌فرض"),
    ]);

    private static readonly SmsProviderDto Development = new("development", "حالت آزمایشی (بدون ارسال)", "بدون ارسال", false, []);

    private void SmsGateway(bool enabled = true, string provider = "kavenegar")
    {
        Gateway.Json("GET api/identity/settings/sms/providers", new[] { Kavenegar, Development })
            .Json("GET api/identity/settings/sms", new SmsSettingsDto(enabled, provider,
                new Dictionary<string, IReadOnlyDictionary<string, string>>
                {
                    ["kavenegar"] = new Dictionary<string, string> { ["apiKey"] = "**********", ["sender"] = "10004346" },
                }))
            .Json("GET api/identity/settings/sms/outbox", Array.Empty<SmsOutboxItemDto>());
    }

    private IRenderedComponent<SmsSettings> Tab(bool canManage = true) => Render<SmsSettings>(p => p.Add(c => c.CanManage, canManage));

    [Fact]
    public void The_form_is_built_from_the_selected_providers_fields_and_hides_stored_secrets()
    {
        SignIn(Permissions.SettingsRead, Permissions.SettingsManage);
        SmsGateway();

        var tab = Tab();

        tab.WaitForAssertion(() => Assert.Equal(2, tab.FindAll("label.av-mode").Count));
        Assert.Contains("av-mode--selected", tab.FindAll("label.av-mode")[0].ClassName);
        var secret = tab.Find("input[type=password]");
        Assert.Equal("", secret.GetAttribute("value") ?? "");
        Assert.Contains("کلید ذخیره شده است", tab.Markup);
        Assert.Equal("10004346", tab.Find("input[name=sms-sender]").GetAttribute("value"));
        Assert.Contains("خالی یعنی شماره پیش‌فرض (نمونه: 10004346)", tab.Markup);
    }

    [Fact]
    public void Saving_sends_the_mask_back_for_an_untouched_secret()
    {
        SignIn(Permissions.SettingsRead, Permissions.SettingsManage);
        SmsGateway();
        Gateway.Json("PUT api/identity/settings/sms", new SmsSettingsDto(true, "kavenegar", new Dictionary<string, IReadOnlyDictionary<string, string>>()));
        var tab = Tab();
        tab.WaitForAssertion(() => Assert.NotEmpty(tab.FindAll("input[type=password]")));

        tab.FindAll("button").First(b => b.TextContent.Contains("ذخیره")).Click();

        tab.WaitForAssertion(() => Assert.Contains(Gateway.Requests, r => r.Route == "PUT api/identity/settings/sms"));
        using var body = JsonDocument.Parse(Gateway.Requests.Single(r => r.Route == "PUT api/identity/settings/sms").Body!);
        Assert.Equal("**********", body.RootElement.GetProperty("settings").GetProperty("kavenegar").GetProperty("apiKey").GetString());
        Assert.True(body.RootElement.GetProperty("enabled").GetBoolean());
    }

    [Fact]
    public void The_development_provider_warns_that_nothing_is_sent()
    {
        SignIn(Permissions.SettingsRead, Permissions.SettingsManage);
        SmsGateway(provider: "development");

        var tab = Tab();

        tab.WaitForAssertion(() => Assert.Contains("هیچ پیامکی ارسال نمی‌شود", tab.Markup));
        Assert.Empty(tab.FindAll("input[type=password]"));
    }

    [Fact]
    public void A_test_message_shows_the_result_and_the_outbox()
    {
        SignIn(Permissions.SettingsRead, Permissions.SettingsManage);
        SmsGateway(provider: "development");
        Gateway.Json("POST api/identity/settings/sms/test", new SmsTestResultDto("development", false, "dev-1", "+98912***4567"));
        var tab = Tab();
        tab.WaitForAssertion(() => Assert.NotEmpty(tab.FindAll("input[name=sms-test-number]")));
        tab.Find("input[name=sms-test-number]").Change("09121234567");
        Gateway.Json("GET api/identity/settings/sms/outbox", new[] { new SmsOutboxItemDto(DateTimeOffset.UtcNow, "+98912***4567", "پیام آزمایشی") });

        tab.FindAll("button").First(b => b.TextContent.Contains("ارسال آزمایشی")).Click();

        tab.WaitForAssertion(() => Assert.Contains("پیام در حالت آزمایشی ثبت شد", tab.Markup));
        Assert.Contains("پیام آزمایشی", tab.Find(".av-feed").TextContent);
    }

    [Fact]
    public void Testing_needs_sms_to_be_enabled_first()
    {
        SignIn(Permissions.SettingsRead, Permissions.SettingsManage);
        SmsGateway(enabled: false);

        var tab = Tab();

        tab.WaitForAssertion(() => Assert.Contains("پیامک را فعال و ذخیره کنید", tab.Markup));
    }

    [Fact]
    public void Readers_see_the_settings_but_cannot_change_or_test()
    {
        SignIn(Permissions.SettingsRead);
        SmsGateway();

        var tab = Tab(canManage: false);

        tab.WaitForAssertion(() => Assert.True(tab.Find("fieldset.av-modes").HasAttribute("disabled")));
        Assert.DoesNotContain("ارسال آزمایشی", tab.Markup);
        Assert.DoesNotContain(Gateway.Requests, r => r.Route.Contains("outbox", StringComparison.Ordinal));
    }

    [Fact]
    public void A_gateway_failure_offers_a_retry()
    {
        SignIn(Permissions.SettingsRead);
        Gateway.Problem("GET api/identity/settings/sms/providers", HttpStatusCode.ServiceUnavailable);

        var tab = Tab(canManage: false);

        tab.WaitForAssertion(() => Assert.Contains("تنظیمات پیامک خوانده نشد", tab.Markup));
    }
}
