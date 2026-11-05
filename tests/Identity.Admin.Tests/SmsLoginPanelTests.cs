using System.Text.Json;
using Identity.Admin.Services;
using Identity.Admin.Components.Pages.Settings;
using Identity.Contracts;

namespace Identity.Admin.Tests;

/// <summary>The SMS sign-in panel: mode cards, code rules, warnings and saving.</summary>
public sealed class SmsLoginPanelTests : ConsoleTestContext
{
    private IRenderedComponent<SmsLoginPanel> Panel(SmsLoginSettingsDto settings, bool smsEnabled = true, bool canManage = true)
    {
        Gateway.Json("GET api/identity/settings/sms/login", settings);
        return Render<SmsLoginPanel>(p => p.Add(c => c.CanManage, canManage).Add(c => c.SmsEnabled, smsEnabled));
    }

    [Fact]
    public void Off_shows_the_three_modes_without_the_code_rules()
    {
        SignIn(Permissions.SettingsRead, Permissions.SettingsManage);

        var panel = Panel(new SmsLoginSettingsDto(SmsLoginModes.Off));

        panel.WaitForAssertion(() => Assert.Equal(3, panel.FindAll("label.av-mode").Count));
        Assert.Contains("av-mode--selected", panel.FindAll("label.av-mode")[0].ClassName);
        Assert.Empty(panel.FindAll("input[name=sms-login-length]"));
    }

    [Fact]
    public void Second_factor_shows_the_rules_and_warns_about_users_without_a_number()
    {
        SignIn(Permissions.SettingsRead, Permissions.SettingsManage);

        var panel = Panel(new SmsLoginSettingsDto(SmsLoginModes.SecondFactor, CodeLength: 5));

        panel.WaitForAssertion(() => Assert.NotEmpty(panel.FindAll("input[name=sms-login-length]")));
        Assert.Equal("5", panel.Find("input[name=sms-login-length]").GetAttribute("value"));
        Assert.Contains("کاربری که شماره موبایل ندارد نمی‌تواند وارد شود", panel.Markup);
    }

    [Fact]
    public void A_missing_keycloak_extension_or_disabled_sms_is_explained()
    {
        SignIn(Permissions.SettingsRead, Permissions.SettingsManage);
        var withoutExtension = Panel(new SmsLoginSettingsDto(SmsLoginModes.Off, FlowsReady: false));
        withoutExtension.WaitForAssertion(() => Assert.Contains("افزونه ورود پیامکی روی Keycloak نصب نیست", withoutExtension.Markup));

        var withoutSms = Panel(new SmsLoginSettingsDto(SmsLoginModes.Passwordless), smsEnabled: false);
        withoutSms.WaitForAssertion(() => Assert.Contains("اول ارسال پیامک را فعال و ذخیره کنید", withoutSms.Markup));
    }

    [Fact]
    public void Choosing_a_mode_and_saving_sends_it_with_the_rules()
    {
        SignIn(Permissions.SettingsRead, Permissions.SettingsManage);
        Gateway.Json("PUT api/identity/settings/sms/login", new SmsLoginSettingsDto(SmsLoginModes.Passwordless));
        var panel = Panel(new SmsLoginSettingsDto(SmsLoginModes.Off));
        panel.WaitForAssertion(() => Assert.Equal(3, panel.FindAll("input[name=sms-login-mode]").Count));

        panel.FindAll("input[name=sms-login-mode]")[1].Change(SmsLoginModes.Passwordless);
        panel.Find("button[name=sms-login-save]").Click();

        panel.WaitForAssertion(() => Assert.Contains(Gateway.Requests, r => r.Route == "PUT api/identity/settings/sms/login"));
        using var body = JsonDocument.Parse(Gateway.Requests.Single(r => r.Route == "PUT api/identity/settings/sms/login").Body!);
        Assert.Equal("passwordless", body.RootElement.GetProperty("mode").GetString());
        Assert.Equal(120, body.RootElement.GetProperty("codeLifetimeSeconds").GetInt32());
    }

    [Fact]
    public void Readers_see_the_settings_but_cannot_change_them()
    {
        SignIn(Permissions.SettingsRead);

        var panel = Panel(new SmsLoginSettingsDto(SmsLoginModes.Passwordless), canManage: false);

        panel.WaitForAssertion(() => Assert.Equal(3, panel.FindAll("label.av-mode").Count));
        Assert.True(panel.Find("fieldset.av-modes").HasAttribute("disabled"));
        Assert.Empty(panel.FindAll("button[name=sms-login-save]"));
    }
}
