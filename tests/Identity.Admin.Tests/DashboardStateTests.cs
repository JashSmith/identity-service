using System.Net;
using Identity.Admin.Components.Pages;
using Identity.Admin.Services;
using Identity.Contracts;

namespace Identity.Admin.Tests;

/// <summary>The dashboard in every content state: success, loading, partial, error, empty and permission.</summary>
public sealed class DashboardStateTests : ConsoleTestContext
{
    private static readonly DateOnly Today = new(2026, 11, 5);

    private static AuditSummaryDto Summary(bool loginEvents = true, bool adminEvents = true) => new(
        Today.AddDays(-6), Today, loginEvents, adminEvents, 12, 3, 1,
        Enumerable.Range(0, 7).Select(i => new DailyLoginCountDto(Today.AddDays(i - 6), i == 6 ? 12 : 0, i == 6 ? 3 : 0)).ToArray(),
        [new ApplicationLoginCountDto("crm", 9), new ApplicationLoginCountDto("hr", 3)],
        [new AdminEventDto(DateTimeOffset.Parse("2026-11-05T08:30:00Z"), "DELETE", "GROUP", "groups/g-1", "u", "c", null, null)],
        false);

    private void HealthyGateway(AuditSummaryDto? summary = null)
    {
        Gateway.Json("GET api/identity/users?pageSize=1", new PagedResponse<UserDto>([], 1, 1, 62))
            .Json("GET api/identity/business-roles", new[] { new BusinessRoleDto("clerk", null, true, []) })
            .Json("GET api/identity/applications", Array.Empty<ApplicationDto>())
            .Json("GET api/identity/permissions", Array.Empty<CatalogPermissionDto>())
            .Json("GET api/identity/audit/summary?days=7", summary ?? Summary());
    }

    private static string[] Values(IRenderedComponent<Home> home) =>
        home.FindAll(".av-stat__value").Select(v => v.TextContent.Trim()).ToArray();

    [Fact]
    public void Success_shows_every_figure_the_trend_the_top_applications_and_recent_changes()
    {
        SignIn(AllRead);
        HealthyGateway();

        var home = Render<Home>();

        home.WaitForAssertion(() => Assert.Equal(["۶۲", "۱", "۰", "۰", "۱۲", "۳"], Values(home)));
        Assert.Equal(7, home.FindAll("g.av-chart__day").Count);
        Assert.Equal(["crm", "hr"], home.FindAll(".av-rank__name").Select(n => n.TextContent));
        Assert.Contains("حذف", home.Find(".av-feed__op").TextContent);
        Assert.Contains("نقش", home.Find(".av-feed__what").TextContent);
    }

    [Fact]
    public void Loading_shows_skeletons_until_the_gateway_answers()
    {
        SignIn(Permissions.UsersRead);
        var gate = Gateway.Hold("GET api/identity/users?pageSize=1", new PagedResponse<UserDto>([], 1, 1, 5));

        var home = Render<Home>();

        home.WaitForAssertion(() => Assert.Equal("true", home.Find("article.av-stat").GetAttribute("aria-busy")));
        Assert.NotNull(home.Find(".av-skeleton"));
        gate.SetResult();
        home.WaitForAssertion(() => Assert.Equal(["۵"], Values(home)));
    }

    [Fact]
    public void Partial_a_failing_section_shows_a_dash_and_the_others_still_load()
    {
        SignIn(AllRead);
        HealthyGateway();
        Gateway.Problem("GET api/identity/business-roles", HttpStatusCode.ServiceUnavailable);

        var home = Render<Home>();

        home.WaitForAssertion(() => Assert.Equal(["۶۲", "—", "۰", "۰", "۱۲", "۳"], Values(home)));
        Assert.Equal(7, home.FindAll("g.av-chart__day").Count);
    }

    [Fact]
    public void Error_when_events_cannot_be_read_offers_a_retry_that_recovers()
    {
        SignIn(Permissions.AuditRead);
        Gateway.Problem("GET api/identity/audit/summary?days=7", HttpStatusCode.ServiceUnavailable);

        var home = Render<Home>();

        home.WaitForAssertion(() => Assert.Contains("رویدادها خوانده نشد", home.Markup));
        Gateway.Json("GET api/identity/audit/summary?days=7", Summary());
        home.Find(".av-empty__action button").Click();
        home.WaitForAssertion(() => Assert.Equal(7, home.FindAll("g.av-chart__day").Count));
    }

    [Fact]
    public void Empty_when_login_events_are_off_explains_and_links_settings_for_managers_only()
    {
        SignIn(Permissions.AuditRead, Permissions.SettingsManage);
        Gateway.Json("GET api/identity/audit/summary?days=7", Summary(loginEvents: false, adminEvents: false));

        var manager = Render<Home>();

        manager.WaitForAssertion(() => Assert.Contains("ثبت رویدادهای ورود خاموش است", manager.Markup));
        Assert.Contains("روشن کردن در تنظیمات", manager.Find(".av-empty__action").TextContent);
        Assert.Contains("ثبت رویدادهای مدیریتی خاموش است", manager.Markup);
    }

    [Fact]
    public void Empty_for_an_auditor_without_settings_rights_asks_the_administrator()
    {
        SignIn(Permissions.AuditRead);
        Gateway.Json("GET api/identity/audit/summary?days=7", Summary(loginEvents: false));

        var auditor = Render<Home>();

        auditor.WaitForAssertion(() => Assert.Contains("از مدیر سامانه بخواهید", auditor.Markup));
        Assert.Empty(auditor.FindAll(".av-empty__action button"));
    }

    [Fact]
    public void Permission_an_administrator_without_read_rights_sees_why_and_no_gateway_call_is_made()
    {
        SignIn();

        var home = Render<Home>();

        home.WaitForAssertion(() => Assert.Contains("بخشی برای نمایش ندارید", home.Markup));
        Assert.Empty(Gateway.Requests);
        Assert.Empty(home.FindAll(".av-page-header__actions button"));
    }

    [Fact]
    public void Quick_actions_follow_the_manage_permissions()
    {
        SignIn(Permissions.UsersRead, Permissions.UsersManage);
        Gateway.Json("GET api/identity/users?pageSize=1", new PagedResponse<UserDto>([], 1, 1, 1));

        var home = Render<Home>();

        home.WaitForAssertion(() => Assert.Equal(["کاربر جدید"],
            home.FindAll(".av-page-header__actions .rz-button-text").Select(b => b.TextContent.Trim())));
    }
}
