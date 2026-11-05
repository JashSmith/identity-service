using Identity.Admin.Auth;
using Identity.Admin.Components.Layout;
using Identity.Admin.Services;

namespace Identity.Admin.Tests;

/// <summary>The menu shows a section only to administrators holding its read permission (permission state).</summary>
public sealed class NavMenuTests : BunitContext
{
    private IRenderedComponent<NavMenu> RenderAs(params string[] permissions)
    {
        var auth = AddAuthorization();
        auth.SetAuthorized("admin");
        auth.SetClaims(permissions.Select(p => new System.Security.Claims.Claim(ConsoleClaims.Permission, p)).ToArray());
        return Render<NavMenu>();
    }

    private static string[] Links(IRenderedComponent<NavMenu> menu) =>
        menu.FindAll("a.av-nav__link").Select(a => a.GetAttribute("href")!).ToArray();

    [Fact]
    public void Administrator_without_permissions_sees_only_the_dashboard()
    {
        var menu = RenderAs();

        Assert.Equal(["/"], Links(menu));
        Assert.Empty(menu.FindAll(".av-nav__title"));
    }

    [Fact]
    public void Each_read_permission_reveals_its_section_and_group()
    {
        var menu = RenderAs(Permissions.UsersRead, Permissions.SettingsRead);

        Assert.Equal(["/", "/users", "/settings"], Links(menu));
        Assert.Equal(["هویت و دسترسی", "سیاست‌ها"], menu.FindAll(".av-nav__title").Select(t => t.TextContent));
    }

    [Fact]
    public void Super_admin_sees_every_section()
    {
        var menu = RenderAs(Permissions.UsersRead, Permissions.RolesRead, Permissions.ScopesRead, Permissions.ApplicationsRead,
            Permissions.SchedulesRead, Permissions.SettingsRead, Permissions.SystemRead);

        Assert.Equal(["/", "/users", "/roles", "/scopes", "/applications", "/schedules", "/settings", "/tenants"], Links(menu));
        Assert.NotNull(menu.Find("nav[aria-label]"));
    }

    [Fact]
    public void Anonymous_visitor_sees_no_menu()
    {
        AddAuthorization();

        var menu = Render<NavMenu>();

        Assert.Empty(menu.FindAll("nav"));
    }
}
