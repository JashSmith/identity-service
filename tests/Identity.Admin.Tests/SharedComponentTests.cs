using Identity.Admin.Components.Shared;
using Microsoft.AspNetCore.Components;

namespace Identity.Admin.Tests;

/// <summary>The design-system components: every content state renders something meaningful and accessible.</summary>
public sealed class SharedComponentTests : BunitContext
{
    [Fact]
    public void StatCard_shows_a_skeleton_while_loading()
    {
        var card = Render<StatCard>(p => p.Add(c => c.Label, "کاربران").Add(c => c.Icon, "group"));

        Assert.Equal("true", card.Find("article").GetAttribute("aria-busy"));
        Assert.NotNull(card.Find(".av-skeleton"));
    }

    [Fact]
    public void StatCard_shows_the_value_with_persian_digits()
    {
        var card = Render<StatCard>(p => p.Add(c => c.Label, "کاربران").Add(c => c.Icon, "group").Add(c => c.Value, 1234));

        Assert.Equal("۱٬۲۳۴", card.Find(".av-stat__value").TextContent);
        Assert.Equal("false", card.Find("article").GetAttribute("aria-busy"));
    }

    [Fact]
    public void StatCard_marks_a_value_that_could_not_be_read()
    {
        var card = Render<StatCard>(p => p.Add(c => c.Label, "نقش‌ها").Add(c => c.Icon, "badge").Add(c => c.Failed, true));

        Assert.Equal("—", card.Find(".av-stat__value").TextContent);
        Assert.Contains("ممکن نشد", card.Find(".av-stat__value").GetAttribute("title"));
        Assert.Empty(card.FindAll(".av-skeleton"));
    }

    [Fact]
    public void StatCard_links_to_its_section_with_an_accessible_name()
    {
        var card = Render<StatCard>(p => p.Add(c => c.Label, "نقش‌ها").Add(c => c.Icon, "badge").Add(c => c.Value, 3)
            .Add(c => c.Path, "/roles").Add(c => c.Tone, "secondary"));

        var link = card.Find("a.av-stat__link");
        Assert.Equal("/roles", link.GetAttribute("href"));
        Assert.Equal("مشاهده نقش‌ها", link.GetAttribute("aria-label"));
        Assert.Contains("av-tone-secondary", card.Find("article").ClassName);
    }

    [Fact]
    public void PageHeader_renders_one_focusable_h1_with_actions()
    {
        var header = Render<PageHeader>(p => p.Add(c => c.Title, "کاربران").Add(c => c.Icon, "group")
            .Add(c => c.Description, (RenderFragment)(b => b.AddContent(0, "توضیح")))
            .Add(c => c.Actions, (RenderFragment)(b => b.AddMarkupContent(0, "<button>کاربر جدید</button>"))));

        var h1 = Assert.Single(header.FindAll("h1"));
        Assert.Contains("کاربران", h1.TextContent);
        Assert.Equal("-1", h1.GetAttribute("tabindex"));
        Assert.Equal("کاربر جدید", header.Find(".av-page-header__actions button").TextContent);
        Assert.Equal("توضیح", header.Find(".av-page-header__description").TextContent);
    }

    [Fact]
    public void EmptyState_explains_and_offers_the_next_step()
    {
        var empty = Render<EmptyState>(p => p.Add(c => c.Title, "کاربری یافت نشد")
            .Add(c => c.ChildContent, (RenderFragment)(b => b.AddContent(0, "جستجو را تغییر دهید.")))
            .Add(c => c.Action, (RenderFragment)(b => b.AddMarkupContent(0, "<a href=\"/users\">همه کاربران</a>"))));

        Assert.Equal("status", empty.Find(".av-empty").GetAttribute("role"));
        Assert.Equal("کاربری یافت نشد", empty.Find(".av-empty__title").TextContent);
        Assert.Equal("/users", empty.Find(".av-empty__action a").GetAttribute("href"));
    }

    [Fact]
    public void ThemeSwitch_offers_light_system_and_dark_with_labels()
    {
        var themeSwitch = Render<ThemeSwitch>();

        var options = themeSwitch.FindAll("button[data-theme-option]");
        Assert.Equal(["light", "system", "dark"], options.Select(o => o.GetAttribute("data-theme-option")));
        Assert.All(options, o =>
        {
            Assert.Equal("button", o.GetAttribute("type"));
            Assert.False(string.IsNullOrWhiteSpace(o.GetAttribute("aria-label")));
        });
    }

    [Fact]
    public void Girih_is_decorative_and_uses_a_unique_pattern_id()
    {
        var first = Render<Girih>();
        var second = Render<Girih>();

        Assert.Equal("true", first.Find("svg").GetAttribute("aria-hidden"));
        Assert.NotEqual(first.Find("pattern").Id, second.Find("pattern").Id);
    }
}
