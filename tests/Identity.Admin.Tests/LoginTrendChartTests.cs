using System.Globalization;
using Identity.Admin.Components.Shared;
using Identity.Admin.Services;
using Identity.Contracts;

namespace Identity.Admin.Tests;

/// <summary>The dashboard's login chart: stacked segments, RTL day order, accessible names and the table view.</summary>
public sealed class LoginTrendChartTests : BunitContext
{
    private static readonly DateOnly Monday = new(2026, 11, 2);

    private IRenderedComponent<LoginTrendChart> Render(params (int Ok, int Failed)[] days) =>
        Render<LoginTrendChart>(p => p.Add(c => c.Days,
            days.Select((d, i) => new DailyLoginCountDto(Monday.AddDays(i), d.Ok, d.Failed)).ToArray()));

    [Fact]
    public void Each_day_has_a_success_and_a_failure_segment_only_when_it_has_counts()
    {
        var chart = Render((5, 1), (3, 0), (0, 2), (0, 0));

        var days = chart.FindAll("g.av-chart__day");
        Assert.Equal(4, days.Count);
        Assert.Equal([1, 1, 0, 0], days.Select(d => d.QuerySelectorAll(".av-chart__ok").Length));
        Assert.Equal([1, 0, 1, 0], days.Select(d => d.QuerySelectorAll(".av-chart__failed").Length));
    }

    [Fact]
    public void Days_run_right_to_left_so_the_oldest_day_is_at_the_right_edge()
    {
        var chart = Render((1, 0), (1, 0), (1, 0));

        var xs = chart.FindAll("g.av-chart__day text").Select(t => double.Parse(t.GetAttribute("x")!, CultureInfo.InvariantCulture)).ToArray();
        Assert.True(xs[0] > xs[1] && xs[1] > xs[2]);
    }

    [Fact]
    public void Every_day_is_reachable_by_keyboard_and_named_in_persian()
    {
        var chart = Render((12, 3));

        var day = chart.Find("g.av-chart__day");
        Assert.Equal("0", day.GetAttribute("tabindex"));
        Assert.Equal("دوشنبه ۱۱ آبان: ۱۲ ورود موفق، ۳ ناموفق", day.GetAttribute("aria-label"));
        Assert.Contains("۱۵ ناموفق", Render((10, 5), (0, 10)).Find("svg").GetAttribute("aria-label"));
    }

    [Fact]
    public void Legend_names_both_series_and_the_table_view_has_one_row_per_day()
    {
        var chart = Render((4, 1), (2, 2));

        Assert.Equal(["موفق", "ناموفق"], chart.FindAll(".av-chart__key").Select(k => k.TextContent.Trim()));
        var rows = chart.FindAll(".av-chart__table tbody tr");
        Assert.Equal(2, rows.Count);
        Assert.Equal(["۴", "۱"], rows[0].QuerySelectorAll("td").Select(td => td.TextContent));
    }

    [Fact]
    public void Axis_ticks_are_round_numbers_from_zero_that_cover_the_tallest_day()
    {
        var chart = Render((40, 7), (12, 0));

        var ticks = chart.FindAll(".av-chart__tick").Select(t => t.TextContent).ToArray();
        Assert.Equal("۰", ticks[0]);
        Assert.Equal(["۰", "۲۰", "۴۰", "۶۰"], ticks);
    }

    [Fact]
    public void Empty_week_still_renders_a_baseline_without_bars()
    {
        var chart = Render((0, 0), (0, 0));

        Assert.Empty(chart.FindAll(".av-chart__ok, .av-chart__failed"));
        Assert.NotNull(chart.Find(".av-chart__axis"));
    }

    [Theory]
    [InlineData(2026, 11, 5, "۱۴ آبان", "پنجشنبه")]
    [InlineData(2026, 3, 21, "۱ فروردین", "شنبه")]
    public void Day_labels_are_jalali(int y, int m, int d, string label, string weekday)
    {
        var date = new DateOnly(y, m, d);

        Assert.Equal(label, PersianFormat.DayLabel(date));
        Assert.Equal(weekday, PersianFormat.Weekday(date));
    }
}
