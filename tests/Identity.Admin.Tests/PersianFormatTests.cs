using Identity.Admin.Services;

namespace Identity.Admin.Tests;

public sealed class PersianFormatTests
{
    [Theory]
    [InlineData("0123456789", "۰۱۲۳۴۵۶۷۸۹")]
    [InlineData("1,234", "۱٬۲۳۴")]
    [InlineData("e2e-clerk", "e۲e-clerk")]
    [InlineData("", "")]
    public void Digits_maps_latin_digits_and_group_separators(string input, string expected) =>
        Assert.Equal(expected, PersianFormat.Digits(input));

    [Fact]
    public void Digits_of_null_is_empty() => Assert.Equal("", PersianFormat.Digits(null));

    [Theory]
    [InlineData(0L, "۰")]
    [InlineData(62L, "۶۲")]
    [InlineData(1234567L, "۱٬۲۳۴٬۵۶۷")]
    [InlineData(null, "—")]
    public void Number_uses_persian_digits_and_thousands_separators(long? value, string expected) =>
        Assert.Equal(expected, PersianFormat.Number(value));

    [Fact]
    public void DateAndTime_is_jalali_in_tehran_time()
    {
        // 2026-11-05 08:30 UTC = 12:00 in Tehran (UTC+03:30, no daylight saving since 2022) = 14 Aban 1405.
        var value = new DateTimeOffset(2026, 11, 5, 8, 30, 0, TimeSpan.Zero);

        Assert.Equal("۱۴۰۵/۰۸/۱۴ ۱۲:۰۰", PersianFormat.DateAndTime(value));
        Assert.Equal("۱۴۰۵/۰۸/۱۴", PersianFormat.Date(value));
    }

    [Fact]
    public void Nowruz_starts_the_jalali_year()
    {
        var nowruz = new DateTimeOffset(2026, 3, 21, 12, 0, 0, TimeSpan.Zero);

        Assert.Equal("۱۴۰۵/۰۱/۰۱", PersianFormat.Date(nowruz));
    }

    [Fact]
    public void Missing_dates_show_a_dash()
    {
        Assert.Equal("—", PersianFormat.DateAndTime(null));
        Assert.Equal("—", PersianFormat.Date(null));
    }
}
