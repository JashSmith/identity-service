using System.Globalization;
using System.Text;

namespace Identity.Admin.Services;

/// <summary>
/// Persian presentation of numbers and dates: Persian digits and the Solar Hijri (Jalali) calendar in Tehran time.
/// .NET formats with Latin digits even for fa-IR, so digits are mapped explicitly.
/// </summary>
public static class PersianFormat
{
    private static readonly TimeZoneInfo Tehran = FindTehran();
    private static readonly PersianCalendar Calendar = new();

    /// <summary>Replaces Latin digits (and the decimal and group separators) with their Persian forms.</summary>
    public static string Digits(string? text)
    {
        if (string.IsNullOrEmpty(text)) return text ?? "";
        var builder = new StringBuilder(text.Length);
        foreach (var c in text)
            builder.Append(c switch
            {
                >= '0' and <= '9' => (char)('۰' + (c - '0')),
                ',' => '٬',
                _ => c,
            });
        return builder.ToString();
    }

    /// <summary>A whole number with Persian digits and thousands separators, or "—" when unknown.</summary>
    public static string Number(long? value) =>
        value is null ? "—" : Digits(value.Value.ToString("N0", CultureInfo.InvariantCulture));

    /// <summary>Jalali date and time in Tehran, e.g. ۱۴۰۵/۰۸/۱۴ ۱۲:۳۰.</summary>
    public static string DateAndTime(DateTimeOffset? value)
    {
        if (value is null) return "—";
        var local = TimeZoneInfo.ConvertTime(value.Value, Tehran).DateTime;
        return Digits(string.Create(CultureInfo.InvariantCulture,
            $"{Calendar.GetYear(local):0000}/{Calendar.GetMonth(local):00}/{Calendar.GetDayOfMonth(local):00} {local:HH:mm}"));
    }

    /// <summary>Jalali date in Tehran, e.g. ۱۴۰۵/۰۸/۱۴.</summary>
    public static string Date(DateTimeOffset? value) => value is null ? "—" : DateAndTime(value)[..10];

    private static readonly string[] Months =
        ["فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور", "مهر", "آبان", "آذر", "دی", "بهمن", "اسفند"];

    /// <summary>Short Jalali day label, e.g. ۱۴ آبان.</summary>
    public static string DayLabel(DateOnly date)
    {
        var d = date.ToDateTime(TimeOnly.MinValue);
        return Digits(Calendar.GetDayOfMonth(d).ToString(CultureInfo.InvariantCulture)) + " " + Months[Calendar.GetMonth(d) - 1];
    }

    /// <summary>Persian weekday name, e.g. پنجشنبه.</summary>
    public static string Weekday(DateOnly date) => date.DayOfWeek switch
    {
        DayOfWeek.Saturday => "شنبه",
        DayOfWeek.Sunday => "یکشنبه",
        DayOfWeek.Monday => "دوشنبه",
        DayOfWeek.Tuesday => "سه‌شنبه",
        DayOfWeek.Wednesday => "چهارشنبه",
        DayOfWeek.Thursday => "پنجشنبه",
        _ => "جمعه",
    };

    private static TimeZoneInfo FindTehran()
    {
        foreach (var id in new[] { "Asia/Tehran", "Iran Standard Time" })
            if (TimeZoneInfo.TryFindSystemTimeZoneById(id, out var zone)) return zone;
        return TimeZoneInfo.Utc;
    }
}
