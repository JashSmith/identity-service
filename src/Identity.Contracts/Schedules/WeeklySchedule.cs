using System.Globalization;
using System.Text;

namespace Identity.Contracts;

/// <summary>
/// Weekly access window, stored compactly in the <c>access.schedule</c> attribute of the realm, a business role
/// (group), a permission (client role) or a user:
/// <list type="bullet">
/// <item><c>unrestricted</c>: access at any time;</item>
/// <item><c>sat=08:00-16:00;sun=08:00-12:00,14:00-18:00</c>: access only inside the listed ranges; a day that is
/// not listed has no access. Times are in the realm's schedule time zone, ends are exclusive, <c>24:00</c> ends a day.</item>
/// </list>
/// An empty or missing attribute means "inherit" (user &gt; permission &gt; role &gt; realm).
/// </summary>
public sealed class WeeklySchedule : IEquatable<WeeklySchedule>
{
    public const string AttributeName = "access.schedule";
    public const string UnrestrictedText = "unrestricted";

    /// <summary>Keycloak stores group and role attribute values in 255 characters.</summary>
    public const int MaxLength = 255;

    private const int MinutesPerDay = 24 * 60;

    /// <summary>Day keys in the order of the Iranian week.</summary>
    public static readonly IReadOnlyList<(string Key, DayOfWeek Day)> DayKeys =
    [
        ("sat", DayOfWeek.Saturday), ("sun", DayOfWeek.Sunday), ("mon", DayOfWeek.Monday), ("tue", DayOfWeek.Tuesday),
        ("wed", DayOfWeek.Wednesday), ("thu", DayOfWeek.Thursday), ("fri", DayOfWeek.Friday),
    ];

    public static readonly WeeklySchedule Unrestricted = new(true, new Dictionary<DayOfWeek, IReadOnlyList<TimeRange>>());

    private WeeklySchedule(bool unrestricted, IReadOnlyDictionary<DayOfWeek, IReadOnlyList<TimeRange>> days)
    {
        IsUnrestricted = unrestricted;
        Days = days;
    }

    public bool IsUnrestricted { get; }

    /// <summary>Sorted, non-overlapping ranges per day; days without access are absent.</summary>
    public IReadOnlyDictionary<DayOfWeek, IReadOnlyList<TimeRange>> Days { get; }

    /// <summary>True when <paramref name="instant"/> falls inside the schedule in <paramref name="timeZone"/>.</summary>
    public bool Allows(DateTimeOffset instant, TimeZoneInfo timeZone)
    {
        if (IsUnrestricted) return true;
        var local = TimeZoneInfo.ConvertTime(instant, timeZone);
        var minute = local.Hour * 60 + local.Minute;
        return Days.TryGetValue(local.DayOfWeek, out var ranges) && ranges.Any(r => r.StartMinute <= minute && minute < r.EndMinute);
    }

    /// <summary>Access whenever either schedule allows it.</summary>
    public WeeklySchedule Union(WeeklySchedule other)
    {
        if (IsUnrestricted || other.IsUnrestricted) return Unrestricted;
        var days = new Dictionary<DayOfWeek, IReadOnlyList<TimeRange>>();
        foreach (var (_, day) in DayKeys)
        {
            var ranges = Days.GetValueOrDefault(day, []).Concat(other.Days.GetValueOrDefault(day, [])).ToList();
            if (ranges.Count > 0) days[day] = Merge(ranges);
        }
        return new WeeklySchedule(false, days);
    }

    /// <summary>Parses the attribute form. Empty text is not a schedule (it means "inherit").</summary>
    public static bool TryParse(string? text, out WeeklySchedule schedule, out string? error)
    {
        schedule = Unrestricted;
        error = null;
        if (string.IsNullOrWhiteSpace(text)) { error = "A schedule is required."; return false; }
        text = text.Trim();
        if (text.Length > MaxLength) { error = $"A schedule is at most {MaxLength} characters."; return false; }
        if (string.Equals(text, UnrestrictedText, StringComparison.OrdinalIgnoreCase)) return true;

        var days = new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal);
        foreach (var part in text.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0) { error = $"'{part}' is not in the form day=HH:mm-HH:mm."; return false; }
            var key = part[..eq].Trim().ToLowerInvariant();
            if (days.ContainsKey(key)) { error = $"Day '{key}' is listed twice."; return false; }
            days[key] = part[(eq + 1)..].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }
        return TryCreate(false, days, out schedule, out error);
    }

    /// <summary>Builds a schedule from its API form.</summary>
    public static bool TryCreate(bool unrestricted, IReadOnlyDictionary<string, IReadOnlyCollection<string>>? days,
        out WeeklySchedule schedule, out string? error)
    {
        schedule = Unrestricted;
        error = null;
        if (unrestricted) return true;

        var parsed = new Dictionary<DayOfWeek, IReadOnlyList<TimeRange>>();
        foreach (var (key, ranges) in days ?? new Dictionary<string, IReadOnlyCollection<string>>())
        {
            var dayKey = key.Trim().ToLowerInvariant();
            var match = DayKeys.Where(d => d.Key == dayKey).ToArray();
            if (match.Length == 0) { error = $"'{key}' is not a day; use sat, sun, mon, tue, wed, thu or fri."; return false; }

            var list = new List<TimeRange>();
            foreach (var range in ranges ?? [])
            {
                if (!TimeRange.TryParse(range, out var r)) { error = $"'{range}' is not a range HH:mm-HH:mm with start before end."; return false; }
                list.Add(r);
            }
            if (list.Count > 0) parsed[match[0].Day] = Merge(list);
        }
        schedule = new WeeklySchedule(false, parsed);
        if (schedule.ToString().Length > MaxLength) { error = $"A schedule is at most {MaxLength} characters."; return false; }
        return true;
    }

    public WeeklyScheduleDto ToDto() => new(IsUnrestricted,
        DayKeys.Where(d => Days.ContainsKey(d.Day))
            .ToDictionary(d => d.Key, d => (IReadOnlyCollection<string>)Days[d.Day].Select(r => r.ToString()).ToArray()));

    /// <summary>The attribute form; a schedule without any day is "sat=" style empty, rendered as an empty day list.</summary>
    public override string ToString()
    {
        if (IsUnrestricted) return UnrestrictedText;
        var sb = new StringBuilder();
        foreach (var (key, day) in DayKeys)
        {
            if (!Days.TryGetValue(day, out var ranges)) continue;
            if (sb.Length > 0) sb.Append(';');
            sb.Append(key).Append('=').Append(string.Join(',', ranges));
        }
        // No allowed day at all: keep a parseable value that denies everything.
        return sb.Length == 0 ? "sat=" : sb.ToString();
    }

    public bool Equals(WeeklySchedule? other) => other is not null && ToString() == other.ToString();
    public override bool Equals(object? obj) => Equals(obj as WeeklySchedule);
    public override int GetHashCode() => ToString().GetHashCode(StringComparison.Ordinal);

    private static IReadOnlyList<TimeRange> Merge(IEnumerable<TimeRange> ranges)
    {
        var merged = new List<TimeRange>();
        foreach (var r in ranges.OrderBy(r => r.StartMinute))
        {
            if (merged.Count > 0 && r.StartMinute <= merged[^1].EndMinute)
                merged[^1] = merged[^1] with { EndMinute = Math.Max(merged[^1].EndMinute, r.EndMinute) };
            else
                merged.Add(r);
        }
        return merged;
    }

    /// <summary>A time range inside one day, in minutes after midnight; the end is exclusive.</summary>
    public readonly record struct TimeRange(int StartMinute, int EndMinute)
    {
        public static bool TryParse(string? text, out TimeRange range)
        {
            range = default;
            var parts = text?.Split('-', StringSplitOptions.TrimEntries);
            if (parts is not { Length: 2 } || !TryMinute(parts[0], out var start) || !TryMinute(parts[1], out var end) || start >= end)
                return false;
            range = new TimeRange(start, end);
            return true;
        }

        private static bool TryMinute(string text, out int minute)
        {
            minute = 0;
            if (text == "24:00") { minute = MinutesPerDay; return true; }
            if (!TimeOnly.TryParseExact(text, "HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out var time)) return false;
            minute = time.Hour * 60 + time.Minute;
            return true;
        }

        public override string ToString() =>
            $"{Format(StartMinute)}-{Format(EndMinute)}";

        private static string Format(int minute) => $"{minute / 60:00}:{minute % 60:00}";
    }
}

/// <summary>API form of a schedule: <c>{"unrestricted": false, "days": {"sat": ["08:00-16:00"]}}</c>.</summary>
public sealed record WeeklyScheduleDto(bool Unrestricted, IReadOnlyDictionary<string, IReadOnlyCollection<string>>? Days = null);

/// <summary>Where a schedule was found for an entity, or that it inherits.</summary>
public sealed record ScheduleSettingDto(string Target, string? Id, string? Schedule, WeeklyScheduleDto? Value);

/// <summary>
/// A user's resolved schedules, as consumers evaluate them: <see cref="Login"/> applies to everything,
/// <see cref="Permissions"/> lists the permissions whose schedule differs from it (attribute form).
/// </summary>
public sealed record AccessScheduleSnapshot(string TimeZone, string Login, IReadOnlyDictionary<string, string> Permissions)
{
    /// <summary>True when <paramref name="permission"/> (full name) may be used at <paramref name="instant"/>.</summary>
    public bool Allows(string? permission, DateTimeOffset instant)
    {
        var text = permission is not null && Permissions.TryGetValue(permission, out var specific) ? specific : Login;
        // An unreadable snapshot denies: it comes from the gateway, so it is never expected to be invalid.
        if (!WeeklySchedule.TryParse(text, out var schedule, out _)) return false;
        return schedule.Allows(instant, TimeZoneInfo.FindSystemTimeZoneById(TimeZone));
    }
}
