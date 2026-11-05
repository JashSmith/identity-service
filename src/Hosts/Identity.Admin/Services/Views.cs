namespace Identity.Admin.Services;

/// <summary>Gateway responses whose types live in server-side assemblies the console does not reference.</summary>
public sealed record ScopeDefinitionView(string Key, string DisplayName, string? Description, bool IsActive, string ValueType, string? Parent);

public sealed record TenantView(string Id, string? DisplayName, string Realm, bool IsDefault);

/// <summary>Persian labels for the schedule days (Saturday first, as the Iranian week).</summary>
public static class Days
{
    public static readonly IReadOnlyList<(string Key, string Name)> All =
    [
        ("sat", "شنبه"), ("sun", "یکشنبه"), ("mon", "دوشنبه"), ("tue", "سه‌شنبه"),
        ("wed", "چهارشنبه"), ("thu", "پنجشنبه"), ("fri", "جمعه"),
    ];
}
