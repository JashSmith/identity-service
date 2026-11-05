using System.Text;
using Identity.Contracts;

namespace Identity.Application.Sms;

/// <summary>A text message to one mobile number (normalised to +98... by <see cref="PhoneNumbers"/>) for one tenant.</summary>
public sealed record SmsMessage(string To, string Text, string Tenant);

/// <summary>Messages the development provider recorded instead of sending, per tenant (never shared across tenants).</summary>
public interface ISmsOutbox
{
    IReadOnlyList<SmsOutboxItemDto> Recent(string tenant, int max);
}

/// <summary>What the provider answered. <see cref="Error"/> is a short, secret-free explanation.</summary>
public sealed record SmsSendResult(bool Accepted, string? MessageId = null, string? Error = null)
{
    public static SmsSendResult Failed(string error) => new(false, null, error);
}

/// <summary>
/// An SMS provider. Add one by implementing this interface and registering it with
/// <c>services.AddSmsProvider&lt;T&gt;()</c>; the console then offers it and builds its settings form from
/// <see cref="Fields"/>. Implementations must never log or return secret settings (API keys are often in URLs).
/// </summary>
public interface ISmsProvider
{
    /// <summary>Stable lower-case id stored in the tenant's settings, e.g. "kavenegar".</summary>
    string Id { get; }

    string DisplayName { get; }
    string Description { get; }

    /// <summary>False only for providers that record instead of sending (development).</summary>
    bool SendsMessages { get; }

    IReadOnlyList<SmsFieldDto> Fields { get; }

    Task<SmsSendResult> SendAsync(SmsMessage message, IReadOnlyDictionary<string, string> settings, CancellationToken ct);
}

/// <summary>The tenant's stored SMS settings (secrets in clear text; never returned as is).</summary>
public sealed record StoredSmsSettings(
    bool Enabled,
    string? Provider,
    IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> Settings)
{
    public static readonly StoredSmsSettings Empty = new(false, null, new Dictionary<string, IReadOnlyDictionary<string, string>>());
}

/// <summary>Where the tenant's SMS settings live (Keycloak realm attributes). Errors: Keycloak availability errors.</summary>
public interface ISmsSettingsStore
{
    Task<Result<StoredSmsSettings>> GetAsync(CancellationToken ct);
    Task<Result> SaveAsync(StoredSmsSettings settings, CancellationToken ct);
}

/// <summary>Iranian mobile numbers in any common spelling (09.., 989.., +989.., 00989.., Persian or Arabic digits).</summary>
public static class PhoneNumbers
{
    /// <summary>Returns +989XXXXXXXXX, or null when the text is not an Iranian mobile number.</summary>
    public static string? NormalizeIranMobile(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var digits = new StringBuilder();
        foreach (var c in text.Trim())
        {
            if (c is >= '0' and <= '9') digits.Append(c);
            else if (c is >= '۰' and <= '۹') digits.Append((char)('0' + (c - '۰')));
            else if (c is >= '٠' and <= '٩') digits.Append((char)('0' + (c - '٠')));
            else if (c is ' ' or '-' or '(' or ')' or '+') continue;
            else return null;
        }
        var d = digits.ToString();
        if (d.StartsWith("0098", StringComparison.Ordinal)) d = d[4..];
        else if (d.StartsWith("98", StringComparison.Ordinal) && d.Length == 12) d = d[2..];
        else if (d.StartsWith('0')) d = d[1..];
        return d.Length == 10 && d[0] == '9' ? "+98" + d : null;
    }

    /// <summary>+98912***4567: enough to recognise, not enough to collect.</summary>
    public static string Mask(string normalized) =>
        normalized.Length < 10 ? "***" : normalized[..6] + "***" + normalized[^4..];
}
