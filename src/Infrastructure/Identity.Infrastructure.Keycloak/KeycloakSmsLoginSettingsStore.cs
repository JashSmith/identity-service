using System.Globalization;
using System.Text.Json;
using Identity.Application;
using Identity.Application.Sms;
using Identity.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// SMS sign-in settings as realm attributes <c>iam.smslogin.*</c>, which Keycloak's Avash SMS authenticators read.
/// Keycloak replaces the whole attribute map on a realm update, so every write reads, merges and writes the full map.
/// The prefix is deliberately not <c>iam.sms.</c> (the SMS provider settings own that namespace).
/// </summary>
public sealed class KeycloakSmsLoginSettingsStore(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakSmsLoginSettingsStore>? logger = null) : ISmsLoginSettingsStore
{
    public const string Prefix = "iam.smslogin.";
    private const string Resource = "sms_login";

    private readonly KeycloakAdminApi _api = new(http, opts.Value, tokenProvider, (ILogger?)logger ?? NullLogger.Instance);

    public async Task<Result<SmsLoginSettingsDto>> GetAsync(CancellationToken ct)
    {
        var attributes = await AttributesAsync(ct);
        return attributes.IsSuccess ? Parse(attributes.Value) : attributes.Error!;
    }

    public async Task<Result> SaveAsync(SmsLoginSettingsDto settings, CancellationToken ct)
    {
        var attributes = await AttributesAsync(ct);
        if (!attributes.IsSuccess) return attributes.Error!;
        var next = attributes.Value.Where(kv => !kv.Key.StartsWith(Prefix, StringComparison.Ordinal))
            .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);
        foreach (var (key, value) in ToAttributes(settings)) next[key] = value;
        return await _api.SendWithoutResultAsync(HttpMethod.Put, "", new { attributes = next }, Resource, ct);
    }

    private async Task<Result<Dictionary<string, string>>> AttributesAsync(CancellationToken ct)
    {
        var realm = await _api.GetAsync("", Resource, ct);
        if (!realm.IsSuccess) return realm.Error!;
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (realm.Value.TryGetProperty("attributes", out var attributes) && attributes.ValueKind == JsonValueKind.Object)
            foreach (var p in attributes.EnumerateObject())
                if (p.Value.ValueKind == JsonValueKind.String) result[p.Name] = p.Value.GetString()!;
        return result;
    }

    /// <summary>Pure mapping attributes -> settings; unknown or out-of-range values fall back to the defaults.</summary>
    public static SmsLoginSettingsDto Parse(IReadOnlyDictionary<string, string> attributes)
    {
        var defaults = new SmsLoginSettingsDto(SmsLoginModes.Off);
        var mode = attributes.GetValueOrDefault(Prefix + "mode");
        return new SmsLoginSettingsDto(
            SmsLoginModes.All.Contains(mode) ? mode! : SmsLoginModes.Off,
            Number(attributes, "code_length", 4, 8, defaults.CodeLength),
            Number(attributes, "ttl_seconds", 60, 600, defaults.CodeLifetimeSeconds),
            Number(attributes, "resend_seconds", 30, 300, defaults.ResendSeconds),
            Number(attributes, "max_attempts", 1, 10, defaults.MaxAttempts));
    }

    /// <summary>Pure mapping settings -> attributes (the names Keycloak's authenticators read).</summary>
    public static IEnumerable<KeyValuePair<string, string>> ToAttributes(SmsLoginSettingsDto settings)
    {
        yield return new(Prefix + "mode", settings.Mode);
        yield return new(Prefix + "code_length", settings.CodeLength.ToString(CultureInfo.InvariantCulture));
        yield return new(Prefix + "ttl_seconds", settings.CodeLifetimeSeconds.ToString(CultureInfo.InvariantCulture));
        yield return new(Prefix + "resend_seconds", settings.ResendSeconds.ToString(CultureInfo.InvariantCulture));
        yield return new(Prefix + "max_attempts", settings.MaxAttempts.ToString(CultureInfo.InvariantCulture));
    }

    private static int Number(IReadOnlyDictionary<string, string> attributes, string key, int min, int max, int fallback) =>
        int.TryParse(attributes.GetValueOrDefault(Prefix + key), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) && n >= min && n <= max
            ? n
            : fallback;
}
