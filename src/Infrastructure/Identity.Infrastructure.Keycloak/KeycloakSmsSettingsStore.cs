using System.Text.Json;
using Identity.Application;
using Identity.Application.Sms;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// SMS settings as attributes of the tenant realm: <c>iam.sms.enabled</c>, <c>iam.sms.provider</c> and
/// <c>iam.sms.&lt;provider&gt;.&lt;field&gt;</c>. Keycloak 26.4 replaces the whole attribute map on a realm update
/// (verified), so every write reads the current map, swaps the iam.sms.* entries and writes the full map back.
/// Like identity-provider secrets, the values are readable by realm administrators in Keycloak itself.
/// </summary>
public sealed class KeycloakSmsSettingsStore(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakSmsSettingsStore>? logger = null) : ISmsSettingsStore
{
    public const string Prefix = "iam.sms.";
    private const string EnabledKey = Prefix + "enabled";
    private const string ProviderKey = Prefix + "provider";
    private const string Resource = "sms";

    private readonly KeycloakAdminApi _api = new(http, opts.Value, tokenProvider, (ILogger?)logger ?? NullLogger.Instance);

    public async Task<Result<StoredSmsSettings>> GetAsync(CancellationToken ct)
    {
        var attributes = await AttributesAsync(ct);
        return attributes.IsSuccess ? Parse(attributes.Value) : attributes.Error!;
    }

    public async Task<Result> SaveAsync(StoredSmsSettings settings, CancellationToken ct)
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

    /// <summary>Pure mapping attributes -> settings (public for tests).</summary>
    public static StoredSmsSettings Parse(IReadOnlyDictionary<string, string> attributes)
    {
        var providers = new Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal);
        foreach (var (key, value) in attributes)
        {
            if (!key.StartsWith(Prefix, StringComparison.Ordinal) || key is EnabledKey or ProviderKey || value.Length == 0) continue;
            var rest = key[Prefix.Length..];
            var dot = rest.IndexOf('.');
            if (dot <= 0 || dot == rest.Length - 1) continue;
            var provider = rest[..dot];
            if (!providers.TryGetValue(provider, out var fields)) providers[provider] = fields = new(StringComparer.Ordinal);
            fields[rest[(dot + 1)..]] = value;
        }
        return new StoredSmsSettings(
            attributes.GetValueOrDefault(EnabledKey) == "true",
            attributes.GetValueOrDefault(ProviderKey) is { Length: > 0 } p ? p : null,
            providers.ToDictionary(kv => kv.Key, kv => (IReadOnlyDictionary<string, string>)kv.Value, StringComparer.Ordinal));
    }

    /// <summary>Pure mapping settings -> attributes (public for tests).</summary>
    public static IEnumerable<KeyValuePair<string, string>> ToAttributes(StoredSmsSettings settings)
    {
        yield return new(EnabledKey, settings.Enabled ? "true" : "false");
        if (settings.Provider is not null) yield return new(ProviderKey, settings.Provider);
        foreach (var (provider, fields) in settings.Settings)
            foreach (var (field, value) in fields)
                if (value.Length > 0) yield return new($"{Prefix}{provider}.{field}", value);
    }
}
