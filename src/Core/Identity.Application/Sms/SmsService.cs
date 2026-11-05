using FluentValidation;
using Identity.Contracts;

namespace Identity.Application.Sms;

/// <summary>
/// SMS settings and sending for the tenant: lists providers, validates and stores settings (keeping masked secrets),
/// and sends through the selected provider. Errors: sms.* or a Keycloak availability error.
/// Future features (SMS login, OTP, notifications) call <see cref="SendAsync"/>; they never talk to a provider directly.
/// </summary>
public sealed class SmsService(IEnumerable<ISmsProvider> providers, ISmsSettingsStore store, ITenantContext tenant, ISmsOutbox? outbox = null,
    ISmsLoginSettingsStore? loginSettings = null)
{
    public const string Mask = "**********";
    public const string TestText = "پیام آزمایشی درگاه هویت آواش: تنظیمات پیامک درست است.";

    private readonly IReadOnlyDictionary<string, ISmsProvider> _providers =
        providers.ToDictionary(p => p.Id, StringComparer.Ordinal);

    public IReadOnlyList<SmsProviderDto> ListProviders() =>
        _providers.Values.OrderBy(p => p.SendsMessages ? 0 : 1).ThenBy(p => p.DisplayName, StringComparer.Ordinal)
            .Select(p => new SmsProviderDto(p.Id, p.DisplayName, p.Description, p.SendsMessages, p.Fields)).ToArray();

    public async Task<Result<SmsSettingsDto>> GetSettingsAsync(CancellationToken ct)
    {
        var stored = await store.GetAsync(ct);
        return stored.IsSuccess ? Masked(stored.Value) : stored.Error!;
    }

    public async Task<Result<SmsSettingsDto>> SaveSettingsAsync(SmsSettingsDto request, CancellationToken ct)
    {
        var stored = await store.GetAsync(ct);
        if (!stored.IsSuccess) return stored.Error!;

        var merged = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.Ordinal);
        foreach (var (providerId, values) in stored.Value.Settings)
            if (_providers.ContainsKey(providerId)) merged[providerId] = values;
        var fieldErrors = new Dictionary<string, string[]>(StringComparer.Ordinal);

        foreach (var (providerId, values) in request.Settings)
        {
            if (!_providers.TryGetValue(providerId, out var provider))
                return Error.Validation("sms.unknown_provider", $"SMS provider '{providerId}' is not installed.");
            var previous = merged.GetValueOrDefault(providerId) ?? new Dictionary<string, string>();
            var next = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var field in provider.Fields)
            {
                var value = values.TryGetValue(field.Key, out var v) ? v?.Trim() ?? "" : "";
                // The console sends the mask back for a secret it was never shown: keep the stored value.
                if (field.Kind == "secret" && value == Mask) value = previous.GetValueOrDefault(field.Key, "");
                if (FieldError(field, value) is { } error) fieldErrors[$"Settings.{providerId}.{field.Key}"] = [error];
                if (value.Length > 0) next[field.Key] = value;
            }
            merged[providerId] = next;
        }

        if (request.Provider is not null && !_providers.ContainsKey(request.Provider))
            return Error.Validation("sms.unknown_provider", $"SMS provider '{request.Provider}' is not installed.");
        if (request.Enabled)
        {
            if (request.Provider is null)
                return Error.Validation("sms.provider_required", "Choose an SMS provider before enabling SMS.");
            var values = merged.GetValueOrDefault(request.Provider) ?? new Dictionary<string, string>();
            foreach (var field in _providers[request.Provider].Fields.Where(f => f.Required && !values.ContainsKey(f.Key)))
                fieldErrors[$"Settings.{request.Provider}.{field.Key}"] = [$"{field.Label} is required to enable SMS."];
        }
        if (fieldErrors.Count > 0) return Error.Validation("request.invalid", "One or more SMS settings are invalid.", fieldErrors);
        if (!request.Enabled && stored.Value.Enabled && loginSettings is not null)
        {
            // Users who sign in with SMS codes would be locked out.
            var login = await loginSettings.GetAsync(ct);
            if (!login.IsSuccess) return login.Error!;
            if (login.Value.Mode != SmsLoginModes.Off)
                return Error.Validation("sms.login_enabled", "Turn off SMS sign-in before disabling SMS sending.");
        }

        var saved = new StoredSmsSettings(request.Enabled, request.Provider, merged);
        var written = await store.SaveAsync(saved, ct);
        return written.IsSuccess ? Masked(saved) : written.Error!;
    }

    /// <summary>Sends through the tenant's provider. The number may be in any common Iranian spelling.</summary>
    public async Task<Result<SmsTestResultDto>> SendAsync(string phoneNumber, string text, CancellationToken ct)
    {
        var to = PhoneNumbers.NormalizeIranMobile(phoneNumber);
        if (to is null) return Error.Validation("sms.invalid_number", "The number is not an Iranian mobile number (e.g. 09121234567).");
        var stored = await store.GetAsync(ct);
        if (!stored.IsSuccess) return stored.Error!;
        var settings = stored.Value;
        if (!settings.Enabled || settings.Provider is null)
            return Error.Validation("sms.disabled", "SMS is not enabled for this organisation.");
        if (!_providers.TryGetValue(settings.Provider, out var provider))
            return Error.Unavailable("sms.provider_missing", $"The configured SMS provider '{settings.Provider}' is not installed on this gateway.");

        var result = await provider.SendAsync(new SmsMessage(to, text, tenant.TenantId),
            settings.Settings.GetValueOrDefault(provider.Id) ?? new Dictionary<string, string>(), ct);
        return result.Accepted
            ? new SmsTestResultDto(provider.Id, provider.SendsMessages, result.MessageId, PhoneNumbers.Mask(to))
            : Error.Upstream("sms.send_failed", $"{provider.DisplayName} did not accept the message: {result.Error}");
    }

    public Task<Result<SmsTestResultDto>> SendTestAsync(string phoneNumber, CancellationToken ct) => SendAsync(phoneNumber, TestText, ct);

    /// <summary>What the development provider recorded for this tenant (empty when it is not installed).</summary>
    public IReadOnlyList<SmsOutboxItemDto> Outbox(int max = 20) => outbox?.Recent(tenant.TenantId, Math.Clamp(max, 1, 50)) ?? [];

    private SmsSettingsDto Masked(StoredSmsSettings settings) => new(settings.Enabled, settings.Provider,
        settings.Settings.Where(kv => _providers.ContainsKey(kv.Key)).ToDictionary(kv => kv.Key, kv =>
        {
            var fields = _providers[kv.Key].Fields;
            return (IReadOnlyDictionary<string, string>)kv.Value.ToDictionary(v => v.Key,
                v => fields.Any(f => f.Key == v.Key && f.Kind == "secret") ? Mask : v.Value, StringComparer.Ordinal);
        }, StringComparer.Ordinal));

    private static string? FieldError(SmsFieldDto field, string value)
    {
        if (value.Length == 0) return null;
        if (value.Length > 500) return $"{field.Label} is at most 500 characters.";
        if (value.Any(char.IsControl)) return $"{field.Label} cannot contain control characters.";
        return field.Kind switch
        {
            "phone" when !value.All(c => char.IsAsciiDigit(c) || c == '+') => $"{field.Label} is a number (digits only).",
            "url" when !(Uri.TryCreate(value, UriKind.Absolute, out var u) && u.Scheme is "https" or "http") => $"{field.Label} is an http(s) URL.",
            _ => null,
        };
    }
}

public sealed class SmsSettingsDtoValidator : AbstractValidator<SmsSettingsDto>
{
    public SmsSettingsDtoValidator()
    {
        RuleFor(s => s.Provider).Matches("^[a-z][a-z0-9-]{1,39}$").When(s => s.Provider is not null);
        RuleFor(s => s.Settings).Must(s => s.Count <= 10).WithMessage("At most 10 providers.");
    }
}

public sealed class SmsTestRequestValidator : AbstractValidator<SmsTestRequest>
{
    public SmsTestRequestValidator() => RuleFor(r => r.PhoneNumber).NotEmpty().MaximumLength(30);
}
