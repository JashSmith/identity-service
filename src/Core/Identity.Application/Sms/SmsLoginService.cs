using FluentValidation;
using Identity.Contracts;

namespace Identity.Application.Sms;

/// <summary>Where the tenant's SMS sign-in settings live (Keycloak realm attributes <c>iam.smslogin.*</c>).</summary>
public interface ISmsLoginSettingsStore
{
    Task<Result<SmsLoginSettingsDto>> GetAsync(CancellationToken ct);
    Task<Result> SaveAsync(SmsLoginSettingsDto settings, CancellationToken ct);
}

/// <summary>Keycloak's sign-in flows of the tenant: the SMS steps are added once and switched on or off by mode.</summary>
public interface ISmsLoginFlows
{
    /// <summary>False when Keycloak does not have the Avash SMS authenticators (keycloak/extensions not built).</summary>
    Task<Result<bool>> ReadyAsync(CancellationToken ct);

    /// <summary>Adds the SMS steps when missing and enables the ones <paramref name="mode"/> needs.</summary>
    Task<Result> ApplyAsync(string mode, CancellationToken ct);
}

/// <summary>
/// SMS sign-in of the tenant: settings (validated, stored in Keycloak) and the codes Keycloak asks the gateway to
/// send. Keycloak generates and checks the codes; the gateway only delivers them through the tenant's SMS provider.
/// Errors: sms_login.*, sms.* or a Keycloak availability error.
/// </summary>
public sealed class SmsLoginService(ISmsLoginSettingsStore store, ISmsLoginFlows flows, ISmsSettingsStore smsSettings, SmsService sms)
{
    public async Task<Result<SmsLoginSettingsDto>> GetAsync(CancellationToken ct)
    {
        var settings = await store.GetAsync(ct);
        if (!settings.IsSuccess) return settings.Error!;
        var ready = await flows.ReadyAsync(ct);
        return ready.IsSuccess ? settings.Value with { FlowsReady = ready.Value } : ready.Error!;
    }

    public async Task<Result<SmsLoginSettingsDto>> SaveAsync(SmsLoginSettingsDto request, CancellationToken ct)
    {
        if (request.Mode != SmsLoginModes.Off)
        {
            var sending = await smsSettings.GetAsync(ct);
            if (!sending.IsSuccess) return sending.Error!;
            if (!sending.Value.Enabled)
                return Error.Validation("sms_login.sms_disabled", "Enable and configure SMS sending before turning on SMS sign-in.");
            var ready = await flows.ReadyAsync(ct);
            if (!ready.IsSuccess) return ready.Error!;
            if (!ready.Value)
                return Error.Unavailable("sms_login.extension_missing",
                    "Keycloak does not have the Avash SMS authenticators; build keycloak/extensions and restart Keycloak.");
        }

        var saved = request with { FlowsReady = true };
        // Attributes first: the authenticators also check the mode, so a flow change that fails afterwards cannot
        // switch SMS sign-in on by itself. The bootstrap applies the stored mode again on the next start.
        var written = await store.SaveAsync(saved, ct);
        if (!written.IsSuccess) return written.Error!;
        var applied = await flows.ApplyAsync(saved.Mode, ct);
        return applied.IsSuccess ? saved : applied.Error!;
    }

    /// <summary>Delivers a code Keycloak generated. The code is never logged or returned.</summary>
    public async Task<Result<SmsTestResultDto>> SendCodeAsync(string phoneNumber, string code, int lifetimeSeconds, string purpose, CancellationToken ct)
    {
        var settings = await store.GetAsync(ct);
        if (!settings.IsSuccess) return settings.Error!;
        if (settings.Value.Mode == SmsLoginModes.Off)
            return Error.Validation("sms_login.disabled", "SMS sign-in is not enabled for this organisation.");
        return await sms.SendAsync(phoneNumber, Text(code, lifetimeSeconds, purpose), ct);
    }

    /// <summary>The SMS text. Latin digits for the code, so phones can offer it for automatic filling.</summary>
    public static string Text(string code, int lifetimeSeconds, string purpose)
    {
        var minutes = Math.Max(1, (int)Math.Ceiling(lifetimeSeconds / 60.0));
        return purpose == "second-factor"
            ? $"کد تأیید ورود: {code}\nاعتبار: {PersianDigits(minutes)} دقیقه. اگر شما در حال ورود نیستید، رمز عبور خود را عوض کنید."
            : $"کد ورود: {code}\nاعتبار: {PersianDigits(minutes)} دقیقه. این کد را به هیچ‌کس ندهید.";
    }

    private static string PersianDigits(int n) => string.Concat(n.ToString(System.Globalization.CultureInfo.InvariantCulture)
        .Select(c => (char)('۰' + (c - '0'))));
}

public sealed class SmsLoginSettingsDtoValidator : AbstractValidator<SmsLoginSettingsDto>
{
    public SmsLoginSettingsDtoValidator()
    {
        RuleFor(s => s.Mode).Must(m => SmsLoginModes.All.Contains(m))
            .WithMessage($"Mode is one of: {string.Join(", ", SmsLoginModes.All)}.");
        RuleFor(s => s.CodeLength).InclusiveBetween(4, 8);
        RuleFor(s => s.CodeLifetimeSeconds).InclusiveBetween(60, 600);
        RuleFor(s => s.ResendSeconds).InclusiveBetween(30, 300);
        RuleFor(s => s.MaxAttempts).InclusiveBetween(1, 10);
    }
}
