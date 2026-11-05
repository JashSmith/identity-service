using FluentValidation;
using Identity.Contracts;

namespace Identity.Application.Settings;

/// <summary>
/// Authentication settings of the tenant realm, stored by Keycloak itself (realm representation, required
/// actions, identity providers and user-storage components). Errors: settings.*, idp.*, ldap.* or a Keycloak
/// availability error.
/// </summary>
public interface IAuthSettingsService
{
    Task<Result<TokenSettingsDto>> GetTokensAsync(CancellationToken ct);
    Task<Result> SetTokensAsync(TokenSettingsDto settings, CancellationToken ct);

    Task<Result<PasswordPolicyDto>> GetPasswordPolicyAsync(CancellationToken ct);
    Task<Result> SetPasswordPolicyAsync(PasswordPolicyDto policy, CancellationToken ct);

    Task<Result<BruteForceSettingsDto>> GetBruteForceAsync(CancellationToken ct);
    Task<Result> SetBruteForceAsync(BruteForceSettingsDto settings, CancellationToken ct);

    Task<Result<OtpSettingsDto>> GetOtpAsync(CancellationToken ct);
    Task<Result> SetOtpAsync(OtpSettingsDto settings, CancellationToken ct);

    Task<Result<LoginSettingsDto>> GetLoginAsync(CancellationToken ct);
    Task<Result> SetLoginAsync(LoginSettingsDto settings, CancellationToken ct);

    Task<Result<IReadOnlyCollection<IdentityProviderDto>>> ListIdentityProvidersAsync(CancellationToken ct);
    Task<Result<IdentityProviderDto>> GetIdentityProviderAsync(string alias, CancellationToken ct);
    Task<Result<IdentityProviderDto>> CreateIdentityProviderAsync(IdentityProviderDto provider, CancellationToken ct);
    Task<Result<IdentityProviderDto>> UpdateIdentityProviderAsync(string alias, IdentityProviderDto provider, CancellationToken ct);
    Task<Result> DeleteIdentityProviderAsync(string alias, CancellationToken ct);

    Task<Result<IReadOnlyCollection<LdapProviderDto>>> ListLdapAsync(CancellationToken ct);
    Task<Result<LdapProviderDto>> GetLdapAsync(string id, CancellationToken ct);
    Task<Result<LdapProviderDto>> CreateLdapAsync(LdapProviderDto provider, CancellationToken ct);
    Task<Result<LdapProviderDto>> UpdateLdapAsync(string id, LdapProviderDto provider, CancellationToken ct);
    Task<Result> DeleteLdapAsync(string id, CancellationToken ct);
    Task<Result> TestLdapAsync(LdapTestRequest request, CancellationToken ct);
    Task<Result<LdapSyncResultDto>> SyncLdapAsync(string id, bool full, CancellationToken ct);
}

/// <summary>
/// Converts between <see cref="PasswordPolicyDto"/> and Keycloak's policy string
/// (<c>length(8) and digits(1) and notUsername(undefined)</c>), keeping rules the DTO does not model.
/// </summary>
public static class PasswordPolicyFormat
{
    private static readonly string[] Modelled =
        ["length", "digits", "upperCase", "lowerCase", "specialChars", "notUsername", "notEmail", "passwordHistory", "forceExpiredPasswordChange"];

    public static PasswordPolicyDto Parse(string? policy)
    {
        var rules = Rules(policy).ToDictionary(r => r.Name, r => r.Value, StringComparer.Ordinal);
        int? Number(string name) => rules.TryGetValue(name, out var v) && int.TryParse(v, out var n) ? n : null;
        return new PasswordPolicyDto(Number("length"), Number("digits"), Number("upperCase"), Number("lowerCase"),
            Number("specialChars"), rules.ContainsKey("notUsername"), rules.ContainsKey("notEmail"),
            Number("passwordHistory"), Number("forceExpiredPasswordChange"));
    }

    public static string Format(PasswordPolicyDto dto, string? current)
    {
        var rules = Rules(current).Where(r => !Modelled.Contains(r.Name, StringComparer.Ordinal))
            .Select(r => $"{r.Name}({r.Value})").ToList();
        void Add(string name, int? value) { if (value is > 0) rules.Add($"{name}({value})"); }
        Add("length", dto.MinLength);
        Add("digits", dto.Digits);
        Add("upperCase", dto.UpperCase);
        Add("lowerCase", dto.LowerCase);
        Add("specialChars", dto.SpecialChars);
        if (dto.NotUsername) rules.Add("notUsername(undefined)");
        if (dto.NotEmail) rules.Add("notEmail(undefined)");
        Add("passwordHistory", dto.History);
        Add("forceExpiredPasswordChange", dto.ExpireDays);
        return string.Join(" and ", rules);
    }

    private static IEnumerable<(string Name, string Value)> Rules(string? policy)
    {
        if (string.IsNullOrWhiteSpace(policy)) yield break;
        foreach (var part in policy.Split(" and ", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var open = part.IndexOf('(');
            if (open > 0 && part.EndsWith(')')) yield return (part[..open], part[(open + 1)..^1]);
            else yield return (part, "undefined");
        }
    }
}

public sealed class TokenSettingsValidator : AbstractValidator<TokenSettingsDto>
{
    public TokenSettingsValidator()
    {
        RuleFor(s => s.AccessTokenLifespan).InclusiveBetween(60, 86_400);
        RuleFor(s => s.SsoSessionIdleTimeout).InclusiveBetween(60, 30 * 86_400);
        RuleFor(s => s.SsoSessionMaxLifespan).InclusiveBetween(60, 365 * 86_400)
            .GreaterThanOrEqualTo(s => s.SsoSessionIdleTimeout).WithMessage("The maximum session must not be shorter than the idle timeout.");
        RuleFor(s => s.AccessTokenLifespan).LessThanOrEqualTo(s => s.SsoSessionIdleTimeout)
            .WithMessage("Access tokens must not outlive the session idle timeout.");
        RuleFor(s => s.OfflineSessionIdleTimeout).InclusiveBetween(60, 365 * 86_400);
        RuleFor(s => s.RefreshTokenMaxReuse).InclusiveBetween(0, 10);
    }
}

public sealed class PasswordPolicyValidator : AbstractValidator<PasswordPolicyDto>
{
    public PasswordPolicyValidator()
    {
        RuleFor(p => p.MinLength).InclusiveBetween(6, 128).When(p => p.MinLength.HasValue);
        RuleFor(p => p.Digits).InclusiveBetween(0, 20).When(p => p.Digits.HasValue);
        RuleFor(p => p.UpperCase).InclusiveBetween(0, 20).When(p => p.UpperCase.HasValue);
        RuleFor(p => p.LowerCase).InclusiveBetween(0, 20).When(p => p.LowerCase.HasValue);
        RuleFor(p => p.SpecialChars).InclusiveBetween(0, 20).When(p => p.SpecialChars.HasValue);
        RuleFor(p => p.History).InclusiveBetween(0, 50).When(p => p.History.HasValue);
        RuleFor(p => p.ExpireDays).InclusiveBetween(0, 3650).When(p => p.ExpireDays.HasValue);
    }
}

public sealed class BruteForceSettingsValidator : AbstractValidator<BruteForceSettingsDto>
{
    public BruteForceSettingsValidator()
    {
        RuleFor(s => s.FailureFactor).InclusiveBetween(1, 100);
        RuleFor(s => s.WaitIncrementSeconds).InclusiveBetween(1, 86_400);
        RuleFor(s => s.MaxFailureWaitSeconds).InclusiveBetween(1, 30 * 86_400)
            .GreaterThanOrEqualTo(s => s.WaitIncrementSeconds).WithMessage("The maximum wait must not be shorter than one wait increment.");
        RuleFor(s => s.MaxDeltaTimeSeconds).InclusiveBetween(1, 30 * 86_400);
    }
}

public sealed class OtpSettingsValidator : AbstractValidator<OtpSettingsDto>
{
    public OtpSettingsValidator()
    {
        RuleFor(s => s.Type).Must(t => t is "totp" or "hotp").WithMessage("Type is totp or hotp.");
        RuleFor(s => s.Algorithm).Must(a => a is "HmacSHA1" or "HmacSHA256" or "HmacSHA512")
            .WithMessage("Algorithm is HmacSHA1, HmacSHA256 or HmacSHA512.");
        RuleFor(s => s.Digits).Must(d => d is 6 or 8).WithMessage("Digits are 6 or 8.");
        RuleFor(s => s.Period).InclusiveBetween(15, 120);
        RuleFor(s => s.LookAheadWindow).InclusiveBetween(0, 10);
    }
}

public sealed class LoginSettingsValidator : AbstractValidator<LoginSettingsDto>
{
    public LoginSettingsValidator()
    {
        RuleFor(s => s.LoginTheme).MaximumLength(100);
        RuleFor(s => s.DefaultLocale).Matches("^[a-z]{2}(-[A-Z]{2})?$").When(s => !string.IsNullOrEmpty(s.DefaultLocale));
    }
}

public sealed class IdentityProviderValidator : AbstractValidator<IdentityProviderDto>
{
    /// <summary>Provider types the gateway offers; others are refused instead of being passed to Keycloak blindly.</summary>
    public static readonly string[] ProviderIds = ["oidc", "keycloak-oidc", "saml", "google", "microsoft", "github"];

    public IdentityProviderValidator()
    {
        RuleFor(p => p.Alias).NotEmpty().Matches("^[a-z][a-z0-9-]{1,49}$")
            .WithMessage("Alias is lower-case letters, digits or '-' (2-50 characters).");
        RuleFor(p => p.ProviderId).Must(id => ProviderIds.Contains(id))
            .WithMessage($"Provider type is one of: {string.Join(", ", ProviderIds)}.");
        RuleFor(p => p.DisplayName).MaximumLength(100);
    }
}

public sealed class LdapProviderValidator : AbstractValidator<LdapProviderDto>
{
    public LdapProviderValidator()
    {
        RuleFor(p => p.Name).NotEmpty().MaximumLength(100);
        RuleFor(p => p.Vendor).Must(v => v is "ad" or "other" or "rhds" or "tivoli" or "edirectory")
            .WithMessage("Vendor is ad, other, rhds, tivoli or edirectory.");
        RuleFor(p => p.ConnectionUrl).NotEmpty().Must(u => u.StartsWith("ldap://", StringComparison.OrdinalIgnoreCase) ||
                                                          u.StartsWith("ldaps://", StringComparison.OrdinalIgnoreCase))
            .WithMessage("Connection URL starts with ldap:// or ldaps://.");
        RuleFor(p => p.UsersDn).NotEmpty();
        RuleFor(p => p.UsernameAttribute).NotEmpty();
        RuleFor(p => p.RdnAttribute).NotEmpty();
        RuleFor(p => p.UuidAttribute).NotEmpty();
        RuleFor(p => p.UserObjectClasses).NotEmpty();
        RuleFor(p => p.EditMode).Must(m => m is "READ_ONLY" or "WRITABLE" or "UNSYNCED")
            .WithMessage("Edit mode is READ_ONLY, WRITABLE or UNSYNCED.");
        RuleFor(p => p.FullSyncPeriodSeconds).GreaterThanOrEqualTo(60).When(p => p.FullSyncPeriodSeconds.HasValue);
        RuleFor(p => p.ChangedSyncPeriodSeconds).GreaterThanOrEqualTo(60).When(p => p.ChangedSyncPeriodSeconds.HasValue);
    }
}

public sealed class LdapTestRequestValidator : AbstractValidator<LdapTestRequest>
{
    public LdapTestRequestValidator()
    {
        RuleFor(r => r.Mode).Must(m => m is "connection" or "authentication").WithMessage("Mode is connection or authentication.");
        RuleFor(r => r.ConnectionUrl).NotEmpty();
        RuleFor(r => r.BindDn).NotEmpty().When(r => r.Mode == "authentication");
    }
}
