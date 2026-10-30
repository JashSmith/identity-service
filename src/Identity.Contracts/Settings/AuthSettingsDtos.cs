namespace Identity.Contracts;

/// <summary>Token and session lifetimes of the tenant realm, in seconds.</summary>
public sealed record TokenSettingsDto(
    int AccessTokenLifespan,
    int SsoSessionIdleTimeout,
    int SsoSessionMaxLifespan,
    int OfflineSessionIdleTimeout,
    bool RevokeRefreshToken,
    int RefreshTokenMaxReuse);

/// <summary>
/// Password rules. Null/false turns a rule off. Rules Keycloak supports but this API does not model
/// (e.g. regexPattern) are kept unchanged.
/// </summary>
public sealed record PasswordPolicyDto(
    int? MinLength = null,
    int? Digits = null,
    int? UpperCase = null,
    int? LowerCase = null,
    int? SpecialChars = null,
    bool NotUsername = false,
    bool NotEmail = false,
    int? History = null,
    int? ExpireDays = null);

/// <summary>Lockout after failed logins.</summary>
public sealed record BruteForceSettingsDto(
    bool Enabled,
    bool PermanentLockout,
    int FailureFactor,
    int WaitIncrementSeconds,
    int MaxFailureWaitSeconds,
    int MaxDeltaTimeSeconds);

/// <summary>
/// One-time-password (MFA) policy. <paramref name="RequiredForNewUsers"/> makes every new user enrol an
/// authenticator app at the first login (CONFIGURE_TOTP becomes a default required action).
/// </summary>
public sealed record OtpSettingsDto(
    string Type,
    string Algorithm,
    int Digits,
    int Period,
    int LookAheadWindow,
    bool RequiredForNewUsers);

/// <summary>Sign-in options of the realm login page.</summary>
public sealed record LoginSettingsDto(
    bool RegistrationAllowed,
    bool ResetPasswordAllowed,
    bool RememberMe,
    bool VerifyEmail,
    bool LoginWithEmailAllowed,
    string? LoginTheme,
    string? DefaultLocale);

/// <summary>
/// An external identity provider (OIDC, SAML, Google, Microsoft, ...). Secrets in <paramref name="Config"/>
/// are never returned; send "**********" (or leave them out on update) to keep the stored value.
/// </summary>
public sealed record IdentityProviderDto(
    string Alias,
    string ProviderId,
    string? DisplayName,
    bool Enabled,
    bool TrustEmail,
    IReadOnlyDictionary<string, string>? Config);

/// <summary>
/// An LDAP or Active Directory user federation. <paramref name="BindCredential"/> is write-only: it is returned as
/// "**********", and sending that value keeps the stored password.
/// </summary>
/// <param name="Vendor">ad, other, rhds, tivoli or edirectory.</param>
/// <param name="EditMode">READ_ONLY, WRITABLE or UNSYNCED.</param>
public sealed record LdapProviderDto(
    string? Id,
    string Name,
    bool Enabled,
    string Vendor,
    string ConnectionUrl,
    string? BindDn,
    string? BindCredential,
    string UsersDn,
    string UsernameAttribute,
    string RdnAttribute,
    string UuidAttribute,
    string UserObjectClasses,
    string EditMode,
    bool ImportEnabled = true,
    bool SyncRegistrations = false,
    bool StartTls = false,
    int? FullSyncPeriodSeconds = null,
    int? ChangedSyncPeriodSeconds = null);

/// <summary>Checks an LDAP server before saving: "connection" only connects, "authentication" also binds.</summary>
public sealed record LdapTestRequest(string Mode, string ConnectionUrl, string? BindDn, string? BindCredential,
    bool StartTls = false, string? ProviderId = null);

/// <summary>Outcome of an LDAP synchronization.</summary>
public sealed record LdapSyncResultDto(int Added, int Updated, int Removed, int Failed, string? Status);
