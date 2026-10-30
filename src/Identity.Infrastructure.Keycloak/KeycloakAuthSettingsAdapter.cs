using System.Text.Json;
using Identity.Application;
using Identity.Application.Settings;
using Identity.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Authentication settings on the Keycloak Admin API: realm fields (partial PUT on the realm, which only
/// updates the fields that are sent), <c>authentication/required-actions/CONFIGURE_TOTP</c>,
/// <c>identity-provider/instances</c>, LDAP <c>components</c>, <c>testLDAPConnection</c> and <c>user-storage/{id}/sync</c>.
/// </summary>
public sealed class KeycloakAuthSettingsAdapter(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakAuthSettingsAdapter>? logger = null) : IAuthSettingsService
{
    private const string Resource = "settings";
    private const string IdpResource = "idp";
    private const string LdapResource = "ldap";
    private const string Mask = "**********";
    private const string UserStorageType = "org.keycloak.storage.UserStorageProvider";

    private readonly KeycloakAdminApi _api = new(http, opts.Value, tokenProvider, (ILogger?)logger ?? NullLogger.Instance);

    // ---------- realm fields ----------

    public Task<Result<TokenSettingsDto>> GetTokensAsync(CancellationToken ct) => ReadRealmAsync(r => new TokenSettingsDto(
        Int(r, "accessTokenLifespan", 300), Int(r, "ssoSessionIdleTimeout", 1800), Int(r, "ssoSessionMaxLifespan", 36000),
        Int(r, "offlineSessionIdleTimeout", 2_592_000), Bool(r, "revokeRefreshToken"), Int(r, "refreshTokenMaxReuse", 0)), ct);

    public Task<Result> SetTokensAsync(TokenSettingsDto s, CancellationToken ct) => WriteRealmAsync(new
    {
        accessTokenLifespan = s.AccessTokenLifespan,
        ssoSessionIdleTimeout = s.SsoSessionIdleTimeout,
        ssoSessionMaxLifespan = s.SsoSessionMaxLifespan,
        offlineSessionIdleTimeout = s.OfflineSessionIdleTimeout,
        revokeRefreshToken = s.RevokeRefreshToken,
        refreshTokenMaxReuse = s.RefreshTokenMaxReuse,
    }, ct);

    public Task<Result<PasswordPolicyDto>> GetPasswordPolicyAsync(CancellationToken ct) =>
        ReadRealmAsync(r => PasswordPolicyFormat.Parse(KeycloakAdminApi.GetString(r, "passwordPolicy")), ct);

    public async Task<Result> SetPasswordPolicyAsync(PasswordPolicyDto policy, CancellationToken ct)
    {
        var realm = await _api.GetAsync("", Resource, ct);
        if (!realm.IsSuccess) return realm.Error!;
        var text = PasswordPolicyFormat.Format(policy, KeycloakAdminApi.GetString(realm.Value, "passwordPolicy"));
        return await WriteRealmAsync(new { passwordPolicy = text }, ct);
    }

    public Task<Result<BruteForceSettingsDto>> GetBruteForceAsync(CancellationToken ct) => ReadRealmAsync(r => new BruteForceSettingsDto(
        Bool(r, "bruteForceProtected"), Bool(r, "permanentLockout"), Int(r, "failureFactor", 30), Int(r, "waitIncrementSeconds", 60),
        Int(r, "maxFailureWaitSeconds", 900), Int(r, "maxDeltaTimeSeconds", 43_200)), ct);

    public Task<Result> SetBruteForceAsync(BruteForceSettingsDto s, CancellationToken ct) => WriteRealmAsync(new
    {
        bruteForceProtected = s.Enabled,
        permanentLockout = s.PermanentLockout,
        failureFactor = s.FailureFactor,
        waitIncrementSeconds = s.WaitIncrementSeconds,
        maxFailureWaitSeconds = s.MaxFailureWaitSeconds,
        maxDeltaTimeSeconds = s.MaxDeltaTimeSeconds,
    }, ct);

    public async Task<Result<OtpSettingsDto>> GetOtpAsync(CancellationToken ct)
    {
        var realm = await _api.GetAsync("", Resource, ct);
        if (!realm.IsSuccess) return realm.Error!;
        var action = await _api.GetAsync("authentication/required-actions/CONFIGURE_TOTP", Resource, ct);
        if (!action.IsSuccess) return action.Error!;
        var r = realm.Value;
        return new OtpSettingsDto(KeycloakAdminApi.GetString(r, "otpPolicyType") ?? "totp",
            KeycloakAdminApi.GetString(r, "otpPolicyAlgorithm") ?? "HmacSHA1", Int(r, "otpPolicyDigits", 6),
            Int(r, "otpPolicyPeriod", 30), Int(r, "otpPolicyLookAheadWindow", 1),
            Bool(action.Value, "enabled") && Bool(action.Value, "defaultAction"));
    }

    public async Task<Result> SetOtpAsync(OtpSettingsDto s, CancellationToken ct)
    {
        var realm = await WriteRealmAsync(new
        {
            otpPolicyType = s.Type,
            otpPolicyAlgorithm = s.Algorithm,
            otpPolicyDigits = s.Digits,
            otpPolicyPeriod = s.Period,
            otpPolicyLookAheadWindow = s.LookAheadWindow,
        }, ct);
        if (!realm.IsSuccess) return realm;

        const string path = "authentication/required-actions/CONFIGURE_TOTP";
        var action = await _api.GetAsync(path, Resource, ct);
        if (!action.IsSuccess) return action.Error!;
        var body = JsonSerializer.Deserialize<Dictionary<string, object?>>(action.Value.GetRawText())!;
        body["defaultAction"] = s.RequiredForNewUsers;
        if (s.RequiredForNewUsers) body["enabled"] = true;
        return await _api.SendWithoutResultAsync(HttpMethod.Put, path, body, Resource, ct, includeKeycloakMessage: true);
    }

    public Task<Result<LoginSettingsDto>> GetLoginAsync(CancellationToken ct) => ReadRealmAsync(r => new LoginSettingsDto(
        Bool(r, "registrationAllowed"), Bool(r, "resetPasswordAllowed"), Bool(r, "rememberMe"), Bool(r, "verifyEmail"),
        Bool(r, "loginWithEmailAllowed"), KeycloakAdminApi.GetString(r, "loginTheme"), KeycloakAdminApi.GetString(r, "defaultLocale")), ct);

    public Task<Result> SetLoginAsync(LoginSettingsDto s, CancellationToken ct) => WriteRealmAsync(new
    {
        registrationAllowed = s.RegistrationAllowed,
        resetPasswordAllowed = s.ResetPasswordAllowed,
        rememberMe = s.RememberMe,
        verifyEmail = s.VerifyEmail,
        loginWithEmailAllowed = s.LoginWithEmailAllowed,
        // "" returns to Keycloak's default theme.
        loginTheme = s.LoginTheme ?? "",
        defaultLocale = s.DefaultLocale ?? "",
    }, ct);

    private async Task<Result<T>> ReadRealmAsync<T>(Func<JsonElement, T> map, CancellationToken ct)
    {
        var realm = await _api.GetAsync("", Resource, ct);
        return realm.IsSuccess ? map(realm.Value) : realm.Error!;
    }

    private Task<Result> WriteRealmAsync(object fields, CancellationToken ct) =>
        _api.SendWithoutResultAsync(HttpMethod.Put, "", fields, Resource, ct, includeKeycloakMessage: true);

    // ---------- identity providers ----------

    private static string IdpPath(string alias) => $"identity-provider/instances/{Uri.EscapeDataString(alias)}";

    private static Error IdpNotFound(string alias) => Error.NotFound("idp.not_found", $"Identity provider '{alias}' was not found.");

    public async Task<Result<IReadOnlyCollection<IdentityProviderDto>>> ListIdentityProvidersAsync(CancellationToken ct)
    {
        var list = await _api.GetAsync("identity-provider/instances", IdpResource, ct);
        if (!list.IsSuccess) return list.Error!;
        return list.Value.EnumerateArray().Select(ToIdp).OrderBy(p => p.Alias, StringComparer.Ordinal).ToArray();
    }

    public async Task<Result<IdentityProviderDto>> GetIdentityProviderAsync(string alias, CancellationToken ct)
    {
        var idp = await _api.GetAsync(IdpPath(alias), IdpResource, ct);
        if (idp.IsSuccess) return ToIdp(idp.Value);
        return idp.Error!.Kind == ErrorKind.NotFound ? IdpNotFound(alias) : idp.Error;
    }

    public async Task<Result<IdentityProviderDto>> CreateIdentityProviderAsync(IdentityProviderDto provider, CancellationToken ct)
    {
        var existing = await GetIdentityProviderAsync(provider.Alias, ct);
        if (existing.IsSuccess) return Error.Conflict("idp.already_exists", $"Identity provider '{provider.Alias}' already exists.");
        if (existing.Error!.Kind != ErrorKind.NotFound) return existing.Error;

        var created = await _api.SendWithoutResultAsync(HttpMethod.Post, "identity-provider/instances", IdpBody(provider),
            IdpResource, ct, includeKeycloakMessage: true);
        return created.IsSuccess ? await GetIdentityProviderAsync(provider.Alias, ct) : created.Error!;
    }

    public async Task<Result<IdentityProviderDto>> UpdateIdentityProviderAsync(string alias, IdentityProviderDto provider, CancellationToken ct)
    {
        var current = await _api.GetAsync(IdpPath(alias), IdpResource, ct);
        if (!current.IsSuccess) return current.Error!.Kind == ErrorKind.NotFound ? IdpNotFound(alias) : current.Error;

        // Start from the stored config: keys that are not sent stay, and masked secrets are sent back masked,
        // which Keycloak treats as "keep the stored secret".
        var config = ReadConfig(current.Value);
        foreach (var (key, value) in provider.Config ?? new Dictionary<string, string>()) config[key] = value;
        var body = IdpBody(provider with { Alias = alias, Config = config });
        if (KeycloakAdminApi.GetString(current.Value, "internalId") is { } internalId) body["internalId"] = internalId;

        var updated = await _api.SendWithoutResultAsync(HttpMethod.Put, IdpPath(alias), body, IdpResource, ct, includeKeycloakMessage: true);
        return updated.IsSuccess ? await GetIdentityProviderAsync(alias, ct) : updated.Error!;
    }

    public async Task<Result> DeleteIdentityProviderAsync(string alias, CancellationToken ct)
    {
        var deleted = await _api.SendWithoutResultAsync(HttpMethod.Delete, IdpPath(alias), null, IdpResource, ct);
        return deleted.IsSuccess || deleted.Error!.Kind != ErrorKind.NotFound ? deleted : IdpNotFound(alias);
    }

    private static Dictionary<string, object?> IdpBody(IdentityProviderDto p) => new()
    {
        ["alias"] = p.Alias,
        ["providerId"] = p.ProviderId,
        ["displayName"] = p.DisplayName,
        ["enabled"] = p.Enabled,
        ["trustEmail"] = p.TrustEmail,
        ["config"] = p.Config ?? new Dictionary<string, string>(),
    };

    private static IdentityProviderDto ToIdp(JsonElement e) => new(
        KeycloakAdminApi.GetString(e, "alias") ?? "",
        KeycloakAdminApi.GetString(e, "providerId") ?? "",
        KeycloakAdminApi.GetString(e, "displayName"),
        Bool(e, "enabled"),
        Bool(e, "trustEmail"),
        ReadConfig(e).ToDictionary(kv => kv.Key, kv => IsSecret(kv.Key) && kv.Value.Length > 0 ? Mask : kv.Value, StringComparer.Ordinal));

    private static Dictionary<string, string> ReadConfig(JsonElement e) =>
        e.TryGetProperty("config", out var c) && c.ValueKind == JsonValueKind.Object
            ? c.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() ?? "" : p.Value.GetRawText(), StringComparer.Ordinal)
            : new Dictionary<string, string>(StringComparer.Ordinal);

    private static bool IsSecret(string key) =>
        key.Contains("secret", StringComparison.OrdinalIgnoreCase) || key.Contains("password", StringComparison.OrdinalIgnoreCase);

    // ---------- LDAP / Active Directory ----------

    private static string ComponentPath(string id) => $"components/{Uri.EscapeDataString(id)}";

    private static Error LdapNotFound(string id) => Error.NotFound("ldap.not_found", $"LDAP provider '{id}' was not found.");

    public async Task<Result<IReadOnlyCollection<LdapProviderDto>>> ListLdapAsync(CancellationToken ct)
    {
        var components = await _api.GetAsync($"components?type={Uri.EscapeDataString(UserStorageType)}", LdapResource, ct);
        if (!components.IsSuccess) return components.Error!;
        return components.Value.EnumerateArray()
            .Where(c => KeycloakAdminApi.GetString(c, "providerId") == "ldap")
            .Select(ToLdap).OrderBy(p => p.Name, StringComparer.Ordinal).ToArray();
    }

    public async Task<Result<LdapProviderDto>> GetLdapAsync(string id, CancellationToken ct)
    {
        var component = await ReadLdapComponentAsync(id, ct);
        return component.IsSuccess ? ToLdap(component.Value) : component.Error!;
    }

    public async Task<Result<LdapProviderDto>> CreateLdapAsync(LdapProviderDto provider, CancellationToken ct)
    {
        var realm = await _api.GetAsync("", Resource, ct);
        if (!realm.IsSuccess) return realm.Error!;
        var body = LdapBody(provider, KeycloakAdminApi.GetString(realm.Value, "id"), existing: null);
        var id = await _api.CreateAsync("components", body, LdapResource, ct, includeKeycloakMessage: true);
        return id.IsSuccess ? await GetLdapAsync(id.Value, ct) : id.Error!;
    }

    public async Task<Result<LdapProviderDto>> UpdateLdapAsync(string id, LdapProviderDto provider, CancellationToken ct)
    {
        var current = await ReadLdapComponentAsync(id, ct);
        if (!current.IsSuccess) return current.Error!;
        var body = LdapBody(provider, KeycloakAdminApi.GetString(current.Value, "parentId"), current.Value);
        body["id"] = id;
        var updated = await _api.SendWithoutResultAsync(HttpMethod.Put, ComponentPath(id), body, LdapResource, ct, includeKeycloakMessage: true);
        return updated.IsSuccess ? await GetLdapAsync(id, ct) : updated.Error!;
    }

    public async Task<Result> DeleteLdapAsync(string id, CancellationToken ct)
    {
        var current = await ReadLdapComponentAsync(id, ct);
        if (!current.IsSuccess) return current.Error!;
        return await _api.SendWithoutResultAsync(HttpMethod.Delete, ComponentPath(id), null, LdapResource, ct);
    }

    public async Task<Result> TestLdapAsync(LdapTestRequest request, CancellationToken ct)
    {
        var body = new Dictionary<string, object?>
        {
            ["action"] = request.Mode == "authentication" ? "testAuthentication" : "testConnection",
            ["connectionUrl"] = request.ConnectionUrl,
            ["bindDn"] = request.BindDn,
            // The masked value with componentId makes Keycloak use the stored password.
            ["bindCredential"] = request.BindCredential,
            ["authType"] = string.IsNullOrWhiteSpace(request.BindDn) ? "none" : "simple",
            ["startTls"] = request.StartTls.ToString().ToLowerInvariant(),
            ["useTruststoreSpi"] = "always",
            ["componentId"] = request.ProviderId,
        };
        var tested = await _api.SendWithoutResultAsync(HttpMethod.Post, "testLDAPConnection", body, LdapResource, ct, includeKeycloakMessage: true);
        if (tested.IsSuccess) return tested;
        // Keycloak answers 400 with a reason (e.g. "LDAP test error") when the server cannot be reached or bound.
        return tested.Error!.Kind == ErrorKind.Validation
            ? Error.Validation("ldap.test_failed", tested.Error.Message)
            : tested.Error;
    }

    public async Task<Result<LdapSyncResultDto>> SyncLdapAsync(string id, bool full, CancellationToken ct)
    {
        var current = await ReadLdapComponentAsync(id, ct);
        if (!current.IsSuccess) return current.Error!;
        var action = full ? "triggerFullSync" : "triggerChangedUsersSync";
        var result = await _api.SendAsync(HttpMethod.Post, $"user-storage/{Uri.EscapeDataString(id)}/sync?action={action}",
            null, LdapResource, ct, includeKeycloakMessage: true);
        if (!result.IsSuccess) return result.Error!;
        var r = result.Value ?? default;
        return new LdapSyncResultDto(Int(r, "added", 0), Int(r, "updated", 0), Int(r, "removed", 0), Int(r, "failed", 0),
            KeycloakAdminApi.GetString(r, "status"));
    }

    private async Task<Result<JsonElement>> ReadLdapComponentAsync(string id, CancellationToken ct)
    {
        var component = await _api.GetAsync(ComponentPath(id), LdapResource, ct);
        if (!component.IsSuccess) return component.Error!.Kind == ErrorKind.NotFound ? LdapNotFound(id) : component.Error;
        return KeycloakAdminApi.GetString(component.Value, "providerId") == "ldap" ? component.Value : LdapNotFound(id);
    }

    private static Dictionary<string, object?> LdapBody(LdapProviderDto p, string? parentId, JsonElement? existing)
    {
        // Keep config keys this API does not model (pooling, timeouts, Kerberos, ...) from the stored component.
        var config = existing is { } e && e.TryGetProperty("config", out var c) && c.ValueKind == JsonValueKind.Object
            ? JsonSerializer.Deserialize<Dictionary<string, string[]>>(c.GetRawText())!
            : new Dictionary<string, string[]>
            {
                ["searchScope"] = ["2"],
                ["pagination"] = ["true"],
                ["batchSizeForSync"] = ["1000"],
                ["trustEmail"] = ["false"],
                ["useTruststoreSpi"] = ["always"],
                ["connectionPooling"] = ["true"],
                ["cachePolicy"] = ["DEFAULT"],
            };
        void Set(string key, string? value) { if (value is null) config.Remove(key); else config[key] = [value]; }
        Set("enabled", p.Enabled.ToString().ToLowerInvariant());
        Set("vendor", p.Vendor);
        Set("connectionUrl", p.ConnectionUrl);
        Set("authType", string.IsNullOrWhiteSpace(p.BindDn) ? "none" : "simple");
        Set("bindDn", string.IsNullOrWhiteSpace(p.BindDn) ? null : p.BindDn);
        // No credential sent on update: send the mask so Keycloak keeps the stored password.
        Set("bindCredential", string.IsNullOrEmpty(p.BindCredential) ? (existing is null ? null : Mask) : p.BindCredential);
        Set("usersDn", p.UsersDn);
        Set("usernameLDAPAttribute", p.UsernameAttribute);
        Set("rdnLDAPAttribute", p.RdnAttribute);
        Set("uuidLDAPAttribute", p.UuidAttribute);
        Set("userObjectClasses", p.UserObjectClasses);
        Set("editMode", p.EditMode);
        Set("importEnabled", p.ImportEnabled.ToString().ToLowerInvariant());
        Set("syncRegistrations", p.SyncRegistrations.ToString().ToLowerInvariant());
        Set("startTls", p.StartTls.ToString().ToLowerInvariant());
        Set("fullSyncPeriod", (p.FullSyncPeriodSeconds ?? -1).ToString());
        Set("changedSyncPeriod", (p.ChangedSyncPeriodSeconds ?? -1).ToString());

        return new Dictionary<string, object?>
        {
            ["name"] = p.Name,
            ["providerId"] = "ldap",
            ["providerType"] = UserStorageType,
            ["parentId"] = parentId,
            ["config"] = config,
        };
    }

    private static LdapProviderDto ToLdap(JsonElement e)
    {
        var config = e.TryGetProperty("config", out var c) && c.ValueKind == JsonValueKind.Object ? c : default;
        string? Get(string key) => config.ValueKind == JsonValueKind.Object && config.TryGetProperty(key, out var v) &&
                                    v.ValueKind == JsonValueKind.Array && v.GetArrayLength() > 0 ? v[0].GetString() : null;
        int? Period(string key) => int.TryParse(Get(key), out var n) && n > 0 ? n : null;
        return new LdapProviderDto(
            KeycloakAdminApi.GetString(e, "id"), KeycloakAdminApi.GetString(e, "name") ?? "",
            Get("enabled") != "false", Get("vendor") ?? "other", Get("connectionUrl") ?? "", Get("bindDn"),
            string.IsNullOrEmpty(Get("bindCredential")) ? null : Mask,
            Get("usersDn") ?? "", Get("usernameLDAPAttribute") ?? "", Get("rdnLDAPAttribute") ?? "", Get("uuidLDAPAttribute") ?? "",
            Get("userObjectClasses") ?? "", Get("editMode") ?? "READ_ONLY", Get("importEnabled") != "false",
            Get("syncRegistrations") == "true", Get("startTls") == "true", Period("fullSyncPeriod"), Period("changedSyncPeriod"));
    }

    private static int Int(JsonElement e, string property, int fallback) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(property, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : fallback;

    private static bool Bool(JsonElement e, string property) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(property, out var v) && v.ValueKind == JsonValueKind.True;
}
