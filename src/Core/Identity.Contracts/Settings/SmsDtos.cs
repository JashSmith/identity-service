namespace Identity.Contracts;

/// <summary>One setting an SMS provider needs (shown as a form field in the console).</summary>
/// <param name="Kind">text, secret (never returned; masked), phone (sender line, digits) or url.</param>
public sealed record SmsFieldDto(string Key, string Label, string Kind, bool Required, string? Placeholder = null, string? Hint = null);

/// <summary>An SMS provider the gateway can use.</summary>
/// <param name="SendsMessages">False for the development provider, which only records messages.</param>
public sealed record SmsProviderDto(string Id, string DisplayName, string Description, bool SendsMessages, IReadOnlyList<SmsFieldDto> Fields);

/// <summary>
/// SMS settings of the tenant. <see cref="Settings"/> holds the values of every provider (provider id -> field -> value),
/// so switching providers keeps each one's configuration. Secret values are returned as "**********"; sending that
/// mask back keeps the stored secret.
/// </summary>
public sealed record SmsSettingsDto(
    bool Enabled,
    string? Provider,
    IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> Settings);

public sealed record SmsTestRequest(string PhoneNumber);

/// <param name="Provider">The provider that handled the message.</param>
/// <param name="Delivered">True when a real provider accepted the message; false for the development provider.</param>
public sealed record SmsTestResultDto(string Provider, bool Delivered, string? MessageId, string PhoneNumber);

/// <summary>A message recorded by the development provider (nothing is sent).</summary>
public sealed record SmsOutboxItemDto(DateTimeOffset Time, string PhoneNumber, string Text);

/// <summary>SMS sign-in modes of a tenant.</summary>
public static class SmsLoginModes
{
    /// <summary>No SMS sign-in.</summary>
    public const string Off = "off";

    /// <summary>Mobile number + SMS code, no password (password sign-in stays available).</summary>
    public const string Passwordless = "passwordless";

    /// <summary>Password first, then an SMS code to the user's registered number.</summary>
    public const string SecondFactor = "second-factor";

    public static readonly IReadOnlyList<string> All = [Off, Passwordless, SecondFactor];
}

/// <summary>
/// SMS sign-in of the tenant, on Keycloak's login page and in the gateway's login API.
/// </summary>
/// <param name="Mode">off, passwordless or second-factor (see <see cref="SmsLoginModes"/>).</param>
/// <param name="CodeLength">Digits of the code (4-8).</param>
/// <param name="CodeLifetimeSeconds">How long a code stays valid (60-600).</param>
/// <param name="ResendSeconds">Wait before another code may be requested (30-300).</param>
/// <param name="MaxAttempts">Wrong codes allowed before a new code is needed (1-10).</param>
/// <param name="FlowsReady">False when Keycloak lacks the Avash extension, so the mode cannot take effect yet.</param>
public sealed record SmsLoginSettingsDto(
    string Mode,
    int CodeLength = 6,
    int CodeLifetimeSeconds = 120,
    int ResendSeconds = 60,
    int MaxAttempts = 5,
    bool FlowsReady = true);
