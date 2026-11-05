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
