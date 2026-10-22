using System.Text.RegularExpressions;

namespace Identity.Infrastructure;

/// <summary>
/// Cross-cutting, non-secret infrastructure helpers shared across adapters.
/// Strips sensitive credentials, tokens, and private keys from logs and events.
/// </summary>
public static partial class SecretRedaction
{
    private const string Mask = "[REDACTED]";

    /// <summary>Claim, header and configuration keys whose values must never be emitted.</summary>
    private static readonly HashSet<string> SensitiveKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "authorization", "cookie", "password", "pwd", "secret", "client_secret", "token",
        "access_token", "refresh_token", "id_token", "external_token", "organization_token",
        "private_key", "privatekey", "pkcs8", "vault_token", "x-vault-token", "api_key", "apikey"
    };

    [GeneratedRegex(
        "(?i)(authorization|cookie|password|secret|token|private[_-]?key|vault[_-]?token)\\s*[:=]\\s*\\S+",
        RegexOptions.Compiled)]
    private static partial Regex KeyValuePattern();

    [GeneratedRegex(
        "(?i)\"(authorization|password|pwd|secret|client_secret|access_token|refresh_token|id_token|external_token|organization_token|private_key|vault_token)\"\\s*:\\s*\"[^\"]*\"",
        RegexOptions.Compiled)]
    private static partial Regex JsonPattern();

    [GeneratedRegex(
        "(?i)(bearer|basic)\\s+[A-Za-z0-9\\-._~+/]+=*",
        RegexOptions.Compiled)]
    private static partial Regex SchemePattern();

    [GeneratedRegex("eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}", RegexOptions.Compiled)]
    private static partial Regex CompactJwtPattern();

    [GeneratedRegex(
        "-----BEGIN (?<kind>[A-Z ]*PRIVATE KEY)-----(?<body>[\\s\\S]*?)(?:-----END \\k<kind>-----|$)",
        RegexOptions.Compiled)]
    private static partial Regex PemPrivateKeyPattern();

    [GeneratedRegex(
        "(?i)\"data\"\\s*:\\s*\\{[^{}]*(?:\\{[^{}]*\\}[^{}]*)*\\}",
        RegexOptions.Compiled)]
    private static partial Regex VaultPayloadPattern();

    [GeneratedRegex("(?<=[\"'\\s:=,])(?:MII[A-Za-z0-9+/=\\r\\n]{200,})(?=[\"'\\s,}\\]]|$)", RegexOptions.Compiled)]
    private static partial Regex Base64DerPattern();

    /// <summary>
    /// Checks whether a key name corresponds to a sensitive secret.
    /// </summary>
    /// <param name="key">The key name.</param>
    /// <returns>True if sensitive; otherwise false.</returns>
    public static bool IsSensitive(string? key)
        => !string.IsNullOrEmpty(key) && SensitiveKeys.Contains(key.Replace('-', '_'));

    /// <summary>
    /// Strips bearer/basic credentials, compact JWTs, PEM private-key blocks, raw base64 DER key
    /// material and secret key/value pairs from a message.
    /// </summary>
    /// <param name="message">The raw message string.</param>
    /// <returns>A sanitized string with secrets masked.</returns>
    public static string Redact(string? message)
    {
        if (string.IsNullOrEmpty(message)) return string.Empty;
        var result = PemPrivateKeyPattern().Replace(message, _ => Mask);
        result = VaultPayloadPattern().Replace(result, m => MaskVaultPayload(m.Value));
        result = SchemePattern().Replace(result, _ => Mask);
        result = CompactJwtPattern().Replace(result, Mask);
        result = Base64DerPattern().Replace(result, Mask);
        result = JsonPattern().Replace(result, m => MaskJson(m.Value));
        result = KeyValuePattern().Replace(result, m => MaskKeyValue(m.Value));
        return result;
    }

    /// <summary>
    /// Redacts the values of sensitive entries in a dictionary while preserving key names.
    /// </summary>
    /// <param name="details">The dictionary of details.</param>
    /// <returns>A redacted copy of the dictionary.</returns>
    public static IReadOnlyDictionary<string, string?> Redact(
        IReadOnlyDictionary<string, string?> details)
    {
        ArgumentNullException.ThrowIfNull(details);
        var redacted = new Dictionary<string, string?>(details.Count, StringComparer.Ordinal);
        foreach (var (key, value) in details)
            redacted[key] = IsSensitive(key) ? Mask : Redact(value);
        return redacted;
    }

    private static string MaskVaultPayload(string match)
    {
        var open = match.IndexOf('{');
        var close = match.LastIndexOf('}');
        if (open < 0 || close <= open) return Mask;
        return string.Concat(match.AsSpan(0, open + 1), " \"[REDACTED]\" ", match.AsSpan(close));
    }

    private static string MaskJson(string match)
    {
        var separator = match.IndexOf(':');
        return separator < 0 ? Mask : string.Concat(match.AsSpan(0, separator + 1), " \"", Mask, "\"");
    }

    private static string MaskKeyValue(string match)
    {
        var separator = match.IndexOfAny([':', '=']);
        return separator < 0
            ? Mask
            : string.Concat(match.AsSpan(0, separator + 1), match.Contains('=') ? "=" : " ", Mask);
    }
}
