using System.Text.RegularExpressions;
using Identity.Application;
using Identity.Domain;

namespace Identity.Infrastructure;

/// <summary>
/// Cross-cutting, non-secret infrastructure helpers shared by the Keycloak, external-SSO and
/// Redis adapters.
/// </summary>
/// <remarks>
/// This file intentionally contains no password hashing, token minting, session handling or
/// signing-key storage. The facade never issues tokens and never holds private key material:
/// RSA signing and key rotation belong to Keycloak and Vault. What remains here is the
/// redaction and audit plumbing those adapters need so secrets never reach logs or the
/// facade metadata store.
/// </remarks>
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

    /// <summary>
    /// A PEM private-key block, including the base64 body. Matches an unterminated block too, so a
    /// truncated log line still loses its material rather than leaking a prefix of it.
    /// </summary>
    [GeneratedRegex(
        "-----BEGIN (?<kind>[A-Z ]*PRIVATE KEY)-----(?<body>[\\s\\S]*?)(?:-----END \\k<kind>-----|$)",
        RegexOptions.Compiled)]
    private static partial Regex PemPrivateKeyPattern();

    /// <summary>
    /// A Vault KV v2 write/read payload: the <c>"data"</c> wrapper is kept (it names the path shape)
    /// but every value inside it is masked, so a serialized Vault response cannot carry key material.
    /// </summary>
    [GeneratedRegex(
        "(?i)\"data\"\\s*:\\s*\\{[^{}]*(?:\\{[^{}]*\\}[^{}]*)*\\}",
        RegexOptions.Compiled)]
    private static partial Regex VaultPayloadPattern();

    /// <summary>Base64-encoded PKCS#8/PKCS#1 DER, as Vault or Keycloak may store it without PEM armour.</summary>
    [GeneratedRegex("(?<=[\"'\\s:=,])(?:MII[A-Za-z0-9+/=\\r\\n]{200,})(?=[\"'\\s,}\\]]|$)", RegexOptions.Compiled)]
    private static partial Regex Base64DerPattern();

    /// <summary>True when a key names a secret, regardless of casing or separator.</summary>
    public static bool IsSensitive(string? key)
        => !string.IsNullOrEmpty(key) && SensitiveKeys.Contains(key.Replace('-', '_'));

    /// <summary>
    /// Strips bearer/basic credentials, compact JWTs, PEM private-key blocks, raw base64 DER key
    /// material, Vault KV payloads and secret key/value pairs from a message. Apply to every log line
    /// that could carry an inbound token, a signing key or a Keycloak/Vault response.
    /// </summary>
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

    /// <summary>Redacts the values of sensitive entries while preserving their key names.</summary>
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
        // Preserve the wrapper key name but mask every value inside the Vault "data" object.
        var open = match.IndexOf('{');
        var close = match.LastIndexOf('}');
        if (open < 0 || close <= open) return "[REDACTED]";
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

/// <summary>
/// Default sink that redacts detail values before delegating. Registration, provisioning,
/// linking and permission changes are recorded here; passwords, raw tokens, private keys and
/// Vault secrets are never accepted.
/// </summary>
public sealed class RedactingAuditSink(IAuditSink inner) : IAuditSink
{
    public Task RecordAsync(AuditEvent auditEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);
        var safe = new AuditEvent(
            SecretRedaction.Redact(auditEvent.Actor),
            auditEvent.Action,
            SecretRedaction.Redact(auditEvent.Target),
            auditEvent.OccurredAt,
            SecretRedaction.Redact(auditEvent.Details));
        return inner.RecordAsync(safe, cancellationToken);
    }
}

public sealed class NoopAuditSink : Identity.Application.IAuditSink
{
    public Task RecordAsync(Identity.Domain.AuditEvent auditEvent, CancellationToken cancellationToken) => Task.CompletedTask;
}
