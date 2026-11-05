using System.Text.Json;
using Identity.Application;
using Identity.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// User lifecycle on the Keycloak Admin API: <c>attack-detection/brute-force/users/{id}</c>,
/// <c>users/{id}/credentials</c>, <c>authentication/required-actions</c> and
/// <c>users/{id}/execute-actions-email</c>.
/// </summary>
public sealed class KeycloakUserLifecycleAdapter(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakUserLifecycleAdapter>? logger = null) : IUserLifecycleService
{
    private const string Resource = "user";
    private readonly KeycloakAdminApi _api = new(http, opts.Value, tokenProvider, (ILogger?)logger ?? NullLogger.Instance);

    private static string UserPath(string id) => $"users/{Uri.EscapeDataString(id)}";

    private static Error UserNotFound(string id) => Error.NotFound("user.not_found", $"User '{id}' was not found.");

    private static Error Renamed(Error error, string userId) =>
        error.Kind == ErrorKind.NotFound ? UserNotFound(userId) : error;

    public async Task<Result<UserLockoutDto>> GetLockoutAsync(string userId, CancellationToken ct)
    {
        // The brute-force endpoint answers for unknown ids too, so the user is read first.
        var user = await _api.GetAsync(UserPath(userId), Resource, ct);
        if (!user.IsSuccess) return Renamed(user.Error!, userId);

        var status = await _api.GetAsync($"attack-detection/brute-force/users/{Uri.EscapeDataString(userId)}", Resource, ct);
        if (!status.IsSuccess) return status.Error!;
        var s = status.Value;
        var locked = s.TryGetProperty("disabled", out var d) && d.ValueKind == JsonValueKind.True;
        var failures = s.TryGetProperty("numFailures", out var n) && n.ValueKind == JsonValueKind.Number ? n.GetInt32() : 0;
        DateTimeOffset? lastFailure = s.TryGetProperty("lastFailure", out var lf) && lf.ValueKind == JsonValueKind.Number && lf.GetInt64() > 0
            ? DateTimeOffset.FromUnixTimeMilliseconds(lf.GetInt64())
            : null;
        var ip = KeycloakAdminApi.GetString(s, "lastIPFailure");
        return new UserLockoutDto(locked, failures, lastFailure, ip is null or "n/a" ? null : ip);
    }

    public async Task<Result> UnlockAsync(string userId, CancellationToken ct)
    {
        var user = await _api.GetAsync(UserPath(userId), Resource, ct);
        if (!user.IsSuccess) return Renamed(user.Error!, userId);
        return await _api.SendWithoutResultAsync(HttpMethod.Delete,
            $"attack-detection/brute-force/users/{Uri.EscapeDataString(userId)}", null, Resource, ct);
    }

    public async Task<Result<IReadOnlyCollection<UserCredentialDto>>> GetCredentialsAsync(string userId, CancellationToken ct)
    {
        var credentials = await _api.GetAsync($"{UserPath(userId)}/credentials", Resource, ct);
        if (!credentials.IsSuccess) return Renamed(credentials.Error!, userId);
        if (credentials.Value.ValueKind != JsonValueKind.Array) return Array.Empty<UserCredentialDto>();

        // Only metadata is mapped; secretData/credentialData never leave the gateway.
        return credentials.Value.EnumerateArray()
            .Select(c => new UserCredentialDto(
                KeycloakAdminApi.GetString(c, "id") ?? "",
                KeycloakAdminApi.GetString(c, "type") ?? "",
                KeycloakAdminApi.GetString(c, "userLabel"),
                c.TryGetProperty("createdDate", out var created) && created.ValueKind == JsonValueKind.Number
                    ? DateTimeOffset.FromUnixTimeMilliseconds(created.GetInt64())
                    : null))
            .Where(c => c.Id.Length > 0)
            .ToArray();
    }

    public async Task<Result> DeleteCredentialAsync(string userId, string credentialId, CancellationToken ct)
    {
        var credentials = await GetCredentialsAsync(userId, ct);
        if (!credentials.IsSuccess) return credentials.Error!;
        if (credentials.Value.All(c => c.Id != credentialId))
            return Error.NotFound("credential.not_found", $"User '{userId}' has no credential '{credentialId}'.");
        return await _api.SendWithoutResultAsync(HttpMethod.Delete,
            $"{UserPath(userId)}/credentials/{Uri.EscapeDataString(credentialId)}", null, Resource, ct);
    }

    public async Task<Result<IReadOnlyCollection<RequiredActionDto>>> GetRequiredActionCatalogAsync(CancellationToken ct)
    {
        var actions = await _api.GetAsync("authentication/required-actions", "required_action", ct);
        if (!actions.IsSuccess) return actions.Error!;
        if (actions.Value.ValueKind != JsonValueKind.Array) return Array.Empty<RequiredActionDto>();
        return actions.Value.EnumerateArray()
            .Select(a => new RequiredActionDto(
                KeycloakAdminApi.GetString(a, "alias") ?? "",
                KeycloakAdminApi.GetString(a, "name") ?? "",
                a.TryGetProperty("enabled", out var e) && e.ValueKind == JsonValueKind.True))
            .Where(a => a.Alias.Length > 0)
            .ToArray();
    }

    public async Task<Result<IReadOnlyCollection<string>>> GetRequiredActionsAsync(string userId, CancellationToken ct)
    {
        var user = await _api.GetAsync(UserPath(userId), Resource, ct);
        if (!user.IsSuccess) return Renamed(user.Error!, userId);
        return Result<IReadOnlyCollection<string>>.Success(ReadActions(user.Value));
    }

    public async Task<Result> SetRequiredActionsAsync(string userId, IReadOnlyCollection<string> actions, CancellationToken ct)
    {
        var known = await EnsureEnabledActionsAsync(actions, ct);
        if (!known.IsSuccess) return known;

        var current = await _api.GetAsync(UserPath(userId), Resource, ct);
        if (!current.IsSuccess) return Renamed(current.Error!, userId);

        // PUT replaces the representation, so the current one is sent back with only requiredActions changed.
        var user = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(current.Value.GetRawText())!
            .ToDictionary(kv => kv.Key, kv => (object?)kv.Value, StringComparer.Ordinal);
        user["requiredActions"] = actions.Distinct(StringComparer.Ordinal).ToArray();
        var updated = await _api.SendWithoutResultAsync(HttpMethod.Put, UserPath(userId), user, Resource, ct, includeKeycloakMessage: true);
        return updated.IsSuccess ? updated : Renamed(updated.Error!, userId);
    }

    public async Task<Result> SendActionsEmailAsync(string userId, SendActionsEmailRequest request, CancellationToken ct)
    {
        var known = await EnsureEnabledActionsAsync(request.Actions, ct);
        if (!known.IsSuccess) return known;

        var query = new List<string>();
        if (request.LifespanSeconds is { } lifespan) query.Add($"lifespan={lifespan}");
        if (!string.IsNullOrWhiteSpace(request.ClientId)) query.Add($"client_id={Uri.EscapeDataString(request.ClientId)}");
        if (!string.IsNullOrWhiteSpace(request.RedirectUri)) query.Add($"redirect_uri={Uri.EscapeDataString(request.RedirectUri)}");
        var path = $"{UserPath(userId)}/execute-actions-email" + (query.Count > 0 ? "?" + string.Join('&', query) : "");

        var sent = await _api.SendWithoutResultAsync(HttpMethod.Put, path, request.Actions.Distinct(StringComparer.Ordinal).ToArray(),
            Resource, ct, includeKeycloakMessage: true);
        if (sent.IsSuccess) return sent;
        // Keycloak answers 500 when the realm has no working SMTP server; say so instead of "unavailable".
        return sent.Error!.Code == "keycloak.error"
            ? Error.Upstream("user.email_not_sent", "Keycloak could not send the email; check the realm's SMTP settings.")
            : Renamed(sent.Error!, userId);
    }

    private async Task<Result> EnsureEnabledActionsAsync(IReadOnlyCollection<string> actions, CancellationToken ct)
    {
        var catalog = await GetRequiredActionCatalogAsync(ct);
        if (!catalog.IsSuccess) return catalog.Error!;
        var enabled = catalog.Value.Where(a => a.Enabled).Select(a => a.Alias).ToHashSet(StringComparer.Ordinal);
        var unknown = actions.Where(a => !enabled.Contains(a)).Distinct(StringComparer.Ordinal).ToArray();
        return unknown.Length == 0
            ? Result.Success()
            : Error.Validation("user.unknown_required_action",
                $"Not an enabled required action of the realm: {string.Join(", ", unknown)}.");
    }

    private static IReadOnlyCollection<string> ReadActions(JsonElement user) =>
        user.TryGetProperty("requiredActions", out var a) && a.ValueKind == JsonValueKind.Array
            ? a.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToArray()
            : [];
}
