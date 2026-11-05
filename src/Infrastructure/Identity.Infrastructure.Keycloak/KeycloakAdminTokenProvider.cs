using System.Collections.Concurrent;
using System.Text.Json;
using Identity.Application;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Obtains Admin REST API tokens for the gateway's service account: the client_credentials grant
/// of a confidential client inside the tenant realm (never the master realm superuser).
/// Tokens are cached until shortly before they expire, so one Keycloak round-trip serves many
/// admin calls. Returns an empty string when no token can be obtained; the failure is logged.
/// </summary>
public sealed class KeycloakAdminTokenProvider(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenCache? cache = null,
    TimeProvider? time = null,
    ILogger<KeycloakAdminTokenProvider>? logger = null)
{
    private readonly KeycloakOptions _default = opts.Value;

    /// <summary>The current tenant's realm and service account (see <see cref="KeycloakTenant"/>).</summary>
    private KeycloakOptions Current => KeycloakTenant.Resolve(_default);
    private readonly KeycloakAdminTokenCache _cache = cache ?? new KeycloakAdminTokenCache();
    private readonly TimeProvider _time = time ?? TimeProvider.System;

    public async Task<string> GetTokenAsync(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(Current.AdminClientId) || string.IsNullOrWhiteSpace(Current.AdminClientSecret))
        {
            logger?.LogError(
                "Keycloak admin client is not configured; set Identity:KeycloakAdmin:AdminClientId and AdminClientSecret.");
            return string.Empty;
        }

        var key = $"{Current.BaseUrl.TrimEnd('/')}|{Current.Realm}|{Current.AdminClientId}";
        var tenant = Current;
        return await _cache.GetOrRefreshAsync(key, _time, token => RequestTokenAsync(tenant, token), ct);
    }

    /// <summary>Like <see cref="GetTokenAsync"/>, but reports a missing token as an error.</summary>
    public async Task<Result<string>> GetTokenResultAsync(CancellationToken ct)
    {
        var token = await GetTokenAsync(ct);
        return string.IsNullOrEmpty(token) ? KeycloakErrors.AdminTokenUnavailable : token;
    }

    private async Task<AdminToken?> RequestTokenAsync(KeycloakOptions tenant, CancellationToken ct)
    {
        var url = $"{tenant.BaseUrl.TrimEnd('/')}/realms/{Uri.EscapeDataString(tenant.Realm)}/protocol/openid-connect/token";
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = tenant.AdminClientId,
            ["client_secret"] = tenant.AdminClientSecret,
        });

        try
        {
            using var res = await http.PostAsync(url, form, ct);
            if (!res.IsSuccessStatusCode)
            {
                logger?.LogError("Keycloak admin token request for realm {Realm} failed with status {Status}",
                    tenant.Realm, (int)res.StatusCode);
                return null;
            }

            using var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            var token = doc.RootElement.TryGetProperty("access_token", out var t) ? t.GetString() : null;
            if (string.IsNullOrEmpty(token)) return null;

            var expiresIn = doc.RootElement.TryGetProperty("expires_in", out var e) && e.TryGetInt32(out var seconds)
                ? seconds
                : 60;
            return new AdminToken(token, TimeSpan.FromSeconds(expiresIn));
        }
        catch (HttpRequestException ex)
        {
            logger?.LogError(ex, "Keycloak admin token request for realm {Realm} could not reach Keycloak", tenant.Realm);
            return null;
        }
        catch (JsonException ex)
        {
            logger?.LogError(ex, "Keycloak admin token response for realm {Realm} was not valid JSON", tenant.Realm);
            return null;
        }
    }
}

/// <summary>An access token and how long Keycloak says it is valid.</summary>
public sealed record AdminToken(string Value, TimeSpan Lifetime);

/// <summary>
/// Process-wide cache of admin tokens, keyed by Keycloak instance, realm and client. Register it as
/// a singleton; the token provider itself is a transient typed HttpClient.
/// </summary>
public sealed class KeycloakAdminTokenCache
{
    // Refresh before expiry so a token never expires between being handed out and being used.
    private static readonly TimeSpan RefreshMargin = TimeSpan.FromSeconds(30);

    private readonly ConcurrentDictionary<string, (string Token, DateTimeOffset RefreshAt)> _tokens = new();
    private readonly SemaphoreSlim _refreshGate = new(1, 1);

    public async Task<string> GetOrRefreshAsync(
        string key, TimeProvider time, Func<CancellationToken, Task<AdminToken?>> fetch, CancellationToken ct)
    {
        if (TryGetValid(key, time, out var cached)) return cached;

        await _refreshGate.WaitAsync(ct);
        try
        {
            // Another caller may have refreshed while this one waited.
            if (TryGetValid(key, time, out cached)) return cached;

            var fresh = await fetch(ct);
            if (fresh is null) return string.Empty;

            var cacheFor = fresh.Lifetime > RefreshMargin * 2 ? fresh.Lifetime - RefreshMargin : fresh.Lifetime / 2;
            _tokens[key] = (fresh.Value, time.GetUtcNow() + cacheFor);
            return fresh.Value;
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    private bool TryGetValid(string key, TimeProvider time, out string token)
    {
        if (_tokens.TryGetValue(key, out var entry) && time.GetUtcNow() < entry.RefreshAt)
        {
            token = entry.Token;
            return true;
        }

        token = string.Empty;
        return false;
    }
}
