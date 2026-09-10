
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Company.Identity.PermissionRegistration;

/// <summary>
/// Client-side representation of the <c>POST /api/identity/permissions/register</c> response.
/// Decoupled from <c>Identity.Contracts</c> so external consumers of this package do not
/// need a reference to the facade's contract assembly.
/// </summary>
public sealed record RegistrationResponse(
    string ServiceId,
    string ManifestVersion,
    string ManifestHash,
    bool Accepted,
    IReadOnlyCollection<string> DeprecatedPermissions);

/// <summary>
/// HTTP client that discovers permissions from a given assembly and registers them with
/// the Identity Facade. Handles client-credentials token acquisition from Keycloak.
/// Designed for use by external services at startup.
/// </summary>
public interface IPermissionRegistrationClient
{
    /// <summary>
    /// Sends the permission manifest to the Identity Facade and returns the response.
    /// Returns <c>null</c> on transient failure (caller should retry).
    /// </summary>
    Task<RegistrationResponse?> RegisterAsync(PermissionManifest manifest, CancellationToken ct);
}

internal sealed class PermissionRegistrationClient(
    HttpClient http,
    IOptions<PermissionRegistrationOptions> opts) : IPermissionRegistrationClient
{
    private readonly PermissionRegistrationOptions _o = opts.Value;

    private static readonly JsonSerializerOptions s_jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public async Task<RegistrationResponse?> RegisterAsync(PermissionManifest manifest, CancellationToken ct)
    {
        var token = await GetAccessTokenAsync(ct);
        if (string.IsNullOrEmpty(token)) return null;

        var registerUrl = $"{_o.IdentityServer.ToString().TrimEnd('/')}/api/identity/permissions/register";

        try
        {
            var req = new HttpRequestMessage(HttpMethod.Post, registerUrl)
            {
                Content = JsonContent.Create(manifest, options: s_jsonOptions)
            };
            req.Headers.Add("Authorization", $"Bearer {token}");

            var res = await http.SendAsync(req, ct);
            if (res.IsSuccessStatusCode)
            {
                return await res.Content.ReadFromJsonAsync<RegistrationResponse>(s_jsonOptions, ct);
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private async Task<string> GetAccessTokenAsync(CancellationToken ct)
    {
        if (string.IsNullOrEmpty(_o.KeycloakBaseUrl) ||
            string.IsNullOrEmpty(_o.KeycloakClientId) ||
            string.IsNullOrEmpty(_o.KeycloakClientSecret))
        {
            return string.Empty;
        }

        var tokenUrl =
            $"{_o.KeycloakBaseUrl.TrimEnd('/')}/realms/{_o.KeycloakRealm}/protocol/openid-connect/token";

        try
        {
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = _o.KeycloakClientId,
                ["client_secret"] = _o.KeycloakClientSecret,
            });
            var res = await http.PostAsync(tokenUrl, form, ct);
            if (!res.IsSuccessStatusCode) return string.Empty;
            var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
            return doc.RootElement.TryGetProperty("access_token", out var t)
                ? t.GetString() ?? string.Empty
                : string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }
}
