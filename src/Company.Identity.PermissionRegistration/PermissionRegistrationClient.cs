using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Company.Identity.PermissionRegistration;

/// <summary>
/// Client-side representation of the <c>POST /api/identity/permissions/register</c> response.
/// Decoupled from <c>Identity.Contracts</c> so external consumers of this package never need
/// a reference to the facade's contract assembly.
/// </summary>
public sealed record RegistrationResponse(
    string ServiceId,
    string ManifestVersion,
    string ManifestHash,
    bool Accepted,
    IReadOnlyCollection<string> DeprecatedPermissions);

/// <summary>
/// Registers discovered permissions with the Identity Facade. The service token is obtained
/// <b>through the facade's own auth proxy</b> (<c>POST /api/identity/auth/login</c>) with the
/// client-credentials grant — the consuming service never needs to know where Keycloak is.
/// Returns <c>null</c> on transient failure (caller retries).
/// </summary>
public interface IPermissionRegistrationClient
{
    Task<RegistrationResponse?> RegisterAsync(PermissionManifest manifest, CancellationToken ct);
}

internal sealed class PermissionRegistrationClient(
    HttpClient http,
    IOptions<PermissionRegistrationOptions> opts) : IPermissionRegistrationClient
{
    private readonly PermissionRegistrationOptions _o = opts.Value;

    private static readonly JsonSerializerOptions s_json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public async Task<RegistrationResponse?> RegisterAsync(PermissionManifest manifest, CancellationToken ct)
    {
        var token = await GetTokenViaFacadeAsync(ct);
        if (string.IsNullOrEmpty(token)) return null;

        var registerUrl = $"{_o.IdentityServer.ToString().TrimEnd('/')}/api/identity/permissions/register";
        try
        {
            var req = new HttpRequestMessage(HttpMethod.Post, registerUrl)
            {
                Content = JsonContent.Create(manifest, options: s_json)
            };
            req.Headers.Add("Authorization", $"Bearer {token}");
            var res = await http.SendAsync(req, ct);
            return res.IsSuccessStatusCode
                ? await res.Content.ReadFromJsonAsync<RegistrationResponse>(s_json, ct)
                : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// POSTs the client-credentials grant to the facade's login proxy, which forwards it to
    /// Keycloak. Only <c>IdentityServer</c>, <c>ClientId</c> and <c>ClientSecret</c> are needed —
    /// no Keycloak URL, realm, or secret is configured in the consuming service.
    /// </summary>
    private async Task<string> GetTokenViaFacadeAsync(CancellationToken ct)
    {
        if (string.IsNullOrEmpty(_o.ClientId) || string.IsNullOrEmpty(_o.ClientSecret)) return string.Empty;
        var loginUrl = $"{_o.IdentityServer.ToString().TrimEnd('/')}/api/identity/auth/login";
        try
        {
            var res = await http.PostAsync(loginUrl, new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = _o.ClientId,
                ["client_secret"] = _o.ClientSecret,
            }), ct);
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