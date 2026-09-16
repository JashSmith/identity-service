using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

public sealed class KeycloakAdminTokenProvider(HttpClient http, IOptions<KeycloakOptions> opts)
{
    private readonly KeycloakOptions _o = opts.Value;

    public async Task<string> GetTokenAsync(CancellationToken ct)
    {
        if (!string.IsNullOrEmpty(_o.AdminClientSecret))
        {
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = _o.AdminClientId,
                ["client_secret"] = _o.AdminClientSecret,
            });
            try
            {
                var res = await http.PostAsync(
                    $"{_o.BaseUrl.TrimEnd('/')}/realms/master/protocol/openid-connect/token", form, ct);
                if (!res.IsSuccessStatusCode) return string.Empty;
                var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
                return doc.RootElement.TryGetProperty("access_token", out var t)
                    ? t.GetString() ?? string.Empty
                    : string.Empty;
            }
            catch { return string.Empty; }
        }

        if (!string.IsNullOrEmpty(_o.AdminUsername) && !string.IsNullOrEmpty(_o.AdminPassword))
        {
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["client_id"] = _o.AdminClientId,
                ["username"] = _o.AdminUsername,
                ["password"] = _o.AdminPassword,
            });
            try
            {
                var res = await http.PostAsync(
                    $"{_o.BaseUrl.TrimEnd('/')}/realms/master/protocol/openid-connect/token", form, ct);
                if (!res.IsSuccessStatusCode) return string.Empty;
                var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct));
                return doc.RootElement.TryGetProperty("access_token", out var t)
                    ? t.GetString() ?? string.Empty
                    : string.Empty;
            }
            catch { return string.Empty; }
        }

        return string.Empty;
    }
}
