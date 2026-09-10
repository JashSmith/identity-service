using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Identity.Application;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Creates Keycloak realm roles for registered permissions via the Admin REST API.
/// Uses the same admin-token bootstrap as <see cref="KeycloakDirectoryAdapter"/>.
/// Never throws — all failures are logged and swallowed so that role provisioning
/// never blocks permission registration or application startup.
/// </summary>
public sealed class KeycloakRoleProvisioner(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    ILogger<KeycloakRoleProvisioner> logger) : IKeycloakRoleProvisioner
{
    private readonly KeycloakOptions _o = opts.Value;
    private string AdminBase => $"{_o.BaseUrl.TrimEnd('/')}/admin/realms";

    private async Task<string> GetAdminTokenAsync(CancellationToken ct)
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
            catch
            {
                return string.Empty;
            }
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
            catch
            {
                return string.Empty;
            }
        }

        return string.Empty;
    }

    public async Task<bool> EnsureRoleAsync(string name, string? description, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;

        var token = await GetAdminTokenAsync(ct);
        if (string.IsNullOrEmpty(token))
        {
            logger.LogWarning("Cannot provision Keycloak role {RoleName}: admin token unavailable", name);
            return false;
        }

        // Check if the role already exists — GET returns 200 + role body.
        try
        {
            var getReq = new HttpRequestMessage(HttpMethod.Get,
                $"{AdminBase}/{_o.Realm}/roles/{Uri.EscapeDataString(name)}");
            getReq.Headers.Add("Authorization", $"Bearer {token}");
            var getRes = await http.SendAsync(getReq, ct);
            if (getRes.IsSuccessStatusCode)
            {
                // Role already exists — nothing to do.
                return true;
            }
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Error checking role {RoleName} existence", name);
        }

        // Create the role.
        try
        {
            var body = new { name, description = description ?? $"Permission: {name}" };
            var postReq = new HttpRequestMessage(HttpMethod.Post, $"{AdminBase}/{_o.Realm}/roles")
            {
                Content = JsonContent.Create(body)
            };
            postReq.Headers.Add("Authorization", $"Bearer {token}");
            var postRes = await http.SendAsync(postReq, ct);
            if (postRes.IsSuccessStatusCode || postRes.StatusCode == HttpStatusCode.Conflict)
            {
                logger.LogDebug("Keycloak role {RoleName} provisioned (status {Status})", name, postRes.StatusCode);
                return true;
            }

            logger.LogWarning("Failed to provision Keycloak role {RoleName}: HTTP {Status}", name, postRes.StatusCode);
            return false;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to provision Keycloak role {RoleName}", name);
            return false;
        }
    }
}
