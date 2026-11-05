using System.Text.Json;
using Identity.Application;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>Settings of the admin console's OIDC client (<c>Identity:AdminConsole</c>).</summary>
public sealed class AdminConsoleClientOptions
{
    public string ClientId { get; set; } = "identity-admin-console";

    /// <summary>Empty disables the client (no console deployed).</summary>
    public string? ClientSecret { get; set; }

    /// <summary>Base URL of the console, e.g. <c>http://localhost:5090</c>.</summary>
    public string? BaseUrl { get; set; }

    public string LoginTheme { get; set; } = "avash";
}

/// <summary>
/// Keeps the admin console's confidential OIDC client (authorization code + PKCE) in the tenant realm in line
/// with the configuration: redirect URIs, secret, login theme and the claim scopes the gateway relies on.
/// Not an application: it has no permissions of its own and does not appear in the application catalog.
/// </summary>
public sealed class KeycloakAdminConsoleClient(
    HttpClient http,
    IOptions<KeycloakOptions> keycloak,
    IOptions<AdminConsoleClientOptions> console,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakAdminConsoleClient>? logger = null)
{
    private const string Resource = "admin_console";
    private static readonly string[] ClaimScopes = ["iam-access", "authz-scopes", "iam-permissions"];

    private readonly ILogger _logger = (ILogger?)logger ?? NullLogger.Instance;
    private readonly KeycloakAdminApi _api = new(http, keycloak.Value, tokenProvider, (ILogger?)logger ?? NullLogger.Instance);

    public async Task<Result> EnsureAsync(CancellationToken ct)
    {
        var o = console.Value;
        if (string.IsNullOrWhiteSpace(o.ClientSecret) || string.IsNullOrWhiteSpace(o.BaseUrl))
        {
            _logger.LogInformation("Admin console client not configured (Identity:AdminConsole); skipped");
            return Result.Success();
        }
        var baseUrl = o.BaseUrl.TrimEnd('/');

        var found = await _api.GetAsync($"clients?clientId={Uri.EscapeDataString(o.ClientId)}", Resource, ct);
        if (!found.IsSuccess) return found.Error!;
        var existing = found.Value.EnumerateArray().FirstOrDefault(c => KeycloakAdminApi.GetString(c, "clientId") == o.ClientId);

        var body = existing.ValueKind == JsonValueKind.Object
            ? JsonSerializer.Deserialize<Dictionary<string, object?>>(existing.GetRawText())!
            : new Dictionary<string, object?> { ["clientId"] = o.ClientId, ["protocol"] = "openid-connect" };
        body["name"] = "Identity admin console";
        body["enabled"] = true;
        body["publicClient"] = false;
        body["secret"] = o.ClientSecret;
        body["standardFlowEnabled"] = true;
        body["implicitFlowEnabled"] = false;
        body["directAccessGrantsEnabled"] = false;
        body["serviceAccountsEnabled"] = false;
        body["redirectUris"] = new[] { $"{baseUrl}/signin-oidc-*" };
        body["webOrigins"] = new[] { baseUrl };
        var attributes = existing.ValueKind == JsonValueKind.Object && existing.TryGetProperty("attributes", out var a) && a.ValueKind == JsonValueKind.Object
            ? JsonSerializer.Deserialize<Dictionary<string, string>>(a.GetRawText())!
            : new Dictionary<string, string>();
        attributes["pkce.code.challenge.method"] = "S256";
        attributes["post.logout.redirect.uris"] = $"{baseUrl}/signout-callback-oidc-*##{baseUrl}/*";
        attributes["login_theme"] = o.LoginTheme;
        body["attributes"] = attributes;

        string uuid;
        if (existing.ValueKind == JsonValueKind.Object)
        {
            uuid = KeycloakAdminApi.GetString(existing, "id")!;
            var updated = await _api.SendWithoutResultAsync(HttpMethod.Put, $"clients/{Uri.EscapeDataString(uuid)}", body, Resource, ct, includeKeycloakMessage: true);
            if (!updated.IsSuccess) return updated;
        }
        else
        {
            var created = await _api.CreateAsync("clients", body, Resource, ct, includeKeycloakMessage: true);
            if (!created.IsSuccess) return created.Error!;
            uuid = created.Value;
            _logger.LogInformation("Created the admin console client {ClientId}", o.ClientId);
        }
        var mappers = await EnsureMappersAsync(uuid, ct);
        return mappers.IsSuccess ? await EnsureClaimScopesAsync(uuid, ct) : mappers;
    }

    /// <summary>
    /// <c>sub</c> and <c>preferred_username</c> come from client mappers (like the gateway client's), because tenant
    /// realms do not necessarily have Keycloak's built-in profile/basic scopes.
    /// </summary>
    private async Task<Result> EnsureMappersAsync(string uuid, CancellationToken ct)
    {
        var path = $"clients/{Uri.EscapeDataString(uuid)}/protocol-mappers/models";
        var existing = await _api.GetAsync(path, Resource, ct);
        if (!existing.IsSuccess) return existing.Error!;
        var names = existing.Value.EnumerateArray().Select(m => KeycloakAdminApi.GetString(m, "name")).ToHashSet(StringComparer.Ordinal);

        foreach (var (name, attribute, claim) in new[] { ("subject-sub", "id", "sub"), ("username", "username", "preferred_username") })
        {
            if (names.Contains(name)) continue;
            var created = await _api.SendWithoutResultAsync(HttpMethod.Post, path, new
            {
                name,
                protocol = "openid-connect",
                protocolMapper = "oidc-usermodel-property-mapper",
                config = new Dictionary<string, string>
                {
                    ["user.attribute"] = attribute,
                    ["claim.name"] = claim,
                    ["jsonType.label"] = "String",
                    ["id.token.claim"] = "true",
                    ["access.token.claim"] = "true",
                    ["userinfo.token.claim"] = "true",
                },
            }, Resource, ct, includeKeycloakMessage: true);
            if (!created.IsSuccess) return created;
        }
        return Result.Success();
    }

    /// <summary>The console's tokens need the same claims as the gateway's: access, scopes and permissions.</summary>
    private async Task<Result> EnsureClaimScopesAsync(string uuid, CancellationToken ct)
    {
        var scopes = await _api.GetAsync("client-scopes", Resource, ct);
        if (!scopes.IsSuccess) return scopes.Error!;
        var path = $"clients/{Uri.EscapeDataString(uuid)}/default-client-scopes";
        var assigned = await _api.GetAsync(path, Resource, ct);
        if (!assigned.IsSuccess) return assigned.Error!;
        var have = assigned.Value.EnumerateArray().Select(s => KeycloakAdminApi.GetString(s, "name")).ToHashSet(StringComparer.Ordinal);

        foreach (var scope in scopes.Value.EnumerateArray().Where(s => ClaimScopes.Contains(KeycloakAdminApi.GetString(s, "name"))))
        {
            if (have.Contains(KeycloakAdminApi.GetString(scope, "name"))) continue;
            var added = await _api.SendWithoutResultAsync(HttpMethod.Put,
                $"{path}/{Uri.EscapeDataString(KeycloakAdminApi.GetString(scope, "id")!)}", null, Resource, ct);
            if (!added.IsSuccess) return added;
        }
        return Result.Success();
    }
}
