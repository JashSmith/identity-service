using System.Text.Json;
using Identity.Application;
using Identity.Application.Permissions;
using Identity.Contracts;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Sign-out settings on the client: the standard Keycloak attributes <c>post.logout.redirect.uris</c> (joined with "##"),
/// <c>backchannel.logout.url</c> and <c>backchannel.logout.session.required</c> (so logout tokens carry the session id).
/// </summary>
public sealed partial class KeycloakApplicationCatalog : IApplicationLogoutSettings
{
    private const string PostLogoutAttribute = "post.logout.redirect.uris";
    private const string BackchannelUrlAttribute = "backchannel.logout.url";
    private const string BackchannelSessionAttribute = "backchannel.logout.session.required";

    public async Task<Result<ApplicationLogoutDto>> GetLogoutAsync(string clientId, CancellationToken ct)
    {
        var client = await FindApplicationAsync(clientId, ct);
        return client.IsSuccess ? ToLogout(client.Value.Representation) : client.Error!;
    }

    public async Task<Result<ApplicationLogoutDto>> SetLogoutAsync(string clientId, ApplicationLogoutDto settings, CancellationToken ct)
    {
        var client = await FindApplicationAsync(clientId, ct);
        if (!client.IsSuccess) return client.Error!;

        var representation = JsonSerializer.Deserialize<Dictionary<string, object?>>(client.Value.Representation.GetRawText())!;
        var attributes = Attributes(client.Value.Representation)
            .ToDictionary(kv => kv.Key, kv => (object?)(kv.Value.Length > 0 ? kv.Value[0] : ""));
        attributes[PostLogoutAttribute] = string.Join("##", settings.PostLogoutRedirectUris.Distinct(StringComparer.Ordinal));
        attributes[BackchannelUrlAttribute] = settings.BackchannelLogoutUrl ?? "";
        attributes[BackchannelSessionAttribute] = "true";
        representation["attributes"] = attributes;
        // Back-channel logout replaces the browser-based front-channel logout for this client.
        if (!string.IsNullOrEmpty(settings.BackchannelLogoutUrl)) representation["frontchannelLogout"] = false;

        var updated = await _api.SendWithoutResultAsync(HttpMethod.Put, $"clients/{Uri.EscapeDataString(client.Value.Uuid)}",
            representation, "application", ct, includeKeycloakMessage: true);
        return updated.IsSuccess ? await GetLogoutAsync(clientId, ct) : updated.Error!;
    }

    /// <summary>Reads the sign-out settings from a client representation (pure; public for tests).</summary>
    public static ApplicationLogoutDto ToLogout(JsonElement client)
    {
        var attributes = Attributes(client);
        var postLogout = (First(attributes, PostLogoutAttribute) ?? "")
            .Split("##", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(u => u != "+") // "+" means "same as the redirect URIs" in Keycloak's console
            .ToArray();
        return new ApplicationLogoutDto(postLogout, First(attributes, BackchannelUrlAttribute));
    }
}
