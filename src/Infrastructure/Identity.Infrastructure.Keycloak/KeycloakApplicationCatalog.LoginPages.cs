using System.Text.Json;
using Identity.Application;
using Identity.Application.Permissions;
using Identity.Contracts;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Login pages of applications, on the Keycloak client: <c>login_theme</c>, the <c>iam.login.*</c> branding attributes
/// (read by keycloak/themes/avash/login/footer.ftl) and <c>directAccessGrantsEnabled</c> for embedded login.
/// Installed themes come from <c>GET /admin/serverinfo</c>.
/// </summary>
public sealed partial class KeycloakApplicationCatalog : IApplicationLoginPages
{
    private static readonly string[] BrandingAttributes =
    [
        LoginPageAttributes.Title, LoginPageAttributes.Subtitle, LoginPageAttributes.LogoUrl,
        LoginPageAttributes.PrimaryColor, LoginPageAttributes.Background,
    ];

    public async Task<Result<ApplicationLoginPageDto>> GetLoginPageAsync(string clientId, CancellationToken ct)
    {
        var client = await FindApplicationAsync(clientId, ct);
        return client.IsSuccess ? ToLoginPage(client.Value.Representation) : client.Error!;
    }

    public async Task<Result<ApplicationLoginPageDto>> SetLoginPageAsync(string clientId, UpdateLoginPageRequest request, CancellationToken ct)
    {
        // The gateway's own clients keep their sign-in setup (the gateway client needs direct grants for its login API).
        if (ReservedApplications.Contains(clientId, StringComparer.Ordinal))
            return Error.Validation("login_page.reserved", $"Application '{clientId}' is used by the gateway; its login page cannot be changed.");
        var client = await FindApplicationAsync(clientId, ct);
        if (!client.IsSuccess) return client.Error!;

        if (request.Mode == LoginPageModes.Theme)
        {
            var themes = await ListLoginThemesAsync(ct);
            if (!themes.IsSuccess) return themes.Error!;
            if (!themes.Value.Themes.Contains(request.Theme, StringComparer.Ordinal))
                return Error.Validation("login_page.unknown_theme", $"Keycloak has no login theme '{request.Theme}'.");
        }

        var representation = JsonSerializer.Deserialize<Dictionary<string, object?>>(client.Value.Representation.GetRawText())!;
        var attributes = Attributes(client.Value.Representation)
            .ToDictionary(kv => kv.Key, kv => (object?)(kv.Value.Length > 0 ? kv.Value[0] : ""));
        var previousMode = ToLoginPage(client.Value.Representation).Mode;

        attributes[LoginPageAttributes.Mode] = request.Mode;
        attributes[LoginPageAttributes.Theme] = request.Mode switch
        {
            LoginPageModes.Branded => LoginPageAttributes.BrandedTheme,
            LoginPageModes.Theme => request.Theme!,
            _ => "", // inherit and embedded: the organisation's theme (embedded apps rarely show it, e.g. for password reset)
        };
        // Branding is kept when switching away, so switching back restores it.
        if (request.Branding is { } b)
        {
            attributes[LoginPageAttributes.Title] = b.Title?.Trim() ?? "";
            attributes[LoginPageAttributes.Subtitle] = b.Subtitle?.Trim() ?? "";
            attributes[LoginPageAttributes.LogoUrl] = b.LogoUrl ?? "";
            attributes[LoginPageAttributes.PrimaryColor] = b.PrimaryColor?.ToUpperInvariant() ?? "";
            attributes[LoginPageAttributes.Background] = b.Background;
        }
        representation["attributes"] = attributes;

        // Embedded login is the password grant with the application's own credentials; only that mode enables it,
        // and leaving that mode disables it again. Other transitions leave the flag as the administrator set it.
        if (request.Mode == LoginPageModes.Embedded) representation["directAccessGrantsEnabled"] = true;
        else if (previousMode == LoginPageModes.Embedded) representation["directAccessGrantsEnabled"] = false;

        var updated = await _api.SendWithoutResultAsync(HttpMethod.Put, $"clients/{Uri.EscapeDataString(client.Value.Uuid)}",
            representation, "application", ct, includeKeycloakMessage: true);
        return updated.IsSuccess ? await GetLoginPageAsync(clientId, ct) : updated.Error!;
    }

    public async Task<Result<LoginThemesDto>> ListLoginThemesAsync(CancellationToken ct)
    {
        var info = await _api.GetAsync("/serverinfo", "login_page", ct);
        if (!info.IsSuccess) return info.Error!;
        var names = new List<string>();
        if (info.Value.TryGetProperty("themes", out var themes) && themes.TryGetProperty("login", out var login) &&
            login.ValueKind == JsonValueKind.Array)
            foreach (var theme in login.EnumerateArray())
                if (KeycloakAdminApi.GetString(theme, "name") is { Length: > 0 } name) names.Add(name);
        names.Sort(StringComparer.Ordinal);
        return new LoginThemesDto(names, LoginPageAttributes.BrandedTheme);
    }

    /// <summary>Reads the login page from a client representation (pure; public for tests).</summary>
    public static ApplicationLoginPageDto ToLoginPage(JsonElement client)
    {
        var attributes = Attributes(client);
        var theme = First(attributes, LoginPageAttributes.Theme);
        var mode = First(attributes, LoginPageAttributes.Mode) is { } m && LoginPageModes.All.Contains(m)
            ? m
            // Applications created before login modes existed: an explicit theme is a custom theme.
            : theme is null ? LoginPageModes.Inherit : LoginPageModes.Theme;
        var background = First(attributes, LoginPageAttributes.Background);
        var branding = new LoginPageBrandingDto(
            First(attributes, LoginPageAttributes.Title),
            First(attributes, LoginPageAttributes.Subtitle),
            First(attributes, LoginPageAttributes.LogoUrl),
            First(attributes, LoginPageAttributes.PrimaryColor),
            background is not null && LoginPageAttributes.Backgrounds.Contains(background) ? background : "pattern");
        var directLogin = client.TryGetProperty("directAccessGrantsEnabled", out var d) && d.ValueKind == JsonValueKind.True;
        return new ApplicationLoginPageDto(KeycloakAdminApi.GetString(client, "clientId") ?? "", mode, theme, branding, directLogin);
    }
}
