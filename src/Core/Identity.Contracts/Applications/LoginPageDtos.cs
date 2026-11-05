namespace Identity.Contracts;

/// <summary>
/// How users of an application sign in.
/// <list type="bullet">
/// <item><c>inherit</c>: the organisation's central login page (realm theme), shared by every application.</item>
/// <item><c>branded</c>: the central login page with the application's own logo, colour and texts (theme "avash").</item>
/// <item><c>theme</c>: a fully custom Keycloak login theme installed on the server.</item>
/// <item><c>embedded</c>: the application shows its own form and calls the gateway's direct login API (no SSO).</item>
/// </list>
/// The first three keep single sign-on across applications of the organisation.
/// </summary>
public static class LoginPageModes
{
    public const string Inherit = "inherit";
    public const string Branded = "branded";
    public const string Theme = "theme";
    public const string Embedded = "embedded";

    public static readonly string[] All = [Inherit, Branded, Theme, Embedded];
}

/// <summary>Look of a branded login page. Null fields fall back to the organisation's defaults.</summary>
/// <param name="Title">Shown at the top of the login card, e.g. the application's name.</param>
/// <param name="Subtitle">One line under the title, e.g. a welcome text.</param>
/// <param name="LogoUrl">An https URL of the logo image.</param>
/// <param name="PrimaryColor">#RRGGBB for buttons and links; white text on it must stay readable.</param>
/// <param name="Background">pattern (girih), plain or gradient.</param>
public sealed record LoginPageBrandingDto(
    string? Title = null,
    string? Subtitle = null,
    string? LogoUrl = null,
    string? PrimaryColor = null,
    string Background = "pattern");

/// <summary>An application's login page.</summary>
/// <param name="Theme">The Keycloak login theme in use (empty: the organisation's theme).</param>
/// <param name="DirectLogin">Whether the application may sign users in with the direct login API (true in embedded mode).</param>
public sealed record ApplicationLoginPageDto(string ClientId, string Mode, string? Theme, LoginPageBrandingDto Branding, bool DirectLogin);

/// <param name="Theme">Required for mode "theme": the name of an installed Keycloak login theme.</param>
public sealed record UpdateLoginPageRequest(string Mode, string? Theme = null, LoginPageBrandingDto? Branding = null);

/// <summary>Keycloak login themes installed on the server; "theme" mode may use any of them.</summary>
public sealed record LoginThemesDto(IReadOnlyList<string> Themes, string BrandedTheme);
