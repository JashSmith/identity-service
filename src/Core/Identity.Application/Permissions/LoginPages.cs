using System.Globalization;
using FluentValidation;
using Identity.Contracts;

namespace Identity.Application.Permissions;

/// <summary>
/// Per-application login pages, stored on the application's Keycloak client: the <c>login_theme</c> attribute,
/// the <c>iam.login.*</c> attributes read by the Avash theme, and <c>directAccessGrantsEnabled</c> for embedded login.
/// Errors: application.*, login_page.* or a Keycloak availability error.
/// </summary>
public interface IApplicationLoginPages
{
    Task<Result<ApplicationLoginPageDto>> GetLoginPageAsync(string clientId, CancellationToken ct);
    Task<Result<ApplicationLoginPageDto>> SetLoginPageAsync(string clientId, UpdateLoginPageRequest request, CancellationToken ct);
    Task<Result<LoginThemesDto>> ListLoginThemesAsync(CancellationToken ct);
}

/// <summary>Client attribute names shared by the gateway and the Avash Keycloak theme (keycloak/themes/avash).</summary>
public static class LoginPageAttributes
{
    /// <summary>The installed theme that understands the branding attributes.</summary>
    public const string BrandedTheme = "avash";

    public const string Mode = "iam.login.mode";
    public const string Title = "iam.login.title";
    public const string Subtitle = "iam.login.subtitle";
    public const string LogoUrl = "iam.login.logo_url";
    public const string PrimaryColor = "iam.login.primary_color";
    public const string Background = "iam.login.background";
    public const string Theme = "login_theme";

    public static readonly string[] Backgrounds = ["pattern", "plain", "gradient"];
}

public sealed class UpdateLoginPageRequestValidator : AbstractValidator<UpdateLoginPageRequest>
{
    public UpdateLoginPageRequestValidator()
    {
        RuleFor(r => r.Mode).Must(m => LoginPageModes.All.Contains(m))
            .WithMessage("Mode is inherit, branded, theme or embedded.");
        RuleFor(r => r.Theme).NotEmpty().Matches("^[A-Za-z0-9._-]{1,60}$")
            .When(r => r.Mode == LoginPageModes.Theme)
            .WithMessage("Theme is the name of an installed Keycloak login theme.");
        RuleFor(r => r.Branding!).SetValidator(new LoginPageBrandingValidator()).When(r => r.Branding is not null);
    }
}

public sealed class LoginPageBrandingValidator : AbstractValidator<LoginPageBrandingDto>
{
    /// <summary>Buttons show white text on the primary colour: WCAG AA for large text (3:1) at least.</summary>
    public const double MinimumContrastWithWhite = 3.0;

    public LoginPageBrandingValidator()
    {
        RuleFor(b => b.Title).MaximumLength(60).Must(PlainText).WithMessage("Title is plain text without < > or control characters.");
        RuleFor(b => b.Subtitle).MaximumLength(160).Must(PlainText).WithMessage("Subtitle is plain text without < > or control characters.");
        RuleFor(b => b.LogoUrl).MaximumLength(500).Must(SafeHttpsUrl!)
            .When(b => !string.IsNullOrEmpty(b.LogoUrl))
            .WithMessage("Logo is an https URL without spaces, quotes or parentheses.");
        RuleFor(b => b.PrimaryColor).Matches("^#[0-9A-Fa-f]{6}$")
            .When(b => !string.IsNullOrEmpty(b.PrimaryColor))
            .WithMessage("Colour is #RRGGBB.");
        RuleFor(b => b.PrimaryColor).Must(c => ContrastWithWhite(c!) >= MinimumContrastWithWhite)
            .When(b => b.PrimaryColor is { Length: 7 } c && c[0] == '#' && c.Skip(1).All(Uri.IsHexDigit))
            .WithMessage("Colour is too light: white button text on it would be hard to read (contrast below 3:1).");
        RuleFor(b => b.Background).Must(v => LoginPageAttributes.Backgrounds.Contains(v))
            .WithMessage("Background is pattern, plain or gradient.");
    }

    private static bool PlainText(string? text) =>
        text is null || !text.Any(c => c is '<' or '>' || char.IsControl(c));

    private static bool SafeHttpsUrl(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps &&
        !url.Any(c => char.IsWhiteSpace(c) || c is '"' or '\'' or '(' or ')' or '\\' or '<' or '>');

    /// <summary>WCAG 2 contrast ratio of #RRGGBB against white.</summary>
    public static double ContrastWithWhite(string hex)
    {
        double Channel(int start)
        {
            var c = int.Parse(hex.AsSpan(start, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture) / 255.0;
            return c <= 0.03928 ? c / 12.92 : Math.Pow((c + 0.055) / 1.055, 2.4);
        }

        var luminance = 0.2126 * Channel(1) + 0.7152 * Channel(3) + 0.0722 * Channel(5);
        return 1.05 / (luminance + 0.05);
    }
}
