using FluentValidation;
using Identity.Contracts;

namespace Identity.Application.Permissions;

/// <summary>Sign-out settings on the application's Keycloak client. Errors: application.* or a Keycloak availability error.</summary>
public interface IApplicationLogoutSettings
{
    Task<Result<ApplicationLogoutDto>> GetLogoutAsync(string clientId, CancellationToken ct);
    Task<Result<ApplicationLogoutDto>> SetLogoutAsync(string clientId, ApplicationLogoutDto settings, CancellationToken ct);
}

public sealed class ApplicationLogoutValidator : AbstractValidator<ApplicationLogoutDto>
{
    public ApplicationLogoutValidator()
    {
        RuleFor(s => s.PostLogoutRedirectUris).Must(u => u.Count <= 20).WithMessage("At most 20 post-logout URLs.");
        RuleForEach(s => s.PostLogoutRedirectUris).Must(HttpUrl).WithMessage("Post-logout URLs are absolute http(s) URLs.");
        RuleFor(s => s.BackchannelLogoutUrl).Must(u => HttpUrl(u!)).When(s => !string.IsNullOrEmpty(s.BackchannelLogoutUrl))
            .WithMessage("The back-channel logout URL is an absolute http(s) URL Keycloak can reach.");
    }

    private static bool HttpUrl(string url) =>
        url.Length <= 500 && Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
        (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp) && !url.Contains("##", StringComparison.Ordinal);
}
