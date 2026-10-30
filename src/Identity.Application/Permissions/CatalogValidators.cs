using FluentValidation;
using Identity.Contracts;

namespace Identity.Application.Permissions;

internal static class CatalogRules
{
    public static readonly string[] Kinds = ["service", "web", "hybrid"];

    public static IRuleBuilderOptions<T, IReadOnlyCollection<string>?> ValidRedirectUris<T>(this IRuleBuilder<T, IReadOnlyCollection<string>?> rule) =>
        rule.Must(uris => uris is null || uris.All(u => Uri.TryCreate(u?.TrimEnd('*'), UriKind.Absolute, out var uri) &&
                                                      (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp)))
            .WithMessage("Redirect URIs must be absolute http(s) URLs (a trailing '*' is allowed).");
}

public sealed class CreateApplicationRequestValidator : AbstractValidator<CreateApplicationRequest>
{
    public CreateApplicationRequestValidator()
    {
        RuleFor(r => r.ClientId).Must(PermissionName.IsValidApplicationId)
            .WithMessage("Client id: 2–63 characters, lowercase letters, digits and '-', starting with a letter.");
        RuleFor(r => r.DisplayName).NotEmpty().MaximumLength(100);
        RuleFor(r => r.Description).MaximumLength(500);
        RuleFor(r => r.Kind).Must(k => CatalogRules.Kinds.Contains(k)).WithMessage("Kind is service, web or hybrid.");
        RuleFor(r => r.RedirectUris).ValidRedirectUris();
        RuleFor(r => r.RedirectUris).NotEmpty().When(r => r.Kind is "web" or "hybrid")
            .WithMessage("Applications users sign in to need at least one redirect URI.");
    }
}

public sealed class UpdateApplicationRequestValidator : AbstractValidator<UpdateApplicationRequest>
{
    public UpdateApplicationRequestValidator()
    {
        RuleFor(r => r.DisplayName).MaximumLength(100).NotEmpty().When(r => r.DisplayName is not null);
        RuleFor(r => r.Description).MaximumLength(500);
        RuleFor(r => r.RedirectUris).ValidRedirectUris();
        RuleFor(r => r.LoginTheme).MaximumLength(100);
    }
}

public sealed class CreateCatalogPermissionRequestValidator : AbstractValidator<CreateCatalogPermissionRequest>
{
    public CreateCatalogPermissionRequestValidator()
    {
        RuleFor(r => r.Name).Must(PermissionName.IsValidLocal)
            .WithMessage("Name is Module:Resource:Action; each part starts with a letter and contains letters, digits, '-' or '_'.");
        RuleFor(r => r.DisplayName).MaximumLength(100);
        RuleFor(r => r.Description).MaximumLength(500);
    }
}

public sealed class UpdateCatalogPermissionRequestValidator : AbstractValidator<UpdateCatalogPermissionRequest>
{
    public UpdateCatalogPermissionRequestValidator()
    {
        RuleFor(r => r.DisplayName).MaximumLength(100);
        RuleFor(r => r.Description).MaximumLength(500);
    }
}

public sealed class PermissionManifestRequestValidator : AbstractValidator<PermissionManifestRequest>
{
    public PermissionManifestRequestValidator()
    {
        RuleFor(r => r.ServiceId).Must(PermissionName.IsValidApplicationId).WithMessage("ServiceId must be a valid client id.");
        RuleForEach(r => r.Permissions).ChildRules(p =>
            p.RuleFor(x => x.Name).Must(PermissionName.IsValidLocal).WithMessage("Permission names are Module:Resource:Action."));
    }
}
