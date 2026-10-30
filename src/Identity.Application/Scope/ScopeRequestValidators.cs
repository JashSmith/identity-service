using FluentValidation;
using Identity.Contracts;

namespace Identity.Application.Scope;

internal static class ScopeRules
{
    // The key becomes the attribute authz.scope.<key> and the claim of the same name.
    public const string KeyPattern = "^[A-Za-z][A-Za-z0-9_-]{0,63}$";
    public const string ResourcePattern = "^[A-Za-z][A-Za-z0-9_.-]{0,99}$";

    public static IRuleBuilderOptions<T, IReadOnlyCollection<string>?> ValidResources<T>(
        this IRuleBuilder<T, IReadOnlyCollection<string>?> rule) =>
        rule.Must(r => r is null || r.All(x => x is not null && System.Text.RegularExpressions.Regex.IsMatch(x.Trim(), ResourcePattern)))
            .WithMessage("Resource names start with a letter and contain only letters, digits, '.', '-' or '_'.");
}

public sealed class CreateScopeRequestValidator : AbstractValidator<CreateScopeRequest>
{
    public CreateScopeRequestValidator()
    {
        RuleFor(r => r.Key).NotEmpty().WithMessage("Key is required.")
            .Matches(ScopeRules.KeyPattern)
            .WithMessage("Key starts with a letter and contains only letters, digits, '-' or '_' (at most 64 characters).");
        RuleFor(r => r.DisplayName).MaximumLength(100);
        RuleFor(r => r.Description).MaximumLength(500);
        RuleFor(r => r.TargetResources).ValidResources();
    }
}

public sealed class UpdateScopeRequestValidator : AbstractValidator<UpdateScopeRequest>
{
    public UpdateScopeRequestValidator()
    {
        RuleFor(r => r.DisplayName).MaximumLength(100);
        RuleFor(r => r.Description).MaximumLength(500);
        RuleFor(r => r.TargetResources).ValidResources();
    }
}

public sealed class SetScopeResourcesRequestValidator : AbstractValidator<SetScopeResourcesRequest>
{
    public SetScopeResourcesRequestValidator() => RuleFor(r => r.Resources!).ValidResources();
}
