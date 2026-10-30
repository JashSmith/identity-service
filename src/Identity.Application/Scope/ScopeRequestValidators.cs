using FluentValidation;
using Identity.Contracts;

namespace Identity.Application.Scope;

internal static class ScopeRequestRules
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
            .Matches(ScopeRequestRules.KeyPattern)
            .WithMessage("Key starts with a letter and contains only letters, digits, '-' or '_' (at most 64 characters).");
        RuleFor(r => r.DisplayName).MaximumLength(100);
        RuleFor(r => r.Description).MaximumLength(500);
        RuleFor(r => r.TargetResources).ValidResources();
        RuleFor(r => r.Parent).Matches(ScopeRequestRules.KeyPattern).When(r => !string.IsNullOrEmpty(r.Parent))
            .WithMessage("Parent must be an existing scope key.");
        RuleFor(r => r.Parent).NotEqual(r => r.Key).WithMessage("A scope cannot be its own parent.");
    }
}

public sealed class UpdateScopeRequestValidator : AbstractValidator<UpdateScopeRequest>
{
    public UpdateScopeRequestValidator()
    {
        RuleFor(r => r.DisplayName).MaximumLength(100);
        RuleFor(r => r.Description).MaximumLength(500);
        RuleFor(r => r.TargetResources).ValidResources();
        RuleFor(r => r.Parent).Matches(ScopeRequestRules.KeyPattern).When(r => !string.IsNullOrEmpty(r.Parent))
            .WithMessage("Parent must be an existing scope key.");
    }
}

public sealed class SetScopeValuesRequestValidator : AbstractValidator<SetScopeValuesRequest>
{
    public SetScopeValuesRequestValidator()
    {
        RuleFor(r => r.Values).NotNull();
        RuleForEach(r => r.Values).ChildRules(v =>
        {
            v.RuleFor(x => x.Value).NotEmpty().MaximumLength(100)
                .Must(x => x is null || x.Trim() != "*").WithMessage("'*' is reserved for \"all values\".");
            v.RuleFor(x => x.Label).MaximumLength(100);
            v.RuleFor(x => x.Parent).MaximumLength(100);
        });
    }
}

public sealed class SetScopeResourcesRequestValidator : AbstractValidator<SetScopeResourcesRequest>
{
    public SetScopeResourcesRequestValidator() => RuleFor(r => r.Resources!).ValidResources();
}
