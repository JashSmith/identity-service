using FluentValidation;
using Identity.Contracts;

namespace Identity.Application.Users;

internal static class UserRules
{
    public const int MaxLength = 255;

    public static IRuleBuilderOptions<T, string?> ValidUsername<T>(this IRuleBuilder<T, string?> rule) =>
        rule.MaximumLength(MaxLength)
            .Must(u => u is null || !u.Any(char.IsWhiteSpace)).WithMessage("Username must not contain spaces.");
}

public sealed class CreateUserRequestValidator : AbstractValidator<CreateUserRequest>
{
    public CreateUserRequestValidator()
    {
        RuleFor(r => r.Username).NotEmpty().WithMessage("Username is required.");
        RuleFor(r => r.Username).ValidUsername();
        RuleFor(r => r.Email).EmailAddress().MaximumLength(UserRules.MaxLength).When(r => !string.IsNullOrWhiteSpace(r.Email));
        RuleFor(r => r.FirstName).MaximumLength(UserRules.MaxLength);
        RuleFor(r => r.LastName).MaximumLength(UserRules.MaxLength);
        RuleFor(r => r.Credentials!.Password).NotEmpty().WithMessage("Password is required when credentials are given.")
            .When(r => r.Credentials is not null);
        RuleForEach(r => r.Assignments).ChildRules(a =>
            a.RuleFor(x => x.Role).NotEmpty().WithMessage("Role is required."));
    }
}

public sealed class UpdateUserRequestValidator : AbstractValidator<UpdateUserRequest>
{
    public UpdateUserRequestValidator()
    {
        RuleFor(r => r.Username).ValidUsername().When(r => r.Username is not null);
        RuleFor(r => r.Email).EmailAddress().MaximumLength(UserRules.MaxLength).When(r => !string.IsNullOrWhiteSpace(r.Email));
        RuleFor(r => r.FirstName).MaximumLength(UserRules.MaxLength);
        RuleFor(r => r.LastName).MaximumLength(UserRules.MaxLength);
        RuleFor(r => r.Attributes)
            .Must(a => ProtectedUserAttributes.FindIn(a).Count == 0)
            .WithMessage(r =>
                $"Attributes {string.Join(", ", ProtectedUserAttributes.FindIn(r.Attributes))} are managed by the gateway; use the scoped-access APIs instead.");
    }
}

public sealed class ResetPasswordRequestValidator : AbstractValidator<ResetPasswordRequest>
{
    public ResetPasswordRequestValidator() =>
        RuleFor(r => r.Password).NotEmpty().WithMessage("Password is required.");
}

public sealed class ScopedRoleAssignmentValidator : AbstractValidator<ScopedRoleAssignmentDto>
{
    public ScopedRoleAssignmentValidator() =>
        RuleFor(r => r.Role).NotEmpty().WithMessage("Role is required.");
}
