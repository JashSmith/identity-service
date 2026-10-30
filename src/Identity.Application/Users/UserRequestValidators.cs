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

public sealed class SetRequiredActionsRequestValidator : AbstractValidator<SetRequiredActionsRequest>
{
    public SetRequiredActionsRequestValidator()
    {
        RuleFor(r => r.Actions).NotNull().WithMessage("Actions are required; send an empty list to clear them.");
        RuleForEach(r => r.Actions).NotEmpty().MaximumLength(100);
    }
}

public sealed class SendActionsEmailRequestValidator : AbstractValidator<SendActionsEmailRequest>
{
    public SendActionsEmailRequestValidator()
    {
        RuleFor(r => r.Actions).NotEmpty().WithMessage("At least one action is required.");
        RuleForEach(r => r.Actions).NotEmpty().MaximumLength(100);
        RuleFor(r => r.LifespanSeconds).InclusiveBetween(60, 7 * 24 * 3600).When(r => r.LifespanSeconds.HasValue);
        RuleFor(r => r.ClientId).NotEmpty().When(r => !string.IsNullOrWhiteSpace(r.RedirectUri))
            .WithMessage("A redirect URI needs the client it belongs to.");
        RuleFor(r => r.RedirectUri).Must(u => Uri.TryCreate(u, UriKind.Absolute, out _))
            .When(r => !string.IsNullOrWhiteSpace(r.RedirectUri)).WithMessage("Redirect URI must be absolute.");
    }
}

public sealed class ScopedRoleAssignmentValidator : AbstractValidator<ScopedRoleAssignmentDto>
{
    public ScopedRoleAssignmentValidator() =>
        RuleFor(r => r.Role).NotEmpty().WithMessage("Role is required.");
}
