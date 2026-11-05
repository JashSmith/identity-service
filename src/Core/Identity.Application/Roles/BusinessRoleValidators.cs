using FluentValidation;
using Identity.Contracts;

namespace Identity.Application.Roles;

internal static class BusinessRoleRules
{
    public const int MaxNameLength = 100;
    public const int MaxDescriptionLength = 255;

    // Letters of any script (Persian included), digits, spaces, dot, dash and underscore; no "/"
    // because Keycloak builds group paths from names.
    public const string NamePattern = @"^[\p{L}\p{N}][\p{L}\p{N} ._-]*$";

    public static IRuleBuilderOptions<T, IReadOnlyCollection<string>?> ValidPermissionList<T>(
        this IRuleBuilder<T, IReadOnlyCollection<string>?> rule) =>
        rule.Must(p => p is null || p.All(x => !string.IsNullOrWhiteSpace(x)))
            .WithMessage("Permission names must not be empty.");
}

public sealed class CreateBusinessRoleRequestValidator : AbstractValidator<CreateBusinessRoleRequest>
{
    public CreateBusinessRoleRequestValidator()
    {
        RuleFor(r => r.Name)
            .NotEmpty().WithMessage("Name is required.")
            .MaximumLength(BusinessRoleRules.MaxNameLength)
            .Matches(BusinessRoleRules.NamePattern)
            .WithMessage("Name may contain letters, digits, spaces, '.', '-' and '_' and must start with a letter or digit.")
            .Must(n => !ReservedGroups.IsReserved(n)).WithMessage("This name is reserved.");
        RuleFor(r => r.Description).MaximumLength(BusinessRoleRules.MaxDescriptionLength);
        RuleFor(r => r.Permissions).ValidPermissionList();
    }
}

public sealed class UpdateBusinessRoleRequestValidator : AbstractValidator<UpdateBusinessRoleRequest>
{
    public UpdateBusinessRoleRequestValidator()
    {
        RuleFor(r => r.Description).MaximumLength(BusinessRoleRules.MaxDescriptionLength);
        RuleFor(r => r.Permissions).ValidPermissionList();
    }
}

public sealed class AssignPermissionsRequestValidator : AbstractValidator<AssignPermissionsRequest>
{
    public AssignPermissionsRequestValidator()
    {
        RuleFor(r => r.Permissions).NotEmpty().WithMessage("At least one permission is required.");
        RuleFor(r => r.Permissions!).ValidPermissionList();
    }
}
