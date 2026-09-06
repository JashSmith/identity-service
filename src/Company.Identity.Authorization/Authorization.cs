using Company.Identity.Abstractions;
using Microsoft.AspNetCore.Authorization;

namespace Company.Identity.Authorization;

public interface IPermissionEvaluator
{
    ValueTask<bool> IsAllowedAsync(string permission, CancellationToken cancellationToken = default);
}

public sealed class PermissionRequirement(string permission) : IAuthorizationRequirement
{
    public string Permission { get; } = permission;
}