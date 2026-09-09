using Microsoft.AspNetCore.Authorization;

namespace Company.Identity.Authorization;

public sealed class PermissionRequirement(string permission) : IAuthorizationRequirement
{
    public string Permission { get; } = permission;
}