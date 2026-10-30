using Microsoft.AspNetCore.Authorization;

namespace Avash.Identity.Authorization;

public sealed class PermissionRequirement(string permission) : IAuthorizationRequirement
{
    public string Permission { get; } = permission;
}