using Company.Identity.Abstractions;

namespace Identity.Api;

public sealed class IamPermissionSource : IPermissionDefinitionSource
{
    public IReadOnlyCollection<PermissionDescriptor> GetPermissions() => new[]
    {
        new PermissionDescriptor(IamPermissions.UsersRead, "Read users / directory"),
        new PermissionDescriptor(IamPermissions.UsersManage, "Manage users including scoped assignments"),
        new PermissionDescriptor(IamPermissions.RolesRead, "Read business roles"),
        new PermissionDescriptor(IamPermissions.RolesManage, "Manage business (composite) roles"),
        new PermissionDescriptor(IamPermissions.ScopesRead, "Read scoped access assignments"),
        new PermissionDescriptor(IamPermissions.ScopesManage, "Manage scoped access assignments"),
    };
}
