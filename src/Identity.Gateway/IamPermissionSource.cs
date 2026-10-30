using Avash.Identity.Abstractions;

namespace Identity.Gateway;

/// <summary>The gateway's permission manifest (local names), registered at startup.</summary>
public sealed class IamPermissionSource : IPermissionDefinitionSource
{
    public IReadOnlyCollection<PermissionDescriptor> GetPermissions() =>
    [
        Describe(IamPermissions.UsersRead, "Read users and their sessions"),
        Describe(IamPermissions.UsersManage, "Create, edit and delete users and their access"),
        Describe(IamPermissions.RolesRead, "Read business roles"),
        Describe(IamPermissions.RolesManage, "Manage business roles and their permissions"),
        Describe(IamPermissions.ScopesRead, "Read runtime scopes and assignments"),
        Describe(IamPermissions.ScopesManage, "Manage runtime scopes and assignments"),
        Describe(IamPermissions.ApplicationsRead, "Read applications"),
        Describe(IamPermissions.ApplicationsManage, "Manage applications and their secrets"),
        Describe(IamPermissions.PermissionsRead, "Read the permission catalog"),
        Describe(IamPermissions.PermissionsManage, "Manage the permission catalog"),
        Describe(IamPermissions.SchedulesRead, "Read access schedules"),
        Describe(IamPermissions.SchedulesManage, "Manage access schedules"),
        Describe(IamPermissions.SettingsRead, "Read authentication and token settings"),
        Describe(IamPermissions.SettingsManage, "Manage authentication and token settings"),
        Describe(IamPermissions.AuditRead, "Read admin and login events"),
        Describe(IamPermissions.SystemRead, "Read system diagnostics"),
    ];

    private static PermissionDescriptor Describe(string fullName, string description) =>
        new(IamPermissions.Local(fullName), description);
}
