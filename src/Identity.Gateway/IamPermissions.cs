namespace Identity.Gateway;

/// <summary>
/// The gateway's own permissions, as full names (<c>identity-gateway:Module:Resource:Action</c>) used as
/// authorization policy names. They are registered as client roles of the identity-gateway application
/// at startup and always granted to super-admins.
/// </summary>
public static class IamPermissions
{
    public const string Application = "identity-gateway";

    public const string UsersRead = Application + ":Users:User:Read";
    public const string UsersManage = Application + ":Users:User:Manage";
    public const string RolesRead = Application + ":Roles:Role:Read";
    public const string RolesManage = Application + ":Roles:Role:Manage";
    public const string ScopesRead = Application + ":Scopes:Scope:Read";
    public const string ScopesManage = Application + ":Scopes:Scope:Manage";
    public const string ApplicationsRead = Application + ":Applications:Application:Read";
    public const string ApplicationsManage = Application + ":Applications:Application:Manage";
    public const string PermissionsRead = Application + ":Applications:Permission:Read";
    public const string PermissionsManage = Application + ":Applications:Permission:Manage";
    public const string SchedulesRead = Application + ":Access:Schedule:Read";
    public const string SchedulesManage = Application + ":Access:Schedule:Manage";
    public const string SettingsRead = Application + ":Settings:Realm:Read";
    public const string SettingsManage = Application + ":Settings:Realm:Manage";
    public const string AuditRead = Application + ":System:Audit:Read";
    public const string SystemRead = Application + ":System:Diagnostics:Read";

    /// <summary>The local part (<c>Module:Resource:Action</c>) a service declares in its manifest.</summary>
    public static string Local(string fullName) => fullName[(Application.Length + 1)..];
}
