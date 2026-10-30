namespace Identity.Admin.Services;

/// <summary>The gateway's management permissions (see Identity.Gateway.IamPermissions).</summary>
public static class Permissions
{
    private const string App = "identity-gateway";
    public const string UsersRead = App + ":Users:User:Read";
    public const string UsersManage = App + ":Users:User:Manage";
    public const string RolesRead = App + ":Roles:Role:Read";
    public const string RolesManage = App + ":Roles:Role:Manage";
    public const string ScopesRead = App + ":Scopes:Scope:Read";
    public const string ScopesManage = App + ":Scopes:Scope:Manage";
    public const string ApplicationsRead = App + ":Applications:Application:Read";
    public const string ApplicationsManage = App + ":Applications:Application:Manage";
    public const string PermissionsRead = App + ":Applications:Permission:Read";
    public const string PermissionsManage = App + ":Applications:Permission:Manage";
    public const string SchedulesRead = App + ":Access:Schedule:Read";
    public const string SchedulesManage = App + ":Access:Schedule:Manage";
    public const string SettingsRead = App + ":Settings:Realm:Read";
    public const string SettingsManage = App + ":Settings:Realm:Manage";
    public const string SystemRead = App + ":System:Diagnostics:Read";
}
