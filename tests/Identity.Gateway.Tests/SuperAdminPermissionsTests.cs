using Identity.Infrastructure.Keycloak;

namespace Identity.Gateway.Tests;

public sealed class SuperAdminPermissionsTests
{
    [Fact]
    public void Super_admins_are_granted_every_gateway_permission()
    {
        var declared = new IamPermissionSource().GetPermissions().Select(p => p.Name).Order(StringComparer.Ordinal);

        Assert.Equal(declared, KeycloakClientRoleProvisioner.GatewayManagementPermissions.Order(StringComparer.Ordinal));
    }
}
