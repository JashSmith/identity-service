using System.Reflection;
using Identity.Application.Permissions;

namespace Identity.Gateway.Tests;

public sealed class GatewayPermissionsTests
{
    private static readonly string[] Declared = typeof(IamPermissions)
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(f => f.IsLiteral && f.Name != nameof(IamPermissions.Application))
        .Select(f => (string)f.GetRawConstantValue()!)
        .ToArray();

    [Fact]
    public void Every_gateway_policy_is_registered_in_the_manifest()
    {
        var manifest = new IamPermissionSource().GetPermissions().Select(p => $"{IamPermissions.Application}:{p.Name}");

        Assert.Equal(Declared.Order(StringComparer.Ordinal), manifest.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Gateway_permissions_follow_the_naming_scheme()
    {
        Assert.All(Declared, name => Assert.True(PermissionName.TryParseFull(name, out _), name));
    }
}
