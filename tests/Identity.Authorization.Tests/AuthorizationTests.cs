using Company.Identity.Abstractions;
using Company.Identity.PermissionDiscovery;

namespace Identity.Authorization.Tests;

public class AuthorizationTests
{
    private sealed class SecuredEndpoints
    {
        [RequirePermission("Orders.Cancel")]
        public void Cancel()
        {
        }
    }

    [Fact]
    public void Discovers_permission_attributes()
    {
        var values = PermissionDiscovery.Discover(typeof(SecuredEndpoints).Assembly);
        Assert.Contains(values, x => x.Name == "Orders.Cancel");
    }
}