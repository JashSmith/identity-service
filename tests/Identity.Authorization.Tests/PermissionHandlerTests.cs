using System.Security.Claims;
using Avash.Identity.Authorization;
using Avash.Identity.Authorization.AspNetCore;
using Microsoft.AspNetCore.Authorization;

namespace Identity.Authorization.Tests;

/// <summary>Only explicit permission claims may satisfy a permission policy.</summary>
public class PermissionHandlerTests
{
    private static async Task<bool> IsGrantedAsync(string permission, params Claim[] claims)
    {
        var requirement = new PermissionRequirement(permission);
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));
        var context = new AuthorizationHandlerContext([requirement], user, resource: null);

        await new PermissionAuthorizationHandler().HandleAsync(context);

        return context.HasSucceeded;
    }

    [Theory]
    [InlineData("permissions")]
    [InlineData("permission")]
    public async Task Matching_permission_claim_is_granted(string claimType) =>
        Assert.True(await IsGrantedAsync("orders.read", new Claim(claimType, "orders.read")));

    [Fact]
    public async Task Missing_permission_is_denied() =>
        Assert.False(await IsGrantedAsync("orders.delete", new Claim("permissions", "orders.read")));

    [Fact]
    public async Task Realm_admin_does_not_grant_other_permissions() =>
        Assert.False(await IsGrantedAsync("orders.delete", new Claim("permissions", "realm-admin")));

    [Theory]
    [InlineData(ClaimTypes.Role)]
    [InlineData("role")]
    [InlineData("roles")]
    public async Task Role_claims_are_not_permissions(string claimType)
    {
        Assert.False(await IsGrantedAsync("orders.delete", new Claim(claimType, "orders.delete")));
        Assert.False(await IsGrantedAsync("orders.delete", new Claim(claimType, "realm-admin")));
    }

    [Fact]
    public void Access_context_ignores_role_claims()
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.Role, "orders.delete"), new Claim("permissions", "orders.read")], "Bearer"));

        var access = new ClaimsPrincipalAccessContext(user);

        Assert.True(access.HasPermission("orders.read"));
        Assert.False(access.HasPermission("orders.delete"));
    }
}
