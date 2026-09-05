using Identity.Application;
using Identity.Domain;
namespace Identity.Application.Tests;
public class ApplicationTests
{
    [Fact]
    public async Task Permission_evaluator_uses_effective_permissions()
    {
        var repo = new FakePermissionRepository(["Orders.Read"]);
        var service = new PermissionAuthorizationService(repo);
        Assert.True(await service.HasPermissionAsync(UserId.New(), "Orders.Read", default));
        Assert.False(await service.HasPermissionAsync(UserId.New(), "Orders.Delete", default));
    }
    private sealed class FakePermissionRepository(IReadOnlyCollection<string> values) : IPermissionRepository
    {
        public Task<Permission?> FindByNameAsync(string name, CancellationToken cancellationToken) => Task.FromResult<Permission?>(null);
        public Task UpsertManifestAsync(PermissionManifest manifest, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyCollection<string>> GetEffectivePermissionsAsync(UserId userId, CancellationToken cancellationToken) => Task.FromResult(values);
    }
}
