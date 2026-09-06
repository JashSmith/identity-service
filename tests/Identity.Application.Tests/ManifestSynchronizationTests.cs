using Identity.Application;
using Identity.Domain;

namespace Identity.Application.Tests;

public sealed class ManifestSynchronizationTests
{
    [Fact]
    public async Task Duplicate_manifest_is_ignored()
    {
        var repository = new FakePermissionRepository();
        var versions = new FakeVersionStore();
        var synchronizer = new PermissionManifestSynchronizer(repository, versions);
        var manifest = new PermissionManifest("orders", "Orders", "1", "Test", [], "2", Guid.NewGuid(),
            DateTimeOffset.UtcNow);

        Assert.True(await synchronizer.SynchronizeAsync(manifest, CancellationToken.None));
        Assert.False(await synchronizer.SynchronizeAsync(manifest, CancellationToken.None));
        Assert.Equal(1, repository.UpsertCount);
    }

    private sealed class FakeVersionStore : IPermissionManifestVersionStore
    {
        private readonly HashSet<string> _accepted = [];

        public Task<bool> TryAcceptAsync(PermissionManifest manifest, CancellationToken cancellationToken)
            => Task.FromResult(_accepted.Add($"{manifest.ServiceId}:{manifest.ManifestVersion}"));
    }

    private sealed class FakePermissionRepository : IPermissionRepository
    {
        public int UpsertCount { get; private set; }

        public Task<Permission?> FindByNameAsync(string name, CancellationToken cancellationToken) =>
            Task.FromResult<Permission?>(null);

        public Task<IReadOnlyCollection<string>> GetEffectivePermissionsAsync(UserId userId,
            CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyCollection<string>>([]);

        public Task UpsertManifestAsync(PermissionManifest manifest, CancellationToken cancellationToken)
        {
            UpsertCount++;
            return Task.CompletedTask;
        }
    }
}