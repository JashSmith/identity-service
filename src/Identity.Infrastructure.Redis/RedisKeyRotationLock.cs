using Identity.Application;

namespace Identity.Infrastructure.Redis;

public sealed class InMemoryKeyRotationLock : IKeyRotationLock
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _locks = new();

    public Task<RotationLockHandle?> TryAcquireAsync(string realm, TimeSpan ttl, CancellationToken ct)
    {
        var t = Guid.NewGuid().ToString("N");
        return Task.FromResult(_locks.TryAdd($"lock:{realm}", t)
            ? new RotationLockHandle(realm, t, DateTimeOffset.UtcNow)
            : null);
    }

    public Task<bool> RenewAsync(RotationLockHandle h, TimeSpan ttl, CancellationToken ct) =>
        Task.FromResult(_locks.TryGetValue($"lock:{h.Realm}", out var v) && v == h.OwnerToken);

    public Task ReleaseAsync(RotationLockHandle h, CancellationToken ct)
    {
        _locks.TryRemove($"lock:{h.Realm}", out _);
        return Task.CompletedTask;
    }
}