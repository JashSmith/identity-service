using Identity.Domain;

namespace Identity.Domain.Tests;

public class DomainTests
{
    [Fact]
    public void User_lockout_is_enforced_after_threshold()
    {
        var now = DateTimeOffset.UtcNow;
        var user = new User(UserId.New(), "alice", "Alice", now);
        user.RecordFailedLogin(now, 3, TimeSpan.FromMinutes(5));
        user.RecordFailedLogin(now, 3, TimeSpan.FromMinutes(5));
        user.RecordFailedLogin(now, 3, TimeSpan.FromMinutes(5));
        Assert.True(user.IsLocked(now.AddSeconds(1)));
    }

    [Fact]
    public void Permission_assignment_is_idempotent()
    {
        var now = DateTimeOffset.UtcNow;
        var user = new User(UserId.New(), "alice", "Alice", now);
        var p = PermissionId.New();
        user.GrantPermission(p, now);
        user.GrantPermission(p, now);
        Assert.Single(user.DirectPermissions);
    }
}