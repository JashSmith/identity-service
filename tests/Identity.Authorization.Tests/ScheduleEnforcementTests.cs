using System.Security.Claims;
using Avash.Identity.Authorization;
using Avash.Identity.Authorization.AspNetCore;
using Identity.Contracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Identity.Authorization.Tests;

/// <summary>With schedules enforced, a held permission only counts inside the user's weekly schedule.</summary>
public class ScheduleEnforcementTests
{
    // Saturday 2026-10-31 10:00 in Tehran (UTC+3:30).
    private static readonly DateTimeOffset SaturdayMorning = new(2026, 10, 31, 6, 30, 0, TimeSpan.Zero);

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class Schedules(AccessScheduleSnapshot? snapshot) : IAccessScheduleProvider
    {
        public Task<AccessScheduleSnapshot?> GetAsync(ClaimsPrincipal user, CancellationToken ct) => Task.FromResult(snapshot);
    }

    private static async Task<bool> IsGrantedAsync(AccessScheduleSnapshot? snapshot, string permission = "orders:Sales:Order:Read")
    {
        var options = Options.Create(new PermissionAuthorizationOptions { ApplicationId = "orders", EnforceSchedules = true });
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "u1"), new Claim("permissions", permission)], "Bearer"));
        var context = new AuthorizationHandlerContext([new PermissionRequirement(permission)], user, null);
        await new PermissionAuthorizationHandler(options, new Schedules(snapshot), new FixedClock(SaturdayMorning)).HandleAsync(context);
        return context.HasSucceeded;
    }

    private static AccessScheduleSnapshot Snapshot(string login, Dictionary<string, string>? permissions = null) =>
        new("Asia/Tehran", login, permissions ?? []);

    [Fact]
    public async Task Inside_the_schedule_is_granted() =>
        Assert.True(await IsGrantedAsync(Snapshot("sat=08:00-16:00")));

    [Fact]
    public async Task Outside_the_schedule_is_denied() =>
        Assert.False(await IsGrantedAsync(Snapshot("sat=12:00-16:00;sun=08:00-16:00")));

    [Fact]
    public async Task A_permission_schedule_overrides_the_login_schedule() =>
        Assert.False(await IsGrantedAsync(Snapshot("unrestricted", new() { ["orders:Sales:Order:Read"] = "sun=08:00-16:00" })));

    [Fact]
    public async Task Unreadable_schedules_deny() =>
        Assert.False(await IsGrantedAsync(null));
}
