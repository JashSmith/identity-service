using Identity.Application;
using Identity.Application.Schedules;
using Identity.Contracts;

namespace Identity.Gateway.Tests;

/// <summary>Schedule format, evaluation, union and precedence (user &gt; permission &gt; role &gt; realm).</summary>
public sealed class AccessScheduleTests
{
    private static readonly TimeZoneInfo Tehran = TimeZoneInfo.FindSystemTimeZoneById("Asia/Tehran");

    // Saturday 2026-10-31 in Tehran (UTC+3:30).
    private static DateTimeOffset SaturdayAt(int hour, int minute = 0) =>
        new DateTimeOffset(2026, 10, 31, hour, minute, 0, TimeSpan.FromHours(3.5));

    private static WeeklySchedule Parse(string text)
    {
        Assert.True(WeeklySchedule.TryParse(text, out var schedule, out var error), error);
        return schedule;
    }

    [Theory]
    [InlineData("unrestricted", "unrestricted")]
    [InlineData("SUN=08:00-12:00 ; sat=14:00-16:00,08:00-12:00", "sat=08:00-12:00,14:00-16:00;sun=08:00-12:00")]
    [InlineData("sat=08:00-12:00,11:00-13:00", "sat=08:00-13:00")]
    [InlineData("fri=00:00-24:00", "fri=00:00-24:00")]
    [InlineData("sat=", "sat=")]
    public void Schedules_round_trip_in_canonical_form(string text, string canonical) =>
        Assert.Equal(canonical, Parse(text).ToString());

    [Theory]
    [InlineData("")]
    [InlineData("sat=16:00-08:00")]
    [InlineData("sat=8-16")]
    [InlineData("xyz=08:00-16:00")]
    [InlineData("sat=08:00-16:00;sat=17:00-18:00")]
    [InlineData("sat=24:30-25:00")]
    public void Invalid_schedules_are_rejected(string text) =>
        Assert.False(WeeklySchedule.TryParse(text, out _, out _));

    [Fact]
    public void Ranges_are_evaluated_in_the_schedule_time_zone_with_exclusive_ends()
    {
        var schedule = Parse("sat=08:00-16:00");

        Assert.True(schedule.Allows(SaturdayAt(8), Tehran));
        Assert.True(schedule.Allows(SaturdayAt(15, 59), Tehran));
        Assert.False(schedule.Allows(SaturdayAt(16), Tehran));
        Assert.False(schedule.Allows(SaturdayAt(7, 59), Tehran));
        Assert.False(schedule.Allows(SaturdayAt(10).AddDays(1), Tehran));
        Assert.False(Parse("sat=").Allows(SaturdayAt(10), Tehran));
    }

    [Fact]
    public void Union_merges_ranges_and_unrestricted_wins()
    {
        Assert.Equal("sat=08:00-18:00;sun=08:00-12:00", Parse("sat=08:00-12:00;sun=08:00-12:00").Union(Parse("sat=11:00-18:00")).ToString());
        Assert.True(Parse("sat=08:00-12:00").Union(WeeklySchedule.Unrestricted).IsUnrestricted);
    }

    [Fact]
    public void Api_form_converts_both_ways()
    {
        Assert.True(WeeklySchedule.TryCreate(false, new Dictionary<string, IReadOnlyCollection<string>> { ["sun"] = ["09:00-17:00"] }, out var s, out _));
        Assert.Equal("sun=09:00-17:00", s.ToString());
        Assert.Equal(["09:00-17:00"], s.ToDto().Days!["sun"]);
    }

    private static readonly WeeklySchedule Office = Parse("sat=08:00-16:00");
    private static readonly WeeklySchedule Evening = Parse("sat=16:00-22:00");
    private static readonly WeeklySchedule Night = Parse("sat=22:00-24:00");

    private static RoleScheduleSource Role(string name, WeeklySchedule? schedule, params string[] permissions) => new(name, schedule, permissions);

    [Fact]
    public void Without_any_schedule_everything_is_unrestricted()
    {
        var (login, permissions) = AccessScheduleResolver.Resolve(new(null, null, [Role("Clerk", null, "a:M:R:Read")], new Dictionary<string, WeeklySchedule>()));

        Assert.True(login.IsUnrestricted);
        Assert.True(permissions["a:M:R:Read"].IsUnrestricted);
    }

    [Fact]
    public void Roles_without_a_schedule_follow_the_realm_and_several_roles_add_up()
    {
        var (login, permissions) = AccessScheduleResolver.Resolve(new(Office, null,
            [Role("Clerk", null, "a:M:R:Read"), Role("Night", Night, "a:M:R:Write")], new Dictionary<string, WeeklySchedule>()));

        Assert.Equal("sat=08:00-16:00,22:00-24:00", login.ToString());
        Assert.Equal(Office, permissions["a:M:R:Read"]);
        Assert.Equal(Night, permissions["a:M:R:Write"]);
    }

    [Fact]
    public void Permission_schedule_overrides_roles_and_user_schedule_overrides_all()
    {
        var sources = new UserScheduleSources(Office, null, [Role("Clerk", Office, "a:M:R:Read", "a:M:R:Approve")],
            new Dictionary<string, WeeklySchedule> { ["a:M:R:Approve"] = Evening });

        var (_, permissions) = AccessScheduleResolver.Resolve(sources);
        var (remoteLogin, remotePermissions) = AccessScheduleResolver.Resolve(sources with { User = WeeklySchedule.Unrestricted });

        Assert.Equal(Evening, permissions["a:M:R:Approve"]);
        Assert.True(remoteLogin.IsUnrestricted);
        Assert.True(remotePermissions["a:M:R:Approve"].IsUnrestricted);
    }

    private sealed class Store(UserScheduleSources sources) : IAccessScheduleStore
    {
        public int Reads { get; private set; }
        public Task<Result<WeeklySchedule?>> GetAsync(ScheduleTarget target, string? id, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> SetAsync(ScheduleTarget target, string? id, WeeklySchedule? schedule, CancellationToken ct) => Task.FromResult(Result.Success());
        public Task<Result<UserScheduleSources>> GetSourcesAsync(string userId, CancellationToken ct)
        {
            Reads++;
            return Task.FromResult(Result<UserScheduleSources>.Success(sources));
        }
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    [Fact]
    public async Task Sign_in_is_refused_outside_the_schedule_and_snapshots_are_cached_until_a_change()
    {
        var store = new Store(new(Office, null, [], new Dictionary<string, WeeklySchedule>()));
        var service = new AccessScheduleService(store, new AccessScheduleOptions(), new FixedClock(SaturdayAt(17)));

        var signIn = await service.EnsureCanSignInAsync("u1", CancellationToken.None);
        await service.GetSnapshotAsync("u1", CancellationToken.None);
        await service.SetAsync(ScheduleTarget.Realm, null, null, CancellationToken.None);
        await service.GetSnapshotAsync("u1", CancellationToken.None);

        Assert.Equal("access.outside_schedule", signIn.Error?.Code);
        Assert.Equal(2, store.Reads);
    }
}
