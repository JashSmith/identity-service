using Identity.Api;
using Identity.Application;
using Identity.Domain;

namespace Identity.Api.Tests;

public sealed class BffSessionValidatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Active_session_for_enabled_user_is_valid()
    {
        var user = new User(UserId.New(), "user", "User", Now);
        var session = new UserSession(Guid.NewGuid(), user.Id, Now, Now.AddHours(1), user.SecurityStamp);
        var validator = new BffSessionValidator(
            new FakeSessionStore(session),
            new FakeUserRepository(user),
            new FixedClock());

        Assert.True(await validator.ValidateAsync(session.Id.ToString(), CancellationToken.None));
    }

    [Fact]
    public async Task Revoked_session_is_invalid()
    {
        var user = new User(UserId.New(), "user", "User", Now);
        var session = new UserSession(Guid.NewGuid(), user.Id, Now, Now.AddHours(1), user.SecurityStamp);
        session.Revoke(Now);
        var validator = new BffSessionValidator(
            new FakeSessionStore(session),
            new FakeUserRepository(user),
            new FixedClock());

        Assert.False(await validator.ValidateAsync(session.Id.ToString(), CancellationToken.None));
    }

    [Fact]
    public async Task Security_stamp_change_invalidates_session()
    {
        var user = new User(UserId.New(), "user", "User", Now);
        var session = new UserSession(Guid.NewGuid(), user.Id, Now, Now.AddHours(1), user.SecurityStamp);
        user.RotateSecurityStamp(Now);
        var validator = new BffSessionValidator(
            new FakeSessionStore(session),
            new FakeUserRepository(user),
            new FixedClock());

        Assert.False(await validator.ValidateAsync(session.Id.ToString(), CancellationToken.None));
    }

    [Fact]
    public async Task Invalid_session_id_does_not_query_persistence()
    {
        var sessions = new FakeSessionStore();
        var validator = new BffSessionValidator(sessions, new FakeUserRepository(), new FixedClock());

        Assert.False(await validator.ValidateAsync("not-a-guid", CancellationToken.None));
        Assert.Equal(0, sessions.FindCount);
    }

    private sealed class FixedClock : ISystemClock
    {
        public DateTimeOffset UtcNow => Now;
    }

    private sealed class FakeSessionStore(params UserSession[] initial) : ISessionStore
    {
        private readonly Dictionary<Guid, UserSession> sessions = initial.ToDictionary(x => x.Id);
        public int FindCount { get; private set; }

        public Task AddAsync(UserSession session, CancellationToken cancellationToken)
        {
            sessions[session.Id] = session;
            return Task.CompletedTask;
        }

        public Task<IReadOnlyCollection<UserSession>> FindForUserAsync(UserId userId,
            CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyCollection<UserSession>>(sessions.Values.Where(x => x.UserId == userId)
                .ToArray());

        public Task<UserSession?> FindAsync(Guid id, CancellationToken cancellationToken)
        {
            FindCount++;
            sessions.TryGetValue(id, out var session);
            return Task.FromResult(session);
        }

        public Task RevokeAsync(UserSession session, DateTimeOffset at, CancellationToken cancellationToken)
        {
            session.Revoke(at);
            return Task.CompletedTask;
        }
    }

    private sealed class FakeUserRepository(params User[] initial) : IUserRepository
    {
        private readonly Dictionary<UserId, User> users = initial.ToDictionary(x => x.Id);

        public Task<User?> FindByUsernameAsync(string username, CancellationToken cancellationToken)
            => Task.FromResult<User?>(null);

        public Task<User?> FindAsync(UserId id, CancellationToken cancellationToken)
        {
            users.TryGetValue(id, out var user);
            return Task.FromResult(user);
        }

        public Task AddAsync(User user, CancellationToken cancellationToken)
        {
            users[user.Id] = user;
            return Task.CompletedTask;
        }

        public Task SaveAsync(User user, CancellationToken cancellationToken)
            => Task.CompletedTask;
    }
}