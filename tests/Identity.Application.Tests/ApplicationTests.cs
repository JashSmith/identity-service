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
        public Task<Permission?> FindByNameAsync(string name, CancellationToken cancellationToken) =>
            Task.FromResult<Permission?>(null);

        public Task UpsertManifestAsync(PermissionManifest manifest, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<IReadOnlyCollection<string>> GetEffectivePermissionsAsync(UserId userId,
            CancellationToken cancellationToken) => Task.FromResult(values);
    }
}

public sealed class SessionLifecycleTests
{
    [Fact]
    public async Task Token_issuance_rejects_disabled_users()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var user = new User(UserId.New(), "user", "User", now);
        user.Disable(now);
        var service = new LocalAuthenticationService(
            new EmptyUserRepository(), new EmptyCredentialStore(), new EmptyPermissionRepository(),
            new FakeSessionStore(), new EmptyRefreshTokenStore(), new EmptyPasswordVerifier(),
            new EmptyTokenIssuer(), new FixedClock(now));

        var result = await service.IssueTokensAsync(user, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal("session_invalid", result.ErrorCode);
    }

    [Fact]
    public async Task Logout_cannot_revoke_another_users_session()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var owner = new User(UserId.New(), "owner", "Owner", now);
        var caller = new User(UserId.New(), "caller", "Caller", now);
        var session = new UserSession(Guid.NewGuid(), owner.Id, now, now.AddHours(1), owner.SecurityStamp);
        var sessions = new FakeSessionStore(session);
        var service = new LocalAuthenticationService(
            new EmptyUserRepository(), new EmptyCredentialStore(), new EmptyPermissionRepository(), sessions,
            new EmptyRefreshTokenStore(), new EmptyPasswordVerifier(), new EmptyTokenIssuer(), new FixedClock(now));

        var revoked = await service.LogoutAsync(caller.Id, session.Id, CancellationToken.None);

        Assert.False(revoked);
        Assert.Null(session.RevokedAt);
    }

    [Fact]
    public async Task Logout_all_revokes_only_active_sessions()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var user = new User(UserId.New(), "user", "User", now);
        var active = new UserSession(Guid.NewGuid(), user.Id, now, now.AddHours(1), user.SecurityStamp);
        var expired = new UserSession(Guid.NewGuid(), user.Id, now.AddHours(-2), now.AddMinutes(-1),
            user.SecurityStamp);
        var sessions = new FakeSessionStore(active, expired);
        var service = new LocalAuthenticationService(
            new EmptyUserRepository(), new EmptyCredentialStore(), new EmptyPermissionRepository(), sessions,
            new EmptyRefreshTokenStore(), new EmptyPasswordVerifier(), new EmptyTokenIssuer(), new FixedClock(now));

        var revoked = await service.LogoutAllAsync(user.Id, CancellationToken.None);

        Assert.Equal(1, revoked);
        Assert.NotNull(active.RevokedAt);
        Assert.Null(expired.RevokedAt);
    }

    private sealed class FixedClock(DateTimeOffset now) : ISystemClock
    {
        public DateTimeOffset UtcNow => now;
    }

    private sealed class FakeSessionStore(params UserSession[] values) : ISessionStore
    {
        private readonly List<UserSession> sessions = [.. values];
        public Task AddAsync(UserSession session, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<UserSession?> FindAsync(Guid id, CancellationToken cancellationToken) =>
            Task.FromResult(sessions.SingleOrDefault(x => x.Id == id));

        public Task<IReadOnlyCollection<UserSession>> FindForUserAsync(UserId userId,
            CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyCollection<UserSession>>(sessions.Where(x => x.UserId == userId).ToArray());

        public Task RevokeAsync(UserSession session, DateTimeOffset at, CancellationToken cancellationToken)
        {
            session.Revoke(at);
            return Task.CompletedTask;
        }
    }

    private sealed class EmptyUserRepository : IUserRepository
    {
        public Task<User?> FindByUsernameAsync(string username, CancellationToken cancellationToken) =>
            Task.FromResult<User?>(null);

        public Task<User?> FindAsync(UserId id, CancellationToken cancellationToken) => Task.FromResult<User?>(null);
        public Task AddAsync(User user, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task SaveAsync(User user, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class EmptyCredentialStore : IPasswordCredentialStore
    {
        public Task<PasswordCredential?> FindAsync(UserId userId, CancellationToken cancellationToken) =>
            Task.FromResult<PasswordCredential?>(null);

        public Task SaveAsync(PasswordCredential credential, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class EmptyPermissionRepository : IPermissionRepository
    {
        public Task<Permission?> FindByNameAsync(string name, CancellationToken cancellationToken) =>
            Task.FromResult<Permission?>(null);

        public Task UpsertManifestAsync(PermissionManifest manifest, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<IReadOnlyCollection<string>> GetEffectivePermissionsAsync(UserId userId,
            CancellationToken cancellationToken) => Task.FromResult<IReadOnlyCollection<string>>([]);
    }

    private sealed class EmptyRefreshTokenStore : IRefreshTokenStore
    {
        public Task<RefreshTokenRecord?> FindAsync(string tokenHash, CancellationToken cancellationToken) =>
            Task.FromResult<RefreshTokenRecord?>(null);

        public Task AddAsync(RefreshTokenRecord record, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task RotateAsync(RefreshTokenRecord current, RefreshTokenRecord replacement,
            CancellationToken cancellationToken) => Task.CompletedTask;

        public Task RevokeFamilyAsync(string familyId, DateTimeOffset revokedAt, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class EmptyPasswordVerifier : IPasswordVerifier
    {
        public bool Verify(string encodedHash, string password) => false;
        public string Hash(string password) => string.Empty;
    }

    private sealed class EmptyTokenIssuer : IAccessTokenIssuer
    {
        public Task<AccessTokenResult> IssueAsync(User user, IReadOnlyCollection<string> permissions, Guid sessionId,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();
    }
}