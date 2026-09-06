using Identity.Application;
using Identity.Domain;

namespace Identity.Application.Tests;

public sealed class ExternalAuthenticationTests
{
    [Fact]
    public async Task Unknown_external_identity_does_not_create_or_resolve_account()
    {
        var links = new FakeLinkRepository();
        var users = new FakeUserRepository();
        var service = new ExternalAuthenticationService(links, users, new FixedClock());

        var result = await service.ResolveUserAsync(
            new ExternalIdentityDescriptor("oidc", "subject-1", "user", "User"),
            CancellationToken.None);

        Assert.Null(result);
        Assert.Equal(0, users.FindCount);
    }

    [Fact]
    public async Task Linked_external_identity_resolves_enabled_user_and_updates_last_login()
    {
        var user = new User(UserId.New(), "user", "User", DateTimeOffset.UtcNow);
        var link = new ExternalIdentityLink(Guid.NewGuid(), user.Id, "oidc", "subject-1",
            DateTimeOffset.UtcNow.AddDays(-1));
        var links = new FakeLinkRepository(link);
        var users = new FakeUserRepository(user);
        var service = new ExternalAuthenticationService(links, users, new FixedClock());

        var result = await service.ResolveUserAsync(
            new ExternalIdentityDescriptor("oidc", "subject-1", "user", "User"),
            CancellationToken.None);

        Assert.Same(user, result);
        Assert.Equal(1, links.SaveCount);
        Assert.Equal(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), link.LastAuthenticatedAt);
    }

    [Fact]
    public async Task Linking_rejects_identity_already_owned_by_another_user()
    {
        var existingUser = new User(UserId.New(), "existing", "Existing", DateTimeOffset.UtcNow);
        var targetUser = new User(UserId.New(), "target", "Target", DateTimeOffset.UtcNow);
        var link = new ExternalIdentityLink(Guid.NewGuid(), existingUser.Id, "oidc", "subject-1",
            DateTimeOffset.UtcNow);
        var links = new FakeLinkRepository(link);
        var users = new FakeUserRepository(existingUser, targetUser);
        var service = new ExternalIdentityLinkingService(links, users, new FixedClock());

        var result = await service.LinkAsync(
            targetUser.Id,
            new ExternalIdentityDescriptor("oidc", "subject-1", null, null),
            CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Equal("external_identity_linked_to_another_user", result.ErrorCode);
        Assert.Equal(0, links.AddCount);
    }

    [Fact]
    public async Task Linking_creates_new_mapping_for_authenticated_user()
    {
        var user = new User(UserId.New(), "target", "Target", DateTimeOffset.UtcNow);
        var links = new FakeLinkRepository();
        var users = new FakeUserRepository(user);
        var service = new ExternalIdentityLinkingService(links, users, new FixedClock());

        var result = await service.LinkAsync(
            user.Id,
            new ExternalIdentityDescriptor("oidc", "subject-2", null, null),
            CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Equal(1, links.AddCount);
        Assert.Equal("subject-2", links.Added!.Subject);
    }

    private sealed class FixedClock : ISystemClock
    {
        public DateTimeOffset UtcNow => new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    }

    private sealed class FakeLinkRepository(params ExternalIdentityLink[] initial) : IExternalIdentityLinkRepository
    {
        private readonly List<ExternalIdentityLink> links = [.. initial];
        public int SaveCount { get; private set; }
        public int AddCount { get; private set; }
        public ExternalIdentityLink? Added { get; private set; }

        public Task<ExternalIdentityLink?> FindAsync(string provider, string subject,
            CancellationToken cancellationToken)
            => Task.FromResult<ExternalIdentityLink?>(links.SingleOrDefault(x =>
                x.Provider == provider && x.Subject == subject));

        public Task<IReadOnlyCollection<ExternalIdentityLink>> FindForUserAsync(UserId userId,
            CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyCollection<ExternalIdentityLink>>(
                links.Where(x => x.UserId == userId).ToArray());

        public Task AddAsync(ExternalIdentityLink link, CancellationToken cancellationToken)
        {
            AddCount++;
            Added = link;
            links.Add(link);
            return Task.CompletedTask;
        }

        public Task SaveAsync(ExternalIdentityLink link, CancellationToken cancellationToken)
        {
            SaveCount++;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeUserRepository(params User[] initial) : IUserRepository
    {
        private readonly List<User> users = [.. initial];
        public int FindCount { get; private set; }

        public Task<User?> FindByUsernameAsync(string username, CancellationToken cancellationToken) =>
            Task.FromResult<User?>(null);

        public Task<User?> FindAsync(UserId id, CancellationToken cancellationToken)
        {
            FindCount++;
            return Task.FromResult(users.SingleOrDefault(x => x.Id == id));
        }

        public Task AddAsync(User user, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task SaveAsync(User user, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}