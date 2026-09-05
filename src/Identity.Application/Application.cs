using Identity.Domain;

namespace Identity.Application;

public interface ISystemClock { DateTimeOffset UtcNow { get; } }
public sealed class SystemClock(TimeProvider timeProvider) : ISystemClock { public DateTimeOffset UtcNow => timeProvider.GetUtcNow(); }

public interface ICurrentUserContext
{
    bool IsAuthenticated { get; }
    Guid? UserId { get; }
    string? Username { get; }
    string? DisplayName { get; }
    IReadOnlyCollection<string> Roles { get; }
    IReadOnlyCollection<string> Permissions { get; }
    string? SessionId { get; }
    DateTimeOffset RequestDateTime { get; }
}

public interface IUserRepository
{
    Task<User?> FindByUsernameAsync(string username, CancellationToken cancellationToken);
    Task<User?> FindAsync(UserId id, CancellationToken cancellationToken);
    Task AddAsync(User user, CancellationToken cancellationToken);
    Task SaveAsync(User user, CancellationToken cancellationToken);
}
public interface IPasswordCredentialStore
{
    Task<PasswordCredential?> FindAsync(UserId userId, CancellationToken cancellationToken);
    Task SaveAsync(PasswordCredential credential, CancellationToken cancellationToken);
}
public interface IPermissionRepository
{
    Task<Permission?> FindByNameAsync(string name, CancellationToken cancellationToken);
    Task UpsertManifestAsync(PermissionManifest manifest, CancellationToken cancellationToken);
    Task<IReadOnlyCollection<string>> GetEffectivePermissionsAsync(UserId userId, CancellationToken cancellationToken);
}
public interface IPermissionManifestVersionStore
{
    Task<bool> TryAcceptAsync(PermissionManifest manifest, CancellationToken cancellationToken);
}
public interface IUnitOfWork
{
    Task<T> ExecuteInTransactionAsync<T>(Func<CancellationToken, Task<T>> operation, CancellationToken cancellationToken);
}
public interface IRefreshTokenStore
{
    Task<RefreshTokenRecord?> FindAsync(string tokenHash, CancellationToken cancellationToken);
    Task AddAsync(RefreshTokenRecord record, CancellationToken cancellationToken);
    Task RotateAsync(RefreshTokenRecord current, RefreshTokenRecord replacement, CancellationToken cancellationToken);
    Task RevokeFamilyAsync(string familyId, DateTimeOffset revokedAt, CancellationToken cancellationToken);
}
public interface ISessionStore
{
    Task AddAsync(UserSession session, CancellationToken cancellationToken);
    Task<UserSession?> FindAsync(Guid id, CancellationToken cancellationToken);
    Task RevokeAsync(UserSession session, DateTimeOffset at, CancellationToken cancellationToken);
}
public interface IPasswordVerifier { bool Verify(string encodedHash, string password); string Hash(string password); }
public interface IAccessTokenIssuer { Task<AccessTokenResult> IssueAsync(User user, IReadOnlyCollection<string> permissions, Guid sessionId, CancellationToken cancellationToken); }
public interface IIntegrationEventPublisher { Task PublishAsync<T>(T message, CancellationToken cancellationToken) where T : class; }

public sealed record PermissionDefinition(string Name, string Description, string Module);
public sealed record PermissionManifest(string ServiceId, string ServiceName, string Version, string Environment, IReadOnlyCollection<PermissionDefinition> Permissions, string ManifestVersion, Guid CorrelationId, DateTimeOffset PublishedAt);
public sealed record AccessTokenResult(string AccessToken, DateTimeOffset ExpiresAt, string KeyId);
public sealed record AuthenticationResult(bool Succeeded, AccessTokenResult? AccessToken, string? RefreshToken, Guid? SessionId, string? ErrorCode)
{ public static AuthenticationResult Failure(string code) => new(false, null, null, null, code); }

public sealed class LocalAuthenticationService(
    IUserRepository users,
    IPasswordCredentialStore credentials,
    IPermissionRepository permissions,
    ISessionStore sessions,
    IRefreshTokenStore refreshTokens,
    IPasswordVerifier passwordVerifier,
    IAccessTokenIssuer tokenIssuer,
    ISystemClock clock)
{
    public async Task<AuthenticationResult> LoginAsync(string username, string password, CancellationToken cancellationToken)
    {
        var user = await users.FindByUsernameAsync(username.Trim(), cancellationToken);
        if (user is null || !user.IsEnabled) return AuthenticationResult.Failure("invalid_credentials");
        if (user.IsLocked(clock.UtcNow)) return AuthenticationResult.Failure("account_locked");
        var credential = await credentials.FindAsync(user.Id, cancellationToken);
        if (credential is null || !passwordVerifier.Verify(credential.PasswordHash, password))
        {
            user.RecordFailedLogin(clock.UtcNow, 5, TimeSpan.FromMinutes(15));
            await users.SaveAsync(user, cancellationToken);
            return AuthenticationResult.Failure("invalid_credentials");
        }
        user.RecordSuccessfulLogin(clock.UtcNow); await users.SaveAsync(user, cancellationToken);
        var session = new UserSession(Guid.NewGuid(), user.Id, clock.UtcNow, clock.UtcNow.AddHours(8), user.SecurityStamp);
        await sessions.AddAsync(session, cancellationToken);
        var effectivePermissions = await permissions.GetEffectivePermissionsAsync(user.Id, cancellationToken);
        var access = await tokenIssuer.IssueAsync(user, effectivePermissions, session.Id, cancellationToken);
        var rawRefresh = TokenGenerator.Generate();
        var refresh = new RefreshTokenRecord(Guid.NewGuid(), user.Id, session.Id, TokenGenerator.Hash(rawRefresh), Guid.NewGuid().ToString("N"), clock.UtcNow.AddDays(30), clock.UtcNow);
        await refreshTokens.AddAsync(refresh, cancellationToken);
        return new AuthenticationResult(true, access, rawRefresh, session.Id, null);
    }

    public async Task<AuthenticationResult> RefreshAsync(string rawRefreshToken, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(rawRefreshToken)) return AuthenticationResult.Failure("invalid_refresh_token");
        var current = await refreshTokens.FindAsync(TokenGenerator.Hash(rawRefreshToken), cancellationToken);
        if (current is null) return AuthenticationResult.Failure("invalid_refresh_token");
        if (!current.IsActive(clock.UtcNow))
        {
            await refreshTokens.RevokeFamilyAsync(current.FamilyId, clock.UtcNow, cancellationToken);
            return AuthenticationResult.Failure("refresh_token_reuse_detected");
        }
        var session = await sessions.FindAsync(current.SessionId, cancellationToken);
        var user = await users.FindAsync(current.UserId, cancellationToken);
        if (session is null || user is null || !session.IsActive(clock.UtcNow) || !user.IsEnabled || user.IsLocked(clock.UtcNow))
            return AuthenticationResult.Failure("session_invalid");
        var rawReplacement = TokenGenerator.Generate();
        var replacement = new RefreshTokenRecord(Guid.NewGuid(), user.Id, session.Id, TokenGenerator.Hash(rawReplacement), current.FamilyId, clock.UtcNow.AddDays(30), clock.UtcNow);
        current.Replace(replacement.TokenHash, clock.UtcNow);
        await refreshTokens.RotateAsync(current, replacement, cancellationToken);
        var effectivePermissions = await permissions.GetEffectivePermissionsAsync(user.Id, cancellationToken);
        var access = await tokenIssuer.IssueAsync(user, effectivePermissions, session.Id, cancellationToken);
        return new AuthenticationResult(true, access, rawReplacement, session.Id, null);
    }

    public async Task<bool> LogoutAsync(Guid sessionId, CancellationToken cancellationToken)
    {
        var session = await sessions.FindAsync(sessionId, cancellationToken);
        if (session is null) return false;
        await sessions.RevokeAsync(session, clock.UtcNow, cancellationToken);
        return true;
    }

    public static class TokenGenerator
    {
        public static string Generate() => Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(48));
        public static string Hash(string value) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }
}

public sealed class PermissionManifestSynchronizer(
    IPermissionRepository repository,
    IPermissionManifestVersionStore versions,
    IUnitOfWork? unitOfWork = null)
{
    public Task<bool> SynchronizeAsync(PermissionManifest manifest, CancellationToken cancellationToken)
        => unitOfWork is null
            ? SynchronizeCoreAsync(manifest, cancellationToken)
            : unitOfWork.ExecuteInTransactionAsync(operationCancellationToken => SynchronizeCoreAsync(manifest, operationCancellationToken), cancellationToken);

    private async Task<bool> SynchronizeCoreAsync(PermissionManifest manifest, CancellationToken cancellationToken)
    {
        if (!await versions.TryAcceptAsync(manifest, cancellationToken))
            return false;
        await repository.UpsertManifestAsync(manifest, cancellationToken);
        return true;
    }
}
public sealed class PermissionAuthorizationService(IPermissionRepository permissions)
{
    public async Task<bool> HasPermissionAsync(UserId userId, string permission, CancellationToken cancellationToken)
        => (await permissions.GetEffectivePermissionsAsync(userId, cancellationToken)).Contains(permission, StringComparer.Ordinal);
}
