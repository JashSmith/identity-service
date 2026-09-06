using Identity.Application;
using Identity.Domain;
using Microsoft.EntityFrameworkCore;

namespace Identity.Persistence.EntityFrameworkCore;

public sealed class EfUserRepository(IdentityDbContext db) : IUserRepository
{
    public Task<User?> FindByUsernameAsync(string username, CancellationToken cancellationToken) =>
        db.Users.SingleOrDefaultAsync(x => x.Username == username, cancellationToken);

    public Task<User?> FindAsync(UserId id, CancellationToken cancellationToken) =>
        db.Users.SingleOrDefaultAsync(x => x.Id == id, cancellationToken);

    public async Task AddAsync(User user, CancellationToken cancellationToken)
    {
        await db.Users.AddAsync(user, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task SaveAsync(User user, CancellationToken cancellationToken)
    {
        db.Users.Update(user);
        await db.SaveChangesAsync(cancellationToken);
    }
}

public sealed class EfPasswordCredentialStore(IdentityDbContext db) : IPasswordCredentialStore
{
    public Task<PasswordCredential?> FindAsync(UserId userId, CancellationToken cancellationToken) =>
        db.PasswordCredentials.SingleOrDefaultAsync(x => x.UserId == userId, cancellationToken);

    public async Task SaveAsync(PasswordCredential credential, CancellationToken cancellationToken)
    {
        db.PasswordCredentials.Update(credential);
        await db.SaveChangesAsync(cancellationToken);
    }
}

public sealed class EfSessionStore(IdentityDbContext db) : ISessionStore
{
    public async Task AddAsync(UserSession session, CancellationToken cancellationToken)
    {
        await db.Sessions.AddAsync(session, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
    }

    public Task<UserSession?> FindAsync(Guid id, CancellationToken cancellationToken) =>
        db.Sessions.SingleOrDefaultAsync(x => x.Id == id, cancellationToken);

    public async Task<IReadOnlyCollection<UserSession>> FindForUserAsync(UserId userId,
        CancellationToken cancellationToken)
        => await db.Sessions.Where(x => x.UserId == userId).ToArrayAsync(cancellationToken);

    public async Task RevokeAsync(UserSession session, DateTimeOffset at, CancellationToken cancellationToken)
    {
        session.Revoke(at);
        db.Sessions.Update(session);
        await db.SaveChangesAsync(cancellationToken);
    }
}

public sealed class EfRefreshTokenStore(IdentityDbContext db) : IRefreshTokenStore
{
    public Task<RefreshTokenRecord?> FindAsync(string tokenHash, CancellationToken cancellationToken) =>
        db.RefreshTokens.SingleOrDefaultAsync(x => x.TokenHash == tokenHash, cancellationToken);

    public async Task AddAsync(RefreshTokenRecord record, CancellationToken cancellationToken)
    {
        await db.RefreshTokens.AddAsync(record, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task RotateAsync(RefreshTokenRecord current, RefreshTokenRecord replacement,
        CancellationToken cancellationToken)
    {
        db.RefreshTokens.Update(current);
        await db.RefreshTokens.AddAsync(replacement, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task RevokeFamilyAsync(string familyId, DateTimeOffset revokedAt, CancellationToken cancellationToken)
    {
        var records = await db.RefreshTokens.Where(x => x.FamilyId == familyId && x.RevokedAt == null)
            .ToListAsync(cancellationToken);
        foreach (var record in records) record.Revoke(revokedAt);
        await db.SaveChangesAsync(cancellationToken);
    }
}

public sealed class EfPermissionRepository(IdentityDbContext db) : IPermissionRepository
{
    public Task<Permission?> FindByNameAsync(string name, CancellationToken cancellationToken) =>
        db.Permissions.SingleOrDefaultAsync(x => x.Name == name, cancellationToken);

    public async Task UpsertManifestAsync(PermissionManifest manifest, CancellationToken cancellationToken)
    {
        var existingPermissions = await db.Permissions
            .Where(x => x.ServiceName == manifest.ServiceName)
            .ToListAsync(cancellationToken);
        var incomingNames = manifest.Permissions
            .Select(x => x.Name)
            .ToHashSet(StringComparer.Ordinal);

        foreach (var permission in existingPermissions.Where(x => !incomingNames.Contains(x.Name)))
            permission.Deprecate();

        foreach (var definition in manifest.Permissions)
        {
            var existing = existingPermissions.SingleOrDefault(x => x.Name == definition.Name);
            if (existing is null)
                await db.Permissions.AddAsync(
                    new Permission(PermissionId.New(), definition.Name, manifest.ServiceName, definition.Module,
                        definition.Description, manifest.Version, manifest.PublishedAt), cancellationToken);
            else
                existing.Update(definition.Module, definition.Description, manifest.Version);
        }

        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<IReadOnlyCollection<string>> GetEffectivePermissionsAsync(UserId userId,
        CancellationToken cancellationToken)
    {
        var direct = db.UserPermissions
            .Where(x => x.UserId == userId)
            .Join(db.Permissions.Where(x => !x.IsDeprecated), x => x.PermissionId, x => x.Id,
                (_, permission) => permission.Name);
        var inherited = db.UserRoles
            .Where(x => x.UserId == userId)
            .Join(db.RolePermissions, x => x.RoleId, x => x.RoleId, (_, rolePermission) => rolePermission.PermissionId)
            .Join(db.Permissions.Where(x => !x.IsDeprecated), permissionId => permissionId, permission => permission.Id,
                (_, permission) => permission.Name);
        return await direct.Concat(inherited).Distinct().ToArrayAsync(cancellationToken);
    }
}