namespace Identity.Domain;

public readonly record struct UserId(Guid Value)
{
    public static UserId New() => new(Guid.NewGuid());
}

public readonly record struct RoleId(Guid Value)
{
    public static RoleId New() => new(Guid.NewGuid());
}

public readonly record struct PermissionId(Guid Value)
{
    public static PermissionId New() => new(Guid.NewGuid());
}

public sealed class User
{
    private readonly List<UserRole> _roles = [];
    private readonly List<UserPermission> _permissions = [];

    private User()
    {
    }

    public User(UserId id, string username, string displayName, DateTimeOffset createdAt)
    {
        if (string.IsNullOrWhiteSpace(username)) throw new ArgumentException("Username is required.", nameof(username));
        Id = id;
        Username = username.Trim();
        DisplayName = displayName.Trim();
        CreatedAt = createdAt;
        SecurityStamp = Guid.NewGuid().ToString("N");
    }

    public UserId Id { get; private set; }
    public string Username { get; private set; } = string.Empty;
    public string DisplayName { get; private set; } = string.Empty;
    public bool IsEnabled { get; private set; } = true;
    public int FailedLoginCount { get; private set; }
    public DateTimeOffset? LockedUntil { get; private set; }
    public string SecurityStamp { get; private set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset? UpdatedAt { get; private set; }
    public IReadOnlyCollection<UserRole> Roles => _roles;
    public IReadOnlyCollection<UserPermission> DirectPermissions => _permissions;

    public bool IsLocked(DateTimeOffset now) => LockedUntil is { } until && until > now;

    public void RecordFailedLogin(DateTimeOffset now, int threshold, TimeSpan lockout)
    {
        FailedLoginCount++;
        if (FailedLoginCount >= threshold) LockedUntil = now.Add(lockout);
        UpdatedAt = now;
    }

    public void RecordSuccessfulLogin(DateTimeOffset now)
    {
        FailedLoginCount = 0;
        LockedUntil = null;
        UpdatedAt = now;
    }

    public void Disable(DateTimeOffset now)
    {
        IsEnabled = false;
        UpdatedAt = now;
    }

    public void Enable(DateTimeOffset now)
    {
        IsEnabled = true;
        UpdatedAt = now;
    }

    public void RotateSecurityStamp(DateTimeOffset now)
    {
        SecurityStamp = Guid.NewGuid().ToString("N");
        UpdatedAt = now;
    }

    public void AssignRole(RoleId roleId, DateTimeOffset now)
    {
        if (_roles.All(x => x.RoleId != roleId)) _roles.Add(new UserRole(Id, roleId, now));
        UpdatedAt = now;
    }

    public void GrantPermission(PermissionId permissionId, DateTimeOffset now)
    {
        if (_permissions.All(x => x.PermissionId != permissionId))
            _permissions.Add(new UserPermission(Id, permissionId, now));
        UpdatedAt = now;
    }
}

public sealed class PasswordCredential
{
    private PasswordCredential()
    {
    }

    public PasswordCredential(UserId userId, string passwordHash, DateTimeOffset createdAt)
    {
        UserId = userId;
        PasswordHash = passwordHash;
        CreatedAt = createdAt;
    }

    public UserId UserId { get; private set; }
    public string PasswordHash { get; private set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset? ChangedAt { get; private set; }

    public void Change(string hash, DateTimeOffset changedAt)
    {
        PasswordHash = hash;
        ChangedAt = changedAt;
    }
}

public sealed class UserSession
{
    private UserSession()
    {
    }

    public UserSession(Guid id, UserId userId, DateTimeOffset createdAt, DateTimeOffset expiresAt, string securityStamp)
    {
        Id = id;
        UserId = userId;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
        SecurityStamp = securityStamp;
    }

    public Guid Id { get; private set; }
    public UserId UserId { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset ExpiresAt { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }
    public string SecurityStamp { get; private set; } = string.Empty;
    public bool IsActive(DateTimeOffset now) => RevokedAt is null && ExpiresAt > now;
    public void Revoke(DateTimeOffset now) => RevokedAt = now;
}

public sealed record UserRole(UserId UserId, RoleId RoleId, DateTimeOffset AssignedAt);

public sealed record UserPermission(UserId UserId, PermissionId PermissionId, DateTimeOffset AssignedAt);

public sealed class Role
{
    private readonly List<RolePermission> _permissions = [];

    private Role()
    {
    }

    public Role(RoleId id, string name, string description)
    {
        Id = id;
        Name = name.Trim();
        Description = description.Trim();
    }

    public RoleId Id { get; private set; }
    public string Name { get; private set; } = string.Empty;
    public string Description { get; private set; } = string.Empty;
    public IReadOnlyCollection<RolePermission> Permissions => _permissions;

    public void GrantPermission(PermissionId permissionId, DateTimeOffset assignedAt)
    {
        if (_permissions.All(x => x.PermissionId != permissionId))
            _permissions.Add(new RolePermission(Id, permissionId, assignedAt));
    }
}

public sealed record RolePermission(RoleId RoleId, PermissionId PermissionId, DateTimeOffset AssignedAt);

public sealed class Permission
{
    private Permission()
    {
    }

    public Permission(PermissionId id, string name, string serviceName, string module, string description,
        string version, DateTimeOffset registeredAt)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 200)
            throw new ArgumentException("A stable permission name is required.", nameof(name));
        Id = id;
        Name = name.Trim();
        ServiceName = serviceName.Trim();
        Module = module.Trim();
        Description = description.Trim();
        Version = version.Trim();
        RegisteredAt = registeredAt;
    }

    public PermissionId Id { get; private set; }
    public string Name { get; private set; } = string.Empty;
    public string ServiceName { get; private set; } = string.Empty;
    public string Module { get; private set; } = string.Empty;
    public string Description { get; private set; } = string.Empty;
    public string Version { get; private set; } = string.Empty;
    public DateTimeOffset RegisteredAt { get; private set; }
    public bool IsDeprecated { get; private set; }

    public void Update(string module, string description, string version)
    {
        Module = module.Trim();
        Description = description.Trim();
        Version = version.Trim();
        IsDeprecated = false;
    }

    public void Deprecate() => IsDeprecated = true;
}

public sealed class PermissionManifestState
{
    private PermissionManifestState()
    {
    }

    public PermissionManifestState(string serviceId, string serviceName, string manifestVersion, Guid correlationId,
        DateTimeOffset publishedAt)
    {
        if (string.IsNullOrWhiteSpace(serviceId))
            throw new ArgumentException("Service ID is required.", nameof(serviceId));
        if (string.IsNullOrWhiteSpace(serviceName))
            throw new ArgumentException("Service name is required.", nameof(serviceName));
        ServiceId = serviceId.Trim();
        ServiceName = serviceName.Trim();
        ManifestVersion = manifestVersion.Trim();
        CorrelationId = correlationId;
        PublishedAt = publishedAt;
    }

    public string ServiceId { get; private set; } = string.Empty;
    public string ServiceName { get; private set; } = string.Empty;
    public string ManifestVersion { get; private set; } = string.Empty;
    public Guid CorrelationId { get; private set; }
    public DateTimeOffset PublishedAt { get; private set; }

    public void Accept(string serviceId, string manifestVersion, Guid correlationId, DateTimeOffset publishedAt)
    {
        ServiceId = serviceId.Trim();
        ManifestVersion = manifestVersion.Trim();
        CorrelationId = correlationId;
        PublishedAt = publishedAt;
    }
}

public sealed class RefreshTokenRecord
{
    private RefreshTokenRecord()
    {
    }

    public RefreshTokenRecord(Guid id, UserId userId, Guid sessionId, string tokenHash, string familyId,
        DateTimeOffset expiresAt, DateTimeOffset createdAt)
    {
        Id = id;
        UserId = userId;
        SessionId = sessionId;
        TokenHash = tokenHash;
        FamilyId = familyId;
        ExpiresAt = expiresAt;
        CreatedAt = createdAt;
    }

    public Guid Id { get; private set; }
    public UserId UserId { get; private set; }
    public Guid SessionId { get; private set; }
    public string TokenHash { get; private set; } = string.Empty;
    public string FamilyId { get; private set; } = string.Empty;
    public DateTimeOffset ExpiresAt { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }
    public string? ReplacedByHash { get; private set; }
    public bool IsActive(DateTimeOffset now) => RevokedAt is null && ExpiresAt > now;

    public void Replace(string hash, DateTimeOffset revokedAt)
    {
        RevokedAt = revokedAt;
        ReplacedByHash = hash;
    }

    public void Revoke(DateTimeOffset revokedAt) => RevokedAt = revokedAt;
}