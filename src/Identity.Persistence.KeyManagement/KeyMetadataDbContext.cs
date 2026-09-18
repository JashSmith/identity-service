using Identity.Application;
using Identity.Contracts;
using Identity.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Identity.Persistence.KeyManagement;

public sealed class SigningKeyEntity
{
    public string Kid { get; set; } = "";
    public string Realm { get; set; } = "";
    public int Size { get; set; }
    public string PublicPemFingerprint { get; set; } = "";
    public string VaultPath { get; set; } = "";
    public int VaultVersion { get; set; }
    public string State { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public string? KeycloakComponentId { get; set; }
    public DateTimeOffset? ActivatedAt { get; set; }
    public DateTimeOffset? PassivatedAt { get; set; }
    public DateTimeOffset? RetiredAt { get; set; }
    public DateTimeOffset? DestroyedAt { get; set; }
    public string? Origin { get; set; }
}

public sealed class KeyHistoryEntity
{
    public int Id { get; set; }
    public string Realm { get; set; } = "";
    public string Kid { get; set; } = "";
    public string FromState { get; set; } = "";
    public string ToState { get; set; } = "";
    public DateTimeOffset OccurredAt { get; set; }
    public string Actor { get; set; } = "";
    public string? Reason { get; set; }
}

public sealed class RotationOperationEntity
{
    public string OperationId { get; set; } = "";
    public string IdempotencyKey { get; set; } = "";
    public string Realm { get; set; } = "";
    public string? TargetKid { get; set; }
    public string? PreviousKid { get; set; }
    public string CurrentStep { get; set; } = "";
    public string Status { get; set; } = "";
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public string Actor { get; set; } = "";
    public string? FailureReason { get; set; }
    public string? LockOwnerToken { get; set; }
}

[Obsolete(
    "Legacy/test-only. Authorization lives in Keycloak iam-scope-registry, not Oracle. Kept for InMemoryDatabase tests during migration; do not use in production.")]
public sealed class ScopeDefinitionEntity
{
    public Guid Id { get; set; }
    public string Key { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string? Description { get; set; }
    public bool IsActive { get; set; } = true;
    public string ValueType { get; set; } = "String";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

[Obsolete("Legacy/test-only.")]
public sealed class ApplicationResourceEntity
{
    public Guid Id { get; set; }
    public string Key { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string? Description { get; set; }
}

[Obsolete("Legacy/test-only.")]
public sealed class ScopeResourceMappingEntity
{
    public Guid ScopeDefinitionId { get; set; }
    public Guid ApplicationResourceId { get; set; }
}

[Obsolete("Legacy/test-only.")]
public sealed class RoleAllowedScopeEntity
{
    public string RoleName { get; set; } = "";
    public Guid ScopeDefinitionId { get; set; }
}

[Obsolete("Legacy/test-only.")]
public sealed class UserRoleAssignmentEntity
{
    public Guid Id { get; set; }
    public string UserId { get; set; } = "";
    public string RoleName { get; set; } = "";
    public DateTimeOffset AssignedAt { get; set; }
}

[Obsolete("Legacy/test-only.")]
public sealed class AssignmentScopeEntity
{
    public Guid Id { get; set; }
    public Guid UserRoleAssignmentId { get; set; }
    public Guid ScopeDefinitionId { get; set; }
}

[Obsolete("Legacy/test-only.")]
public sealed class AssignmentScopeValueEntity
{
    public Guid Id { get; set; }
    public Guid AssignmentScopeId { get; set; }
    public string Value { get; set; } = "";
}

/// <summary>
/// Oracle identity-meta-db retains only key/Vault sync metadata.
/// Authorization (scopes, resources, assignments) lives in Keycloak
/// Groups/attributes via <c>iam-scope-registry</c>; no dual write.
/// </summary>
public sealed class KeyMetadataDbContext(DbContextOptions<KeyMetadataDbContext> options) : DbContext(options)
{
    public DbSet<SigningKeyEntity> SigningKeys => Set<SigningKeyEntity>();
    public DbSet<KeyHistoryEntity> KeyHistories => Set<KeyHistoryEntity>();
    public DbSet<RotationOperationEntity> RotationOperations => Set<RotationOperationEntity>();
#pragma warning disable CS0618
    public DbSet<ScopeDefinitionEntity> ScopeDefinitions => Set<ScopeDefinitionEntity>();
    public DbSet<ApplicationResourceEntity> ApplicationResources => Set<ApplicationResourceEntity>();
    public DbSet<ScopeResourceMappingEntity> ScopeResourceMappings => Set<ScopeResourceMappingEntity>();
    public DbSet<RoleAllowedScopeEntity> RoleAllowedScopes => Set<RoleAllowedScopeEntity>();
    public DbSet<UserRoleAssignmentEntity> UserRoleAssignments => Set<UserRoleAssignmentEntity>();
    public DbSet<AssignmentScopeEntity> AssignmentScopes => Set<AssignmentScopeEntity>();
    public DbSet<AssignmentScopeValueEntity> AssignmentScopeValues => Set<AssignmentScopeValueEntity>();
#pragma warning restore CS0618

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<SigningKeyEntity>(e =>
        {
            e.HasKey(x => new { x.Realm, x.Kid });
            e.HasIndex(x => x.Kid).IsUnique(false);
            e.Property(x => x.State).HasMaxLength(32).IsRequired();
            e.Property(x => x.PublicPemFingerprint).HasMaxLength(128).IsRequired();
            e.Property(x => x.VaultPath).HasMaxLength(512).IsRequired();
            e.Property(x => x.Realm).HasMaxLength(128).IsRequired();
            e.Property(x => x.Kid).HasMaxLength(128).IsRequired();
        });
        b.Entity<KeyHistoryEntity>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => new { x.Realm, x.Kid, x.OccurredAt });
        });
        b.Entity<RotationOperationEntity>(e =>
        {
            e.HasKey(x => x.OperationId);
            e.HasIndex(x => new { x.Realm, x.IdempotencyKey }).IsUnique();
        });
#pragma warning disable CS0618
        b.Entity<ScopeDefinitionEntity>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.Key).IsUnique();
            e.Property(x => x.Key).HasMaxLength(64).IsRequired();
            e.Property(x => x.DisplayName).HasMaxLength(128).IsRequired();
            e.Property(x => x.ValueType).HasMaxLength(32).IsRequired();
            e.Property(x => x.IsActive)
                .HasConversion(new BoolToZeroOneConverter<int>());
        });
        b.Entity<ApplicationResourceEntity>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.Key).IsUnique();
            e.Property(x => x.Key).HasMaxLength(64).IsRequired();
            e.Property(x => x.DisplayName).HasMaxLength(128).IsRequired();
        });
        b.Entity<ScopeResourceMappingEntity>(e =>
        {
            e.HasKey(x => new { x.ScopeDefinitionId, x.ApplicationResourceId });
            e.HasOne<ScopeDefinitionEntity>().WithMany().HasForeignKey(x => x.ScopeDefinitionId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasOne<ApplicationResourceEntity>().WithMany().HasForeignKey(x => x.ApplicationResourceId)
                .OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<RoleAllowedScopeEntity>(e =>
        {
            e.HasKey(x => new { x.RoleName, x.ScopeDefinitionId });
            e.Property(x => x.RoleName).HasMaxLength(128).IsRequired();
            e.HasOne<ScopeDefinitionEntity>().WithMany().HasForeignKey(x => x.ScopeDefinitionId)
                .OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<UserRoleAssignmentEntity>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => new { x.UserId, x.RoleName }).IsUnique();
            e.HasIndex(x => x.UserId);
            e.Property(x => x.UserId).HasMaxLength(64).IsRequired();
            e.Property(x => x.RoleName).HasMaxLength(128).IsRequired();
        });
        b.Entity<AssignmentScopeEntity>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => new { x.UserRoleAssignmentId, x.ScopeDefinitionId }).IsUnique();
            e.HasOne<UserRoleAssignmentEntity>().WithMany().HasForeignKey(x => x.UserRoleAssignmentId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasOne<ScopeDefinitionEntity>().WithMany().HasForeignKey(x => x.ScopeDefinitionId)
                .OnDelete(DeleteBehavior.Restrict);
        });
        b.Entity<AssignmentScopeValueEntity>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => new { x.AssignmentScopeId, x.Value }).IsUnique();
            e.HasIndex(x => x.AssignmentScopeId);
            e.Property(x => x.Value).HasMaxLength(256).IsRequired();
            e.HasOne<AssignmentScopeEntity>().WithMany().HasForeignKey(x => x.AssignmentScopeId)
                .OnDelete(DeleteBehavior.Cascade);
        });
#pragma warning restore CS0618
    }

    public static void ConfigureProvider(DbContextOptionsBuilder b, string provider, string cs)
    {
        switch (provider.ToLowerInvariant())
        {
            case "oracle": b.UseOracle(cs, builder =>
            {
                builder.UseOracleSQLCompatibility(OracleSQLCompatibility.DatabaseVersion21);
            }); break;
            case "npgsql":
            case "postgres":
            case "postgresql": b.UseNpgsql(cs); break;
            default: b.UseSqlite(cs); break;
        }
    }
}

public sealed class EfKeyLifecycleRepository(KeyMetadataDbContext db) : IKeyLifecycleRepository
{
    public async Task<SigningKeyMetadata?> GetAsync(string realm, string kid, CancellationToken ct)
    {
        var e = await db.SigningKeys.FindAsync([realm, kid], ct);
        return e is null ? null : Map(e);
    }

    public async Task<IReadOnlyCollection<SigningKeyMetadata>> ListAsync(string realm, int page, int pageSize,
        CancellationToken ct)
    {
        var list = await db.SigningKeys.Where(x => x.Realm == realm).OrderBy(x => x.Kid)
            .Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        return list.Select(Map).ToList();
    }

    public Task<int> CountAsync(string realm, CancellationToken ct) =>
        db.SigningKeys.CountAsync(x => x.Realm == realm, ct);

    public async Task UpsertAsync(SigningKeyMetadata meta, CancellationToken ct)
    {
        var e = await db.SigningKeys.FindAsync([meta.Realm, meta.Kid], ct);
        if (e is null) db.SigningKeys.Add(ToEntity(meta));
        else UpdateEntity(e, meta);
        await db.SaveChangesAsync(ct);
    }

    public async Task AddHistoryAsync(string realm, string kid, string fromState, string toState, DateTimeOffset when,
        string actor, string? reason, CancellationToken ct)
    {
        db.KeyHistories.Add(new KeyHistoryEntity
        {
            Realm = realm, Kid = kid, FromState = fromState, ToState = toState, OccurredAt = when, Actor = actor,
            Reason = reason
        });
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyCollection<KeyHistoryEntryDto>> GetHistoryAsync(string realm, string kid,
        CancellationToken ct)
    {
        var list = await db.KeyHistories.Where(x => x.Realm == realm && x.Kid == kid).OrderBy(x => x.OccurredAt)
            .ToListAsync(ct);
        return list.Select(x => new KeyHistoryEntryDto(x.Kid, x.FromState, x.ToState, x.OccurredAt, x.Actor, x.Reason))
            .ToList();
    }

    public async Task<KeyRotationOperation?> GetOperationAsync(string operationId, CancellationToken ct)
    {
        var e = await db.RotationOperations.FindAsync([operationId], ct);
        return e is null ? null : MapOp(e);
    }

    public async Task<KeyRotationOperation?> GetOperationByIdempotencyAsync(string realm, string idempotencyKey,
        CancellationToken ct)
    {
        var e = await db.RotationOperations.FirstOrDefaultAsync(
            x => x.Realm == realm && x.IdempotencyKey == idempotencyKey, ct);
        return e is null ? null : MapOp(e);
    }

    public async Task UpsertOperationAsync(KeyRotationOperation op, CancellationToken ct)
    {
        var e = await db.RotationOperations.FindAsync([op.OperationId], ct);
        if (e is null) db.RotationOperations.Add(ToEntity(op));
        else UpdateEntity(e, op);
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyCollection<KeyRotationOperation>> ListInFlightAsync(string realm, CancellationToken ct)
    {
        var list = await db.RotationOperations
            .Where(x => x.Realm == realm && x.Status == SagaStatus.InProgress.ToString()).ToListAsync(ct);
        return list.Select(MapOp).ToList();
    }

    private static SigningKeyMetadata Map(SigningKeyEntity e) => new(e.Kid, (RsaKeySize)e.Size, e.PublicPemFingerprint,
        e.VaultPath, e.VaultVersion, Enum.Parse<KeyLifecycleState>(e.State), e.CreatedAt, e.Realm,
        e.KeycloakComponentId, e.ActivatedAt, e.PassivatedAt, e.RetiredAt, e.DestroyedAt, e.Origin);

    private static SigningKeyEntity ToEntity(SigningKeyMetadata m) => new()
    {
        Kid = m.Kid, Realm = m.Realm, Size = (int)m.Size, PublicPemFingerprint = m.PublicPemFingerprint,
        VaultPath = m.VaultPath, VaultVersion = m.VaultVersion, State = m.State.ToString(), CreatedAt = m.CreatedAt,
        KeycloakComponentId = m.KeycloakComponentId, ActivatedAt = m.ActivatedAt, PassivatedAt = m.PassivatedAt,
        RetiredAt = m.RetiredAt, DestroyedAt = m.DestroyedAt, Origin = m.Origin
    };

    private static void UpdateEntity(SigningKeyEntity e, SigningKeyMetadata m)
    {
        e.Size = (int)m.Size;
        e.PublicPemFingerprint = m.PublicPemFingerprint;
        e.VaultPath = m.VaultPath;
        e.VaultVersion = m.VaultVersion;
        e.State = m.State.ToString();
        e.KeycloakComponentId = m.KeycloakComponentId;
        e.ActivatedAt = m.ActivatedAt;
        e.PassivatedAt = m.PassivatedAt;
        e.RetiredAt = m.RetiredAt;
        e.DestroyedAt = m.DestroyedAt;
        e.Origin = m.Origin;
    }

    private static KeyRotationOperation MapOp(RotationOperationEntity e) => new(e.OperationId, e.IdempotencyKey,
        e.Realm, e.TargetKid, e.PreviousKid, Enum.Parse<KeyLifecycleState>(e.CurrentStep),
        Enum.Parse<SagaStatus>(e.Status), e.StartedAt, e.UpdatedAt, e.Actor, e.FailureReason, e.LockOwnerToken);

    private static RotationOperationEntity ToEntity(KeyRotationOperation o) => new()
    {
        OperationId = o.OperationId, IdempotencyKey = o.IdempotencyKey, Realm = o.Realm, TargetKid = o.TargetKid,
        PreviousKid = o.PreviousKid, CurrentStep = o.CurrentStep.ToString(), Status = o.Status.ToString(),
        StartedAt = o.StartedAt, UpdatedAt = o.UpdatedAt, Actor = o.Actor, FailureReason = o.FailureReason,
        LockOwnerToken = o.LockOwnerToken
    };

    private static void UpdateEntity(RotationOperationEntity e, KeyRotationOperation o)
    {
        e.IdempotencyKey = o.IdempotencyKey;
        e.TargetKid = o.TargetKid;
        e.PreviousKid = o.PreviousKid;
        e.CurrentStep = o.CurrentStep.ToString();
        e.Status = o.Status.ToString();
        e.UpdatedAt = o.UpdatedAt;
        e.FailureReason = o.FailureReason;
        e.LockOwnerToken = o.LockOwnerToken;
    }
}