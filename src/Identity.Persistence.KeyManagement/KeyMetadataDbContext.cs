using Identity.Application;
using Identity.Contracts;
using Identity.Domain;
using Microsoft.EntityFrameworkCore;

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

public sealed class KeyMetadataDbContext(DbContextOptions<KeyMetadataDbContext> options) : DbContext(options)
{
    public DbSet<SigningKeyEntity> SigningKeys => Set<SigningKeyEntity>();
    public DbSet<KeyHistoryEntity> KeyHistories => Set<KeyHistoryEntity>();
    public DbSet<RotationOperationEntity> RotationOperations => Set<RotationOperationEntity>();

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
    }

    public static void ConfigureProvider(DbContextOptionsBuilder b, string provider, string cs)
    {
        switch (provider.ToLowerInvariant())
        {
            case "oracle": b.UseOracle(cs); break;
            case "npgsql":
            case "postgres":
            case "postgresql": b.UseNpgsql(cs); break;
            case "sqlite": b.UseSqlite(cs); break;
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
    public async Task<IReadOnlyCollection<SigningKeyMetadata>> ListAsync(string realm, int page, int pageSize, CancellationToken ct)
    {
        var list = await db.SigningKeys.Where(x => x.Realm == realm).OrderBy(x => x.Kid)
            .Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        return list.Select(Map).ToList();
    }
    public Task<int> CountAsync(string realm, CancellationToken ct) => db.SigningKeys.CountAsync(x => x.Realm == realm, ct);
    public async Task UpsertAsync(SigningKeyMetadata meta, CancellationToken ct)
    {
        var e = await db.SigningKeys.FindAsync([meta.Realm, meta.Kid], ct);
        if (e is null) db.SigningKeys.Add(ToEntity(meta));
        else UpdateEntity(e, meta);
        await db.SaveChangesAsync(ct);
    }
    public async Task AddHistoryAsync(string realm, string kid, string fromState, string toState, DateTimeOffset when, string actor, string? reason, CancellationToken ct)
    {
        db.KeyHistories.Add(new KeyHistoryEntity { Realm = realm, Kid = kid, FromState = fromState, ToState = toState, OccurredAt = when, Actor = actor, Reason = reason });
        await db.SaveChangesAsync(ct);
    }
    public async Task<IReadOnlyCollection<KeyHistoryEntryDto>> GetHistoryAsync(string realm, string kid, CancellationToken ct)
    {
        var list = await db.KeyHistories.Where(x => x.Realm == realm && x.Kid == kid).OrderBy(x => x.OccurredAt).ToListAsync(ct);
        return list.Select(x => new KeyHistoryEntryDto(x.Kid, x.FromState, x.ToState, x.OccurredAt, x.Actor, x.Reason)).ToList();
    }
    public async Task<KeyRotationOperation?> GetOperationAsync(string operationId, CancellationToken ct)
    {
        var e = await db.RotationOperations.FindAsync([operationId], ct);
        return e is null ? null : MapOp(e);
    }
    public async Task<KeyRotationOperation?> GetOperationByIdempotencyAsync(string realm, string idempotencyKey, CancellationToken ct)
    {
        var e = await db.RotationOperations.FirstOrDefaultAsync(x => x.Realm == realm && x.IdempotencyKey == idempotencyKey, ct);
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
        var list = await db.RotationOperations.Where(x => x.Realm == realm && x.Status == SagaStatus.InProgress.ToString()).ToListAsync(ct);
        return list.Select(MapOp).ToList();
    }
    private static SigningKeyMetadata Map(SigningKeyEntity e) => new(e.Kid, (RsaKeySize)e.Size, e.PublicPemFingerprint, e.VaultPath, e.VaultVersion, Enum.Parse<KeyLifecycleState>(e.State), e.CreatedAt, e.Realm, e.KeycloakComponentId, e.ActivatedAt, e.PassivatedAt, e.RetiredAt, e.DestroyedAt, e.Origin);
    private static SigningKeyEntity ToEntity(SigningKeyMetadata m) => new() { Kid = m.Kid, Realm = m.Realm, Size = (int)m.Size, PublicPemFingerprint = m.PublicPemFingerprint, VaultPath = m.VaultPath, VaultVersion = m.VaultVersion, State = m.State.ToString(), CreatedAt = m.CreatedAt, KeycloakComponentId = m.KeycloakComponentId, ActivatedAt = m.ActivatedAt, PassivatedAt = m.PassivatedAt, RetiredAt = m.RetiredAt, DestroyedAt = m.DestroyedAt, Origin = m.Origin };
    private static void UpdateEntity(SigningKeyEntity e, SigningKeyMetadata m) { e.Size = (int)m.Size; e.PublicPemFingerprint = m.PublicPemFingerprint; e.VaultPath = m.VaultPath; e.VaultVersion = m.VaultVersion; e.State = m.State.ToString(); e.KeycloakComponentId = m.KeycloakComponentId; e.ActivatedAt = m.ActivatedAt; e.PassivatedAt = m.PassivatedAt; e.RetiredAt = m.RetiredAt; e.DestroyedAt = m.DestroyedAt; e.Origin = m.Origin; }
    private static KeyRotationOperation MapOp(RotationOperationEntity e) => new(e.OperationId, e.IdempotencyKey, e.Realm, e.TargetKid, e.PreviousKid, Enum.Parse<KeyLifecycleState>(e.CurrentStep), Enum.Parse<SagaStatus>(e.Status), e.StartedAt, e.UpdatedAt, e.Actor, e.FailureReason, e.LockOwnerToken);
    private static RotationOperationEntity ToEntity(KeyRotationOperation o) => new() { OperationId = o.OperationId, IdempotencyKey = o.IdempotencyKey, Realm = o.Realm, TargetKid = o.TargetKid, PreviousKid = o.PreviousKid, CurrentStep = o.CurrentStep.ToString(), Status = o.Status.ToString(), StartedAt = o.StartedAt, UpdatedAt = o.UpdatedAt, Actor = o.Actor, FailureReason = o.FailureReason, LockOwnerToken = o.LockOwnerToken };
    private static void UpdateEntity(RotationOperationEntity e, KeyRotationOperation o) { e.IdempotencyKey = o.IdempotencyKey; e.TargetKid = o.TargetKid; e.PreviousKid = o.PreviousKid; e.CurrentStep = o.CurrentStep.ToString(); e.Status = o.Status.ToString(); e.UpdatedAt = o.UpdatedAt; e.FailureReason = o.FailureReason; e.LockOwnerToken = o.LockOwnerToken; }
}
