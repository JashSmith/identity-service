using Identity.Domain;

namespace Identity.Application;

/// <summary>Reference returned when a key has been persisted to Vault. No secret material.</summary>
public sealed record VaultKeyReference(string Path, int Version);

/// <summary>What Vault returns on a versioned read. Public fields only.</summary>
public sealed record VaultStoredKey(
    string Kid,
    int VaultVersion,
    string PublicPem,
    string PublicPemFingerprint,
    DateTimeOffset StoredAt);

/// <summary>
/// Vault port. Implementations are the only place allowed to touch Vault HTTP. Never returns a private key
/// through a DTO that outlives the call that needs it.
/// </summary>
public interface ISigningKeyVault
{
    /// <summary>Write a new immutable version. Returns the path/version just created.</summary>
    Task<VaultKeyReference> StorePrivateKeyAsync(
        string kid, RsaKeySize size, string privatePem, string publicPem,
        string publicFingerprint, string realm, CancellationToken cancellationToken);

    /// <summary>Write a public-only mirror entry (for Keycloak-generated pairs that were split).</summary>
    Task<VaultKeyReference> StorePublicMirrorAsync(
        string kid, string publicPem, string publicFingerprint, string realm,
        CancellationToken cancellationToken)
        => throw new NotImplementedException();

    Task<VaultStoredKey?> ReadPublicAsync(string kid, CancellationToken cancellationToken);
    Task<bool> ExistsAsync(string kid, CancellationToken cancellationToken);

    /// <summary>Check-and-set delete of the Vault version(s) at this path. Returns true when deleted.</summary>
    Task<bool> DestroyAsync(string kid, CancellationToken cancellationToken);
}

/// <summary>
/// Holder for a private PEM whose lifetime is the single call that hands it to Vault and/or Keycloak.
/// Implementations must zero memory on <see cref="IDisposable.Dispose"/>.
/// </summary>
public sealed class TransientPrivatePem : IDisposable
{
    private string? _pem;
    private bool _disposed;

    public TransientPrivatePem(string pem) => _pem = pem ?? throw new ArgumentNullException(nameof(pem));

    public string Pem => _disposed || _pem is null
        ? throw new ObjectDisposedException(nameof(TransientPrivatePem))
        : _pem;

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_pem is not null)
        {
            // Overwrite the managed string's characters where possible (best-effort in .NET).
            // Callers must also avoid keeping additional copies.
            _pem = new string('\0', _pem.Length);
            _pem = null;
        }
        GC.SuppressFinalize(this);
    }

    public override string ToString() => "private:***";
}

/// <summary>
/// Generates or parses RSA material without publishing it anywhere. Callers are responsible for
/// handing the transient private PEM to <see cref="ISigningKeyVault"/> immediately and disposing it.
/// </summary>
public interface IKeyGenerationService
{
    /// <summary>Create a fresh RSA key pair of <paramref name="size"/>.</summary>
    (string PublicPem, TransientPrivatePem Private, string PublicFingerprint) Generate(RsaKeySize size, string kid);

    /// <summary>Parse an externally supplied private PEM PKCS#1/PKCS#8 and derive public material.</summary>
    (string PublicPem, TransientPrivatePem Private, RsaKeySize Size, string PublicFingerprint) ParseImport(string privatePem, string kid);
}

/// <summary>Minimal Keycloak Admin component view. Internal representation, never returned to clients.</summary>
public sealed record KeycloakComponentDto(
    string Id,
    string Name,
    string ProviderId,
    string ProviderType,
    IReadOnlyDictionary<string, IReadOnlyCollection<string>> Config);

/// <summary>Port to Keycloak Admin REST (<c>components</c>) and realm JWKS.</summary>
public interface IKeycloakKeyManager
{
    Task<IReadOnlyCollection<KeycloakComponentDto>> ListRsaComponentsAsync(string realm, CancellationToken cancellationToken);
    Task<KeycloakComponentDto> RegisterPassiveAsync(
        string realm, string kid, RsaKeySize size,
        string privatePem, string publicPem, CancellationToken cancellationToken);
    Task ActivateAsync(string realm, string componentId, CancellationToken cancellationToken);
    Task PassivateAsync(string realm, string componentId, CancellationToken cancellationToken);
    Task DisableAsync(string realm, string componentId, CancellationToken cancellationToken);
    Task RemoveAsync(string realm, string componentId, CancellationToken cancellationToken);

    /// <summary>Read the realm JWKS and assert presence/modulus of <paramref name="kid"/>.</summary>
    Task<JwksVerificationResult> VerifyInJwksAsync(string realm, string kid, string publicPem, CancellationToken cancellationToken);

    /// <summary>Raw JWKS fetch for cluster-convergence polling and the smoke-token verifier.</summary>
    Task<JwksSnapshot> GetJwksAsync(string realm, CancellationToken cancellationToken);
}

public sealed record JwksVerificationResult(bool Present, bool FingerprintMatches, string? Reason = null);
public sealed record JwksSnapshot(DateTimeOffset FetchedAt, IReadOnlyCollection<JwkEntry> Keys);
public sealed record JwkEntry(string Kid, string Kty, string Alg, string Use, string N, string E);

/// <summary>Per-realm distributed rotation lock (Redis <c>SET NX PX</c>). Holds a fencing token.</summary>
public interface IKeyRotationLock
{
    Task<RotationLockHandle?> TryAcquireAsync(string realm, TimeSpan ttl, CancellationToken cancellationToken);
    Task<bool> RenewAsync(RotationLockHandle handle, TimeSpan ttl, CancellationToken cancellationToken);
    Task ReleaseAsync(RotationLockHandle handle, CancellationToken cancellationToken);
}

public sealed record RotationLockHandle(string Realm, string OwnerToken, DateTimeOffset AcquiredAt);

/// <summary>Facade's own metadata store for keys and rotation operations. No secret columns.</summary>
public interface IKeyLifecycleRepository
{
    Task<SigningKeyMetadata?> GetAsync(string realm, string kid, CancellationToken cancellationToken);
    Task<IReadOnlyCollection<SigningKeyMetadata>> ListAsync(string realm, int page, int pageSize, CancellationToken cancellationToken);
    Task<int> CountAsync(string realm, CancellationToken cancellationToken);
    Task UpsertAsync(SigningKeyMetadata meta, CancellationToken cancellationToken);
    Task AddHistoryAsync(string realm, string kid, string fromState, string toState, DateTimeOffset when, string actor, string? reason, CancellationToken cancellationToken);
    Task<IReadOnlyCollection<Identity.Contracts.KeyHistoryEntryDto>> GetHistoryAsync(string realm, string kid, CancellationToken cancellationToken);

    Task<KeyRotationOperation?> GetOperationAsync(string operationId, CancellationToken cancellationToken);
    Task<KeyRotationOperation?> GetOperationByIdempotencyAsync(string realm, string idempotencyKey, CancellationToken cancellationToken);
    Task UpsertOperationAsync(KeyRotationOperation op, CancellationToken cancellationToken);
    Task<IReadOnlyCollection<KeyRotationOperation>> ListInFlightAsync(string realm, CancellationToken cancellationToken);
}

/// <summary>
/// Sink for facade audit records. Declared in the Application layer so orchestration can depend on it
/// without referencing Infrastructure. Implementations must not receive unredacted input.
/// </summary>
public interface IAuditSink
{
    Task RecordAsync(AuditEvent auditEvent, CancellationToken cancellationToken);
}

/// <summary>Retirement safety guard. Refuses Destroy unless every condition is met.</summary>
public interface IKeyRetirementSafety
{
    Task<RetirementSafetyAssessment> AssessAsync(string realm, string kid, CancellationToken cancellationToken);
}

/// <summary>
/// Tunables for the lifecycle subsystem. Bound from <c>Identity:KeyManagement</c>.
/// </summary>
public sealed class KeyManagementOptions
{
    public string Realm { get; set; } = "company";
    public TimeSpan GracePeriod { get; set; } = TimeSpan.FromHours(1);
    public TimeSpan RetentionAfterGrace { get; set; } = TimeSpan.FromHours(24);
    public TimeSpan RotationLockTtl { get; set; } = TimeSpan.FromMinutes(5);
    public TimeSpan ConvergenceTimeout { get; set; } = TimeSpan.FromMinutes(2);
    public TimeSpan ConvergencePollInterval { get; set; } = TimeSpan.FromSeconds(3);
    public RsaKeySize DefaultSize { get; set; } = RsaKeySize.Rsa2048;
    public string KidPrefix { get; set; } = "iam-rsa-";
}
