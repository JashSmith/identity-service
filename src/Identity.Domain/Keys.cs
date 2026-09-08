namespace Identity.Domain;

/// <summary>RSA key sizes accepted by the platform. 1024-bit and lower are excluded on purpose.</summary>
public enum RsaKeySize
{
    Rsa2048 = 2048,
    Rsa3072 = 3072,
    Rsa4096 = 4096
}

/// <summary>
/// Canonical lifecycle states tracked by the facade. Only a strict subset of these maps to the
/// Keycloak-facing states (Active, Passive, Disabled). Staging never changes which key signs.
/// </summary>
public enum KeyLifecycleState
{
    /// <summary>Material just produced (generated or parsed on import). Not yet persisted.</summary>
    Generated,
    /// <summary>Stored under its immutable Vault path/version, not yet visible to Keycloak.</summary>
    VaultStored,
    /// <summary>Registered as a Passive Keycloak component. Enabled for verification, not signing.</summary>
    Passive,
    /// <summary>Passive key whose presence and modulus have been validated against realm JWKS.</summary>
    Validated,
    /// <summary>Currently signing. At most one key per realm is Active at any instant.</summary>
    Active,
    /// <summary>Was Active, atomically passivated on activation of its successor; still verifies.</summary>
    InGrace,
    /// <summary>Grace window elapsed; retirement is pending operator or policy action.</summary>
    Retiring,
    /// <summary>Retired from verification. Enabled=false in Keycloak. Retained for audit and rollback.</summary>
    Retired,
    /// <summary>Explicitly Disabled by operator. Not signing, not verifying, retained for emergency.</summary>
    Disabled,
    /// <summary>Terminal. Vault version purged and Keycloak component removed. Never reused.</summary>
    Destroyed,
    /// <summary>Validation of a staged or newly-activated key failed; automatic rollback begins.</summary>
    ValidationFailed,
    /// <summary>A rollback has been requested but not yet completed.</summary>
    RollbackPending,
    /// <summary>A rotation was aborted before activation. No production impact.</summary>
    RotationAborted
}

/// <summary>The three states Keycloak's <c>rsa</c> key provider components actually distinguish.</summary>
public enum KeycloakKeyState
{
    /// <summary>Signing tokens. <c>config.active=true</c>, <c>enabled=true</c>.</summary>
    Active,
    /// <summary>Verifying tokens with the old kid. <c>config.active=false</c>, <c>enabled=true</c>.</summary>
    Passive,
    /// <summary>Neither signing nor verifying. <c>config.enabled=false</c>.</summary>
    Disabled
}

/// <summary>The lifecycle transitions the state machine allows. Everything else is illegal.</summary>
public static class KeyLifecycleTransitions
{
    private static readonly IReadOnlyDictionary<KeyLifecycleState, KeyLifecycleState[]> Allowed =
        new Dictionary<KeyLifecycleState, KeyLifecycleState[]>
        {
            [KeyLifecycleState.Generated]        = [KeyLifecycleState.VaultStored, KeyLifecycleState.RotationAborted],
            [KeyLifecycleState.VaultStored]      = [KeyLifecycleState.Passive, KeyLifecycleState.RotationAborted, KeyLifecycleState.Destroyed],
            [KeyLifecycleState.Passive]          = [KeyLifecycleState.Validated, KeyLifecycleState.RotationAborted, KeyLifecycleState.Destroyed],
            [KeyLifecycleState.Validated]        = [KeyLifecycleState.Active, KeyLifecycleState.RotationAborted, KeyLifecycleState.Destroyed],
            [KeyLifecycleState.Active]           = [KeyLifecycleState.InGrace, KeyLifecycleState.RollbackPending],
            [KeyLifecycleState.InGrace]          = [KeyLifecycleState.Retiring, KeyLifecycleState.RollbackPending],
            [KeyLifecycleState.Retiring]         = [KeyLifecycleState.Retired],
            [KeyLifecycleState.Retired]          = [KeyLifecycleState.Disabled, KeyLifecycleState.Destroyed],
            [KeyLifecycleState.Disabled]         = [KeyLifecycleState.Destroyed, KeyLifecycleState.RollbackPending],
            [KeyLifecycleState.ValidationFailed] = [KeyLifecycleState.RollbackPending, KeyLifecycleState.RotationAborted],
            [KeyLifecycleState.RollbackPending]  = [KeyLifecycleState.Passive, KeyLifecycleState.Disabled, KeyLifecycleState.RotationAborted],
            [KeyLifecycleState.RotationAborted]  = [KeyLifecycleState.Destroyed],
            [KeyLifecycleState.Destroyed]        = []
        };

    public static bool CanTransition(KeyLifecycleState from, KeyLifecycleState to)
        => Allowed.TryGetValue(from, out var next) && Array.IndexOf(next, to) >= 0;

    /// <summary>Raised when a state change would break the state machine (kid reuse, premature destroy, etc.).</summary>
    public static void Ensure(KeyLifecycleState from, KeyLifecycleState to)
    {
        if (!CanTransition(from, to))
            throw new InvalidOperationException($"Illegal key lifecycle transition {from} -> {to}.");
    }
}

/// <summary>
/// Non-secret metadata about a signing key. This record never carries raw private material; the
/// Vault path/version and the Keycloak component id are its only references to where material lives.
/// </summary>
public sealed record SigningKeyMetadata(
    string Kid,
    RsaKeySize Size,
    string PublicPemFingerprint,
    string VaultPath,
    int VaultVersion,
    KeyLifecycleState State,
    DateTimeOffset CreatedAt,
    string Realm,
    string? KeycloakComponentId = null,
    DateTimeOffset? ActivatedAt = null,
    DateTimeOffset? PassivatedAt = null,
    DateTimeOffset? RetiredAt = null,
    DateTimeOffset? DestroyedAt = null,
    string? Origin = null)
{
    /// <summary>A kid is immutable and never reused. Only these fields may change as the key progresses.</summary>
    public SigningKeyMetadata With(KeyLifecycleState state, DateTimeOffset now, string actor,
        string? keycloakComponentId = null)
    {
        KeyLifecycleTransitions.Ensure(State, state);
        return this with
        {
            State = state,
            KeycloakComponentId = keycloakComponentId ?? KeycloakComponentId,
            ActivatedAt   = state == KeyLifecycleState.Active    ? now : ActivatedAt,
            PassivatedAt  = state == KeyLifecycleState.InGrace   ? now : PassivatedAt,
            RetiredAt     = state == KeyLifecycleState.Retired   ? now : RetiredAt,
            DestroyedAt   = state == KeyLifecycleState.Destroyed ? now : DestroyedAt
        };
    }
}

/// <summary>Persistable saga bookkeeping for a single rotation operation. Never holds secret material.</summary>
public sealed record KeyRotationOperation(
    string OperationId,
    string IdempotencyKey,
    string Realm,
    string? TargetKid,
    string? PreviousKid,
    KeyLifecycleState CurrentStep,
    SagaStatus Status,
    DateTimeOffset StartedAt,
    DateTimeOffset UpdatedAt,
    string Actor,
    string? FailureReason = null,
    string? LockOwnerToken = null)
{
    public KeyRotationOperation Advanced(KeyLifecycleState step, SagaStatus status, DateTimeOffset now,
        string? targetKid = null, string? previousKid = null, string? failure = null)
        => this with
        {
            CurrentStep = step,
            Status = status,
            UpdatedAt = now,
            TargetKid = targetKid ?? TargetKid,
            PreviousKid = previousKid ?? PreviousKid,
            FailureReason = failure ?? FailureReason
        };
}

public enum SagaStatus
{
    InProgress,
    Completed,
    Failed,
    RolledBack
}

/// <summary>
/// Result of the safety check that gates Destroy. Destroy refuses unless all conditions hold;
/// every unmet condition appears in <see cref="BlockingReasons"/>.
/// </summary>
public sealed record RetirementSafetyAssessment(
    string Kid,
    bool Safe,
    IReadOnlyCollection<string> BlockingReasons);
