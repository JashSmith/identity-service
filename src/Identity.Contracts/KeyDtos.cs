namespace Identity.Contracts;

/// <summary>Metadata-only representation of a single signing key. Private material is never included.</summary>
public sealed record SigningKeyDto(
    string Kid,
    int Size,
    string PublicPemFingerprint,
    string VaultPath,
    int VaultVersion,
    string State,
    DateTimeOffset CreatedAt,
    string Realm,
    string? KeycloakComponentId,
    DateTimeOffset? ActivatedAt,
    DateTimeOffset? RetiredAt,
    string? Origin);

/// <summary>Single key plus its Vault/JWKS status hints for the detail view.</summary>
public sealed record SigningKeyDetailDto(
    SigningKeyDto Key,
    bool PresentInJwks,
    string? JwksFingerprintMatch);

/// <summary>Paginated list of keys for one realm.</summary>
public sealed record SigningKeyListDto(
    IReadOnlyCollection<SigningKeyDto> Items,
    int Page,
    int PageSize,
    int Total);

/// <summary>Per-kid event in the history log.</summary>
public sealed record KeyHistoryEntryDto(
    string Kid,
    string FromState,
    string ToState,
    DateTimeOffset OccurredAt,
    string Actor,
    string? Reason);

public sealed record KeyHistoryDto(
    string Kid,
    IReadOnlyCollection<KeyHistoryEntryDto> Entries);

/// <summary>Single rotation operation visible to operators.</summary>
public sealed record RotationOperationDto(
    string OperationId,
    string Realm,
    string? TargetKid,
    string? PreviousKid,
    string CurrentStep,
    string Status,
    DateTimeOffset StartedAt,
    DateTimeOffset UpdatedAt,
    string Actor,
    string? FailureReason);

/// <summary>Current signing/verification state for a realm.</summary>
public sealed record RotationStateDto(
    string Realm,
    string? ActiveKid,
    IReadOnlyCollection<string> PassiveKids,
    IReadOnlyCollection<string> DisabledKids,
    IReadOnlyCollection<RotationOperationDto> InFlightOperations,
    DateTimeOffset AsOf);

/// <summary>Whether it is safe to destroy a retired/disabled key.</summary>
public sealed record RetirementSafetyDto(
    string Kid,
    bool Safe,
    IReadOnlyCollection<string> BlockingReasons);

/// <summary>Admin write requests. Private import material travels only on the Import path and is zeroized.</summary>
public sealed record GenerateKeyRequest(int Size, string? Kid = null, string? Reason = null);
public sealed record ImportKeyRequest(string Pem, string? Kid = null, string? Reason = null);
public sealed record RotateRequest(string Reason, string? IdempotencyKey = null, int? Size = null, string? TargetKid = null);
public sealed record EmergencyRotateRequest(string Reason, string? IdempotencyKey = null, int? Size = null);
public sealed record RollbackRequest(string Reason, string? IdempotencyKey = null);
public sealed record DestroyRequest(string ConfirmKid, string Reason);
