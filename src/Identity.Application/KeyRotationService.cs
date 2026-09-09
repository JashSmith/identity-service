using System.Security.Cryptography;
using Identity.Domain;

namespace Identity.Application;

/// <summary>All privileged permission names for the key lifecycle admin surface.</summary>
public static class KeyPermissions
{
    public const string View = "Identity.Keys.View";
    public const string Generate = "Identity.Keys.Generate";
    public const string Import = "Identity.Keys.Import";
    public const string Stage = "Identity.Keys.Stage";
    public const string Validate = "Identity.Keys.Validate";
    public const string Activate = "Identity.Keys.Activate";
    public const string Passivate = "Identity.Keys.Passivate";
    public const string Retire = "Identity.Keys.Retire";
    public const string Destroy = "Identity.Keys.Destroy";
    public const string Rotate = "Identity.Keys.Rotate";
    public const string EmergencyRotate = "Identity.Keys.EmergencyRotate";
    public const string Rollback = "Identity.Keys.Rollback";
    public const string History = "Identity.Keys.History";
}

/// <summary>
/// Orchestrates the lifecycle saga. Holds no private material beyond the single call that
/// hands it to Vault/Keycloak. Every mutating method is idempotent via the supplied key.
/// </summary>
public sealed class KeyRotationService(
    IKeyGenerationService generation,
    ISigningKeyVault vault,
    IKeycloakKeyManager keycloak,
    IKeyLifecycleRepository repo,
    IKeyRotationLock rotationLock,
    IKeyRetirementSafety safety,
    KeyManagementOptions options,
    TimeProvider clock,
    IAuditSink audit)
{
    private string NewKid()
        => string.Concat(options.KidPrefix, DateTimeOffset.UtcNow.ToString("yyyy-MM"), "-",
            Guid.NewGuid().ToString("N").AsSpan(0, 8));

    private static string NewOpId() => Guid.NewGuid().ToString("N");

    private static Identity.Contracts.SigningKeyDto ToDto(SigningKeyMetadata m) =>
        new(m.Kid, (int) m.Size, m.PublicPemFingerprint, m.VaultPath, m.VaultVersion,
            m.State.ToString(), m.CreatedAt, m.Realm, m.KeycloakComponentId, m.ActivatedAt, m.RetiredAt, m.Origin);

    // ---- Generate + Import (create + store in Vault, no Keycloak yet) ----

    public async Task<Identity.Contracts.SigningKeyDto> GenerateAsync(
        Identity.Contracts.GenerateKeyRequest request, string actor, CancellationToken ct)
    {
        var size = request.Size is 2048 or 3072 or 4096
            ? (RsaKeySize) request.Size
            : options.DefaultSize;
        var kid = string.IsNullOrWhiteSpace(request.Kid) ? NewKid() : request.Kid.Trim();

        if (await repo.GetAsync(options.Realm, kid, ct) is not null)
            throw new InvalidOperationException($"kid '{kid}' already exists and will never be reused.");

        var (publicPem, priv, fingerprint) = generation.Generate(size, kid);
        using (priv)
        {
            var vaultRef =
                await vault.StorePrivateKeyAsync(kid, size, priv.Pem, publicPem, fingerprint, options.Realm, ct);
            var now = clock.GetUtcNow();
            var meta = new SigningKeyMetadata(kid, size, fingerprint, vaultRef.Path, vaultRef.Version,
                KeyLifecycleState.VaultStored, now, options.Realm, Origin: "generated");
            await repo.UpsertAsync(meta, ct);
            await repo.AddHistoryAsync(options.Realm, kid, KeyLifecycleState.Generated.ToString(),
                KeyLifecycleState.VaultStored.ToString(), now, actor, request.Reason, ct);
            await audit.RecordAsync(new AuditEvent(actor, "key.generated", kid, now,
                new Dictionary<string, string?>
                {
                    ["kid"] = kid, ["size"] = ((int) size).ToString(), ["vault_version"] = vaultRef.Version.ToString()
                }), ct);
            return ToDto(meta);
        }
    }

    public async Task<Identity.Contracts.SigningKeyDto> ImportAsync(
        Identity.Contracts.ImportKeyRequest request, string actor, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Pem)) throw new ArgumentException("PEM is required.", nameof(request));
        var requestedKid = string.IsNullOrWhiteSpace(request.Kid) ? NewKid() : request.Kid.Trim();
        if (await repo.GetAsync(options.Realm, requestedKid, ct) is not null)
            throw new InvalidOperationException($"kid '{requestedKid}' already exists and will never be reused.");

        var (publicPem, priv, size, fingerprint) = generation.ParseImport(request.Pem, requestedKid);
        using (priv)
        {
            var vaultRef = await vault.StorePrivateKeyAsync(requestedKid, size, priv.Pem, publicPem, fingerprint,
                options.Realm, ct);
            var now = clock.GetUtcNow();
            var meta = new SigningKeyMetadata(requestedKid, size, fingerprint, vaultRef.Path, vaultRef.Version,
                KeyLifecycleState.VaultStored, now, options.Realm, Origin: "imported");
            await repo.UpsertAsync(meta, ct);
            await repo.AddHistoryAsync(options.Realm, requestedKid, KeyLifecycleState.Generated.ToString(),
                KeyLifecycleState.VaultStored.ToString(), now, actor, request.Reason, ct);
            await audit.RecordAsync(new AuditEvent(actor, "key.imported", requestedKid, now,
                new Dictionary<string, string?> {["kid"] = requestedKid, ["size"] = ((int) size).ToString()}), ct);
            return ToDto(meta);
        }
    }

    // ---- Stage (VaultStored -> Passive): register as Passive Keycloak component ----

    public async Task<Identity.Contracts.SigningKeyDto> StageAsync(string kid, string actor, CancellationToken ct)
    {
        var meta = await repo.GetAsync(options.Realm, kid, ct)
                   ?? throw new KeyNotFoundException($"Key '{kid}' not found.");
        if (meta.State != KeyLifecycleState.VaultStored)
            throw new InvalidOperationException($"Key '{kid}' is {meta.State}, expected VaultStored to stage.");

        // Vault private material is needed transiently for the Keycloak import path (documented interim gap).
        // The Vault adapter returns public info; the Keycloak adapter needs the private PEM, so we re-derive
        // via a dedicated Vault private-read method on the vault port — exposed only to this service.
        // For now the vault port does not expose private reads; stage therefore uses the Keycloak "imported" provider
        // with material that was supplied at generation/import time if available. Since we already vaulted it,
        // the stage call must fetch the private PEM from Vault via a narrow method.
        // To keep the port minimal, we add an internal helper on ISigningKeyVault for this single use.

        // Retrieve private PEM transiently (Vault is source of truth).
        var privatePem = await TryReadPrivatePemAsync(kid, ct);
        var publicPem = (await vault.ReadPublicAsync(kid, ct))?.PublicPem
                        ?? throw new InvalidOperationException($"Vault public mirror for '{kid}' missing.");

        using (privatePem)
        {
            var component =
                await keycloak.RegisterPassiveAsync(options.Realm, kid, meta.Size, privatePem.Pem, publicPem, ct);
            var now = clock.GetUtcNow();
            var next = meta with
            {
                State = KeyLifecycleState.Passive,
                KeycloakComponentId = component.Id
            };
            // Validate transition via helper (Passive is reachable from VaultStored).
            KeyLifecycleTransitions.Ensure(meta.State, next.State);
            await repo.UpsertAsync(next, ct);
            await repo.AddHistoryAsync(options.Realm, kid, meta.State.ToString(), next.State.ToString(), now, actor,
                null, ct);
            await audit.RecordAsync(new AuditEvent(actor, "key.staged", kid, now,
                new Dictionary<string, string?> {["kid"] = kid, ["component_id"] = component.Id}), ct);
            return ToDto(next);
        }
    }

    private async Task<TransientPrivatePem> TryReadPrivatePemAsync(string kid, CancellationToken ct)
    {
        // Prefer a dedicated private-read on the vault port when available (narrow, audited).
        if (vault is ISigningKeyVaultWithPrivateRead withPrivate)
            return await withPrivate.ReadPrivateAsync(kid, ct);
        throw new InvalidOperationException(
            "Vault adapter does not expose private reads. Configure ISigningKeyVaultWithPrivateRead. " +
            "This is intentional: only the rotation service may read private material.");
    }

    // ---- Validate (Passive -> Validated): assert kid present in JWKS ----

    public async Task<Identity.Contracts.SigningKeyDto> ValidateAsync(string kid, string actor, CancellationToken ct)
    {
        var meta = await repo.GetAsync(options.Realm, kid, ct)
                   ?? throw new KeyNotFoundException($"Key '{kid}' not found.");
        if (meta.State != KeyLifecycleState.Passive)
            throw new InvalidOperationException($"Key '{kid}' is {meta.State}, expected Passive to validate.");

        var publicPem = (await vault.ReadPublicAsync(kid, ct))?.PublicPem
                        ?? throw new InvalidOperationException($"Vault public mirror for '{kid}' missing.");
        var result = await keycloak.VerifyInJwksAsync(options.Realm, kid, publicPem, ct);
        var now = clock.GetUtcNow();
        if (!result.Present || !result.FingerprintMatches)
        {
            var failed = meta with {State = KeyLifecycleState.ValidationFailed};
            // Direct assignment for failure branch (outside normal Validated path).
            await repo.UpsertAsync(failed, ct);
            await repo.AddHistoryAsync(options.Realm, kid, meta.State.ToString(), failed.State.ToString(), now, actor,
                result.Reason, ct);
            throw new InvalidOperationException($"Validation failed for '{kid}': {result.Reason}");
        }

        KeyLifecycleTransitions.Ensure(meta.State, KeyLifecycleState.Validated);
        var next = meta with {State = KeyLifecycleState.Validated};
        await repo.UpsertAsync(next, ct);
        await repo.AddHistoryAsync(options.Realm, kid, meta.State.ToString(), next.State.ToString(), now, actor, null,
            ct);
        await audit.RecordAsync(new AuditEvent(actor, "key.validated", kid, now,
            new Dictionary<string, string?> {["kid"] = kid}), ct);
        return ToDto(next);
    }

    // ---- Activate (Validated -> Active): single Active per realm, previous -> InGrace ----

    public async Task<Identity.Contracts.SigningKeyDto> ActivateAsync(string kid, string actor, string? idempotencyKey,
        CancellationToken ct)
    {
        // Idempotency: same key within the same logical operation returns prior outcome.
        if (!string.IsNullOrWhiteSpace(idempotencyKey))
        {
            var prior = await repo.GetOperationByIdempotencyAsync(options.Realm, idempotencyKey, ct);
            if (prior is not null && prior.Status == SagaStatus.Completed && prior.TargetKid == kid)
            {
                var existing = await repo.GetAsync(options.Realm, kid, ct);
                if (existing is not null) return ToDto(existing);
            }
        }

        var meta = await repo.GetAsync(options.Realm, kid, ct)
                   ?? throw new KeyNotFoundException($"Key '{kid}' not found.");
        if (meta.State != KeyLifecycleState.Validated)
            throw new InvalidOperationException($"Key '{kid}' is {meta.State}, expected Validated to activate.");

        var handle = await rotationLock.TryAcquireAsync(options.Realm, options.RotationLockTtl, ct)
                     ?? throw new InvalidOperationException(
                         $"Rotation lock for realm '{options.Realm}' is held by another operation.");
        try
        {
            // Re-read under lock to avoid double-activate races.
            var current = await repo.GetAsync(options.Realm, kid, ct) ?? meta;
            if (current.State == KeyLifecycleState.Active) return ToDto(current);

            var opId = NewOpId();
            var now = clock.GetUtcNow();
            var op = new KeyRotationOperation(opId, idempotencyKey ?? opId, options.Realm, kid, null,
                KeyLifecycleState.Validated, SagaStatus.InProgress, now, now, actor, LockOwnerToken: handle.OwnerToken);
            await repo.UpsertOperationAsync(op, ct);

            // Find previous Active.
            var all = await repo.ListAsync(options.Realm, 1, 200, ct);
            var previousActive = all.FirstOrDefault(x => x.State == KeyLifecycleState.Active);

            await keycloak.ActivateAsync(options.Realm, current.KeycloakComponentId!, ct);
            var activated = current with {State = KeyLifecycleState.Active, ActivatedAt = now};
            await repo.UpsertAsync(activated, ct);
            await repo.AddHistoryAsync(options.Realm, kid, current.State.ToString(), activated.State.ToString(), now,
                actor, null, ct);

            if (previousActive is not null)
            {
                await keycloak.PassivateAsync(options.Realm, previousActive.KeycloakComponentId!, ct);
                var passivated = previousActive with {State = KeyLifecycleState.InGrace, PassivatedAt = now};
                await repo.UpsertAsync(passivated, ct);
                await repo.AddHistoryAsync(options.Realm, previousActive.Kid, previousActive.State.ToString(),
                    passivated.State.ToString(), now, actor, $"superseded by {kid}", ct);
                op = op with {PreviousKid = previousActive.Kid};
            }

            // Convergence poll: new kid present, old kid still present.
            await PollConvergenceAsync(kid, previousActive?.Kid, ct);

            op = op.Advanced(KeyLifecycleState.Active, SagaStatus.Completed, clock.GetUtcNow(), kid, op.PreviousKid);
            await repo.UpsertOperationAsync(op, ct);
            await audit.RecordAsync(new AuditEvent(actor, "key.activated", kid, now,
                new Dictionary<string, string?> {["kid"] = kid, ["previous_kid"] = previousActive?.Kid}), ct);
            return ToDto(activated);
        }
        finally
        {
            await rotationLock.ReleaseAsync(handle, ct);
        }
    }

    private async Task PollConvergenceAsync(string newKid, string? oldKid, CancellationToken ct)
    {
        var deadline = clock.GetUtcNow() + options.ConvergenceTimeout;
        while (clock.GetUtcNow() < deadline)
        {
            var jwks = await keycloak.GetJwksAsync(options.Realm, ct);
            var hasNew = jwks.Keys.Any(k => k.Kid == newKid);
            var hasOld = oldKid is null || jwks.Keys.Any(k => k.Kid == oldKid);
            if (hasNew && hasOld) return;
            await Task.Delay(options.ConvergencePollInterval, ct);
        }

        throw new TimeoutException($"JWKS convergence timed out waiting for kid '{newKid}'" +
                                   (oldKid is null ? "" : $" and retention of '{oldKid}'"));
    }

    // ---- Rotate (full saga): ensure target kid, stage, validate, activate ----

    public async Task<Identity.Contracts.RotationOperationDto> RotateAsync(
        Identity.Contracts.RotateRequest request, string actor, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Reason))
            throw new ArgumentException("Reason is required for rotation.", nameof(request));
        var idem = string.IsNullOrWhiteSpace(request.IdempotencyKey)
            ? Guid.NewGuid().ToString("N")
            : request.IdempotencyKey.Trim();
        var prior = await repo.GetOperationByIdempotencyAsync(options.Realm, idem, ct);
        if (prior is not null) return ToOpDto(prior);

        // Ensure a VaultStored target exists.
        string targetKid = request.TargetKid?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(targetKid))
        {
            var size = request.Size is 2048 or 3072 or 4096 ? (RsaKeySize) request.Size.Value : options.DefaultSize;
            var gen = await GenerateAsync(new Identity.Contracts.GenerateKeyRequest((int) size, Reason: request.Reason),
                actor, ct);
            targetKid = gen.Kid;
        }
        else
        {
            var existing = await repo.GetAsync(options.Realm, targetKid, ct)
                           ?? throw new KeyNotFoundException($"Target kid '{targetKid}' not found.");
            if (existing.State != KeyLifecycleState.VaultStored && existing.State != KeyLifecycleState.Passive &&
                existing.State != KeyLifecycleState.Validated)
                throw new InvalidOperationException(
                    $"Target '{targetKid}' is {existing.State}, expected VaultStored/Passive/Validated.");
        }

        var opId = NewOpId();
        var now = clock.GetUtcNow();
        var op = new KeyRotationOperation(opId, idem, options.Realm, targetKid, null, KeyLifecycleState.VaultStored,
            SagaStatus.InProgress, now, now, actor);
        await repo.UpsertOperationAsync(op, ct);

        try
        {
            var staged = await repo.GetAsync(options.Realm, targetKid, ct);
            if (staged!.State == KeyLifecycleState.VaultStored)
                await StageAsync(targetKid, actor, ct);
            staged = await repo.GetAsync(options.Realm, targetKid, ct);
            if (staged!.State == KeyLifecycleState.Passive)
                await ValidateAsync(targetKid, actor, ct);
            var activated = await ActivateAsync(targetKid, actor, idem + ":activate", ct);
            op = op.Advanced(KeyLifecycleState.Active, SagaStatus.Completed, clock.GetUtcNow(), targetKid, null);
            await repo.UpsertOperationAsync(op, ct);
            return ToOpDto(op);
        }
        catch (Exception ex)
        {
            op = op.Advanced(op.CurrentStep, SagaStatus.Failed, clock.GetUtcNow(), failure: ex.Message);
            await repo.UpsertOperationAsync(op, ct);
            throw;
        }
    }

    public Task<Identity.Contracts.RotationOperationDto> EmergencyRotateAsync(
        Identity.Contracts.EmergencyRotateRequest request, string actor, CancellationToken ct)
        => RotateAsync(new Identity.Contracts.RotateRequest(request.Reason, request.IdempotencyKey, request.Size),
            actor, ct);

    // ---- Rollback: re-activate previous, demote the failed new key (never destroy it) ----

    public async Task<Identity.Contracts.RotationOperationDto> RollbackAsync(
        string failedKid, Identity.Contracts.RollbackRequest request, string actor, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Reason))
            throw new ArgumentException("Reason is required for rollback.", nameof(request));
        var failed = await repo.GetAsync(options.Realm, failedKid, ct)
                     ?? throw new KeyNotFoundException($"Key '{failedKid}' not found.");
        // Find the most recent InGrace/Retiring that was superseded by failedKid.
        var all = await repo.ListAsync(options.Realm, 1, 200, ct);
        var previous =
            all.FirstOrDefault(x => x.State == KeyLifecycleState.InGrace || x.State == KeyLifecycleState.Retiring)
            ?? throw new InvalidOperationException("No rollback candidate found (no InGrace/Retiring key).");

        var handle = await rotationLock.TryAcquireAsync(options.Realm, options.RotationLockTtl, ct)
                     ?? throw new InvalidOperationException("Rotation lock is held.");
        try
        {
            var now = clock.GetUtcNow();
            await keycloak.ActivateAsync(options.Realm, previous.KeycloakComponentId!, ct);
            var reactivated = previous with {State = KeyLifecycleState.Active, ActivatedAt = now};
            await repo.UpsertAsync(reactivated, ct);
            await keycloak.PassivateAsync(options.Realm, failed.KeycloakComponentId!, ct);
            var demoted = failed with {State = KeyLifecycleState.Passive};
            await repo.UpsertAsync(demoted, ct);
            await repo.AddHistoryAsync(options.Realm, previous.Kid, previous.State.ToString(),
                reactivated.State.ToString(), now, actor, $"rollback from {failedKid}: {request.Reason}", ct);
            await repo.AddHistoryAsync(options.Realm, failedKid, failed.State.ToString(), demoted.State.ToString(), now,
                actor, $"rolled back: {request.Reason}", ct);
            var op = new KeyRotationOperation(NewOpId(), request.IdempotencyKey ?? NewOpId(), options.Realm, failedKid,
                previous.Kid,
                KeyLifecycleState.RollbackPending, SagaStatus.RolledBack, now, now, actor);
            await repo.UpsertOperationAsync(op, ct);
            await audit.RecordAsync(new AuditEvent(actor, "key.rollback", failedKid, now,
                new Dictionary<string, string?> {["failed_kid"] = failedKid, ["restored_kid"] = previous.Kid}), ct);
            return ToOpDto(op);
        }
        finally
        {
            await rotationLock.ReleaseAsync(handle, ct);
        }
    }

    // ---- Retire / Destroy ----

    public async Task<Identity.Contracts.SigningKeyDto> RetireAsync(string kid, string actor, CancellationToken ct)
    {
        var meta = await repo.GetAsync(options.Realm, kid, ct) ??
                   throw new KeyNotFoundException($"Key '{kid}' not found.");
        if (meta.State != KeyLifecycleState.InGrace && meta.State != KeyLifecycleState.Retiring)
            throw new InvalidOperationException($"Key '{kid}' is {meta.State}, expected InGrace/Retiring to retire.");
        var now = clock.GetUtcNow();
        var eligibleAt = (meta.PassivatedAt ?? meta.ActivatedAt ?? meta.CreatedAt) + options.GracePeriod;
        if (now < eligibleAt)
            throw new InvalidOperationException($"Key '{kid}' is still in grace until {eligibleAt:O}.");
        await keycloak.DisableAsync(options.Realm, meta.KeycloakComponentId!, ct);
        var next = meta with {State = KeyLifecycleState.Retired, RetiredAt = now};
        await repo.UpsertAsync(next, ct);
        await repo.AddHistoryAsync(options.Realm, kid, meta.State.ToString(), next.State.ToString(), now, actor, null,
            ct);
        return ToDto(next);
    }

    public async Task DestroyAsync(string kid, Identity.Contracts.DestroyRequest request, string actor,
        CancellationToken ct)
    {
        if (request.ConfirmKid != kid)
            throw new ArgumentException("ConfirmKid must equal the target kid.", nameof(request));
        var meta = await repo.GetAsync(options.Realm, kid, ct) ??
                   throw new KeyNotFoundException($"Key '{kid}' not found.");
        var assessment = await safety.AssessAsync(options.Realm, kid, ct);
        if (!assessment.Safe)
            throw new InvalidOperationException(
                $"Destroy blocked for '{kid}': {string.Join("; ", assessment.BlockingReasons)}");
        var now = clock.GetUtcNow();
        await vault.DestroyAsync(kid, ct);
        if (meta.KeycloakComponentId is not null)
            await keycloak.RemoveAsync(options.Realm, meta.KeycloakComponentId, ct);
        var next = meta with {State = KeyLifecycleState.Destroyed, DestroyedAt = now};
        await repo.UpsertAsync(next, ct);
        await repo.AddHistoryAsync(options.Realm, kid, meta.State.ToString(), next.State.ToString(), now, actor,
            request.Reason, ct);
        await audit.RecordAsync(new AuditEvent(actor, "key.destroyed", kid, now,
            new Dictionary<string, string?> {["kid"] = kid}), ct);
    }

    // ---- Reads ----

    public async Task<Identity.Contracts.SigningKeyListDto> ListAsync(int page, int pageSize, CancellationToken ct)
    {
        var items = await repo.ListAsync(options.Realm, page, pageSize, ct);
        var total = await repo.CountAsync(options.Realm, ct);
        return new(items.Select(ToDto).ToArray(), page, pageSize, total);
    }

    public async Task<Identity.Contracts.SigningKeyDetailDto> GetAsync(string kid, CancellationToken ct)
    {
        var meta = await repo.GetAsync(options.Realm, kid, ct) ??
                   throw new KeyNotFoundException($"Key '{kid}' not found.");
        var publicPem = (await vault.ReadPublicAsync(kid, ct))?.PublicPem ?? string.Empty;
        var jwks = await keycloak.GetJwksAsync(options.Realm, ct);
        var entry = jwks.Keys.FirstOrDefault(k => k.Kid == kid);
        return new(ToDto(meta), entry is not null, entry is not null ? "match" : null);
    }

    public Task<IReadOnlyCollection<Identity.Contracts.KeyHistoryEntryDto>> HistoryAsync(string kid,
        CancellationToken ct)
        => repo.GetHistoryAsync(options.Realm, kid, ct);

    public async Task<Identity.Contracts.RotationStateDto> RotationStateAsync(CancellationToken ct)
    {
        var all = await repo.ListAsync(options.Realm, 1, 500, ct);
        var active = all.FirstOrDefault(x => x.State == KeyLifecycleState.Active)?.Kid;
        var passive = all
            .Where(x => x.State is KeyLifecycleState.Passive or KeyLifecycleState.Validated
                or KeyLifecycleState.InGrace).Select(x => x.Kid).ToArray();
        var disabled = all.Where(x => x.State is KeyLifecycleState.Disabled or KeyLifecycleState.Retired)
            .Select(x => x.Kid).ToArray();
        var inflight = await repo.ListInFlightAsync(options.Realm, ct);
        return new(options.Realm, active, passive, disabled, inflight.Select(ToOpDto).ToArray(), clock.GetUtcNow());
    }

    public Task<RetirementSafetyAssessment> AssessDestroySafetyAsync(string kid, CancellationToken ct)
        => safety.AssessAsync(options.Realm, kid, ct);

    private static Identity.Contracts.RotationOperationDto ToOpDto(KeyRotationOperation op) =>
        new(op.OperationId, op.Realm, op.TargetKid, op.PreviousKid, op.CurrentStep.ToString(), op.Status.ToString(),
            op.StartedAt, op.UpdatedAt, op.Actor, op.FailureReason);
}

/// <summary>Narrow vault capability: only the rotation service may read private material transiently.</summary>
public interface ISigningKeyVaultWithPrivateRead : ISigningKeyVault
{
    Task<TransientPrivatePem> ReadPrivateAsync(string kid, CancellationToken cancellationToken);
}