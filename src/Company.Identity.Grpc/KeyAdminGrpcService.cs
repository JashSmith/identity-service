using Grpc.Core;
using Identity.Application;
using Identity.Contracts;

namespace Company.Identity.Grpc;

public sealed class KeyAdminGrpcService(KeyRotationService svc) : KeyAdminService.KeyAdminServiceBase
{
    private static SigningKey ToProto(SigningKeyDto d) => new()
    {
        Kid = d.Kid, Size = d.Size, State = d.State, PublicFingerprint = d.PublicPemFingerprint,
        VaultPath = d.VaultPath, VaultVersion = d.VaultVersion, Realm = d.Realm,
        KeycloakComponentId = d.KeycloakComponentId ?? "", CreatedAt = d.CreatedAt.ToString("O"),
        ActivatedAt = d.ActivatedAt?.ToString("O") ?? "", Origin = d.Origin ?? ""
    };

    private static RotationOperation ToOpProto(RotationOperationDto o) => new()
    {
        OperationId = o.OperationId, Realm = o.Realm, TargetKid = o.TargetKid ?? "", PreviousKid = o.PreviousKid ?? "",
        CurrentStep = o.CurrentStep, Status = o.Status, StartedAt = o.StartedAt.ToString("O"),
        UpdatedAt = o.UpdatedAt.ToString("O"),
        Actor = o.Actor, FailureReason = o.FailureReason ?? ""
    };

    public override async Task<SigningKey> GenerateKey(GenerateKeyRequest request, ServerCallContext ctx)
    {
        var dto = await svc.GenerateAsync(
            new global::Identity.Contracts.GenerateKeyRequest(request.Size == 0 ? 2048 : request.Size,
                string.IsNullOrWhiteSpace(request.Kid) ? null : request.Kid, request.Reason), Actor(ctx),
            ctx.CancellationToken);
        return ToProto(dto);
    }

    public override async Task<SigningKey> ImportKey(ImportKeyRequest request, ServerCallContext ctx)
    {
        var dto = await svc.ImportAsync(
            new global::Identity.Contracts.ImportKeyRequest(request.Pem,
                string.IsNullOrWhiteSpace(request.Kid) ? null : request.Kid, request.Reason), Actor(ctx),
            ctx.CancellationToken);
        return ToProto(dto);
    }

    public override async Task<SigningKeyDetail> GetKey(GetKeyRequest request, ServerCallContext ctx)
    {
        var d = await svc.GetAsync(request.Kid, ctx.CancellationToken) ??
                throw new RpcException(new Status(StatusCode.NotFound, $"key {request.Kid} not found"));
        return new SigningKeyDetail
        {
            Key = ToProto(d.Key), PresentInJwks = d.PresentInJwks, JwksFingerprintMatch = d.JwksFingerprintMatch ?? ""
        };
    }

    public override async Task<ListKeysResponse> ListKeys(ListKeysRequest request, ServerCallContext ctx)
    {
        var l = await svc.ListAsync(request.Page <= 0 ? 1 : request.Page, request.PageSize <= 0 ? 20 : request.PageSize,
            ctx.CancellationToken);
        var r = new ListKeysResponse { Total = l.Total, Page = l.Page, PageSize = l.PageSize };
        r.Items.AddRange(l.Items.Select(ToProto));
        return r;
    }

    public override async Task<RotationOperation> Rotate(RotateRequest request, ServerCallContext ctx)
    {
        var dto = await svc.RotateAsync(
            new global::Identity.Contracts.RotateRequest(request.Reason,
                string.IsNullOrWhiteSpace(request.IdempotencyKey) ? null : request.IdempotencyKey,
                request.Size == 0 ? null : request.Size,
                string.IsNullOrWhiteSpace(request.TargetKid) ? null : request.TargetKid), Actor(ctx),
            ctx.CancellationToken);
        return ToOpProto(dto);
    }

    public override async Task<RotationOperation> Rollback(RollbackRequest request, ServerCallContext ctx)
    {
        var dto = await svc.RollbackAsync(request.Kid,
            new global::Identity.Contracts.RollbackRequest(request.Reason,
                string.IsNullOrWhiteSpace(request.IdempotencyKey) ? null : request.IdempotencyKey), Actor(ctx),
            ctx.CancellationToken);
        return ToOpProto(dto);
    }

    public override async Task<RotationState> GetRotationState(GetRotationStateRequest request, ServerCallContext ctx)
    {
        var s = await svc.RotationStateAsync(ctx.CancellationToken);
        var r = new RotationState { Realm = s.Realm, ActiveKid = s.ActiveKid ?? "", AsOf = s.AsOf.ToString("O") };
        r.PassiveKids.AddRange(s.PassiveKids);
        r.DisabledKids.AddRange(s.DisabledKids);
        r.InFlight.AddRange(s.InFlightOperations.Select(ToOpProto));
        return r;
    }

    private static string Actor(ServerCallContext ctx) => ctx.GetHttpContext().User.Identity?.Name ?? "grpc";
}