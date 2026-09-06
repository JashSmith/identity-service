using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using Identity.Application;
using Identity.Domain;
using Microsoft.AspNetCore.Authorization;

namespace Company.Identity.Grpc;

public sealed class IdentityGrpcService(
    LocalAuthenticationService authentication,
    ICurrentUserContext currentUser) : IdentityService.IdentityServiceBase
{
    public override async Task<TokenResponse> Login(LoginRequest request, ServerCallContext context)
    {
        var result = await authentication.LoginAsync(request.Username, request.Password, context.CancellationToken);
        return ToTokenResponseOrThrow(result);
    }

    public override async Task<TokenResponse> Refresh(RefreshRequest request, ServerCallContext context)
    {
        var result = await authentication.RefreshAsync(request.RefreshToken, context.CancellationToken);
        return ToTokenResponseOrThrow(result);
    }

    [Authorize]
    public override async Task<LogoutResponse> Logout(LogoutRequest request, ServerCallContext context)
    {
        if (!Guid.TryParse(request.SessionId, out var sessionId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "A valid session ID is required."));

        if (currentUser.UserId is not { } userId)
            throw new RpcException(new Status(StatusCode.Unauthenticated, "Authentication is required."));

        await authentication.LogoutAsync(
            new UserId(userId),
            sessionId,
            context.CancellationToken);
        return new LogoutResponse();
    }

    [Authorize]
    public override Task<CurrentUserResponse> GetCurrentUser(CurrentUserRequest request, ServerCallContext context)
    {
        if (!currentUser.IsAuthenticated)
            throw new RpcException(new Status(StatusCode.Unauthenticated, "Authentication is required."));

        var response = new CurrentUserResponse
        {
            UserId = currentUser.UserId?.ToString() ?? string.Empty,
            Username = currentUser.Username ?? string.Empty,
            DisplayName = currentUser.DisplayName ?? string.Empty,
            SessionId = currentUser.SessionId ?? string.Empty
        };
        response.Roles.AddRange(currentUser.Roles);
        response.Permissions.AddRange(currentUser.Permissions);
        return Task.FromResult(response);
    }

    private static TokenResponse ToTokenResponseOrThrow(AuthenticationResult result)
    {
        if (!result.Succeeded || result.AccessToken is null || result.RefreshToken is null || result.SessionId is null)
            throw new RpcException(new Status(StatusCode.Unauthenticated, result.ErrorCode ?? "authentication_failed"));

        return new TokenResponse
        {
            AccessToken = result.AccessToken.AccessToken,
            RefreshToken = result.RefreshToken,
            ExpiresAt = Timestamp.FromDateTimeOffset(result.AccessToken.ExpiresAt),
            SessionId = result.SessionId.Value.ToString()
        };
    }
}