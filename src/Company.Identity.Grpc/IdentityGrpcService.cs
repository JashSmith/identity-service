using System.Security.Claims;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using Identity.Application;
using Microsoft.AspNetCore.Authorization;

namespace Company.Identity.Grpc;

public sealed class IdentityGrpcService(LocalAuthenticationService authentication) : IdentityService.IdentityServiceBase
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

        await authentication.LogoutAsync(sessionId, context.CancellationToken);
        return new LogoutResponse();
    }

    [Authorize]
    public override Task<CurrentUserResponse> GetCurrentUser(CurrentUserRequest request, ServerCallContext context)
    {
        var principal = context.GetHttpContext().User;
        if (principal.Identity?.IsAuthenticated != true)
            throw new RpcException(new Status(StatusCode.Unauthenticated, "Authentication is required."));

        var response = new CurrentUserResponse
        {
            UserId = principal.FindFirstValue("sub") ?? string.Empty,
            Username = principal.Identity.Name ?? principal.FindFirstValue("unique_name") ?? string.Empty,
            DisplayName = principal.FindFirstValue("name") ?? principal.Identity.Name ?? string.Empty,
            SessionId = principal.FindFirstValue("sid") ?? string.Empty
        };
        response.Roles.AddRange(principal.FindAll("role").Select(x => x.Value));
        response.Roles.AddRange(principal.FindAll("roles").Select(x => x.Value));
        response.Permissions.AddRange(principal.FindAll("permission").Select(x => x.Value));
        response.Permissions.AddRange(principal.FindAll("permissions").Select(x => x.Value));
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
