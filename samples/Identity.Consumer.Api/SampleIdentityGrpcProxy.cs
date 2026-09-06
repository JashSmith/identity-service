using Company.Identity.Grpc;
using Grpc.Core;
using Grpc.Core.Interceptors;

public sealed class SampleIdentityGrpcProxy(
    IdentityService.IdentityServiceClient client) : IdentityService.IdentityServiceBase
{
    public override async Task<CurrentUserResponse> GetCurrentUser(
        CurrentUserRequest request,
        ServerCallContext context)
        => await client.GetCurrentUserAsync(request, cancellationToken: context.CancellationToken);
}

public sealed class BearerTokenGrpcInterceptor(IHttpContextAccessor accessor) : Interceptor
{
    public override AsyncUnaryCall<TResponse> AsyncUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncUnaryCallContinuation<TRequest, TResponse> continuation)
    {
        var token = accessor.HttpContext?.Request.Headers.Authorization.ToString();
        var headers = context.Options.Headers ?? new Metadata();
        if (!string.IsNullOrWhiteSpace(token) && !headers.Any(x => x.Key == "authorization"))
            headers.Add("authorization", token);

        var options = context.Options.WithHeaders(headers);
        return continuation(request, new ClientInterceptorContext<TRequest, TResponse>(context.Method, context.Host, options));
    }
}
