using System.Net.Http.Headers;

namespace Company.Identity.Authentication.AspNetCore;

/// <summary>Forwards the inbound bearer token to a trusted downstream identity API.</summary>
public sealed class BearerTokenDelegatingHandler(IHttpContextAccessor accessor) : DelegatingHandler
{
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var authorization = accessor.HttpContext?.Request.Headers.Authorization.ToString();
        if (!string.IsNullOrWhiteSpace(authorization) &&
            AuthenticationHeaderValue.TryParse(authorization, out var header) &&
            string.Equals(header.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", header.Parameter);
        }

        return base.SendAsync(request, cancellationToken);
    }
}
