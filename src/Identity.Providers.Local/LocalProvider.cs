using Identity.Providers.Abstractions;

namespace Identity.Providers.Local;

public sealed class LocalExternalIdentityProvider : IExternalIdentityProvider
{
    public string Name => "local";

    public Task<ExternalIdentity?> AuthenticateAsync(
        ExternalAuthenticationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return Task.FromResult<ExternalIdentity?>(null);
    }
}
