using Identity.Providers.Abstractions;
using Identity.Providers.OpenIdConnect;

namespace Identity.Providers.Keycloak;

public sealed class KeycloakOptions
{
    public required string Authority { get; init; }
    public required string ClientId { get; init; }
    public string? ClientSecret { get; init; }
    public string Name { get; init; } = "keycloak";
    public bool RequireHttpsMetadata { get; init; } = true;
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);
}

public sealed class KeycloakIdentityProvider : IExternalIdentityProvider
{
    private readonly OpenIdConnectIdentityProvider inner;

    public KeycloakIdentityProvider(HttpClient httpClient, KeycloakOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        inner = new OpenIdConnectIdentityProvider(httpClient, new OpenIdConnectOptions
        {
            Authority = options.Authority,
            ClientId = options.ClientId,
            ClientSecret = options.ClientSecret,
            Name = options.Name,
            RequireHttpsMetadata = options.RequireHttpsMetadata,
            Timeout = options.Timeout,
            ExpectedIssuer = options.Authority.TrimEnd('/')
        });
    }

    public string Name => inner.Name;

    public Task<ExternalIdentity?> AuthenticateAsync(
        ExternalAuthenticationRequest request,
        CancellationToken cancellationToken)
        => inner.AuthenticateAsync(request, cancellationToken);
}