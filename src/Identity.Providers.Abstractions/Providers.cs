namespace Identity.Providers.Abstractions;

public sealed record ExternalIdentity(
    string Provider,
    string Subject,
    string? Username,
    string? DisplayName,
    IReadOnlyCollection<string> Claims);

public sealed record ExternalAuthenticationRequest(
    string AuthorizationCode,
    string RedirectUri,
    string CodeVerifier,
    CancellationToken CancellationToken = default);

public interface IExternalIdentityProvider
{
    string Name { get; }
    Task<ExternalIdentity?> AuthenticateAsync(
        ExternalAuthenticationRequest request,
        CancellationToken cancellationToken);
}

public interface IExternalIdentityProviderRegistry
{
    IReadOnlyCollection<IExternalIdentityProvider> Providers { get; }
    IExternalIdentityProvider? Find(string name);
}

public sealed class ExternalIdentityProviderRegistry(
    IEnumerable<IExternalIdentityProvider> providers) : IExternalIdentityProviderRegistry
{
    public IReadOnlyCollection<IExternalIdentityProvider> Providers { get; } = providers
        .GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
        .Select(x => x.First())
        .ToArray();

    public IExternalIdentityProvider? Find(string name)
        => Providers.FirstOrDefault(x => string.Equals(x.Name, name, StringComparison.OrdinalIgnoreCase));
}
