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
