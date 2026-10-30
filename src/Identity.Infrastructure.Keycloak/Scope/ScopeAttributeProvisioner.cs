using Identity.Application;

namespace Identity.Infrastructure.Keycloak.Scope;

/// <summary>
/// Makes registry scope keys usable: declares <c>authz.scope.&lt;key&gt;</c> in the user profile (otherwise
/// Keycloak silently drops the attribute) and provisions the token claim mapper for each key.
/// </summary>
public interface IScopeAttributeProvisioner
{
    Task<Result> EnsureAsync(IReadOnlyCollection<string> scopeKeys, CancellationToken ct);
}

public sealed class ScopeAttributeProvisioner(
    KeycloakUserProfileHardening profile,
    KeycloakScopeClaimMapper claims) : IScopeAttributeProvisioner
{
    public async Task<Result> EnsureAsync(IReadOnlyCollection<string> scopeKeys, CancellationToken ct)
    {
        var declared = await profile.EnsureAsync(scopeKeys, ct);
        return declared.IsSuccess ? await claims.EnsureAsync(scopeKeys, ct) : declared;
    }
}
