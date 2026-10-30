namespace Identity.Application;

/// <summary>
/// The tenant (organization) of the current request. Each tenant is one Keycloak realm; anything cached
/// across requests must be keyed by <see cref="TenantId"/>.
/// </summary>
public interface ITenantContext
{
    string TenantId { get; }
}
