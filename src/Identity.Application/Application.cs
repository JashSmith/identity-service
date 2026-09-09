using Identity.Contracts;

namespace Identity.Application;

public interface IIdentityProvider
{
    Task<AccessTokenResponse> ExchangeOrganizationTokenAsync(string externalToken, CancellationToken cancellationToken);
}

public interface IUserDirectory
{
    Task<PagedResponse<UserDto>> GetUsersAsync(string? search, int page, int pageSize,
        CancellationToken cancellationToken);

    Task<UserDto?> GetUserAsync(string id, CancellationToken cancellationToken);
    Task<IReadOnlyCollection<RoleDto>> GetUserRolesAsync(string id, CancellationToken cancellationToken);
    Task<IReadOnlyCollection<PermissionDto>> GetUserPermissionsAsync(string id, CancellationToken cancellationToken);
}

public interface IRoleDirectory
{
    Task<PagedResponse<RoleDto>> GetRolesAsync(string? clientId, int page, int pageSize,
        CancellationToken cancellationToken);

    Task<RoleDto?> GetRoleAsync(string id, CancellationToken cancellationToken);
}

public interface IPermissionRegistry
{
    Task<ManifestRegistrationResponse> RegisterAsync(PermissionManifestRequest manifest, string authenticatedServiceId,
        CancellationToken cancellationToken);

    Task<IReadOnlyCollection<PermissionDto>> GetPermissionsAsync(string? serviceId, bool includeDeprecated,
        CancellationToken cancellationToken);
}

public interface IExternalIdentityValidator
{
    Task<ExternalIdentityValidationResult?> ValidateAsync(string externalToken, CancellationToken cancellationToken);
}

public interface ICurrentUserContext
{
    string? UserId { get; }
    string? Username { get; }
    IReadOnlyCollection<string> Roles { get; }
    IReadOnlyCollection<string> Permissions { get; }
    IReadOnlyDictionary<string, string?> Claims { get; }
    string? SessionId { get; }
    DateTimeOffset RequestDateTime { get; }
}

public sealed class PermissionRegistrationService(IPermissionRegistry registry)
{
    public Task<ManifestRegistrationResponse> RegisterAsync(PermissionManifestRequest manifest,
        string authenticatedServiceId, CancellationToken cancellationToken)
        => registry.RegisterAsync(manifest, authenticatedServiceId, cancellationToken);
}