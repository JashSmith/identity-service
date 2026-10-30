using Identity.Contracts;

namespace Identity.Application;

/// <summary>
/// Reads users from the identity provider. Failures are errors (user.not_found or a Keycloak
/// availability error), never an empty result.
/// </summary>
public interface IUserDirectory
{
    /// <summary>
    /// One page of users. With <paramref name="includeSessions"/>, each user carries its online state and
    /// active session count, which costs one extra Keycloak call per user.
    /// </summary>
    Task<Result<PagedResponse<UserDto>>> GetUsersAsync(string? search, int page, int pageSize, bool includeSessions, CancellationToken ct);

    /// <summary>A user with its online state and active session count.</summary>
    Task<Result<UserDto>> GetUserAsync(string id, CancellationToken ct);

    /// <summary>Realm and client roles mapped directly to the user.</summary>
    Task<Result<IReadOnlyCollection<RoleDto>>> GetUserRolesAsync(string id, CancellationToken ct);

    /// <summary>Effective permissions: direct and group roles with realm and client composites expanded.</summary>
    Task<Result<IReadOnlyCollection<PermissionDto>>> GetUserPermissionsAsync(string id, CancellationToken ct);
}
