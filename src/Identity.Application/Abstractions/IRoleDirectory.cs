using Identity.Contracts;

namespace Identity.Application;

/// <summary>Reads Keycloak realm roles or the roles of one client.</summary>
public interface IRoleDirectory
{
    /// <summary>One page of realm roles, or of the client with internal id <paramref name="clientId"/>.</summary>
    Task<Result<PagedResponse<RoleDto>>> GetRolesAsync(string? clientId, int page, int pageSize, CancellationToken ct);

    Task<Result<RoleDto>> GetRoleAsync(string id, CancellationToken ct);
}
