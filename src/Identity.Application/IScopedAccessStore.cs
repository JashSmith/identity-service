using Identity.Contracts;

namespace Identity.Application;

public interface IScopedAccessStore
{
    Task<ScopedAccessDocument> GetAsync(string userId, CancellationToken ct);
    Task SetAsync(string userId, ScopedAccessDocument document, CancellationToken ct);
    Task AddAssignmentAsync(string userId, ScopedRoleAssignmentDto assignment, CancellationToken ct);
    Task UpdateAssignmentAsync(string userId, string role, IReadOnlyDictionary<string, IReadOnlyCollection<string>> scopes, CancellationToken ct);
    Task RemoveAssignmentAsync(string userId, string role, CancellationToken ct);
}

public interface IBusinessRoleStore
{
    Task<BusinessRoleDto?> GetAsync(string name, CancellationToken ct);
    Task<IReadOnlyCollection<BusinessRoleDto>> ListAsync(CancellationToken ct);
    Task<BusinessRoleDto> CreateAsync(string name, string? description, IReadOnlyCollection<string> permissions, CancellationToken ct);
    Task<BusinessRoleDto?> UpdateAsync(string name, string? description, CancellationToken ct);
    Task<bool> DeleteAsync(string name, CancellationToken ct);
    Task<IReadOnlyCollection<string>> GetEffectivePermissionsAsync(string name, CancellationToken ct);
    Task AddPermissionsAsync(string name, IReadOnlyCollection<string> permissions, CancellationToken ct);
    Task RemovePermissionAsync(string name, string permission, CancellationToken ct);
}

public interface IUserProvisioningService
{
    Task<UserDto> CreateUserAsync(CreateUserRequest request, CancellationToken ct);
    Task<UserDto?> UpdateUserAsync(string userId, UpdateUserRequest request, CancellationToken ct);
    Task<bool> DeleteUserAsync(string userId, CancellationToken ct);
}

public sealed class ScopedAccessOptions
{
    public string AttributeName { get; set; } = ScopedAccessConstants.AttributeName;
    public string ClaimName { get; set; } = ScopedAccessConstants.ClaimName;
    public int MaxInlineClaimBytes { get; set; } = ScopedAccessConstants.MaxInlineClaimBytes;
}
