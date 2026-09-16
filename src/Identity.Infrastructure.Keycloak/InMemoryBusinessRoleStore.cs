using Identity.Application;
using Identity.Contracts;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// In-memory fallback for IBusinessRoleStore — used for host startup seeding and tests when
/// Keycloak is unavailable. Never used in production (the composite store is registered instead
/// when Keycloak is configured). Kept here alongside the real store.
/// </summary>
public sealed class InMemoryBusinessRoleStore : IBusinessRoleStore
{
    private readonly Dictionary<string, BusinessRoleDto> _roles = new(StringComparer.Ordinal);

    public Task<BusinessRoleDto?> GetAsync(string name, CancellationToken ct)
    {
        _roles.TryGetValue(name, out var dto);
        return Task.FromResult(dto);
    }

    public Task<IReadOnlyCollection<BusinessRoleDto>> ListAsync(CancellationToken ct)
        => Task.FromResult<IReadOnlyCollection<BusinessRoleDto>>(_roles.Values.OrderBy(r => r.Name, StringComparer.Ordinal).ToArray());

    public Task<BusinessRoleDto> CreateAsync(string name, string? description, IReadOnlyCollection<string> permissions, CancellationToken ct)
    {
        name = name.Trim();
        if (_roles.ContainsKey(name)) throw new InvalidOperationException($"Business role '{name}' already exists.");
        var dto = new BusinessRoleDto(name, description, true, permissions?.ToArray() ?? Array.Empty<string>());
        _roles[name] = dto;
        return Task.FromResult(dto);
    }

    public Task<BusinessRoleDto?> UpdateAsync(string name, string? description, CancellationToken ct)
    {
        if (!_roles.TryGetValue(name, out var cur)) return Task.FromResult<BusinessRoleDto?>(null);
        var next = cur with { Description = description ?? cur.Description };
        _roles[name] = next;
        return Task.FromResult<BusinessRoleDto?>(next);
    }

    public Task<bool> DeleteAsync(string name, CancellationToken ct) => Task.FromResult(_roles.Remove(name));

    public Task<IReadOnlyCollection<string>> GetEffectivePermissionsAsync(string name, CancellationToken ct)
    {
        _roles.TryGetValue(name, out var cur);
        return Task.FromResult<IReadOnlyCollection<string>>(cur?.Permissions ?? Array.Empty<string>());
    }

    public Task AddPermissionsAsync(string name, IReadOnlyCollection<string> permissions, CancellationToken ct)
    {
        if (!_roles.TryGetValue(name, out var cur)) throw new InvalidOperationException($"Role '{name}' not found.");
        var merged = cur.Permissions.Concat(permissions).Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToArray();
        _roles[name] = cur with { Permissions = merged };
        return Task.CompletedTask;
    }

    public Task RemovePermissionAsync(string name, string permission, CancellationToken ct)
    {
        if (!_roles.TryGetValue(name, out var cur)) throw new InvalidOperationException($"Role '{name}' not found.");
        _roles[name] = cur with { Permissions = cur.Permissions.Where(p => p != permission).ToArray() };
        return Task.CompletedTask;
    }
}
