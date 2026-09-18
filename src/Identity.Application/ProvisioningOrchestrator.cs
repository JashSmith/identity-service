using Identity.Application.Scope;
using Identity.Contracts;

namespace Identity.Application;

public sealed class ProvisioningOrchestrator(
    IUserProvisioningService users,
    IScopedAccessStore scopedStore,
    IBusinessRoleStore roles,
    IUserRoleMapping roleMapping,
    IPermissionRegistry permissionRegistry,
    ScopeAssignmentValidator? scopeValidator = null)
{
    public async Task<(UserDto User, ScopedAccessDocument Scoped)> CreateUserWithAssignmentsAsync(
        CreateUserRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Assignments is not null)
        {
            foreach (var a in request.Assignments) ScopedAccessSerializer.Validate(a);
            if (scopeValidator is not null)
            {
                var errors = await scopeValidator.ValidateAsync(request.Assignments, roles, ct);
                if (errors.Count > 0) throw new Scope.ScopedValidationException(errors);
            }
            else
            {
                foreach (var a in request.Assignments)
                {
                    var role = await roles.GetAsync(a.Role, ct);
                    if (role is null) throw new InvalidOperationException($"Role '{a.Role}' does not exist.");
                }
            }
        }
        UserDto created;
        try { created = await users.CreateUserAsync(request, ct); }
        catch (Exception ex) { throw new InvalidOperationException($"Failed to create user '{request.Username}': {ex.Message}", ex); }
        if (request.Assignments is null || request.Assignments.Count == 0) return (created, ScopedAccessDocument.Empty);
        try
        {
            var doc = ToDocument(request.Assignments);
            // scopedStore persists both authz.scope.* attributes and the legacy blob in one PUT.
            await scopedStore.SetAsync(created.Id, doc, ct);
            foreach (var a in request.Assignments) await SafeMapRoleAsync(created.Id, a.Role, ct);
            return (created, doc);
        }
        catch (Scope.ScopedValidationException) { try { await users.DeleteUserAsync(created.Id, ct); } catch { } throw; }
        catch (Exception ex)
        {
            try { await users.DeleteUserAsync(created.Id, ct); } catch { }
            throw new InvalidOperationException($"User '{request.Username}' was not created because scoped assignment failed: {ex.Message}", ex);
        }
    }

    public async Task<ScopedAccessDocument> AddScopedAssignmentAsync(string userId, ScopedRoleAssignmentDto assignment, CancellationToken ct)
    {
        ScopedAccessSerializer.Validate(assignment);
        if (scopeValidator is not null)
        {
            var errors = await scopeValidator.ValidateAsync(new[] { assignment }, roles, ct);
            if (errors.Count > 0) throw new Scope.ScopedValidationException(errors);
        }
        else
        {
            var role = await roles.GetAsync(assignment.Role, ct);
            if (role is null) throw new InvalidOperationException($"Role '{assignment.Role}' does not exist.");
        }
        await scopedStore.AddAssignmentAsync(userId, assignment, ct);
        await SafeMapRoleAsync(userId, assignment.Role, ct);
        return await scopedStore.GetAsync(userId, ct);
    }

    public async Task<ScopedAccessDocument> ReplaceAssignmentsAsync(string userId, IReadOnlyCollection<ScopedRoleAssignmentDto> assignments, CancellationToken ct)
    {
        foreach (var a in assignments) ScopedAccessSerializer.Validate(a);
        if (scopeValidator is not null)
        {
            var errors = await scopeValidator.ValidateAsync(assignments, roles, ct);
            if (errors.Count > 0) throw new Scope.ScopedValidationException(errors);
        }
        else
        {
            foreach (var a in assignments)
            {
                var role = await roles.GetAsync(a.Role, ct);
                if (role is null) throw new InvalidOperationException($"Role '{a.Role}' does not exist.");
            }
        }
        var previous = await scopedStore.GetAsync(userId, ct);
        var previousRoles = previous.Assignments.Select(a => a.Role).ToHashSet(StringComparer.Ordinal);
        var nextRoles = assignments.Select(a => a.Role.Trim()).ToHashSet(StringComparer.Ordinal);
        var doc = ToDocument(assignments);
        await scopedStore.SetAsync(userId, doc, ct);
        foreach (var r in nextRoles.Except(previousRoles, StringComparer.Ordinal)) await SafeMapRoleAsync(userId, r, ct);
        foreach (var r in previousRoles.Except(nextRoles, StringComparer.Ordinal)) await SafeUnmapRoleAsync(userId, r, ct);
        return doc;
    }

    public async Task RemoveScopedAssignmentAsync(string userId, string role, CancellationToken ct)
    {
        await scopedStore.RemoveAssignmentAsync(userId, role, ct);
        var still = await scopedStore.GetAsync(userId, ct);
        if (!still.Assignments.Any(a => string.Equals(a.Role, role, StringComparison.Ordinal)))
            await SafeUnmapRoleAsync(userId, role, ct);
    }

    public async Task<bool> DeleteBusinessRoleSafeAsync(string roleName, CancellationToken ct)
    {
        var usersWithRole = await roleMapping.GetUsersWithRealmRoleAsync(roleName, ct);
        if (usersWithRole.Count > 0) throw new InvalidOperationException($"Cannot delete business role '{roleName}': still assigned to {usersWithRole.Count} user(s). Remove scoped assignments first.");
        return await roles.DeleteAsync(roleName, ct);
    }

    public async Task<BusinessRoleDto> CreateBusinessRoleAsync(string name, string? description, IReadOnlyCollection<string> permissions, CancellationToken ct)
    {
        permissions ??= Array.Empty<string>();
        if (permissions.Count > 0)
        {
            var known = await permissionRegistry.GetPermissionsAsync(null, true, ct);
            foreach (var p in permissions)
                if (!known.Any(x => string.Equals(x.Name, p, StringComparison.Ordinal)))
                    throw new InvalidOperationException($"Permission '{p}' does not exist.");
        }
        return await roles.CreateAsync(name.Trim(), description, permissions, ct);
    }

    private static ScopedAccessDocument ToDocument(IReadOnlyCollection<ScopedRoleAssignmentDto> dtos)
    {
        var normalized = dtos.Select(dto =>
        {
            var role = dto.Role.Trim();
            var scopes = dto.Scopes is null ? new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal)
                : dto.Scopes.Where(kv => !string.IsNullOrWhiteSpace(kv.Key))
                    .ToDictionary(kv => kv.Key.Trim(), kv => kv.Value?.Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v.Trim()).Distinct(StringComparer.Ordinal).OrderBy(v => v, StringComparer.Ordinal).ToArray() as IReadOnlyCollection<string> ?? Array.Empty<string>(), StringComparer.Ordinal);
            return new ScopedRoleAssignment(role, scopes);
        }).OrderBy(a => a.Role, StringComparer.Ordinal).ToArray();
        return new ScopedAccessDocument(normalized);
    }

    private async Task SafeMapRoleAsync(string userId, string roleName, CancellationToken ct) { try { await roleMapping.MapRealmRoleAsync(userId, roleName, ct); } catch { } }
    private async Task SafeUnmapRoleAsync(string userId, string roleName, CancellationToken ct) { try { await roleMapping.UnmapRealmRoleAsync(userId, roleName, ct); } catch { } }
}
