using System.Text.Json;
using Identity.Application;
using Identity.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// <see cref="IBusinessRoleStore"/> backed by Keycloak Groups.
/// Each business role is a top-level Keycloak group named after the role; its attributes hold the
/// description and scope policy (authz.allowed-scopes). Permissions are client roles of the owning
/// service client mapped onto the group; legacy realm-role permissions are still supported.
/// Reserved groups (<see cref="ReservedGroups"/>) are never visible or writable through this store.
/// </summary>
public sealed class KeycloakGroupBusinessRoleStore(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakGroupBusinessRoleStore> logger) : IBusinessRoleStore
{
    private const string Resource = "role";
    private readonly KeycloakAdminApi _api = new(http, opts.Value, tokenProvider, logger);

    private sealed record GroupRef(string Id, string Name, string Path, Dictionary<string, string[]> Attributes);

    /// <summary>
    /// A role mapped as a permission. <see cref="Name"/> is what the API shows (the full
    /// <c>{clientId}:{Module}:{Resource}:{Action}</c> for client roles); <see cref="RoleName"/> is Keycloak's role name.
    /// </summary>
    private sealed record PermissionRole(string Id, string Name, string RoleName, string? ClientUuid);

    private static Error RoleNotFound(string name) =>
        Error.NotFound("role.not_found", $"Business role '{name}' was not found.");

    public async Task<Result<BusinessRoleDto>> GetAsync(string name, CancellationToken ct)
    {
        var group = await FindGroupAsync(name, ct);
        if (!group.IsSuccess) return group.Error!;
        return await ToDtoAsync(group.Value, ct);
    }

    public async Task<Result<IReadOnlyCollection<BusinessRoleDto>>> ListAsync(CancellationToken ct)
    {
        var groups = await _api.GetAllAsync("groups?briefRepresentation=false", Resource, ct);
        if (!groups.IsSuccess) return groups.Error!;

        var roles = new List<BusinessRoleDto>();
        foreach (var group in groups.Value.Select(MapGroup).Where(g => !ReservedGroups.IsReserved(g.Name)))
        {
            var dto = await ToDtoAsync(group, ct);
            if (!dto.IsSuccess) return dto.Error!;
            roles.Add(dto.Value);
        }
        return roles.OrderBy(r => r.Name, StringComparer.Ordinal).ToArray();
    }

    public async Task<Result<BusinessRoleDto>> CreateAsync(
        string name, string? description, IReadOnlyCollection<string> permissions, CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        name = name.Trim();
        if (ReservedGroups.IsReserved(name))
            return Error.Validation("role.reserved", $"Business role name '{name}' is reserved.");

        var existing = await FindGroupAsync(name, ct);
        if (existing.IsSuccess)
            return Error.Conflict("role.already_exists", $"Business role '{name}' already exists.");
        if (existing.Error!.Kind != ErrorKind.NotFound) return existing.Error;

        // Resolve permissions before creating anything, so unknown permissions leave no half-made role.
        var resolved = await ResolvePermissionsAsync(permissions, ct);
        if (!resolved.IsSuccess) return resolved.Error!;

        var body = new Dictionary<string, object> { ["name"] = name };
        if (!string.IsNullOrWhiteSpace(description))
            body["attributes"] = new Dictionary<string, string[]> { ["description"] = [description] };

        var created = await _api.SendAsync(HttpMethod.Post, "groups", body, Resource, ct);
        if (!created.IsSuccess)
            return created.Error!.Kind == ErrorKind.Conflict
                ? Error.Conflict("role.already_exists", $"Business role '{name}' already exists.")
                : created.Error;

        var group = await FindGroupAsync(name, ct);
        if (!group.IsSuccess) return group.Error!;

        var mapped = await MapPermissionsAsync(group.Value, resolved.Value, ct);
        if (!mapped.IsSuccess)
        {
            // Compensate: do not leave a role without the permissions the caller asked for.
            var removed = await _api.SendWithoutResultAsync(HttpMethod.Delete, $"groups/{Escape(group.Value.Id)}", null, Resource, ct);
            if (!removed.IsSuccess)
                logger.LogError("Business role {Role} was created but its permissions failed and it could not be removed: {Code}",
                    name, removed.Error!.Code);
            return mapped.Error!;
        }

        return await ToDtoAsync(group.Value, ct);
    }

    public async Task<Result<BusinessRoleDto>> UpdateAsync(string name, string? description, CancellationToken ct)
    {
        var group = await FindGroupAsync(name, ct);
        if (!group.IsSuccess) return group.Error!;

        // PUT replaces the whole attribute map, so every existing attribute (authz.allowed-scopes, ...)
        // is sent back and only the description changes.
        var attributes = new Dictionary<string, string[]>(group.Value.Attributes, StringComparer.Ordinal);
        if (description is not null) attributes["description"] = [description];
        var body = new Dictionary<string, object>
        {
            ["name"] = group.Value.Name,
            ["path"] = group.Value.Path,
            ["attributes"] = attributes,
        };

        var updated = await _api.SendWithoutResultAsync(HttpMethod.Put, $"groups/{Escape(group.Value.Id)}", body, Resource, ct);
        if (!updated.IsSuccess) return updated.Error!;
        return await GetAsync(name, ct);
    }

    public async Task<Result> DeleteAsync(string name, CancellationToken ct)
    {
        var group = await FindGroupAsync(name, ct);
        if (!group.IsSuccess) return group.Error!;

        var members = await _api.GetAsync(
            $"groups/{Escape(group.Value.Id)}/members?first=0&max=1&briefRepresentation=true", Resource, ct);
        if (!members.IsSuccess) return members.Error!;
        if (members.Value.ValueKind == JsonValueKind.Array && members.Value.GetArrayLength() > 0)
            return Error.Conflict("role.in_use",
                $"Business role '{name}' is still assigned to users. Remove their assignments first.");

        return await _api.SendWithoutResultAsync(HttpMethod.Delete, $"groups/{Escape(group.Value.Id)}", null, Resource, ct);
    }

    public async Task<Result<IReadOnlyCollection<string>>> GetEffectivePermissionsAsync(string name, CancellationToken ct)
    {
        var group = await FindGroupAsync(name, ct);
        if (!group.IsSuccess) return group.Error!;

        var assigned = await GetAssignedRolesAsync(group.Value.Id, ct);
        if (!assigned.IsSuccess) return assigned.Error!;
        var realmEffective = await _api.GetAsync($"groups/{Escape(group.Value.Id)}/role-mappings/realm/composite", Resource, ct);
        if (!realmEffective.IsSuccess) return realmEffective.Error!;

        var names = new HashSet<string>(assigned.Value.Select(r => r.Name), StringComparer.Ordinal);
        foreach (var role in realmEffective.Value.EnumerateArray())
            if (KeycloakAdminApi.GetString(role, "name") is { Length: > 0 } roleName) names.Add(roleName);
        return names.Order(StringComparer.Ordinal).ToArray();
    }

    public async Task<Result> AddPermissionsAsync(string name, IReadOnlyCollection<string> permissions, CancellationToken ct)
    {
        var group = await FindGroupAsync(name, ct);
        if (!group.IsSuccess) return group.Error!;
        var resolved = await ResolvePermissionsAsync(permissions, ct);
        if (!resolved.IsSuccess) return resolved.Error!;
        return await MapPermissionsAsync(group.Value, resolved.Value, ct);
    }

    public async Task<Result> RemovePermissionAsync(string name, string permission, CancellationToken ct)
    {
        var group = await FindGroupAsync(name, ct);
        if (!group.IsSuccess) return group.Error!;
        var assigned = await GetAssignedRolesAsync(group.Value.Id, ct);
        if (!assigned.IsSuccess) return assigned.Error!;

        var role = assigned.Value.FirstOrDefault(r => string.Equals(r.Name, permission, StringComparison.Ordinal));
        if (role is null)
            return Error.NotFound("permission.not_assigned", $"Permission '{permission}' is not assigned to business role '{name}'.");
        return await UnmapPermissionsAsync(group.Value, [role], ct);
    }

    public async Task<Result> SetPermissionsAsync(string name, IReadOnlyCollection<string> permissions, CancellationToken ct)
    {
        var group = await FindGroupAsync(name, ct);
        if (!group.IsSuccess) return group.Error!;
        var assigned = await GetAssignedRolesAsync(group.Value.Id, ct);
        if (!assigned.IsSuccess) return assigned.Error!;

        var desired = permissions.Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p.Trim())
            .ToHashSet(StringComparer.Ordinal);
        var current = assigned.Value.Select(r => r.Name).ToHashSet(StringComparer.Ordinal);

        // Resolve additions first: an unknown permission must fail before anything is removed.
        var toAdd = await ResolvePermissionsAsync(desired.Except(current).ToArray(), ct);
        if (!toAdd.IsSuccess) return toAdd.Error!;

        var added = await MapPermissionsAsync(group.Value, toAdd.Value, ct);
        if (!added.IsSuccess) return added.Error!;
        return await UnmapPermissionsAsync(group.Value, assigned.Value.Where(r => !desired.Contains(r.Name)).ToArray(), ct);
    }

    private async Task<Result<GroupRef>> FindGroupAsync(string name, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(name) || ReservedGroups.IsReserved(name)) return RoleNotFound(name);
        name = name.Trim();

        // briefRepresentation=false is required: the brief form omits attributes.
        var found = await _api.GetAsync(
            $"groups?search={Uri.EscapeDataString(name)}&exact=true&briefRepresentation=false", Resource, ct);
        if (!found.IsSuccess) return found.Error!;

        foreach (var element in found.Value.EnumerateArray())
        {
            var group = MapGroup(element);
            if (string.Equals(group.Name, name, StringComparison.Ordinal)) return group;
        }
        return RoleNotFound(name);
    }

    private async Task<Result<BusinessRoleDto>> ToDtoAsync(GroupRef group, CancellationToken ct)
    {
        var assigned = await GetAssignedRolesAsync(group.Id, ct);
        if (!assigned.IsSuccess) return assigned.Error!;
        var description = group.Attributes.TryGetValue("description", out var d) ? d.FirstOrDefault() : null;
        var permissions = assigned.Value.Select(r => r.Name).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        return new BusinessRoleDto(group.Name, description, true, permissions);
    }

    /// <summary>Roles mapped directly onto the group: realm roles and the client roles of every client, in one call.</summary>
    private async Task<Result<IReadOnlyCollection<PermissionRole>>> GetAssignedRolesAsync(string groupId, CancellationToken ct)
    {
        var mappings = await _api.GetAsync($"groups/{Escape(groupId)}/role-mappings", Resource, ct);
        if (!mappings.IsSuccess) return mappings.Error!;

        var roles = new List<PermissionRole>();
        if (mappings.Value.TryGetProperty("realmMappings", out var realm) && realm.ValueKind == JsonValueKind.Array)
            roles.AddRange(realm.EnumerateArray().Select(r => ToRole(r, clientId: null, clientUuid: null)).OfType<PermissionRole>());

        if (mappings.Value.TryGetProperty("clientMappings", out var clients) && clients.ValueKind == JsonValueKind.Object)
        {
            foreach (var client in clients.EnumerateObject())
            {
                var clientUuid = KeycloakAdminApi.GetString(client.Value, "id");
                if (clientUuid is null || !client.Value.TryGetProperty("mappings", out var mapped)) continue;
                roles.AddRange(mapped.EnumerateArray().Select(r => ToRole(r, client.Name, clientUuid)).OfType<PermissionRole>());
            }
        }
        return roles;
    }

    /// <summary>
    /// Resolves full permission names (<c>{clientId}:{Module}:{Resource}:{Action}</c>) to the client roles of that
    /// application; names without an application are legacy realm roles. Reports all unknown permissions at once.
    /// </summary>
    private async Task<Result<IReadOnlyCollection<PermissionRole>>> ResolvePermissionsAsync(
        IReadOnlyCollection<string> permissions, CancellationToken ct)
    {
        var wanted = permissions.Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p.Trim())
            .Distinct(StringComparer.Ordinal).ToArray();
        var resolved = new List<PermissionRole>();
        var missing = new List<string>();
        var clientUuids = new Dictionary<string, string?>(StringComparer.Ordinal);

        foreach (var permission in wanted)
        {
            string path;
            string? clientId = null, clientUuid = null;
            if (Identity.Application.Permissions.PermissionName.TryParseFull(permission, out var name))
            {
                clientId = name.Application;
                if (!clientUuids.TryGetValue(clientId, out clientUuid))
                {
                    var found = await _api.GetAsync($"clients?clientId={Uri.EscapeDataString(clientId)}", Resource, ct);
                    if (!found.IsSuccess) return found.Error!;
                    clientUuid = found.Value.EnumerateArray()
                        .Where(c => KeycloakAdminApi.GetString(c, "clientId") == clientId)
                        .Select(c => KeycloakAdminApi.GetString(c, "id")).FirstOrDefault();
                    clientUuids[clientId] = clientUuid;
                }
                if (clientUuid is null)
                {
                    missing.Add(permission);
                    continue;
                }
                path = $"clients/{Escape(clientUuid)}/roles/{Escape(name.Local)}";
            }
            else
            {
                path = $"roles/{Escape(permission)}";
            }

            var role = await _api.GetAsync(path, Resource, ct);
            if (!role.IsSuccess)
            {
                if (role.Error!.Kind != ErrorKind.NotFound) return role.Error;
                missing.Add(permission);
                continue;
            }
            if (ToRole(role.Value, clientId, clientUuid) is { } mapped) resolved.Add(mapped);
        }

        if (missing.Count > 0)
            return Error.Validation("permission.not_found", $"Unknown permissions: {string.Join(", ", missing)}.",
                new Dictionary<string, string[]> { ["permissions"] = missing.Select(m => $"Permission '{m}' does not exist.").ToArray() });
        return resolved;
    }

    private Task<Result> MapPermissionsAsync(GroupRef group, IReadOnlyCollection<PermissionRole> roles, CancellationToken ct) =>
        ChangeMappingsAsync(HttpMethod.Post, group, roles, ct);

    private Task<Result> UnmapPermissionsAsync(GroupRef group, IReadOnlyCollection<PermissionRole> roles, CancellationToken ct) =>
        ChangeMappingsAsync(HttpMethod.Delete, group, roles, ct);

    private async Task<Result> ChangeMappingsAsync(HttpMethod method, GroupRef group, IReadOnlyCollection<PermissionRole> roles, CancellationToken ct)
    {
        foreach (var byContainer in roles.GroupBy(r => r.ClientUuid))
        {
            var path = byContainer.Key is null
                ? $"groups/{Escape(group.Id)}/role-mappings/realm"
                : $"groups/{Escape(group.Id)}/role-mappings/clients/{Escape(byContainer.Key)}";
            var body = byContainer.Select(r => new { id = r.Id, name = r.RoleName }).ToArray();
            var result = await _api.SendWithoutResultAsync(method, path, body, Resource, ct);
            if (!result.IsSuccess) return result;
        }
        return Result.Success();
    }

    private static PermissionRole? ToRole(JsonElement role, string? clientId, string? clientUuid)
    {
        var id = KeycloakAdminApi.GetString(role, "id");
        var name = KeycloakAdminApi.GetString(role, "name");
        if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(name)) return null;
        return new PermissionRole(id, clientId is null ? name : $"{clientId}:{name}", name, clientUuid);
    }

    private static GroupRef MapGroup(JsonElement e)
    {
        var name = KeycloakAdminApi.GetString(e, "name") ?? "";
        var attributes = new Dictionary<string, string[]>(StringComparer.Ordinal);
        if (e.TryGetProperty("attributes", out var a) && a.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in a.EnumerateObject())
            {
                if (prop.Value.ValueKind == JsonValueKind.Array)
                    attributes[prop.Name] = prop.Value.EnumerateArray().Select(x => x.GetString() ?? "").ToArray();
                else if (prop.Value.ValueKind == JsonValueKind.String)
                    attributes[prop.Name] = [prop.Value.GetString() ?? ""];
            }
        }
        return new GroupRef(KeycloakAdminApi.GetString(e, "id") ?? "", name, KeycloakAdminApi.GetString(e, "path") ?? $"/{name}", attributes);
    }

    private static string Escape(string value) => Uri.EscapeDataString(value);
}
