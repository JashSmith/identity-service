using Identity.Application;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// <see cref="IUserRoleMapping"/> backed by Keycloak group membership: a business role is a group, so
/// assigning a role adds the user to the group and its role mappings reach the user's token.
/// Reserved groups are never resolved, so super-admins membership cannot be granted or revoked here.
/// </summary>
public sealed class KeycloakUserGroupMembership(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakUserGroupMembership>? logger = null) : IUserRoleMapping
{
    private const string Resource = "user";
    private readonly KeycloakAdminApi _api = new(http, opts.Value, tokenProvider,
        (ILogger?)logger ?? NullLogger.Instance);

    public Task<Result> AssignRoleAsync(string userId, string roleName, CancellationToken ct) =>
        ChangeMembershipAsync(HttpMethod.Put, userId, roleName, ct);

    public Task<Result> UnassignRoleAsync(string userId, string roleName, CancellationToken ct) =>
        ChangeMembershipAsync(HttpMethod.Delete, userId, roleName, ct);

    private async Task<Result> ChangeMembershipAsync(HttpMethod method, string userId, string roleName, CancellationToken ct)
    {
        var groupId = await ResolveGroupIdAsync(roleName, ct);
        if (!groupId.IsSuccess) return groupId.Error!;

        var changed = await _api.SendWithoutResultAsync(method,
            $"users/{Uri.EscapeDataString(userId)}/groups/{Uri.EscapeDataString(groupId.Value)}", null, Resource, ct);
        if (changed.IsSuccess) return changed;
        return changed.Error!.Kind == ErrorKind.NotFound
            ? Error.NotFound("user.not_found", $"User '{userId}' was not found.")
            : changed;
    }

    private async Task<Result<string>> ResolveGroupIdAsync(string roleName, CancellationToken ct)
    {
        var notFound = Error.NotFound("role.not_found", $"Business role '{roleName}' was not found.");
        if (string.IsNullOrWhiteSpace(roleName) || ReservedGroups.IsReserved(roleName)) return notFound;

        var found = await _api.GetAsync(
            $"groups?search={Uri.EscapeDataString(roleName.Trim())}&exact=true&briefRepresentation=true", "role", ct);
        if (!found.IsSuccess) return found.Error!;

        foreach (var group in found.Value.EnumerateArray())
        {
            if (string.Equals(KeycloakAdminApi.GetString(group, "name"), roleName.Trim(), StringComparison.Ordinal) &&
                KeycloakAdminApi.GetString(group, "id") is { Length: > 0 } id)
                return id;
        }
        return notFound;
    }
}
