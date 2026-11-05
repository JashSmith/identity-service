using System.Text.Json;
using Identity.Application;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Keeps the super-admins group complete: every client role of every registered application
/// (<c>iam.application=true</c>) is mapped to it. Idempotent; failures are returned.
/// </summary>
public sealed class KeycloakClientRoleProvisioner(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakClientRoleProvisioner> logger) : IKeycloakClientRoleProvisioner
{
    private const string Resource = "role";
    private const string SuperAdminGroupName = ReservedGroups.SuperAdmins;
    private readonly KeycloakAdminApi _api = new(http, opts.Value, tokenProvider, logger);

    public async Task<Result> EnsureSuperAdminGroupAsync(CancellationToken ct)
    {
        var group = await FindGroupIdAsync(ct);
        if (!group.IsSuccess) return group.Error!;
        if (group.Value is null)
        {
            var created = await _api.CreateAsync("groups", new
            {
                name = SuperAdminGroupName,
                attributes = new Dictionary<string, string[]>
                {
                    ["description"] = ["Always-present unrestricted administrators; every application permission is mapped to this group"],
                },
            }, Resource, ct);
            if (!created.IsSuccess && created.Error!.Kind != ErrorKind.Conflict) return created.Error;
            logger.LogInformation("Created the {Group} group", SuperAdminGroupName);
        }

        var reconciled = await ReconcileAdminAsync(ct);
        return reconciled.IsSuccess ? Result.Success() : reconciled.Error!;
    }

    public async Task<Result<int>> ReconcileAdminAsync(CancellationToken ct)
    {
        var group = await FindGroupIdAsync(ct);
        if (!group.IsSuccess) return group.Error!;
        if (group.Value is null) return Error.NotFound("role.not_found", $"The {SuperAdminGroupName} group does not exist yet.");

        var clients = await _api.GetAllAsync("clients", Resource, ct);
        if (!clients.IsSuccess) return clients.Error!;

        var added = 0;
        foreach (var client in clients.Value.Where(IsApplication))
        {
            var clientUuid = KeycloakAdminApi.GetString(client, "id")!;
            var roles = await _api.GetAllAsync($"clients/{Uri.EscapeDataString(clientUuid)}/roles?briefRepresentation=true", Resource, ct);
            if (!roles.IsSuccess) return roles.Error!;
            if (roles.Value.Count == 0) continue;

            var path = $"groups/{Uri.EscapeDataString(group.Value)}/role-mappings/clients/{Uri.EscapeDataString(clientUuid)}";
            var mapped = await _api.GetAsync(path, Resource, ct);
            if (!mapped.IsSuccess) return mapped.Error!;
            var already = mapped.Value.EnumerateArray().Select(r => KeycloakAdminApi.GetString(r, "name")).ToHashSet(StringComparer.Ordinal);

            var missing = roles.Value
                .Select(r => (Id: KeycloakAdminApi.GetString(r, "id"), Name: KeycloakAdminApi.GetString(r, "name")))
                .Where(r => r.Id is not null && r.Name is not null && !already.Contains(r.Name))
                .Select(r => new { id = r.Id, name = r.Name })
                .ToArray();
            if (missing.Length == 0) continue;

            var result = await _api.SendWithoutResultAsync(HttpMethod.Post, path, missing, Resource, ct);
            if (!result.IsSuccess) return result.Error!;
            added += missing.Length;
        }
        if (added > 0) logger.LogInformation("Mapped {Count} application permission(s) to {Group}", added, SuperAdminGroupName);
        return added;
    }

    private async Task<Result<string?>> FindGroupIdAsync(CancellationToken ct)
    {
        var found = await _api.GetAsync($"groups?search={Uri.EscapeDataString(SuperAdminGroupName)}&exact=true&briefRepresentation=true", Resource, ct);
        if (!found.IsSuccess) return found.Error!;
        return found.Value.EnumerateArray()
            .Where(g => KeycloakAdminApi.GetString(g, "name") == SuperAdminGroupName)
            .Select(g => KeycloakAdminApi.GetString(g, "id"))
            .FirstOrDefault();
    }

    private static bool IsApplication(JsonElement client) =>
        client.TryGetProperty("attributes", out var attrs) && attrs.ValueKind == JsonValueKind.Object &&
        attrs.TryGetProperty(KeycloakApplicationCatalog.ApplicationAttribute, out var flag) &&
        flag.ValueKind == JsonValueKind.String && flag.GetString() == "true";
}
