using System.Text.Json;
using Identity.Application;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Provisions the <c>authz-scopes</c> client scope that exposes <c>authz.scope.*</c> user/group
/// attributes as token claims: one <c>oidc-usermodel-attribute-mapper</c> per registry scope key
/// (claim <c>authz.scope.&lt;key&gt;</c>, multivalued, aggregated over groups), attached as a default
/// scope of the realm and of every client.
/// Freshness: already-issued access tokens do not change; short-lived access tokens plus refresh
/// rotation carry new scope claims on the next refresh.
/// </summary>
public sealed class KeycloakScopeClaimMapper(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakScopeClaimMapper> logger)
{
    private const string ScopeName = "authz-scopes";
    private const string ScopeAttrPrefix = "authz.scope.";
    private const string Resource = "client_scope";
    private readonly KeycloakAdminApi _api = new(http, opts.Value, tokenProvider, logger);

    /// <summary>Ensures the client scope, one mapper per key in <paramref name="scopeKeys"/>, and its assignment.</summary>
    public async Task<Result> EnsureAsync(IReadOnlyCollection<string> scopeKeys, CancellationToken ct)
    {
        var scopeId = await EnsureClientScopeAsync(ct);
        if (!scopeId.IsSuccess) return scopeId.Error!;

        var realmDefault = await EnsureRealmDefaultAsync(scopeId.Value, ct);
        if (!realmDefault.IsSuccess) return realmDefault;

        var mappers = await _api.GetAsync($"client-scopes/{Uri.EscapeDataString(scopeId.Value)}/protocol-mappers/models", Resource, ct);
        if (!mappers.IsSuccess) return mappers.Error!;
        var existing = mappers.Value.EnumerateArray().Select(m => KeycloakAdminApi.GetString(m, "name")).OfType<string>()
            .ToHashSet(StringComparer.Ordinal);
        foreach (var key in scopeKeys.Where(k => !existing.Contains(MapperName(k))))
        {
            var created = await _api.SendWithoutResultAsync(HttpMethod.Post,
                $"client-scopes/{Uri.EscapeDataString(scopeId.Value)}/protocol-mappers/models", MapperFor(key), Resource, ct);
            if (!created.IsSuccess) return created;
            logger.LogInformation("Provisioned token claim mapper {Mapper}", MapperName(key));
        }

        // Realm defaults are not applied to existing clients, and a realm imported with IGNORE_EXISTING
        // keeps its old clients, so the scope is attached to every client; otherwise no client carries the claims.
        return await AssignToClientsAsync(scopeId.Value, ct);
    }

    private async Task<Result<string>> EnsureClientScopeAsync(CancellationToken ct)
    {
        var found = await FindClientScopeAsync(ct);
        if (!found.IsSuccess) return found.Error!;
        if (found.Value is not null) return found.Value;

        var body = new
        {
            name = ScopeName,
            description = "Exposes authz.scope.* attributes as token claims",
            protocol = "openid-connect",
            attributes = new Dictionary<string, string> { ["include.in.token.scope"] = "false", ["display.on.consent.screen"] = "false" },
        };
        var created = await _api.CreateAsync("client-scopes", body, Resource, ct);
        if (created.IsSuccess) return created.Value;
        if (created.Error!.Kind != ErrorKind.Conflict) return created.Error;

        // Created concurrently by another replica.
        var again = await FindClientScopeAsync(ct);
        if (!again.IsSuccess) return again.Error!;
        if (again.Value is not null) return again.Value;
        return created.Error;
    }

    private async Task<Result<string?>> FindClientScopeAsync(CancellationToken ct)
    {
        var scopes = await _api.GetAsync("client-scopes", Resource, ct);
        if (!scopes.IsSuccess) return scopes.Error!;
        return scopes.Value.EnumerateArray()
            .Where(s => KeycloakAdminApi.GetString(s, "name") == ScopeName)
            .Select(s => KeycloakAdminApi.GetString(s, "id"))
            .FirstOrDefault();
    }

    private async Task<Result> EnsureRealmDefaultAsync(string scopeId, CancellationToken ct)
    {
        var defaults = await _api.GetAsync("default-default-client-scopes", Resource, ct);
        if (!defaults.IsSuccess) return defaults.Error!;
        if (defaults.Value.EnumerateArray().Any(s => KeycloakAdminApi.GetString(s, "id") == scopeId)) return Result.Success();
        return await _api.SendWithoutResultAsync(HttpMethod.Put, $"default-default-client-scopes/{Uri.EscapeDataString(scopeId)}", null, Resource, ct);
    }

    private async Task<Result> AssignToClientsAsync(string scopeId, CancellationToken ct)
    {
        var clients = await _api.GetAllAsync("clients", Resource, ct);
        if (!clients.IsSuccess) return clients.Error!;

        var assigned = 0;
        foreach (var clientUuid in clients.Value.Select(c => KeycloakAdminApi.GetString(c, "id")).OfType<string>())
        {
            var path = $"clients/{Uri.EscapeDataString(clientUuid)}/default-client-scopes";
            var current = await _api.GetAsync(path, Resource, ct);
            if (!current.IsSuccess) return current.Error!;
            if (current.Value.EnumerateArray().Any(s => KeycloakAdminApi.GetString(s, "id") == scopeId)) continue;

            var added = await _api.SendWithoutResultAsync(HttpMethod.Put, $"{path}/{Uri.EscapeDataString(scopeId)}", null, Resource, ct);
            if (!added.IsSuccess) return added;
            assigned++;
        }
        if (assigned > 0) logger.LogInformation("Assigned client scope {Scope} to {Count} client(s)", ScopeName, assigned);
        return Result.Success();
    }

    private static string MapperName(string scopeKey) => $"authz-scope-{scopeKey}";

    private static object MapperFor(string scopeKey) => new
    {
        name = MapperName(scopeKey),
        protocol = "openid-connect",
        protocolMapper = "oidc-usermodel-attribute-mapper",
        config = new Dictionary<string, string>
        {
            ["user.attribute"] = ScopeAttrPrefix + scopeKey,
            ["claim.name"] = $"authz.scope.{scopeKey}",
            ["jsonType.label"] = "String",
            ["multivalued"] = "true",
            ["aggregate.attrs"] = "true",
            ["userinfo.token.claim"] = "true",
            ["access.token.claim"] = "true",
            ["id.token.claim"] = "false",
        },
    };
}
