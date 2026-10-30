using Identity.Application;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// Provisions the <c>iam-access</c> client scope whose mapper copies the per-role scope document
/// (user attribute <c>iam.scoped_access</c>) into the <c>iam_access</c> token claim, and makes it a
/// realm default scope. Consumers fall back to the gateway's access-context endpoint when the claim is
/// missing or too large. Idempotent; failures are returned.
/// </summary>
public sealed class KeycloakIamAccessClaimMapper(
    HttpClient http,
    IOptions<KeycloakOptions> opts,
    KeycloakAdminTokenProvider tokenProvider,
    ILogger<KeycloakIamAccessClaimMapper> logger)
{
    private const string ScopeName = "iam-access";
    private const string MapperName = "iam-access-mapper";
    private const string AttributeName = "iam.scoped_access";
    private const string ClaimName = "iam_access";
    private const string Resource = "client_scope";
    private readonly KeycloakAdminApi _api = new(http, opts.Value, tokenProvider, logger);

    public async Task<Result> EnsureAsync(CancellationToken ct)
    {
        var scopeId = await EnsureClientScopeAsync(ct);
        if (!scopeId.IsSuccess) return scopeId.Error!;

        var mappersPath = $"client-scopes/{Uri.EscapeDataString(scopeId.Value)}/protocol-mappers/models";
        var mappers = await _api.GetAsync(mappersPath, Resource, ct);
        if (!mappers.IsSuccess) return mappers.Error!;
        if (!mappers.Value.EnumerateArray().Any(m => KeycloakAdminApi.GetString(m, "name") == MapperName))
        {
            var created = await _api.SendWithoutResultAsync(HttpMethod.Post, mappersPath, new
            {
                name = MapperName,
                protocol = "openid-connect",
                protocolMapper = "oidc-usermodel-attribute-mapper",
                config = new Dictionary<string, string>
                {
                    ["user.attribute"] = AttributeName,
                    ["claim.name"] = ClaimName,
                    ["jsonType.label"] = "String",
                    ["multivalued"] = "false",
                    ["aggregate.attrs"] = "false",
                    ["userinfo.token.claim"] = "true",
                    ["access.token.claim"] = "true",
                    ["id.token.claim"] = "false",
                    ["access.tokenResponse.claim"] = "false",
                },
            }, Resource, ct);
            if (!created.IsSuccess) return created;
            logger.LogInformation("Provisioned the {Claim} claim mapper", ClaimName);
        }

        var defaults = await _api.GetAsync("default-default-client-scopes", Resource, ct);
        if (!defaults.IsSuccess) return defaults.Error!;
        if (defaults.Value.EnumerateArray().Any(s => KeycloakAdminApi.GetString(s, "id") == scopeId.Value)) return Result.Success();
        return await _api.SendWithoutResultAsync(HttpMethod.Put,
            $"default-default-client-scopes/{Uri.EscapeDataString(scopeId.Value)}", null, Resource, ct);
    }

    private async Task<Result<string>> EnsureClientScopeAsync(CancellationToken ct)
    {
        var found = await FindAsync(ct);
        if (!found.IsSuccess) return found.Error!;
        if (found.Value is not null) return found.Value;

        var created = await _api.CreateAsync("client-scopes", new
        {
            name = ScopeName,
            description = "Exposes iam.scoped_access as the iam_access claim",
            protocol = "openid-connect",
            attributes = new Dictionary<string, string>
            {
                ["include.in.token.scope"] = "false",
                ["display.on.consent.screen"] = "false",
            },
        }, Resource, ct);
        if (created.IsSuccess) return created.Value;
        if (created.Error!.Kind != ErrorKind.Conflict) return created.Error;
        var again = await FindAsync(ct);
        if (!again.IsSuccess) return again.Error!;
        if (again.Value is not null) return again.Value;
        return created.Error;
    }

    private async Task<Result<string?>> FindAsync(CancellationToken ct)
    {
        var scopes = await _api.GetAsync("client-scopes", Resource, ct);
        if (!scopes.IsSuccess) return scopes.Error!;
        return scopes.Value.EnumerateArray()
            .Where(s => KeycloakAdminApi.GetString(s, "name") == ScopeName)
            .Select(s => KeycloakAdminApi.GetString(s, "id"))
            .FirstOrDefault();
    }
}
