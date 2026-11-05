using Identity.Gateway.Tenancy;
using System.Text.Json.Nodes;

namespace Identity.Gateway;

/// <summary>
/// OIDC discovery + JWKS proxy. Consuming services point their Authority at the gateway
/// (e.g. http://gateway:5080) with <c>AcceptIssuerFromDiscovery</c>; the gateway forwards
/// Keycloak's discovery document and rewrites <c>jwks_uri</c> to itself. Tokens stay
/// genuine Keycloak-issued (the issuer claim is untouched); the consumer only ever talks
/// to the gateway — it never learns where Keycloak lives.
/// </summary>
public static class OidcProxyEndpoints
{
    public static void MapOidcProxy(this IEndpointRouteBuilder app)
    {
        app.MapGet("/.well-known/openid-configuration",
                (HttpContext ctx, IConfiguration cfg, IHttpClientFactory fac, CancellationToken ct) =>
                    DiscoverAsync(ctx, cfg, fac, ct))
            .AllowAnonymous().WithTags("Auth").WithName("OidcDiscovery")
            .Produces<object>(200);

        app.MapGet("/api/identity/oidc/jwks",
                (HttpContext ctx, IHttpClientFactory fac, CancellationToken ct) =>
                    JwksAsync(ctx, fac, ct))
            .AllowAnonymous().WithTags("Auth").WithName("OidcJwks")
            .Produces<object>(200);
    }

    internal static async Task<IResult> DiscoverAsync(HttpContext httpCtx, IConfiguration cfg,
        IHttpClientFactory fac, CancellationToken ct)
    {
        var (baseUrl, realm) = Keycloak(httpCtx);
        using var http = fac.CreateClient();
        var res = await http.GetAsync(
            $"{baseUrl}/realms/{realm}/.well-known/openid-configuration", ct);
        if (!res.IsSuccessStatusCode)
            return Results.StatusCode((int)res.StatusCode);
        var node = JsonNode.Parse(await res.Content.ReadAsStringAsync(ct));
        if (node is not JsonObject doc)
            return Results.StatusCode(StatusCodes.Status502BadGateway);
        // Rewrite only the key-material location, relative to the requesting consumer so the
        // discovery document works both from the host (localhost:5080) and from containers
        // (identity-gateway:5080). The issuer and every endpoint stay exactly as Keycloak
        // published them so genuine tokens validate unchanged.
        var tenant = httpCtx.GetTenant();
        var tenantQuery = ReferenceEquals(tenant, httpCtx.RequestServices.GetRequiredService<TenantRegistry>().Default)
            ? "" : $"?tenant={Uri.EscapeDataString(tenant.Id)}";
        doc["jwks_uri"] = $"{httpCtx.Request.Scheme}://{httpCtx.Request.Host.Value}" +
                          "/api/identity/oidc/jwks" + tenantQuery;
        return Results.Content(doc.ToJsonString(), "application/json", System.Text.Encoding.UTF8, 200);
    }

    internal static async Task<IResult> JwksAsync(HttpContext ctx, IHttpClientFactory fac, CancellationToken ct)
    {
        var (baseUrl, realm) = Keycloak(ctx);
        using var http = fac.CreateClient();
        var res = await http.GetAsync(
            $"{baseUrl}/realms/{realm}/protocol/openid-connect/certs", ct);
        var body = await res.Content.ReadAsStringAsync(ct);
        return Results.Content(body, "application/json", System.Text.Encoding.UTF8, (int)res.StatusCode);
    }

    /// <summary>Keycloak URL and realm of the request's tenant.</summary>
    private static (string baseUrl, string realm) Keycloak(HttpContext ctx)
    {
        var tenants = ctx.RequestServices.GetRequiredService<TenantRegistry>();
        var tenant = ctx.GetTenant(tenants);
        return (tenants.BaseUrl(tenant), tenant.Realm);
    }
}