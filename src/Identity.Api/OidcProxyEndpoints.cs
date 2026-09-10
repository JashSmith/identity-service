using System.Text.Json.Nodes;

namespace Identity.Api;

/// <summary>
/// OIDC discovery + JWKS proxy. Consuming services point their Authority at the facade
/// (e.g. http://facade:5080) with <c>AcceptIssuerFromDiscovery</c>; the facade forwards
/// Keycloak's discovery document and rewrites <c>jwks_uri</c> to itself. Tokens stay
/// genuine Keycloak-issued (the issuer claim is untouched); the consumer only ever talks
/// to the facade — it never learns where Keycloak lives.
/// </summary>
public static class OidcProxyEndpoints
{
    public static void MapOidcProxy(this IEndpointRouteBuilder app)
    {
        app.MapGet("/.well-known/openid-configuration",
                (IConfiguration cfg, IHttpClientFactory fac, CancellationToken ct) =>
                    DiscoverAsync(cfg, fac, ct))
            .AllowAnonymous().WithTags("Auth").WithName("OidcDiscovery")
            .Produces<object>(200);

        app.MapGet("/api/identity/oidc/jwks",
                (IConfiguration cfg, IHttpClientFactory fac, CancellationToken ct) =>
                    JwksAsync(cfg, fac, ct))
            .AllowAnonymous().WithTags("Auth").WithName("OidcJwks")
            .Produces<object>(200);
    }

    internal static async Task<IResult> DiscoverAsync(IConfiguration cfg, IHttpClientFactory fac, CancellationToken ct)
    {
        var (baseUrl, realm) = (Keycloak(cfg).baseUrl, Keycloak(cfg).realm);
        using var http = fac.CreateClient();
        var res = await http.GetAsync(
            $"{baseUrl}/realms/{realm}/.well-known/openid-configuration", ct);
        if (!res.IsSuccessStatusCode)
            return Results.StatusCode((int) res.StatusCode);
        var node = JsonNode.Parse(await res.Content.ReadAsStringAsync(ct));
        if (node is not JsonObject doc)
            return Results.StatusCode(StatusCodes.Status502BadGateway);
        // Rewrite only the key-material location. The issuer and every endpoint stay
        // exactly as Keycloak published them so genuine tokens validate unchanged.
        doc["jwks_uri"] = $"{SelfBase(cfg)}/api/identity/oidc/jwks";
        return Results.Content(doc.ToJsonString(), "application/json", System.Text.Encoding.UTF8, 200);
    }

    internal static async Task<IResult> JwksAsync(IConfiguration cfg, IHttpClientFactory fac, CancellationToken ct)
    {
        var (baseUrl, realm) = (Keycloak(cfg).baseUrl, Keycloak(cfg).realm);
        using var http = fac.CreateClient();
        var res = await http.GetAsync(
            $"{baseUrl}/realms/{realm}/protocol/openid-connect/certs", ct);
        var body = await res.Content.ReadAsStringAsync(ct);
        return Results.Content(body, "application/json", System.Text.Encoding.UTF8, (int) res.StatusCode);
    }

    private static (string baseUrl, string realm) Keycloak(IConfiguration c) =>
        ((c["Identity:Keycloak:BaseUrl"] ?? c["Identity:KeycloakAdmin:BaseUrl"] ?? "http://localhost:8080")
            .TrimEnd('/'),
            c["Identity:Keycloak:Realm"] ?? c["Identity:KeycloakAdmin:Realm"] ?? "company");

    private static string SelfBase(IConfiguration c) =>
        (c["Identity:PublicBaseUrl"] ?? "http://localhost:5080").TrimEnd('/');
}