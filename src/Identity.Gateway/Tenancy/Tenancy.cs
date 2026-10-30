using Identity.Application;
using Identity.Gateway.Errors;
using Identity.Infrastructure.Keycloak;

namespace Identity.Gateway.Tenancy;

/// <summary>
/// One tenant (organization) = one Keycloak realm with its own gateway clients. The default tenant comes from
/// <c>Identity:KeycloakAdmin</c> and <c>Identity:Keycloak</c>; more come from <c>Identity:Tenants</c>
/// (a list; secrets through configuration/Aspire parameters, never committed). <see cref="BaseUrl"/> lets a
/// very large tenant live on its own Keycloak cluster.
/// </summary>
public sealed class TenantDefinition
{
    public string Id { get; set; } = "";
    public string? DisplayName { get; set; }
    public string Realm { get; set; } = "";
    public string? BaseUrl { get; set; }
    public string AdminClientId { get; set; } = "identity-gateway-admin";
    public string AdminClientSecret { get; set; } = "";
    public string ClientId { get; set; } = "identity-gateway";
    public string? ClientSecret { get; set; }
}

/// <summary>Public view of a tenant (no secrets).</summary>
public sealed record TenantDto(string Id, string? DisplayName, string Realm, bool IsDefault);

/// <summary>The configured tenants and how each maps to Keycloak.</summary>
public sealed class TenantRegistry
{
    public const string HeaderName = "X-Tenant-Id";

    private readonly Dictionary<string, TenantDefinition> _tenants = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _defaultBaseUrl;
    private readonly string _issuerBase;

    public TenantRegistry(IConfiguration cfg)
    {
        _defaultBaseUrl = (cfg["Identity:KeycloakAdmin:BaseUrl"] ?? cfg["Identity:Keycloak:BaseUrl"] ?? "http://localhost:8080").TrimEnd('/');
        // Tokens are issued as <issuer base>/realms/<realm>; the base is the configured authority without its realm.
        var authority = (cfg["Identity:Authority"] ?? $"{_defaultBaseUrl}/realms/company").TrimEnd('/');
        var realmsAt = authority.LastIndexOf("/realms/", StringComparison.Ordinal);
        _issuerBase = realmsAt > 0 ? authority[..realmsAt] : _defaultBaseUrl;

        var realm = cfg["Identity:KeycloakAdmin:Realm"] ?? cfg["Identity:Keycloak:Realm"] ?? "company";
        Default = new TenantDefinition
        {
            Id = cfg["Identity:DefaultTenant"] ?? realm,
            DisplayName = cfg["Identity:DefaultTenantName"],
            Realm = realm,
            AdminClientId = cfg["Identity:KeycloakAdmin:AdminClientId"] ?? "identity-gateway-admin",
            AdminClientSecret = cfg["Identity:KeycloakAdmin:AdminClientSecret"] ?? "",
            ClientId = cfg["Identity:Keycloak:ClientId"] ?? "identity-gateway",
            ClientSecret = cfg["Identity:Keycloak:ClientSecret"],
        };
        _tenants[Default.Id] = Default;

        foreach (var tenant in cfg.GetSection("Identity:Tenants").Get<TenantDefinition[]>() ?? [])
        {
            if (string.IsNullOrWhiteSpace(tenant.Id) || string.IsNullOrWhiteSpace(tenant.Realm))
                throw new InvalidOperationException("Every Identity:Tenants entry needs an Id and a Realm.");
            if (!_tenants.TryAdd(tenant.Id, tenant))
                throw new InvalidOperationException($"Tenant '{tenant.Id}' is configured twice.");
        }
    }

    public TenantDefinition Default { get; }

    public IReadOnlyCollection<TenantDefinition> All => _tenants.Values;

    public bool TryGet(string id, out TenantDefinition tenant) => _tenants.TryGetValue(id, out tenant!);

    public string BaseUrl(TenantDefinition tenant) => (tenant.BaseUrl ?? _defaultBaseUrl).TrimEnd('/');

    /// <summary>The <c>iss</c> of tokens issued by the tenant's realm.</summary>
    public string Issuer(TenantDefinition tenant) =>
        $"{(tenant.BaseUrl is null ? _issuerBase : tenant.BaseUrl.TrimEnd('/'))}/realms/{tenant.Realm}";

    public KeycloakOptions KeycloakOptions(TenantDefinition tenant) => new()
    {
        BaseUrl = BaseUrl(tenant),
        Realm = tenant.Realm,
        AdminClientId = tenant.AdminClientId,
        AdminClientSecret = tenant.AdminClientSecret,
    };

    public TenantDto ToDto(TenantDefinition tenant) => new(tenant.Id, tenant.DisplayName, tenant.Realm, ReferenceEquals(tenant, Default));
}

/// <summary>The current request's tenant (the default one outside requests).</summary>
public sealed class HttpTenantContext(IHttpContextAccessor http, TenantRegistry tenants) : ITenantContext
{
    public string TenantId => http.HttpContext?.GetTenant(tenants).Id ?? tenants.Default.Id;
}

public static class TenantHttpExtensions
{
    private const string ItemKey = "identity.tenant";

    public static TenantDefinition GetTenant(this HttpContext http, TenantRegistry tenants) =>
        http.Items.TryGetValue(ItemKey, out var t) && t is TenantDefinition tenant ? tenant : tenants.Default;

    public static TenantDefinition GetTenant(this HttpContext http) =>
        http.GetTenant(http.RequestServices.GetRequiredService<TenantRegistry>());

    internal static void SetTenant(this HttpContext http, TenantDefinition tenant) => http.Items[ItemKey] = tenant;
}

/// <summary>
/// Picks the tenant from the <c>X-Tenant-Id</c> header, or the <c>tenant</c> query parameter for anonymous
/// discovery/JWKS URLs (default tenant when neither is sent), and runs the request
/// against that tenant's realm. Unknown tenants are rejected before anything else happens.
/// </summary>
public sealed class TenantResolutionMiddleware(RequestDelegate next, TenantRegistry tenants)
{
    public async Task InvokeAsync(HttpContext http)
    {
        var requested = http.Request.Headers[TenantRegistry.HeaderName].ToString();
        if (string.IsNullOrWhiteSpace(requested)) requested = http.Request.Query["tenant"].ToString();
        TenantDefinition tenant;
        if (string.IsNullOrWhiteSpace(requested)) tenant = tenants.Default;
        else if (!tenants.TryGet(requested.Trim(), out tenant))
        {
            await Error.Validation("tenant.unknown", $"Tenant '{requested}' is not configured.").ToProblem().ExecuteAsync(http);
            return;
        }

        http.SetTenant(tenant);
        using (KeycloakTenant.Use(tenants.KeycloakOptions(tenant)))
            await next(http);
    }
}

/// <summary>
/// A token is only valid for the tenant whose realm issued it: an administrator of one tenant cannot act on
/// another by changing the tenant header. Runs after authentication.
/// </summary>
public sealed class TenantIssuerMiddleware(RequestDelegate next, TenantRegistry tenants)
{
    public async Task InvokeAsync(HttpContext http)
    {
        if (http.User.Identity?.IsAuthenticated == true)
        {
            var issuer = http.User.FindFirst("iss")?.Value?.TrimEnd('/');
            var tenant = http.GetTenant(tenants);
            if (!string.Equals(issuer, tenants.Issuer(tenant), StringComparison.Ordinal))
            {
                await Error.Forbidden("tenant.mismatch", "The access token was not issued for this tenant.").ToProblem().ExecuteAsync(http);
                return;
            }
        }
        await next(http);
    }
}
