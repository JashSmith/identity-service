#pragma warning disable ASPDEPR002
using System.Net.Http.Headers;
using System.Text.Json;
using Identity.Contracts;
using Microsoft.Extensions.Options;

namespace Identity.Api;

/// <summary>Thin proxy to Keycloak token endpoints. Facade never mints tokens or stores credentials.</summary>
public static class AuthEndpoints
{
    public static RouteGroupBuilder MapAuth(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/identity/auth").WithTags("Auth");
        g.MapPost("/login", Login).WithName("AuthLogin").AllowAnonymous()
            .Produces<AccessTokenResponse>(200).Produces<ProblemResponse>(400)
            .WithOpenApi(o =>
            {
                o.Summary = "Login via Keycloak (password grant)";
                return o;
            });
        g.MapPost("/refresh", Refresh).WithName("AuthRefresh").AllowAnonymous()
            .Produces<AccessTokenResponse>(200).WithOpenApi(o =>
            {
                o.Summary = "Refresh via Keycloak";
                return o;
            });
        g.MapPost("/introspect", Introspect).WithName("AuthIntrospect").AllowAnonymous()
            .Produces<object>(200).WithOpenApi(o =>
            {
                o.Summary = "Introspect token via Keycloak";
                return o;
            });
        g.MapPost("/logout", Logout).WithName("AuthLogout").AllowAnonymous()
            .Produces<object>(200).WithOpenApi(o =>
            {
                o.Summary = "Logout / revoke refresh token";
                return o;
            });
        return g;
    }

    private static async Task<IResult> Login(HttpContext ctx, IConfiguration cfg, IHttpClientFactory httpFactory,
        CancellationToken ct)
    {
        var form = await ReadFormAsync(ctx, ct);
        // Machine clients authenticate with client_credentials (no username/password) —
        // forward as received, exactly like the password grant.
        var isClientCredentials =
            form.TryGetValue("grant_type", out var gt) &&
            gt.Equals("client_credentials", StringComparison.OrdinalIgnoreCase);
        if (!isClientCredentials &&
            (!form.ContainsKey("username") || !form.ContainsKey("password")))
            return Results.BadRequest(new ProblemResponse("validation_error", "username and password required",
                Correlation(ctx)));
        // Forward exactly as received to Keycloak to avoid re-interpreting credential handling.
        return await ProxyTokenAsync(cfg, httpFactory, form, ct, ctx);
    }

    private static async Task<IResult> Refresh(HttpContext ctx, IConfiguration cfg, IHttpClientFactory httpFactory,
        CancellationToken ct)
    {
        var form = await ReadFormAsync(ctx, ct);
        form["grant_type"] = "refresh_token";
        return await ProxyTokenAsync(cfg, httpFactory, form, ct, ctx);
    }

    private static async Task<IResult> Introspect(HttpContext ctx, IConfiguration cfg, IHttpClientFactory httpFactory,
        CancellationToken ct)
    {
        var form = await ReadFormAsync(ctx, ct);
        var realm = Realm(cfg);
        var baseUrl = BaseUrl(cfg);
        var token = form.TryGetValue("token", out var t)
            ? t
            : ctx.Request.Headers.Authorization.ToString().Replace("Bearer ", "");
        if (string.IsNullOrWhiteSpace(token))
            return Results.BadRequest(new ProblemResponse("validation_error", "token required", Correlation(ctx)));
        using var http = httpFactory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Post,
                $"{baseUrl}/realms/{realm}/protocol/openid-connect/token/introspect")
            { Content = new FormUrlEncodedContent(form) };
        if (!string.IsNullOrWhiteSpace(form.GetValueOrDefault("client_id")) &&
            form.TryGetValue("client_secret", out var cs))
            req.Headers.Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{form["client_id"]}:{cs}")));
        var res = await http.SendAsync(req, ct);
        var body = await res.Content.ReadAsStringAsync(ct);
        return Results.Content(body, "application/json", System.Text.Encoding.UTF8, (int)res.StatusCode);
    }

    private static async Task<IResult> Logout(HttpContext ctx, IConfiguration cfg, IHttpClientFactory httpFactory,
        CancellationToken ct)
    {
        var form = await ReadFormAsync(ctx, ct);
        var realm = Realm(cfg);
        var baseUrl = BaseUrl(cfg);
        // Keycloak logout = token revocation; accept refresh_token or token.
        if (!form.ContainsKey("refresh_token") && form.TryGetValue("token", out var tok)) form["refresh_token"] = tok;
        using var http = httpFactory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/realms/{realm}/protocol/openid-connect/logout")
            { Content = new FormUrlEncodedContent(form) };
        // Also try revocation endpoint for compatibility
        var res = await http.SendAsync(req, ct);
        if (!res.IsSuccessStatusCode)
        {
            var req2 = new HttpRequestMessage(HttpMethod.Post,
                    $"{baseUrl}/realms/{realm}/protocol/openid-connect/revoke")
                { Content = new FormUrlEncodedContent(form) };
            res = await http.SendAsync(req2, ct);
        }

        var body = await res.Content.ReadAsStringAsync(ct);
        if (string.IsNullOrWhiteSpace(body)) return Results.Ok(new { success = res.IsSuccessStatusCode });
        return Results.Content(body, "application/json", System.Text.Encoding.UTF8, (int)res.StatusCode);
    }

    private static async Task<IResult> ProxyTokenAsync(IConfiguration cfg, IHttpClientFactory fac,
        Dictionary<string, string> form, CancellationToken ct, HttpContext ctx)
    {
        var realm = Realm(cfg);
        var baseUrl = BaseUrl(cfg);
        using var http = fac.CreateClient();
        var res = await http.PostAsync($"{baseUrl}/realms/{realm}/protocol/openid-connect/token",
            new FormUrlEncodedContent(form), ct);
        var body = await res.Content.ReadAsStringAsync(ct);
        // Never log body (contains tokens). Redaction is enforced at caller logging boundaries.
        return Results.Content(body, "application/json", System.Text.Encoding.UTF8, (int)res.StatusCode);
    }

    private static string Realm(IConfiguration c) =>
        c["Identity:Keycloak:Realm"] ?? c["Identity:KeycloakAdmin:Realm"] ?? "company";

    private static string BaseUrl(IConfiguration c) =>
        (c["Identity:Keycloak:BaseUrl"] ?? c["Identity:KeycloakAdmin:BaseUrl"] ?? "http://localhost:8080").TrimEnd('/');

    private static string Correlation(HttpContext c) => c.TraceIdentifier ?? Guid.NewGuid().ToString("N");

    private static async Task<Dictionary<string, string>> ReadFormAsync(HttpContext ctx, CancellationToken ct)
    {
        if (ctx.Request.HasFormContentType)
        {
            await ctx.Request.ReadFormAsync(ct);
            return ctx.Request.Form.ToDictionary(k => k.Key, v => v.Value.ToString()!, StringComparer.Ordinal);
        }

        if (ctx.Request.ContentType?.Contains("application/json", StringComparison.OrdinalIgnoreCase) == true)
        {
            try
            {
                var doc = await JsonDocument.ParseAsync(ctx.Request.Body, cancellationToken: ct);
                return doc.RootElement.EnumerateObject().ToDictionary(p => p.Name,
                    p => p.Value.GetString() ?? p.Value.ToString()!, StringComparer.Ordinal);
            }
            catch
            {
            }
        }

        var q = ctx.Request.Query.ToDictionary(k => k.Key, v => v.Value.ToString()!, StringComparer.Ordinal);
        return q;
    }
}