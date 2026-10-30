#pragma warning disable ASPDEPR002
using System.Net.Http.Headers;
using System.Text.Json;
using Identity.Contracts;
using Microsoft.Extensions.Options;
using Identity.Application;
using Identity.Application.Schedules;
using Identity.Gateway.Errors;
using Identity.Gateway.Tenancy;

namespace Identity.Gateway;

/// <summary>Thin proxy to Keycloak token endpoints. Gateway never mints tokens or stores credentials.</summary>
public static class AuthEndpoints
{
    public static RouteGroupBuilder MapAuth(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/identity/auth").WithTags("Auth");
        g.MapPost("/login", Login).WithName("AuthLogin").AllowAnonymous()
            .Produces<AccessTokenResponse>(200).ProducesProblem(400)
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
        AccessScheduleService schedules, CancellationToken ct)
    {
        var form = await ReadFormAsync(ctx, ct);
        // Machine clients authenticate with client_credentials (no username/password) —
        // forward as received, exactly like the password grant.
        var isClientCredentials =
            form.TryGetValue("grant_type", out var gt) &&
            gt.Equals("client_credentials", StringComparison.OrdinalIgnoreCase);
        if (!isClientCredentials &&
            (!form.ContainsKey("username") || !form.ContainsKey("password")))
            return Error.Validation("request.invalid", "username and password required").ToProblem();

        var rejected = ApplyClientCredentials(form, cfg, ctx);
        if (rejected is not null) return rejected;

        return await ProxyTokenAsync(cfg, httpFactory, form, ct, ctx, schedules);
    }

    private static async Task<IResult> Refresh(HttpContext ctx, IConfiguration cfg, IHttpClientFactory httpFactory,
        AccessScheduleService schedules, CancellationToken ct)
    {
        var form = await ReadFormAsync(ctx, ct);
        form["grant_type"] = "refresh_token";
        var rejected = ApplyClientCredentials(form, cfg, ctx);
        if (rejected is not null) return rejected;

        return await ProxyTokenAsync(cfg, httpFactory, form, ct, ctx, schedules);
    }

    private static async Task<IResult> Introspect(HttpContext ctx, IConfiguration cfg, IHttpClientFactory httpFactory,
        CancellationToken ct)
    {
        var form = await ReadFormAsync(ctx, ct);
        var realm = ctx.GetTenant().Realm;
        var baseUrl = BaseUrl(ctx);
        var token = form.TryGetValue("token", out var t)
            ? t
            : ctx.Request.Headers.Authorization.ToString().Replace("Bearer ", "");
        if (string.IsNullOrWhiteSpace(token))
            return Error.Validation("request.invalid", "token required").ToProblem();
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
        var realm = ctx.GetTenant().Realm;
        var baseUrl = BaseUrl(ctx);
        // Keycloak logout = token revocation; accept refresh_token or token.
        if (!form.ContainsKey("refresh_token") && form.TryGetValue("token", out var tok)) form["refresh_token"] = tok;
        var rejected = ApplyClientCredentials(form, cfg, ctx);
        if (rejected is not null) return rejected;

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
        Dictionary<string, string> form, CancellationToken ct, HttpContext ctx, AccessScheduleService schedules)
    {
        var realm = ctx.GetTenant().Realm;
        var baseUrl = BaseUrl(ctx);
        using var http = fac.CreateClient();
        var res = await http.PostAsync($"{baseUrl}/realms/{realm}/protocol/openid-connect/token",
            new FormUrlEncodedContent(form), ct);
        var body = await res.Content.ReadAsStringAsync(ct);

        // People (password and refresh grants) only get tokens inside their weekly schedule.
        if (res.IsSuccessStatusCode && form.GetValueOrDefault("grant_type") is "password" or "refresh_token" &&
            TokenSubject(body) is { } userId)
        {
            var allowed = await schedules.EnsureCanSignInAsync(userId, ct);
            if (!allowed.IsSuccess)
            {
                await RevokeIssuedSessionAsync(http, baseUrl, realm, form, body, ct);
                return allowed.Error!.ToProblem();
            }
        }
        // Never log body (contains tokens). Redaction is enforced at caller logging boundaries.
        return Results.Content(body, "application/json", System.Text.Encoding.UTF8, (int)res.StatusCode);
    }

    /// <summary>The <c>sub</c> of the access token Keycloak just issued (read without validation: it came from Keycloak).</summary>
    private static string? TokenSubject(string tokenResponse)
    {
        using var response = JsonDocument.Parse(tokenResponse);
        var accessToken = response.RootElement.TryGetProperty("access_token", out var at) ? at.GetString() : null;
        var parts = accessToken?.Split('.');
        if (parts is not { Length: 3 }) return null;
        var payload = parts[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
        using var claims = JsonDocument.Parse(Convert.FromBase64String(payload));
        return claims.RootElement.TryGetProperty("sub", out var sub) ? sub.GetString() : null;
    }

    /// <summary>Ends the Keycloak session behind tokens that are not handed out, so its refresh token is useless.</summary>
    private static async Task RevokeIssuedSessionAsync(HttpClient http, string baseUrl, string realm,
        Dictionary<string, string> form, string tokenResponse, CancellationToken ct)
    {
        using var response = JsonDocument.Parse(tokenResponse);
        if (!response.RootElement.TryGetProperty("refresh_token", out var refresh) || refresh.GetString() is not { } refreshToken) return;
        var logout = new Dictionary<string, string> { ["refresh_token"] = refreshToken };
        foreach (var key in new[] { "client_id", "client_secret" })
            if (form.TryGetValue(key, out var value)) logout[key] = value;
        using var revoked = await http.PostAsync($"{baseUrl}/realms/{realm}/protocol/openid-connect/logout",
            new FormUrlEncodedContent(logout), ct);
    }

    /// <summary>Returns an error result when the request must not be forwarded, otherwise null.</summary>
    private static IResult? ApplyClientCredentials(Dictionary<string, string> form, IConfiguration cfg, HttpContext ctx)
    {
        var outcome = GatewayClientCredentials.Apply(form,
            ctx.GetTenant().ClientId,
            ctx.GetTenant().ClientSecret);

        return outcome switch
        {
            GatewayClientCredentials.Outcome.ClientCredentialsNotAllowed => Error.Validation("auth.unauthorized_client", "client_credentials requires the caller's own client_id and client_secret").ToProblem(),
            GatewayClientCredentials.Outcome.MissingGatewaySecret => Results.Problem(
                title: "Gateway client is not configured",
                detail: "Identity:Keycloak:ClientSecret is missing.",
                statusCode: StatusCodes.Status503ServiceUnavailable),
            _ => null
        };
    }

    /// <summary>Keycloak of the request's tenant (a very large tenant may have its own cluster).</summary>
    private static string BaseUrl(HttpContext ctx) =>
        ctx.RequestServices.GetRequiredService<TenantRegistry>().BaseUrl(ctx.GetTenant());

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
                using var doc = await JsonDocument.ParseAsync(ctx.Request.Body, cancellationToken: ct);
                if (doc.RootElement.ValueKind != JsonValueKind.Object)
                    throw new ErrorException(Error.Validation("request.malformed", "The request body must be a JSON object."));
                return doc.RootElement.EnumerateObject().ToDictionary(p => p.Name,
                    p => p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString()! : p.Value.GetRawText(), StringComparer.Ordinal);
            }
            catch (JsonException)
            {
                // A broken body must not silently fall back to the query string.
                throw new ErrorException(Error.Validation("request.malformed", "The request body is not valid JSON."));
            }
        }

        var q = ctx.Request.Query.ToDictionary(k => k.Key, v => v.Value.ToString()!, StringComparer.Ordinal);
        return q;
    }
}