using Grpc.Core;
using Identity.Application;
using Microsoft.Extensions.Configuration;
using Identity.Contracts;

namespace Company.Identity.Grpc;

#pragma warning disable CS9113
public sealed class IdentityGrpcService(
    IUserDirectory users,
    IRoleDirectory roles,
    IPermissionRegistry perms,
    PermissionRegistrationService reg,
    IConfiguration cfg,
    IHttpClientFactory httpFactory) : IdentityService.IdentityServiceBase
{
    public override async Task<TokenResponse> Login(LoginRequest request, ServerCallContext context)
    {
        var realm = cfg["Identity:Keycloak:Realm"] ?? cfg["Identity:KeycloakAdmin:Realm"] ?? "company";
        var baseUrl = (cfg["Identity:Keycloak:BaseUrl"] ?? cfg["Identity:KeycloakAdmin:BaseUrl"] ?? "http://localhost:8080").TrimEnd('/');
        using var http = httpFactory.CreateClient();
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = string.IsNullOrWhiteSpace(request.ClientId) ? "identity-facade" : request.ClientId,
            ["username"] = request.Username, ["password"] = request.Password
        };
        if (!string.IsNullOrWhiteSpace(request.ClientSecret)) form["client_secret"] = request.ClientSecret;
        if (!string.IsNullOrWhiteSpace(request.Scope)) form["scope"] = request.Scope;
        var res = await http.PostAsync($"{baseUrl}/realms/{realm}/protocol/openid-connect/token", new FormUrlEncodedContent(form), context.CancellationToken);
        var body = await res.Content.ReadAsStringAsync(context.CancellationToken);
        if (!res.IsSuccessStatusCode) throw new RpcException(new Status(StatusCode.Unauthenticated, body));
        var doc = System.Text.Json.JsonDocument.Parse(body);
        return new TokenResponse
        {
            AccessToken = doc.RootElement.TryGetProperty("access_token", out var a) ? a.GetString() ?? "" : "",
            RefreshToken = doc.RootElement.TryGetProperty("refresh_token", out var r) ? r.GetString() ?? "" : "",
            ExpiresIn = doc.RootElement.TryGetProperty("expires_in", out var e) ? e.GetInt32() : 0,
            TokenType = doc.RootElement.TryGetProperty("token_type", out var t) ? t.GetString() ?? "Bearer" : "Bearer"
        };
    }

    public override async Task<TokenResponse> RefreshToken(RefreshTokenRequest request, ServerCallContext context)
    {
        var realm = cfg["Identity:Keycloak:Realm"] ?? cfg["Identity:KeycloakAdmin:Realm"] ?? "company";
        var baseUrl = (cfg["Identity:Keycloak:BaseUrl"] ?? cfg["Identity:KeycloakAdmin:BaseUrl"] ?? "http://localhost:8080").TrimEnd('/');
        using var http = httpFactory.CreateClient();
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = request.RefreshToken,
            ["client_id"] = string.IsNullOrWhiteSpace(request.ClientId) ? "identity-facade" : request.ClientId,
        };
        if (!string.IsNullOrWhiteSpace(request.ClientSecret)) form["client_secret"] = request.ClientSecret;
        var res = await http.PostAsync($"{baseUrl}/realms/{realm}/protocol/openid-connect/token", new FormUrlEncodedContent(form), context.CancellationToken);
        var body = await res.Content.ReadAsStringAsync(context.CancellationToken);
        if (!res.IsSuccessStatusCode) throw new RpcException(new Status(StatusCode.Unauthenticated, body));
        var doc = System.Text.Json.JsonDocument.Parse(body);
        return new TokenResponse
        {
            AccessToken = doc.RootElement.TryGetProperty("access_token", out var a) ? a.GetString() ?? "" : "",
            RefreshToken = doc.RootElement.TryGetProperty("refresh_token", out var r) ? r.GetString() ?? "" : "",
            ExpiresIn = doc.RootElement.TryGetProperty("expires_in", out var e) ? e.GetInt32() : 0,
            TokenType = "Bearer"
        };
    }

    public override async Task<IntrospectResponse> Introspect(IntrospectRequest request, ServerCallContext context)
    {
        var realm = cfg["Identity:Keycloak:Realm"] ?? cfg["Identity:KeycloakAdmin:Realm"] ?? "company";
        var baseUrl = (cfg["Identity:Keycloak:BaseUrl"] ?? cfg["Identity:KeycloakAdmin:BaseUrl"] ?? "http://localhost:8080").TrimEnd('/');
        using var http = httpFactory.CreateClient();
        var form = new Dictionary<string, string> { ["token"] = request.Token, ["client_id"] = request.ClientId };
        if (!string.IsNullOrWhiteSpace(request.ClientSecret)) form["client_secret"] = request.ClientSecret;
        var req = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/realms/{realm}/protocol/openid-connect/token/introspect") { Content = new FormUrlEncodedContent(form) };
        var res = await http.SendAsync(req, context.CancellationToken);
        var body = await res.Content.ReadAsStringAsync(context.CancellationToken);
        var doc = System.Text.Json.JsonDocument.Parse(body);
        return new IntrospectResponse
        {
            Active = doc.RootElement.TryGetProperty("active", out var a) && a.GetBoolean(),
            Sub = doc.RootElement.TryGetProperty("sub", out var s) ? s.GetString() ?? "" : "",
            Username = doc.RootElement.TryGetProperty("username", out var u) ? u.GetString() ?? "" : doc.RootElement.TryGetProperty("preferred_username", out var pu) ? pu.GetString() ?? "" : "",
            Scope = doc.RootElement.TryGetProperty("scope", out var sc) ? sc.GetString() ?? "" : "",
            Exp = doc.RootElement.TryGetProperty("exp", out var e) ? e.GetInt64() : 0
        };
    }

    public override async Task<LogoutResponse> Logout(LogoutRequest request, ServerCallContext context)
    {
        var realm = cfg["Identity:Keycloak:Realm"] ?? cfg["Identity:KeycloakAdmin:Realm"] ?? "company";
        var baseUrl = (cfg["Identity:Keycloak:BaseUrl"] ?? cfg["Identity:KeycloakAdmin:BaseUrl"] ?? "http://localhost:8080").TrimEnd('/');
        using var http = httpFactory.CreateClient();
        var form = new Dictionary<string, string> { ["refresh_token"] = request.RefreshToken, ["client_id"] = request.ClientId };
        if (!string.IsNullOrWhiteSpace(request.ClientSecret)) form["client_secret"] = request.ClientSecret;
        var res = await http.PostAsync($"{baseUrl}/realms/{realm}/protocol/openid-connect/logout", new FormUrlEncodedContent(form), context.CancellationToken);
        if (!res.IsSuccessStatusCode)
        {
            var res2 = await http.PostAsync($"{baseUrl}/realms/{realm}/protocol/openid-connect/revoke", new FormUrlEncodedContent(form), context.CancellationToken);
            return new LogoutResponse { Success = res2.IsSuccessStatusCode };
        }
        return new LogoutResponse { Success = true };
    }

    public override async Task<UserResponse> GetUser(GetUserRequest request, ServerCallContext context)
    {
        var u = await users.GetUserAsync(request.UserId, context.CancellationToken);
        if (u is null) throw new RpcException(new Status(StatusCode.NotFound, "user not found"));
        return MapUser(u);
    }

    public override async Task<UserListResponse> ListUsers(ListUsersRequest request, ServerCallContext context)
    {
        var p = await users.GetUsersAsync(string.IsNullOrWhiteSpace(request.Search) ? null : request.Search, request.Page <= 0 ? 1 : request.Page, request.PageSize <= 0 ? 20 : request.PageSize, context.CancellationToken);
        var r = new UserListResponse { Page = p.Page, PageSize = p.PageSize, Total = p.Total ?? p.Items.Count };
        r.Items.AddRange(p.Items.Select(MapUser));
        return r;
    }

    public override async Task<RoleListResponse> ListRoles(ListRolesRequest request, ServerCallContext context)
    {
        var p = await roles.GetRolesAsync(string.IsNullOrWhiteSpace(request.ClientId) ? null : request.ClientId, request.Page <= 0 ? 1 : request.Page, request.PageSize <= 0 ? 20 : request.PageSize, context.CancellationToken);
        var r = new RoleListResponse { Page = p.Page, PageSize = p.PageSize, Total = p.Total ?? p.Items.Count };
        r.Items.AddRange(p.Items.Select(MapRole));
        return r;
    }

    public override async Task<RoleListResponse> GetUserRoles(GetUserRequest request, ServerCallContext context)
    {
        var list = await users.GetUserRolesAsync(request.UserId, context.CancellationToken);
        var r = new RoleListResponse { Page = 1, PageSize = list.Count, Total = list.Count };
        r.Items.AddRange(list.Select(MapRole));
        return r;
    }

    public override async Task<PermissionListResponse> GetUserPermissions(GetUserRequest request, ServerCallContext context)
    {
        var list = await users.GetUserPermissionsAsync(request.UserId, context.CancellationToken);
        var r = new PermissionListResponse();
        r.Items.AddRange(list.Select(p => new PermissionResponse { Name = p.Name, Description = p.Description, ServiceId = p.ServiceId, ServiceVersion = p.ServiceVersion, Deprecated = p.Deprecated, KeycloakRoleId = p.KeycloakRoleId ?? "" }));
        return r;
    }

    public override async Task<ManifestRegistrationResponse> RegisterPermissions(PermissionManifestRequest request, ServerCallContext context)
    {
        var httpCtx = context.GetHttpContext();
        var serviceId = httpCtx.User.FindFirst("client_id")?.Value ?? httpCtx.User.FindFirst("azp")?.Value ?? request.ServiceId;
        var dto = new global::Identity.Contracts.PermissionManifestRequest(request.ServiceId, request.ServiceVersion, request.ManifestVersion, request.Permissions.Select(p => new global::Identity.Contracts.PermissionDefinitionDto(p.Name, p.Description)).ToList(), request.ManifestHash, string.IsNullOrWhiteSpace(request.IdempotencyKey) ? null : request.IdempotencyKey);
        var res = await reg.RegisterAsync(dto, serviceId, context.CancellationToken);
        var outRes = new ManifestRegistrationResponse { ServiceId = res.ServiceId, ManifestVersion = res.ManifestVersion, ManifestHash = res.ManifestHash, Accepted = res.Accepted };
        outRes.DeprecatedPermissions.AddRange(res.DeprecatedPermissions);
        return outRes;
    }

    private static UserResponse MapUser(UserDto u)
    {
        var r = new UserResponse { Id = u.Id, Username = u.Username, DisplayName = u.DisplayName ?? "", Enabled = u.Enabled };
        foreach (var kv in u.Attributes) r.Attributes[kv.Key] = string.Join(",", kv.Value);
        return r;
    }
    private static RoleResponse MapRole(RoleDto r) => new() { Id = r.Id, Name = r.Name, Description = r.Description ?? "", ClientId = r.ClientId ?? "", Composite = r.Composite };
}
