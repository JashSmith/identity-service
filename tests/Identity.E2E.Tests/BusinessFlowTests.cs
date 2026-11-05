using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Identity.E2E.Tests;

/// <summary>
/// The owner's business scenarios against the real stack: permissions in tokens, scoped users, delegated
/// administration, weekly schedules, consumer enforcement and tenant isolation.
/// </summary>
[Collection(StackCollection.Name)]
public sealed class BusinessFlowTests(IdentityStack stack)
{
    private const string Admin = "admin";
    private static readonly string Run = Guid.NewGuid().ToString("N")[..8];
    private static string Password => $"P@ssw0rd-{Run}";

    private static object NewUser(string username, string role, Dictionary<string, string[]> scopes) => new
    {
        username,
        email = $"{username}@e2e.local",
        firstName = "E2E",
        lastName = "User",
        enabled = true,
        credentials = new { password = Password, temporary = false },
        assignments = new[] { new { role, scopes } },
    };

    private static async Task<JsonElement> JsonAsync(HttpResponseMessage response) =>
        await response.Content.ReadFromJsonAsync<JsonElement>();

    [E2EFact]
    public async Task Super_admin_token_carries_the_gateway_management_permissions()
    {
        var token = await stack.LoginAsync(Admin, Admin);

        var permissions = IdentityStack.Claims(token, "permissions");

        Assert.Contains("identity-gateway:Users:User:Manage", permissions);
        Assert.Contains("identity-gateway:Roles:Role:Manage", permissions);
    }

    [E2EFact]
    public async Task Scoped_user_gets_role_permissions_and_scopes_and_a_consumer_service_enforces_them()
    {
        var admin = await stack.LoginAsync(Admin, Admin);
        var application = $"e2e-orders-{Run}";
        var view = $"{application}:{ConsumerHost.ViewPermission}";
        using (var app = await stack.CallAsync(HttpMethod.Post, "/api/identity/applications", admin,
                   new { clientId = application, displayName = "E2E orders", kind = "service" }))
            Assert.Equal(HttpStatusCode.Created, app.StatusCode);
        using (var permission = await stack.CallAsync(HttpMethod.Post, $"/api/identity/applications/{application}/permissions", admin,
                   new { name = ConsumerHost.ViewPermission, displayName = "View orders" }))
            Assert.Equal(HttpStatusCode.Created, permission.StatusCode);
        var role = $"e2e-clerk-{Run}";
        using (var created = await stack.CallAsync(HttpMethod.Post, "/api/identity/business-roles", admin,
                   new { name = role, permissions = new[] { view } }))
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        using (var user = await stack.CallAsync(HttpMethod.Post, "/api/identity/users", admin,
                   NewUser($"e2e-clerk-{Run}", role, new() { ["region"] = ["tehran"] })))
            Assert.Equal(HttpStatusCode.Created, user.StatusCode);

        var token = await stack.LoginAsync($"e2e-clerk-{Run}", Password);

        Assert.Contains(view, IdentityStack.Claims(token, "permissions"));
        Assert.Contains("tehran", IdentityStack.Claims(token, "authz.scope.region"));
        await using var consumer = await ConsumerHost.StartAsync(stack.Gateway.BaseAddress!, application);
        using var allowed = await stack.CallAsync(HttpMethod.Get, "/api/orders", token, client: consumer.Client);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        using var denied = await stack.CallAsync(HttpMethod.Post, "/api/orders", token, client: consumer.Client);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        using var anonymous = await consumer.Client.GetAsync("/api/orders");
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
    }

    [E2EFact]
    public async Task Delegated_admin_cannot_act_outside_their_scope()
    {
        var admin = await stack.LoginAsync(Admin, Admin);
        var managerRole = $"e2e-manager-{Run}";
        using (var created = await stack.CallAsync(HttpMethod.Post, "/api/identity/business-roles", admin, new
               {
                   name = managerRole,
                   permissions = new[] { "identity-gateway:Users:User:Read", "identity-gateway:Users:User:Manage" },
               }))
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        using (var manager = await stack.CallAsync(HttpMethod.Post, "/api/identity/users", admin,
                   NewUser($"e2e-mgr-{Run}", managerRole, new() { ["region"] = ["tehran"] })))
            Assert.Equal(HttpStatusCode.Created, manager.StatusCode);
        var token = await stack.LoginAsync($"e2e-mgr-{Run}", Password);

        using var inside = await stack.CallAsync(HttpMethod.Post, "/api/identity/users", token,
            NewUser($"e2e-teh-{Run}", managerRole, new() { ["region"] = ["tehran"] }));
        using var outside = await stack.CallAsync(HttpMethod.Post, "/api/identity/users", token,
            NewUser($"e2e-shz-{Run}", managerRole, new() { ["region"] = ["shiraz"] }));

        Assert.Equal(HttpStatusCode.Created, inside.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, outside.StatusCode);
        Assert.Equal("delegation.scope_outside_admin", (await JsonAsync(outside)).GetProperty("code").GetString());
    }

    [E2EFact]
    public async Task Sign_in_outside_the_users_weekly_schedule_is_refused()
    {
        var admin = await stack.LoginAsync(Admin, Admin);
        var role = $"e2e-shift-{Run}";
        using (await stack.CallAsync(HttpMethod.Post, "/api/identity/business-roles", admin, new { name = role, permissions = Array.Empty<string>() })) { }
        using var created = await stack.CallAsync(HttpMethod.Post, "/api/identity/users", admin,
            NewUser($"e2e-shift-{Run}", role, new() { ["region"] = ["tehran"] }));
        var userId = (await JsonAsync(created)).GetProperty("id").GetString();

        // A schedule that allows only a day other than today (in Tehran).
        var otherDay = new[] { "sun", "mon", "tue", "wed", "thu", "fri", "sat" }[
            ((int)TimeZoneInfo.ConvertTime(DateTimeOffset.UtcNow, TimeZoneInfo.FindSystemTimeZoneById("Asia/Tehran")).DayOfWeek + 3) % 7];
        using (var set = await stack.CallAsync(HttpMethod.Put, $"/api/identity/schedules/users/{userId}", admin,
                   new { unrestricted = false, days = new Dictionary<string, string[]> { [otherDay] = ["08:00-16:00"] } }))
            Assert.Equal(HttpStatusCode.OK, set.StatusCode);

        using var refused = await stack.LoginResponseAsync($"e2e-shift-{Run}", Password);
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.Equal("access.outside_schedule", (await JsonAsync(refused)).GetProperty("code").GetString());

        using (await stack.CallAsync(HttpMethod.Put, $"/api/identity/schedules/users/{userId}", admin, new { unrestricted = true })) { }
        using var allowed = await stack.LoginResponseAsync($"e2e-shift-{Run}", Password);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
    }

    [E2EFact]
    public async Task Failed_sign_in_is_recorded_and_counted_in_the_audit_summary()
    {
        var ghost = $"e2e-ghost-{Run}";
        using (var refused = await stack.LoginResponseAsync(ghost, "wrong-password"))
            Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        var admin = await stack.LoginAsync(Admin, Admin);

        using var events = await stack.CallAsync(HttpMethod.Get, "/api/identity/audit/login-events?type=LOGIN_ERROR&max=100", admin);
        using var summary = await stack.CallAsync(HttpMethod.Get, "/api/identity/audit/summary?days=1", admin);
        using var anonymous = await stack.Gateway.GetAsync("/api/identity/audit/summary");

        Assert.Equal(HttpStatusCode.OK, events.StatusCode);
        Assert.Contains((await JsonAsync(events)).EnumerateArray(), e => e.GetProperty("username").GetString() == ghost);
        var s = await JsonAsync(summary);
        Assert.True(s.GetProperty("loginEventsEnabled").GetBoolean());
        Assert.True(s.GetProperty("failedLogins").GetInt32() >= 1);
        Assert.True(s.GetProperty("logins").GetInt32() >= 1);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
    }

    [E2EFact]
    public async Task Each_application_gets_its_own_login_page_and_only_embedded_mode_allows_direct_login()
    {
        var admin = await stack.LoginAsync(Admin, Admin);
        var application = $"e2e-web-{Run}";
        const string callback = "http://localhost:5999/callback";
        string secret;
        using (var created = await stack.CallAsync(HttpMethod.Post, "/api/identity/applications", admin,
                   new { clientId = application, displayName = "E2E web", kind = "web", redirectUris = new[] { callback } }))
        {
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
            secret = (await JsonAsync(created)).GetProperty("clientSecret").GetString()!;
        }
        var loginPage = $"/realms/company/protocol/openid-connect/auth?client_id={application}&redirect_uri={Uri.EscapeDataString(callback)}&response_type=code&scope=openid&ui_locales=fa";
        Task<HttpResponseMessage> SetMode(object body) => stack.CallAsync(HttpMethod.Put, $"/api/identity/applications/{application}/login-page", admin, body);
        async Task<HttpStatusCode> DirectLogin()
        {
            using var response = await stack.Gateway.PostAsync("/api/identity/auth/login", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password", ["client_id"] = application, ["client_secret"] = secret, ["username"] = Admin, ["password"] = Admin,
            }));
            return response.StatusCode;
        }

        using (var branded = await SetMode(new { mode = "branded", branding = new { title = $"سامانه {Run}", primaryColor = "#26428B", background = "plain" } }))
            Assert.Equal(HttpStatusCode.OK, branded.StatusCode);
        var brandedHtml = await stack.Keycloak.GetStringAsync(loginPage);
        Assert.Contains("class=\"avash-brand\"", brandedHtml);
        Assert.Contains($"سامانه {Run}", brandedHtml);
        Assert.Contains("--avash-brand: #26428B", brandedHtml);
        Assert.Equal(HttpStatusCode.BadRequest, await DirectLogin());

        using (var embedded = await SetMode(new { mode = "embedded" }))
            Assert.True((await JsonAsync(embedded)).GetProperty("directLogin").GetBoolean());
        Assert.Equal(HttpStatusCode.OK, await DirectLogin());

        using (await SetMode(new { mode = "inherit" })) { }
        Assert.DoesNotContain("class=\"avash-brand\"", await stack.Keycloak.GetStringAsync(loginPage));
        Assert.Equal(HttpStatusCode.BadRequest, await DirectLogin());
    }

    [E2EFact]
    public async Task Tokens_only_work_for_their_own_tenant()
    {
        var company = await stack.LoginAsync(Admin, Admin);
        var acme = await stack.LoginAsync(Admin, Admin, "acme");

        using var foreign = await stack.CallAsync(HttpMethod.Get, "/api/identity/business-roles", company, tenant: "acme");
        using var own = await stack.CallAsync(HttpMethod.Get, "/api/identity/business-roles", acme, tenant: "acme");
        using var unknown = await stack.CallAsync(HttpMethod.Get, "/api/identity/business-roles", company, tenant: "ghost");

        Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode);
        Assert.Equal(HttpStatusCode.OK, own.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
    }

    [E2EFact]
    public async Task Login_page_settings_belong_to_one_tenant()
    {
        var company = await stack.LoginAsync(Admin, Admin);
        var acme = await stack.LoginAsync(Admin, Admin, "acme");
        var application = $"e2e-tenant-{Run}";
        foreach (var (token, tenant) in new[] { (company, (string?)null), (acme, "acme") })
            using (var created = await stack.CallAsync(HttpMethod.Post, "/api/identity/applications", token,
                       new { clientId = application, displayName = "E2E", kind = "web", redirectUris = new[] { "http://localhost:5999/*" } }, tenant))
                Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        using (var branded = await stack.CallAsync(HttpMethod.Put, $"/api/identity/applications/{application}/login-page", acme,
                   new { mode = "branded", branding = new { title = "Acme", background = "plain" } }, "acme"))
            Assert.Equal(HttpStatusCode.OK, branded.StatusCode);
        using var inCompany = await stack.CallAsync(HttpMethod.Get, $"/api/identity/applications/{application}/login-page", company);
        using var crossTenant = await stack.CallAsync(HttpMethod.Put, $"/api/identity/applications/{application}/login-page", company,
            new { mode = "embedded" }, "acme");

        Assert.Equal("inherit", (await JsonAsync(inCompany)).GetProperty("mode").GetString());
        Assert.Equal(HttpStatusCode.Forbidden, crossTenant.StatusCode);
    }

    [E2EFact]
    public async Task Admin_console_renders_the_chosen_theme_on_the_first_paint()
    {
        using var dark = new HttpRequestMessage(HttpMethod.Get, "/login");
        dark.Headers.Add("Cookie", "avash-theme=dark");
        using var forged = new HttpRequestMessage(HttpMethod.Get, "/login");
        forged.Headers.Add("Cookie", "avash-theme=%22%3E%3Cscript%3E");

        var darkPage = await (await stack.Console.SendAsync(dark)).Content.ReadAsStringAsync();
        var forgedPage = await (await stack.Console.SendAsync(forged)).Content.ReadAsStringAsync();

        Assert.Contains("data-theme=\"dark\"", darkPage);
        Assert.Contains("data-theme=\"system\"", forgedPage); // unknown values fall back, never echoed
        Assert.DoesNotContain("<script>\"", forgedPage);
    }

    [E2EFact]
    public async Task Admin_console_sends_administrators_to_their_tenants_sign_in_page()
    {
        using var login = await stack.Console.GetAsync("/login");
        var page = await login.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.Contains("dir=\"rtl\"", page);
        Assert.Contains("/auth/login/acme", page);
    }
}
