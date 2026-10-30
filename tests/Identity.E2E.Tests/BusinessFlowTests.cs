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
    public async Task Scoped_user_gets_role_permissions_and_scopes_and_the_sample_service_enforces_them()
    {
        var admin = await stack.LoginAsync(Admin, Admin);
        var role = $"e2e-clerk-{Run}";
        using (var created = await stack.CallAsync(HttpMethod.Post, "/api/identity/business-roles", admin,
                   new { name = role, permissions = new[] { "order-service:Orders:Order:View" } }))
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        using (var user = await stack.CallAsync(HttpMethod.Post, "/api/identity/users", admin,
                   NewUser($"e2e-clerk-{Run}", role, new() { ["region"] = ["tehran"] })))
            Assert.Equal(HttpStatusCode.Created, user.StatusCode);

        var token = await stack.LoginAsync($"e2e-clerk-{Run}", Password);

        Assert.Contains("order-service:Orders:Order:View", IdentityStack.Claims(token, "permissions"));
        Assert.Contains("tehran", IdentityStack.Claims(token, "authz.scope.region"));
        using var allowed = await stack.CallAsync(HttpMethod.Get, "/api/orders", token, client: stack.Sample);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        using var denied = await stack.CallAsync(HttpMethod.Post, "/api/orders?customerUsername=x&total=1", token, client: stack.Sample);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
    }

    [E2EFact]
    public async Task Delegated_admin_cannot_act_outside_their_scope()
    {
        var admin = await stack.LoginAsync(Admin, Admin);
        var managerRole = $"e2e-manager-{Run}";
        using (var created = await stack.CallAsync(HttpMethod.Post, "/api/identity/business-roles", admin, new
               {
                   name = managerRole,
                   permissions = new[] { "identity-gateway:Users:User:Read", "identity-gateway:Users:User:Manage", "order-service:Orders:Order:View" },
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
    public async Task Admin_console_sends_administrators_to_their_tenants_sign_in_page()
    {
        using var login = await stack.Console.GetAsync("/login");
        var page = await login.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.Contains("dir=\"rtl\"", page);
        Assert.Contains("/auth/login/acme", page);
    }
}
