using Identity.Application;
using Identity.Application.Settings;
using Identity.Contracts;
using Identity.Gateway.Errors;

namespace Identity.Gateway;

/// <summary>
/// Authentication settings of the tenant realm: tokens and sessions, password policy, brute-force lockout,
/// OTP/MFA, login page options, external identity providers and LDAP/Active Directory federation.
/// </summary>
public static class SettingsEndpoints
{
    public static IEndpointRouteBuilder MapSettings(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/identity/settings").WithTags("Settings");

        MapSetting<TokenSettingsDto>(g, "/tokens", "TokenSettings", (s, ct) => s.GetTokensAsync(ct), (s, v, ct) => s.SetTokensAsync(v, ct));
        MapSetting<PasswordPolicyDto>(g, "/password-policy", "PasswordPolicy", (s, ct) => s.GetPasswordPolicyAsync(ct), (s, v, ct) => s.SetPasswordPolicyAsync(v, ct));
        MapSetting<BruteForceSettingsDto>(g, "/brute-force", "BruteForceSettings", (s, ct) => s.GetBruteForceAsync(ct), (s, v, ct) => s.SetBruteForceAsync(v, ct));
        MapSetting<OtpSettingsDto>(g, "/otp", "OtpSettings", (s, ct) => s.GetOtpAsync(ct), (s, v, ct) => s.SetOtpAsync(v, ct));
        MapSetting<LoginSettingsDto>(g, "/login", "LoginSettings", (s, ct) => s.GetLoginAsync(ct), (s, v, ct) => s.SetLoginAsync(v, ct));

        var idp = g.MapGroup("/identity-providers");
        idp.MapGet("", async (IAuthSettingsService s, CancellationToken ct) =>
                (await s.ListIdentityProvidersAsync(ct)).ToHttpResult(list => Results.Ok(list)))
            .RequireAuthorization(IamPermissions.SettingsRead).WithName("ListIdentityProviders")
            .Produces<IReadOnlyCollection<IdentityProviderDto>>(200);
        idp.MapGet("/{alias}", async (string alias, IAuthSettingsService s, CancellationToken ct) =>
                (await s.GetIdentityProviderAsync(alias, ct)).ToHttpResult(p => Results.Ok(p)))
            .RequireAuthorization(IamPermissions.SettingsRead).WithName("GetIdentityProvider")
            .Produces<IdentityProviderDto>(200).ProducesProblem(404);
        idp.MapPost("", async (IdentityProviderDto req, IAuthSettingsService s, CancellationToken ct) =>
                (await s.CreateIdentityProviderAsync(req, ct)).ToHttpResult(p =>
                    Results.Created($"/api/identity/settings/identity-providers/{Uri.EscapeDataString(p.Alias)}", p)))
            .WithValidation<IdentityProviderDto>()
            .RequireAuthorization(IamPermissions.SettingsManage).WithName("CreateIdentityProvider")
            .Produces<IdentityProviderDto>(201).ProducesProblem(400).ProducesProblem(409);
        idp.MapPut("/{alias}", async (string alias, IdentityProviderDto req, IAuthSettingsService s, CancellationToken ct) =>
                (await s.UpdateIdentityProviderAsync(alias, req, ct)).ToHttpResult(p => Results.Ok(p)))
            .WithValidation<IdentityProviderDto>()
            .RequireAuthorization(IamPermissions.SettingsManage).WithName("UpdateIdentityProvider")
            .Produces<IdentityProviderDto>(200).ProducesProblem(400).ProducesProblem(404);
        idp.MapDelete("/{alias}", async (string alias, IAuthSettingsService s, CancellationToken ct) =>
                (await s.DeleteIdentityProviderAsync(alias, ct)).ToHttpResult(() => Results.NoContent()))
            .RequireAuthorization(IamPermissions.SettingsManage).WithName("DeleteIdentityProvider")
            .Produces(204).ProducesProblem(404);

        var ldap = g.MapGroup("/ldap");
        ldap.MapGet("", async (IAuthSettingsService s, CancellationToken ct) =>
                (await s.ListLdapAsync(ct)).ToHttpResult(list => Results.Ok(list)))
            .RequireAuthorization(IamPermissions.SettingsRead).WithName("ListLdapProviders")
            .Produces<IReadOnlyCollection<LdapProviderDto>>(200);
        ldap.MapGet("/{id}", async (string id, IAuthSettingsService s, CancellationToken ct) =>
                (await s.GetLdapAsync(id, ct)).ToHttpResult(p => Results.Ok(p)))
            .RequireAuthorization(IamPermissions.SettingsRead).WithName("GetLdapProvider")
            .Produces<LdapProviderDto>(200).ProducesProblem(404);
        ldap.MapPost("", async (LdapProviderDto req, IAuthSettingsService s, CancellationToken ct) =>
                (await s.CreateLdapAsync(req, ct)).ToHttpResult(p =>
                    Results.Created($"/api/identity/settings/ldap/{Uri.EscapeDataString(p.Id ?? "")}", p)))
            .WithValidation<LdapProviderDto>()
            .RequireAuthorization(IamPermissions.SettingsManage).WithName("CreateLdapProvider")
            .Produces<LdapProviderDto>(201).ProducesProblem(400);
        ldap.MapPut("/{id}", async (string id, LdapProviderDto req, IAuthSettingsService s, CancellationToken ct) =>
                (await s.UpdateLdapAsync(id, req, ct)).ToHttpResult(p => Results.Ok(p)))
            .WithValidation<LdapProviderDto>()
            .RequireAuthorization(IamPermissions.SettingsManage).WithName("UpdateLdapProvider")
            .Produces<LdapProviderDto>(200).ProducesProblem(400).ProducesProblem(404);
        // Removing a federation also removes the users Keycloak imported from it, so it must be confirmed.
        ldap.MapDelete("/{id}", async (string id, bool? confirm, IAuthSettingsService s, CancellationToken ct) =>
                confirm == true
                    ? (await s.DeleteLdapAsync(id, ct)).ToHttpResult(() => Results.NoContent())
                    : Error.Validation("ldap.confirm_required",
                        "Deleting an LDAP provider also deletes the users imported from it; repeat with ?confirm=true.").ToProblem())
            .RequireAuthorization(IamPermissions.SettingsManage).WithName("DeleteLdapProvider")
            .Produces(204).ProducesProblem(400).ProducesProblem(404);
        ldap.MapPost("/test", async (LdapTestRequest req, IAuthSettingsService s, CancellationToken ct) =>
                (await s.TestLdapAsync(req, ct)).ToHttpResult(() => Results.Ok(new { success = true })))
            .WithValidation<LdapTestRequest>()
            .RequireAuthorization(IamPermissions.SettingsManage).WithName("TestLdapConnection")
            .Produces<object>(200).ProducesProblem(400);
        ldap.MapPost("/{id}/sync", async (string id, string? mode, IAuthSettingsService s, CancellationToken ct) =>
                (await s.SyncLdapAsync(id, mode != "changed", ct)).ToHttpResult(r => Results.Ok(r)))
            .RequireAuthorization(IamPermissions.SettingsManage).WithName("SyncLdapProvider")
            .Produces<LdapSyncResultDto>(200).ProducesProblem(404);

        return app;
    }

    private static void MapSetting<T>(RouteGroupBuilder g, string pattern, string name,
        Func<IAuthSettingsService, CancellationToken, Task<Result<T>>> get,
        Func<IAuthSettingsService, T, CancellationToken, Task<Result>> set)
    {
        g.MapGet(pattern, async (IAuthSettingsService s, CancellationToken ct) => (await get(s, ct)).ToHttpResult(v => Results.Ok(v)))
            .RequireAuthorization(IamPermissions.SettingsRead).WithName($"Get{name}").Produces<T>(200);

        g.MapPut(pattern, async (T body, IAuthSettingsService s, CancellationToken ct) =>
            {
                var written = await set(s, body, ct);
                if (!written.IsSuccess) return written.Error!.ToProblem();
                return (await get(s, ct)).ToHttpResult(v => Results.Ok(v));
            })
            .WithValidation<T>()
            .RequireAuthorization(IamPermissions.SettingsManage).WithName($"Set{name}")
            .Produces<T>(200).ProducesProblem(400);
    }
}
