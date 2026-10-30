using Identity.Application;
using Identity.Infrastructure.Keycloak;
using Identity.Infrastructure.Keycloak.Scope;

namespace Identity.Gateway.Bootstrap;

public static class BootstrapRegistration
{
    /// <summary>
    /// Registers the Keycloak bootstrap: the steps in execution order, the background runner, and its
    /// readiness health check ("keycloak-bootstrap").
    /// </summary>
    public static IServiceCollection AddKeycloakBootstrap(this IServiceCollection services)
    {
        // 1. Scope registry, its user-profile declarations and token mappers.
        services.AddSingleton(new BootstrapStep("scope-registry", (sp, ct) =>
            sp.GetRequiredService<KeycloakScopeRegistryStore>().EnsureRegistryAsync(ct)));

        // 2. The iam_access claim mapper used by consumer services.
        services.AddSingleton(new BootstrapStep("iam-access-claim", (sp, ct) =>
            sp.GetRequiredService<KeycloakIamAccessClaimMapper>().EnsureAsync(ct)));

        // 3. The super-admins group, which must always exist and hold every permission.
        services.AddSingleton(new BootstrapStep("super-admins", (sp, ct) =>
            sp.GetRequiredService<IKeycloakClientRoleProvisioner>().EnsureSuperAdminGroupAsync(ct)));

        // 4. The gateway's own management permissions (identity-gateway:*), granted to super-admins.
        services.AddSingleton(new BootstrapStep("gateway-permissions", (sp, ct) =>
            sp.GetRequiredService<GatewayPermissionRegistrar>().RegisterAsync(typeof(Program).Assembly, ct)));

        // 5. One prefixed permission mapper per application in the shared iam-permissions client scope.
        services.AddSingleton(new BootstrapStep("permission-claims", (sp, ct) =>
            sp.GetRequiredService<Identity.Application.Permissions.IApplicationCatalog>().EnsurePermissionClaimsAsync(ct)));

        services.AddSingleton<KeycloakBootstrapper>();
        services.AddHostedService(sp => sp.GetRequiredService<KeycloakBootstrapper>());
        services.AddHealthChecks().AddCheck<KeycloakBootstrapper>("keycloak-bootstrap", tags: ["ready"]);
        return services;
    }
}
