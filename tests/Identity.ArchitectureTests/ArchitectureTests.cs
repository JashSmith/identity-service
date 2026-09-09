namespace Identity.ArchitectureTests;

public sealed class ArchitectureTests
{
    [Fact]
    public void Domain_assembly_has_no_transport_or_adapter_references()
    {
        var names = typeof(Identity.Domain.PermissionManifest).Assembly.GetReferencedAssemblies().Select(x => x.Name)
            .ToArray();
        Assert.DoesNotContain("Microsoft.EntityFrameworkCore", names);
        Assert.DoesNotContain("Microsoft.AspNetCore.Http", names);
        Assert.DoesNotContain("Grpc.Core.Api", names);
        Assert.DoesNotContain("Grpc.AspNetCore", names);
    }

    [Fact]
    public void Application_has_no_keycloak_or_ef_or_redis_references()
    {
        var names = typeof(Identity.Application.IUserDirectory).Assembly.GetReferencedAssemblies().Select(x => x.Name)
            .ToArray();
        Assert.DoesNotContain("Microsoft.EntityFrameworkCore", names);
        Assert.DoesNotContain("StackExchange.Redis", names);
        Assert.DoesNotContain("Microsoft.AspNetCore.Http", names);
        Assert.DoesNotContain("Keycloak.AuthServices", names);
    }

    [Fact]
    public void Authentication_has_no_authorization_dependency()
    {
        var names = typeof(Company.Identity.Authentication.IdentityAuthenticationOptions).Assembly
            .GetReferencedAssemblies().Select(x => x.Name).ToArray();
        Assert.DoesNotContain("Company.Identity.Authorization", names);
    }

    [Fact]
    public void Domain_types_surface_is_facade_owned_only()
    {
        var names = typeof(Identity.Domain.PermissionDefinition).Assembly.GetTypes()
            .Where(x => x.Namespace == "Identity.Domain").Select(x => x.Name).ToArray();
        Assert.DoesNotContain("User", names);
        Assert.DoesNotContain("RefreshTokenRecord", names);
        Assert.DoesNotContain("UserSession", names);
    }

    [Fact]
    public void Contracts_have_no_private_key_material()
    {
        var types = typeof(Identity.Contracts.SigningKeyDto).Assembly.GetTypes();
        foreach (var tp in types)
        foreach (var pr in tp.GetProperties())
            Assert.DoesNotContain("private", pr.Name, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Application_has_no_vault_keycloak_ef_redis_grpc()
    {
        var names = typeof(Identity.Application.KeyRotationService).Assembly.GetReferencedAssemblies()
            .Select(x => x.Name).ToArray();
        Assert.DoesNotContain("Identity.Infrastructure.Vault", names);
        Assert.DoesNotContain("Identity.Infrastructure.Keycloak", names);
        Assert.DoesNotContain("Identity.Persistence.KeyManagement", names);
    }
}