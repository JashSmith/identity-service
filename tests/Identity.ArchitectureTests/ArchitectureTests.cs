namespace Identity.ArchitectureTests;

public sealed class ArchitectureTests
{
    [Fact]
    public void Domain_assembly_has_no_transport_or_adapter_references()
    {
        var names = typeof(Identity.Domain.PermissionManifest).Assembly.GetReferencedAssemblies().Select(x => x.Name).ToArray();
        Assert.DoesNotContain("Microsoft.EntityFrameworkCore", names);
        Assert.DoesNotContain("Microsoft.AspNetCore.Http", names);
        Assert.DoesNotContain("Grpc.Core.Api", names);
        Assert.DoesNotContain("Grpc.AspNetCore", names);
    }

    [Fact]
    public void Application_has_no_keycloak_or_ef_or_redis_references()
    {
        var names = typeof(Identity.Application.IUserDirectory).Assembly.GetReferencedAssemblies().Select(x => x.Name).ToArray();
        Assert.DoesNotContain("Microsoft.EntityFrameworkCore", names);
        Assert.DoesNotContain("StackExchange.Redis", names);
        Assert.DoesNotContain("Microsoft.AspNetCore.Http", names);
        Assert.DoesNotContain("Keycloak.AuthServices", names);
    }

    [Fact]
    public void Authentication_has_no_authorization_dependency()
    {
        var names = typeof(Company.Identity.Authentication.IdentityAuthenticationOptions).Assembly.GetReferencedAssemblies().Select(x => x.Name).ToArray();
        Assert.DoesNotContain("Company.Identity.Authorization", names);
    }

    [Fact]
    public void Domain_types_surface_is_facade_owned_only()
    {
        var names = typeof(Identity.Domain.PermissionDefinition).Assembly
            .GetTypes().Where(x => x.Namespace == "Identity.Domain").Select(x => x.Name).ToArray();
        Assert.DoesNotContain("User", names);
        Assert.DoesNotContain("RefreshTokenRecord", names);
        Assert.DoesNotContain("UserSession", names);
    }
}
