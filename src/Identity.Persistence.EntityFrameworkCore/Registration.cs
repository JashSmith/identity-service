using Identity.Application;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
namespace Identity.Persistence.EntityFrameworkCore;
public static class Registration
{
    public static IServiceCollection AddIdentityPersistence(this IServiceCollection services, string connectionString, bool useSqlite = false)
    {
        if (useSqlite) services.AddDbContext<IdentityDbContext>(o => o.UseSqlite(connectionString));
        else services.AddDbContext<IdentityDbContext>(o => o.UseNpgsql(connectionString));
        services.AddScoped<IUserRepository, EfUserRepository>();
        services.AddScoped<IPasswordCredentialStore, EfPasswordCredentialStore>();
        services.AddScoped<ISessionStore, EfSessionStore>();
        services.AddScoped<IRefreshTokenStore, EfRefreshTokenStore>();
        services.AddScoped<IPermissionRepository, EfPermissionRepository>();
        return services;
    }
}
