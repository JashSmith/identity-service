using Identity.Application;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Identity.Persistence.EntityFrameworkCore;

public enum IdentityDatabaseProvider
{
    Sqlite,
    PostgreSql,
    Oracle
}

public sealed class IdentityPersistenceOptions
{
    public const string SectionName = "Identity:Persistence";

    public IdentityDatabaseProvider Provider { get; init; } = IdentityDatabaseProvider.Sqlite;
    public string ConnectionString { get; init; } = string.Empty;
}

public static class Registration
{
    public static IServiceCollection AddIdentityPersistence(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var section = configuration.GetSection(IdentityPersistenceOptions.SectionName);
        var provider = ParseProvider(section["Provider"] ?? "sqlite");
        var connectionString = configuration.GetConnectionString("Identity")
            ?? "Data Source=identity.db";
        var configuredConnectionString = section["ConnectionString"];
        if (!string.IsNullOrWhiteSpace(configuredConnectionString))
            connectionString = configuredConnectionString;

        return services.AddIdentityPersistence(new IdentityPersistenceOptions
        {
            Provider = provider,
            ConnectionString = connectionString
        });
    }

    public static IServiceCollection AddIdentityPersistence(
        this IServiceCollection services,
        IdentityPersistenceOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.ConnectionString))
            throw new InvalidOperationException("Identity persistence requires a connection string.");

        services.AddDbContext<IdentityDbContext>(db => ConfigureProvider(db, options));
        services.AddScoped<IUserRepository, EfUserRepository>();
        services.AddScoped<IExternalIdentityLinkRepository, EfExternalIdentityLinkRepository>();
        services.AddScoped<IPasswordCredentialStore, EfPasswordCredentialStore>();
        services.AddScoped<ISessionStore, EfSessionStore>();
        services.AddScoped<IRefreshTokenStore, EfRefreshTokenStore>();
        services.AddScoped<IPermissionRepository, EfPermissionRepository>();
        services.AddScoped<IPermissionManifestVersionStore, EfPermissionManifestVersionStore>();
        services.AddScoped<IUnitOfWork, EfUnitOfWork>();
        return services;
    }

    public static void ConfigureProvider(
        DbContextOptionsBuilder builder,
        IdentityPersistenceOptions options)
    {
        switch (options.Provider)
        {
            case IdentityDatabaseProvider.Sqlite:
                builder.UseSqlite(options.ConnectionString);
                break;
            case IdentityDatabaseProvider.PostgreSql:
                builder.UseNpgsql(options.ConnectionString);
                break;
            case IdentityDatabaseProvider.Oracle:
                builder.UseOracle(options.ConnectionString);
                break;
            default:
                throw new InvalidOperationException($"Unsupported identity database provider: {options.Provider}.");
        }
    }

    public static IdentityDatabaseProvider ParseProvider(string value)
        => value.Trim().ToLowerInvariant() switch
        {
            "sqlite" => IdentityDatabaseProvider.Sqlite,
            "postgres" or "postgresql" or "npgsql" => IdentityDatabaseProvider.PostgreSql,
            "oracle" => IdentityDatabaseProvider.Oracle,
            _ => throw new InvalidOperationException(
                $"Unsupported identity database provider '{value}'. Use sqlite, postgres, or oracle.")
        };
}
