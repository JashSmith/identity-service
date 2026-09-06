using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Identity.Persistence.EntityFrameworkCore;

public sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<IdentityDbContext>
{
    public IdentityDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("IDENTITY_DESIGN_TIME_CONNECTION")
            ?? "Data Source=identity-design-time.db";
        var provider = Registration.ParseProvider(
            Environment.GetEnvironmentVariable("IDENTITY_DESIGN_TIME_PROVIDER") ?? "sqlite");
        var options = new IdentityPersistenceOptions
        {
            Provider = provider,
            ConnectionString = connectionString
        };
        var builder = new DbContextOptionsBuilder<IdentityDbContext>();
        Registration.ConfigureProvider(builder, options);
        return new IdentityDbContext(builder.Options);
    }
}
