using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Identity.Persistence.EntityFrameworkCore;

public sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<IdentityDbContext>
{
    public IdentityDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("IDENTITY_DESIGN_TIME_CONNECTION")
            ?? "Data Source=identity-design-time.db";
        var provider = Environment.GetEnvironmentVariable("IDENTITY_DESIGN_TIME_PROVIDER")
            ?? "sqlite";

        var builder = new DbContextOptionsBuilder<IdentityDbContext>();
        if (string.Equals(provider, "postgres", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(provider, "postgresql", StringComparison.OrdinalIgnoreCase))
        {
            builder.UseNpgsql(connectionString);
        }
        else
        {
            builder.UseSqlite(connectionString);
        }

        return new IdentityDbContext(builder.Options);
    }
}
