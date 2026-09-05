using Identity.Domain;
using Microsoft.EntityFrameworkCore;

namespace Identity.Persistence.EntityFrameworkCore;

public sealed class IdentityDbContext(DbContextOptions<IdentityDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<PasswordCredential> PasswordCredentials => Set<PasswordCredential>();
    public DbSet<UserSession> Sessions => Set<UserSession>();
    public DbSet<RefreshTokenRecord> RefreshTokens => Set<RefreshTokenRecord>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<Permission> Permissions => Set<Permission>();
    public DbSet<UserPermission> UserPermissions => Set<UserPermission>();
    public DbSet<UserRole> UserRoles => Set<UserRole>();
    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();
    public DbSet<PermissionManifestState> PermissionManifestStates => Set<PermissionManifestState>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(b =>
        {
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasConversion(x => x.Value, x => new UserId(x));
            b.Property(x => x.Username).HasMaxLength(256).IsRequired();
            b.HasIndex(x => x.Username).IsUnique();
            b.Property(x => x.SecurityStamp).HasMaxLength(64).IsRequired();
            b.Ignore(x => x.Roles); b.Ignore(x => x.DirectPermissions);
        });
        modelBuilder.Entity<PasswordCredential>(b =>
        {
            b.HasKey(x => x.UserId);
            b.Property(x => x.UserId).HasConversion(x => x.Value, x => new UserId(x));
            b.Property(x => x.PasswordHash).HasMaxLength(512).IsRequired();
        });
        modelBuilder.Entity<UserSession>(b =>
        {
            b.HasKey(x => x.Id);
            b.Property(x => x.UserId).HasConversion(x => x.Value, x => new UserId(x));
            b.HasIndex(x => new { x.UserId, x.RevokedAt });
            b.HasIndex(x => x.ExpiresAt);
        });
        modelBuilder.Entity<RefreshTokenRecord>(b =>
        {
            b.HasKey(x => x.Id);
            b.Property(x => x.UserId).HasConversion(x => x.Value, x => new UserId(x));
            b.Property(x => x.TokenHash).HasMaxLength(128).IsRequired();
            b.Property(x => x.FamilyId).HasMaxLength(64).IsRequired();
            b.HasIndex(x => x.TokenHash).IsUnique();
            b.HasIndex(x => new { x.FamilyId, x.RevokedAt });
        });
        modelBuilder.Entity<Role>(b =>
        {
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasConversion(x => x.Value, x => new RoleId(x));
            b.Property(x => x.Name).HasMaxLength(128).IsRequired(); b.HasIndex(x => x.Name).IsUnique(); b.Ignore(x => x.Permissions);
        });
        modelBuilder.Entity<UserPermission>(b =>
        {
            b.HasKey(x => new { x.UserId, x.PermissionId });
            b.Property(x => x.UserId).HasConversion(x => x.Value, x => new UserId(x));
            b.Property(x => x.PermissionId).HasConversion(x => x.Value, x => new PermissionId(x));
        });
        modelBuilder.Entity<UserRole>(b =>
        {
            b.HasKey(x => new { x.UserId, x.RoleId });
            b.Property(x => x.UserId).HasConversion(x => x.Value, x => new UserId(x));
            b.Property(x => x.RoleId).HasConversion(x => x.Value, x => new RoleId(x));
        });
        modelBuilder.Entity<RolePermission>(b =>
        {
            b.HasKey(x => new { x.RoleId, x.PermissionId });
            b.Property(x => x.RoleId).HasConversion(x => x.Value, x => new RoleId(x));
            b.Property(x => x.PermissionId).HasConversion(x => x.Value, x => new PermissionId(x));
        });
        modelBuilder.Entity<PermissionManifestState>(b =>
        {
            b.HasKey(x => x.ServiceId);
            b.Property(x => x.ServiceId).HasMaxLength(128).IsRequired();
            b.Property(x => x.ServiceName).HasMaxLength(128).IsRequired();
            b.Property(x => x.ManifestVersion).HasMaxLength(64).IsRequired();
            b.HasIndex(x => new { x.ServiceName, x.ManifestVersion });
        });
        modelBuilder.Entity<Permission>(b =>
        {
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasConversion(x => x.Value, x => new PermissionId(x));
            b.Property(x => x.Name).HasMaxLength(200).IsRequired(); b.HasIndex(x => new { x.ServiceName, x.Name }).IsUnique();
            b.Property(x => x.ServiceName).HasMaxLength(128).IsRequired(); b.Property(x => x.Version).HasMaxLength(64).IsRequired();
        });
    }
}
