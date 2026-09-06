using Identity.Domain;
using Identity.Persistence.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Identity.Persistence.EntityFrameworkCore.Tests;

public sealed class IdentityDbContextTests
{
    [Fact]
    public async Task External_identity_provider_and_subject_are_unique()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = CreateContext(connection);
        await db.Database.EnsureCreatedAsync();

        db.ExternalIdentityLinks.Add(new ExternalIdentityLink(
            Guid.NewGuid(), UserId.New(), "oidc", "subject-1", DateTimeOffset.UtcNow));
        await db.SaveChangesAsync();

        db.ExternalIdentityLinks.Add(new ExternalIdentityLink(
            Guid.NewGuid(), UserId.New(), "oidc", "subject-1", DateTimeOffset.UtcNow));

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public void Security_lookup_indexes_are_present_in_the_model()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        using var db = CreateContext(connection);
        var model = db.Model;

        var sessionIndexes = model.FindEntityType(typeof(UserSession))!.GetIndexes();
        Assert.Contains(sessionIndexes, index =>
            index.Properties.Select(property => property.Name)
                .SequenceEqual([nameof(UserSession.UserId), nameof(UserSession.RevokedAt)]));

        var refreshIndexes = model.FindEntityType(typeof(RefreshTokenRecord))!.GetIndexes();
        Assert.Contains(refreshIndexes, index =>
            index.Properties.Select(property => property.Name)
                .SequenceEqual([nameof(RefreshTokenRecord.FamilyId), nameof(RefreshTokenRecord.RevokedAt)]));

        var externalIndexes = model.FindEntityType(typeof(ExternalIdentityLink))!.GetIndexes();
        Assert.Contains(externalIndexes, index =>
            index.IsUnique && index.Properties.Select(property => property.Name)
                .SequenceEqual([nameof(ExternalIdentityLink.Provider), nameof(ExternalIdentityLink.Subject)]));
    }

    private static IdentityDbContext CreateContext(SqliteConnection connection)
    {
        var options = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlite(connection)
            .Options;
        return new IdentityDbContext(options);
    }
}
