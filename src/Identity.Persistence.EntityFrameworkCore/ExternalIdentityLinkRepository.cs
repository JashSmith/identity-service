using Identity.Application;
using Identity.Domain;
using Microsoft.EntityFrameworkCore;

namespace Identity.Persistence.EntityFrameworkCore;

public sealed class EfExternalIdentityLinkRepository(IdentityDbContext db) : IExternalIdentityLinkRepository
{
    public Task<ExternalIdentityLink?> FindAsync(
        string provider,
        string subject,
        CancellationToken cancellationToken)
        => db.ExternalIdentityLinks.SingleOrDefaultAsync(
            x => x.Provider == provider && x.Subject == subject,
            cancellationToken);

    public async Task<IReadOnlyCollection<ExternalIdentityLink>> FindForUserAsync(
        UserId userId,
        CancellationToken cancellationToken)
        => await db.ExternalIdentityLinks
            .Where(x => x.UserId == userId)
            .ToArrayAsync(cancellationToken);

    public async Task AddAsync(ExternalIdentityLink link, CancellationToken cancellationToken)
    {
        await db.ExternalIdentityLinks.AddAsync(link, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task SaveAsync(ExternalIdentityLink link, CancellationToken cancellationToken)
    {
        db.ExternalIdentityLinks.Update(link);
        await db.SaveChangesAsync(cancellationToken);
    }
}