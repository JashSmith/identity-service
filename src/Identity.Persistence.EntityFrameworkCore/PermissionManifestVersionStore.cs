using Identity.Application;
using Identity.Domain;
using Microsoft.EntityFrameworkCore;

namespace Identity.Persistence.EntityFrameworkCore;

public sealed class EfPermissionManifestVersionStore(IdentityDbContext db) : IPermissionManifestVersionStore
{
    public async Task<bool> TryAcceptAsync(PermissionManifest manifest, CancellationToken cancellationToken)
    {
        var existing = await db.PermissionManifestStates
            .SingleOrDefaultAsync(x => x.ServiceId == manifest.ServiceId, cancellationToken);
        if (existing is not null && !IsNewer(manifest, existing))
            return false;

        if (existing is null)
        {
            await db.PermissionManifestStates.AddAsync(
                new PermissionManifestState(
                    manifest.ServiceId,
                    manifest.ServiceName,
                    manifest.ManifestVersion,
                    manifest.CorrelationId,
                    manifest.PublishedAt),
                cancellationToken);
        }
        else
        {
            existing.Accept(
                manifest.ServiceId,
                manifest.ManifestVersion,
                manifest.CorrelationId,
                manifest.PublishedAt);
            db.PermissionManifestStates.Update(existing);
        }

        // The scoped DbContext is committed by the permission repository after the
        // manifest and its version are updated together.
        return true;
    }

    private static bool IsNewer(PermissionManifest manifest, PermissionManifestState existing)
    {
        if (string.Equals(existing.ManifestVersion, manifest.ManifestVersion, StringComparison.Ordinal))
            return false;
        if (Version.TryParse(existing.ManifestVersion, out var current) && Version.TryParse(manifest.ManifestVersion, out var incoming))
            return incoming > current;
        return manifest.PublishedAt > existing.PublishedAt;
    }
}
