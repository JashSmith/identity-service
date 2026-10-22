using Identity.Application;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;

namespace Identity.Infrastructure.Redis;

/// <summary>
/// Redis-backed implementation of <see cref="ICacheInvalidationService"/>.
/// Invalidates cached user authorization state, tokens, and role scopes when changes or revocations occur.
/// </summary>
/// <param name="cache">The distributed cache provider.</param>
/// <param name="logger">Logger instance.</param>
public sealed class RedisCacheInvalidator(
    IDistributedCache cache,
    ILogger<RedisCacheInvalidator> logger) : ICacheInvalidationService
{
    private const string UserCachePrefix = "identity:user:";
    private const string RoleCachePrefix = "identity:role:";
    private const string RevokedPrefix = "identity:revoked:";

    /// <summary>
    /// Invalidates all cached authorizations and registers revocation for the specified user in Redis.
    /// </summary>
    /// <param name="userId">The unique user ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task InvalidateUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        try
        {
            // Remove cached user session and permission profiles
            await cache.RemoveAsync($"{UserCachePrefix}{userId}:permissions", cancellationToken);
            await cache.RemoveAsync($"{UserCachePrefix}{userId}:roles", cancellationToken);
            await cache.RemoveAsync($"{UserCachePrefix}{userId}:scopes", cancellationToken);
            await cache.RemoveAsync($"{UserCachePrefix}{userId}:sessions", cancellationToken);

            // Record immediate revocation marker in cache for token introspection fast-path
            var revokedMarker = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            await cache.SetStringAsync(
                $"{RevokedPrefix}{userId}",
                revokedMarker,
                new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(24)
                },
                cancellationToken);

            logger.LogInformation("Invalidated Redis cache and registered token revocation for user '{UserId}'.", userId);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to invalidate Redis cache for user '{UserId}'. Proceeding with best effort.", userId);
        }
    }

    /// <summary>
    /// Invalidates cached role definitions and composite permissions in Redis.
    /// </summary>
    /// <param name="roleName">The business role name.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task InvalidateRoleAsync(string roleName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(roleName);
        try
        {
            await cache.RemoveAsync($"{RoleCachePrefix}{roleName}", cancellationToken);
            await cache.RemoveAsync($"{RoleCachePrefix}{roleName}:permissions", cancellationToken);
            logger.LogInformation("Invalidated Redis cache for role '{RoleName}'.", roleName);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to invalidate Redis cache for role '{RoleName}'. Proceeding with best effort.", roleName);
        }
    }
}
