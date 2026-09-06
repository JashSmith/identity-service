using Company.Identity.Authentication;
using Identity.Application;

namespace Identity.Api;

public sealed class BffSessionValidator(
    ISessionStore sessions,
    IUserRepository users,
    ISystemClock clock) : IBffSessionValidator
{
    public async Task<bool> ValidateAsync(
        string sessionId,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(sessionId, out var id))
            return false;

        var session = await sessions.FindAsync(id, cancellationToken);
        if (session is null)
            return false;

        var now = clock.UtcNow;
        if (!session.IsActive(now))
            return false;

        var user = await users.FindAsync(session.UserId, cancellationToken);
        return user is not null &&
               user.IsEnabled &&
               !user.IsLocked(now) &&
               string.Equals(session.SecurityStamp, user.SecurityStamp, StringComparison.Ordinal);
    }
}