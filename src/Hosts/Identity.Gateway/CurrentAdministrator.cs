using Identity.Application;

namespace Identity.Gateway;

/// <summary>The caller of the current HTTP request as an administrator; super-admin membership is read once per request.</summary>
public sealed class HttpCurrentAdministrator(ICurrentUserContext user, IUserDirectory directory) : ICurrentAdministrator
{
    private Result<bool>? _isSuperAdmin;

    public string? UserId => user.UserId;

    public IReadOnlyCollection<string> Permissions => user.Permissions;

    public async Task<Result<bool>> IsSuperAdminAsync(CancellationToken ct)
    {
        if (UserId is null) return false;
        return _isSuperAdmin ??= await directory.IsSuperAdminAsync(UserId, ct);
    }
}
