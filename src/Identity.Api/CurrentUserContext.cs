using System.Security.Claims;
using Identity.Application;

namespace Identity.Api;

public sealed class HttpCurrentUserContext(
    IHttpContextAccessor accessor,
    ISystemClock clock) : ICurrentUserContext
{
    private ClaimsPrincipal Principal => accessor.HttpContext?.User ?? new ClaimsPrincipal(new ClaimsIdentity());

    public bool IsAuthenticated => Principal.Identity?.IsAuthenticated == true;
    public Guid? UserId => Guid.TryParse(Principal.FindFirstValue("sub"), out var value) ? value : null;
    public string? Username => Principal.Identity?.Name ?? Principal.FindFirstValue("unique_name");
    public string? DisplayName => Principal.FindFirstValue("name") ?? Username;
    public IReadOnlyCollection<string> Roles => Principal
        .FindAll(ClaimTypes.Role)
        .Concat(Principal.FindAll("role"))
        .Concat(Principal.FindAll("roles"))
        .Select(x => x.Value)
        .Distinct(StringComparer.Ordinal)
        .ToArray();
    public IReadOnlyCollection<string> Permissions => Principal
        .FindAll("permission")
        .Concat(Principal.FindAll("permissions"))
        .Select(x => x.Value)
        .Distinct(StringComparer.Ordinal)
        .ToArray();
    public string? SessionId => Principal.FindFirstValue("sid");
    public DateTimeOffset RequestDateTime => clock.UtcNow;
}
